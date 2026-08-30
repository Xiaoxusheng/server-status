package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/p4gefau1t/trojan-go/api/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TrojanConfig 定义 Trojan-Go API 客户端运行参数。
type TrojanConfig struct {
	Enabled         bool                   `json:"enabled"`
	APIAddr         string                 `json:"api_addr"`
	APITimeout      time.Duration          `json:"-"`
	RefreshInterval time.Duration          `json:"-"`
	Connection      TrojanConnectionConfig `json:"-"`
}

// TrojanConnectionConfig 客户端连接配置（对外暴露给用户生成配置）。
type TrojanConnectionConfig struct {
	Server    string                `json:"server"`
	Port      int                   `json:"port"`
	TLS       bool                  `json:"tls"`
	SNI       string                `json:"sni"`
	WebSocket TrojanWebSocketConfig `json:"websocket"`
	UDP       bool                  `json:"udp"`
	LanCIDR   string                `json:"lan_cidr"`
}

// TrojanWebSocketConfig WebSocket 传输配置。
type TrojanWebSocketConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	Host    string `json:"host"`
}

// TrojanFileConfig 对应 config.json 中 "trojan" 段（超时/间隔以秒为单位）。
type TrojanFileConfig struct {
	Enabled         *bool                   `json:"enabled"`
	APIAddr         string                  `json:"api_addr"`
	APITimeout      int                     `json:"api_timeout"`
	RefreshInterval int                     `json:"refresh_interval"`
	Connection      *TrojanConnectionConfig `json:"connection"`
}

// TrojanJSON 与项目现有 JSON 配置文件风格一致（类似 private_notes.json）。
type TrojanJSON struct {
	Trojan TrojanFileConfig `json:"trojan"`
}

// TrojanUser 是面向前端的 Trojan-Go 用户状态模型。
type TrojanUser struct {
	Hash          string `json:"hash"`
	Online        bool   `json:"online"`
	IPCurrent     int32  `json:"ip_current"`
	IPLimit       int32  `json:"ip_limit"`
	UploadSpeed   uint64 `json:"upload_speed"`
	DownloadSpeed uint64 `json:"download_speed"`
	UploadTotal   uint64 `json:"upload_total"`
	DownloadTotal uint64 `json:"download_total"`
	UploadLimit   uint64 `json:"upload_limit"`
	DownloadLimit uint64 `json:"download_limit"`
}

// TrojanStatus 是面向 API 和 WebSocket 的 Trojan-Go 总体状态模型。
type TrojanStatus struct {
	Enabled       bool         `json:"enabled"`
	Connected     bool         `json:"connected"`
	Uptime        string       `json:"uptime,omitempty"`
	OnlineUsers   int          `json:"online_users"`
	OnlineIPs     int          `json:"online_ips"`
	UploadSpeed   uint64       `json:"upload_speed"`
	DownloadSpeed uint64       `json:"download_speed"`
	UploadTotal   uint64       `json:"upload_total"`
	DownloadTotal uint64       `json:"download_total"`
	Timestamp     time.Time    `json:"timestamp"`
	Users         []TrojanUser `json:"users"`
}

// TrojanUserRequest 是添加和修改用户的 HTTP 请求模型。
// upload_limit / download_limit 单位为 B/s（前端负责把 MB/s 转换为字节）。
type TrojanUserRequest struct {
	Hash          string `json:"hash"`
	Password      string `json:"password"`
	UploadLimit   uint64 `json:"upload_limit"`
	DownloadLimit uint64 `json:"download_limit"`
	IPLimit       int32  `json:"ip_limit"`
}

// TrojanClient 复用单个 gRPC 连接并缓存最新 Trojan-Go 状态。
type TrojanClient struct {
	cfg       TrojanConfig
	mu        sync.RWMutex
	conn      *grpc.ClientConn
	status    TrojanStatus
	lastError time.Time
	closed    atomic.Bool
}

var trojanClient *TrojanClient

// TrojanCredential 存储 Trojan 用户档案：密码明文 + 限速/IP 限额。
// 它是 Trojan-Go 重启后恢复用户的唯一数据源（v0.10.6 用户表在内存里，重启即清空）。
type TrojanCredential struct {
	Hash          string `json:"hash"`
	Password      string `json:"password"`
	IPLimit       int32  `json:"ip_limit,omitempty"`
	UploadLimit   uint64 `json:"upload_limit,omitempty"`
	DownloadLimit uint64 `json:"download_limit,omitempty"`
}

// TrojanCredentialStore 凭据存储文件结构
type TrojanCredentialStore struct {
	Credentials []TrojanCredential `json:"credentials"`
}

// trojanCredMu 串行化凭据文件的读改写，避免并发请求与后台恢复流程互相覆盖丢数据
var trojanCredMu sync.Mutex

// trojanCredentialsFilePath 返回凭据存储文件路径
func trojanCredentialsFilePath() string {
	return filepath.Join(privateRoot(), "trojan_credentials.json")
}

// loadTrojanCredentials 加载存储的凭据
func loadTrojanCredentials() (*TrojanCredentialStore, error) {
	path := trojanCredentialsFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &TrojanCredentialStore{Credentials: []TrojanCredential{}}, nil
		}
		return nil, err
	}
	var store TrojanCredentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return &store, nil
}

// saveTrojanCredentials 保存凭据到文件（设置 0600 权限保证安全）
func saveTrojanCredentials(store *TrojanCredentialStore) error {
	path := trojanCredentialsFilePath()
	jsonData, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return err
	}
	return nil
}

// getTrojanCredential 根据 hash 获取密码
func getTrojanCredential(hash string) (string, bool) {
	store, err := loadTrojanCredentials()
	if err != nil {
		return "", false
	}
	for _, cred := range store.Credentials {
		if cred.Hash == hash {
			return cred.Password, true
		}
	}
	return "", false
}

// setTrojanCredential 添加/更新凭据（补录密码场景：已存在的档案保留限额，避免恢复时降级）
func setTrojanCredential(hash, password string) error {
	trojanCredMu.Lock()
	defer trojanCredMu.Unlock()
	store, err := loadTrojanCredentials()
	if err != nil {
		return err
	}
	// 查找并替换
	found := false
	for i := range store.Credentials {
		if store.Credentials[i].Hash == hash {
			store.Credentials[i].Password = password
			found = true
			break
		}
	}
	if !found {
		store.Credentials = append(store.Credentials, TrojanCredential{Hash: hash, Password: password})
	}
	return saveTrojanCredentials(store)
}

// upsertTrojanUserRecord 保存完整用户档案（密码 + 限速/IP 限额），供重启后恢复用户
func upsertTrojanUserRecord(hash, password string, ipLimit int32, uploadLimit, downloadLimit uint64) error {
	trojanCredMu.Lock()
	defer trojanCredMu.Unlock()
	store, err := loadTrojanCredentials()
	if err != nil {
		return err
	}
	for i := range store.Credentials {
		if store.Credentials[i].Hash == hash {
			store.Credentials[i].IPLimit = ipLimit
			store.Credentials[i].UploadLimit = uploadLimit
			store.Credentials[i].DownloadLimit = downloadLimit
			if password != "" {
				store.Credentials[i].Password = password
			}
			return saveTrojanCredentials(store)
		}
	}
	store.Credentials = append(store.Credentials, TrojanCredential{
		Hash:          hash,
		Password:      password,
		IPLimit:       ipLimit,
		UploadLimit:   uploadLimit,
		DownloadLimit: downloadLimit,
	})
	return saveTrojanCredentials(store)
}

// updateTrojanUserLimits 把限速/IP 限制的变更同步到本地档案（仅更新已记录用户）
func updateTrojanUserLimits(hash string, ipLimit int32, uploadLimit, downloadLimit uint64) error {
	trojanCredMu.Lock()
	defer trojanCredMu.Unlock()
	store, err := loadTrojanCredentials()
	if err != nil {
		return err
	}
	for i := range store.Credentials {
		if store.Credentials[i].Hash == hash {
			store.Credentials[i].IPLimit = ipLimit
			store.Credentials[i].UploadLimit = uploadLimit
			store.Credentials[i].DownloadLimit = downloadLimit
			return saveTrojanCredentials(store)
		}
	}
	return nil
}

// deleteTrojanCredential 删除凭据
func deleteTrojanCredential(hash string) error {
	trojanCredMu.Lock()
	defer trojanCredMu.Unlock()
	store, err := loadTrojanCredentials()
	if err != nil {
		return err
	}
	newCreds := make([]TrojanCredential, 0, len(store.Credentials))
	for _, cred := range store.Credentials {
		if cred.Hash != hash {
			newCreds = append(newCreds, cred)
		}
	}
	store.Credentials = newCreds
	return saveTrojanCredentials(store)
}

// loadTrojanConfig 依次从默认值、config.json、环境变量加载 Trojan-Go 配置。
// config.json 与 private_notes.json 使用同一根目录（SERVER_STATUS_HOME 或 /opt/server-status）。
func loadTrojanConfig() TrojanConfig {
	cfg := TrojanConfig{
		Enabled:         true,
		APIAddr:         "127.0.0.1:10000",
		APITimeout:      5 * time.Second,
		RefreshInterval: 2 * time.Second,
		Connection: TrojanConnectionConfig{
			Server: "example.com",
			Port:   8388,
			TLS:    true,
			SNI:    "example.com",
			WebSocket: TrojanWebSocketConfig{
				Enabled: true,
				Path:    "/ws",
				Host:    "example.com",
			},
			UDP:     true,
			LanCIDR: "192.168.1.0/24",
		},
	}
	loadTrojanJSON(privateRoot(), &cfg)

	if value := os.Getenv("SERVER_STATUS_TROJAN_ENABLED"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Enabled = parsed
		}
	}
	if value := os.Getenv("SERVER_STATUS_TROJAN_API_ADDR"); value != "" {
		cfg.APIAddr = value
	}
	if value := os.Getenv("SERVER_STATUS_TROJAN_API_TIMEOUT"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			cfg.APITimeout = time.Duration(seconds) * time.Second
		}
	}
	if value := os.Getenv("SERVER_STATUS_TROJAN_REFRESH_INTERVAL"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			cfg.RefreshInterval = time.Duration(seconds) * time.Second
		}
	}
	return cfg
}

// loadTrojanJSON 读取 config.json 中的 "trojan" 段并合并进默认配置。
func loadTrojanJSON(baseDir string, cfg *TrojanConfig) {
	data, err := os.ReadFile(filepath.Join(baseDir, "config.json"))
	if err != nil {
		return
	}
	var fileCfg TrojanJSON
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		log.Printf("⚠️ config.json 解析失败，使用默认 Trojan-Go 配置: %v", err)
		return
	}
	if fileCfg.Trojan.Enabled != nil {
		cfg.Enabled = *fileCfg.Trojan.Enabled
	}
	if fileCfg.Trojan.APIAddr != "" {
		cfg.APIAddr = fileCfg.Trojan.APIAddr
	}
	if fileCfg.Trojan.APITimeout > 0 {
		cfg.APITimeout = time.Duration(fileCfg.Trojan.APITimeout) * time.Second
	}
	if fileCfg.Trojan.RefreshInterval > 0 {
		cfg.RefreshInterval = time.Duration(fileCfg.Trojan.RefreshInterval) * time.Second
	}
	// 加载连接配置（覆盖默认值）
	if fileCfg.Trojan.Connection != nil {
		cc := fileCfg.Trojan.Connection
		if cc.Server != "" {
			cfg.Connection.Server = cc.Server
		}
		if cc.Port > 0 {
			cfg.Connection.Port = cc.Port
		}
		cfg.Connection.TLS = cc.TLS
		if cc.SNI != "" {
			cfg.Connection.SNI = cc.SNI
		}
		if cc.WebSocket.Enabled {
			cfg.Connection.WebSocket.Enabled = true
		}
		if cc.WebSocket.Path != "" {
			cfg.Connection.WebSocket.Path = cc.WebSocket.Path
		}
		if cc.WebSocket.Host != "" {
			cfg.Connection.WebSocket.Host = cc.WebSocket.Host
		}
		cfg.Connection.UDP = cc.UDP
		if cc.LanCIDR != "" {
			cfg.Connection.LanCIDR = cc.LanCIDR
		}
	}
}

// newTrojanClient 创建客户端并启动定时刷新协程。
func newTrojanClient() *TrojanClient {
	client := &TrojanClient{cfg: loadTrojanConfig()}
	client.status = TrojanStatus{Enabled: client.cfg.Enabled, Timestamp: time.Now(), Users: []TrojanUser{}}
	if client.cfg.Enabled {
		log.Printf("Trojan-Go 客户端已启用，API: %s，刷新间隔: %v", client.cfg.APIAddr, client.cfg.RefreshInterval)
		go client.refreshLoop()
	} else {
		log.Println("Trojan-Go 客户端未启用（config.json 中 trojan.enabled=false）")
	}
	return client
}

// refreshLoop 定期从 Trojan-Go 获取状态，并在断开时保留可用的离线快照。
func (c *TrojanClient) refreshLoop() {
	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()
	c.refresh()
	for range ticker.C {
		if c.closed.Load() {
			return
		}
		c.refresh()
	}
}

// refresh 执行一次有超时保护的用户状态采集。
func (c *TrojanClient) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.APITimeout)
	defer cancel()
	users, err := c.listUsers(ctx)
	if err != nil {
		c.setOffline(err)
		return
	}
	c.mu.RLock()
	wasConnected := c.status.Connected
	c.mu.RUnlock()
	if !wasConnected {
		// Trojan-Go 刚恢复连接（或面板首次连上）：其用户表存于内存、重启即清空，
		// 按本地档案对齐——补发缺失用户，并把服务端已有用户记入档案。
		c.reconcileTrojanUsers(users)
		// 恢复的用户不在本次快照里，重取一次让状态立即完整
		if refreshed, listErr := c.listUsers(ctx); listErr == nil {
			users = refreshed
		}
	}
	var status TrojanStatus
	status.Enabled = true
	status.Connected = true
	status.Timestamp = time.Now()
	status.Users = users
	for _, user := range users {
		if user.Online {
			status.OnlineUsers++
		}
		status.OnlineIPs += int(user.IPCurrent)
		status.UploadSpeed += user.UploadSpeed
		status.DownloadSpeed += user.DownloadSpeed
		status.UploadTotal += user.UploadTotal
		status.DownloadTotal += user.DownloadTotal
	}
	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
	if !wasConnected {
		log.Printf("Trojan-Go API connection restored")
	}
}

// reconcileTrojanUsers 在连接恢复时对齐 Trojan-Go 用户表与本地档案（trojanCredMu 全程持有，
// 防止与并发的用户变更请求互相覆盖）。触发时机仅为离线→在线转换（Trojan-Go 重启或面板冷启动）。
func (c *TrojanClient) reconcileTrojanUsers(live []TrojanUser) {
	trojanCredMu.Lock()
	defer trojanCredMu.Unlock()
	store, err := loadTrojanCredentials()
	if err != nil {
		log.Printf("Trojan 用户档案读取失败，跳过恢复: %v", err)
		return
	}
	byHash := make(map[string]*TrojanCredential, len(store.Credentials))
	for i := range store.Credentials {
		byHash[store.Credentials[i].Hash] = &store.Credentials[i]
	}

	// merge：把服务端已有但本地未记录的用户写入档案（含手动在 trojan-go 侧创建的用户），
	// 已记录但限额全零而服务端非零的（旧版凭据文件升级），用服务端现值补齐。
	changed := false
	for _, u := range live {
		if rec, ok := byHash[u.Hash]; ok {
			if rec.IPLimit == 0 && rec.UploadLimit == 0 && rec.DownloadLimit == 0 &&
				(u.IPLimit != 0 || u.UploadLimit != 0 || u.DownloadLimit != 0) {
				rec.IPLimit, rec.UploadLimit, rec.DownloadLimit = u.IPLimit, u.UploadLimit, u.DownloadLimit
				changed = true
			}
			continue
		}
		store.Credentials = append(store.Credentials, TrojanCredential{
			Hash:          u.Hash,
			IPLimit:       u.IPLimit,
			UploadLimit:   u.UploadLimit,
			DownloadLimit: u.DownloadLimit,
		})
		byHash[u.Hash] = &store.Credentials[len(store.Credentials)-1]
		changed = true
	}
	if changed {
		if err := saveTrojanCredentials(store); err != nil {
			log.Printf("Trojan 用户档案保存失败: %v", err)
		}
	}

	// restore：本地已记录而服务端缺失的用户重新下发（Add 语义）
	liveSet := make(map[string]bool, len(live))
	for _, u := range live {
		liveSet[u.Hash] = true
	}
	restored := 0
	for _, rec := range store.Credentials {
		if liveSet[rec.Hash] {
			continue
		}
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), c.cfg.APITimeout)
		err := c.setUser(restoreCtx, TrojanUserRequest{
			Hash:          rec.Hash,
			IPLimit:       rec.IPLimit,
			UploadLimit:   rec.UploadLimit,
			DownloadLimit: rec.DownloadLimit,
		}, service.SetUsersRequest_Add)
		restoreCancel()
		if err != nil {
			// 已存在等错误按失败记录，下轮离线→在线转换会再次尝试
			log.Printf("Trojan 用户恢复失败 hash=%s: %v", rec.Hash, err)
			continue
		}
		restored++
	}
	if restored > 0 {
		log.Printf("Trojan 用户已按本地档案恢复: %d 个", restored)
	}
}

// listUsers 调用 v0.10.6 官方 ListUsers 流式 RPC。
func (c *TrojanClient) listUsers(ctx context.Context) ([]TrojanUser, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := service.NewTrojanServerServiceClient(conn).ListUsers(ctx, &service.ListUsersRequest{})
	if err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	users := make([]TrojanUser, 0)
	for {
		response, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			return users, nil
		}
		if recvErr != nil {
			return nil, recvErr
		}
		if response != nil && response.Status != nil {
			users = append(users, mapTrojanUser(response.Status))
		}
	}
}

// connection 建立并复用到 Trojan-Go API 的 gRPC 连接（程序生命周期内只创建一次）。
func (c *TrojanClient) connection(ctx context.Context) (*grpc.ClientConn, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn != nil {
		return conn, nil
	}
	newConn, err := grpc.DialContext(ctx, c.cfg.APIAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.conn == nil {
		c.conn = newConn
		conn = newConn
	} else {
		conn = c.conn
		_ = newConn.Close()
	}
	c.mu.Unlock()
	return conn, nil
}

// setOffline 标记 API 离线并按 30 秒间隔记录错误（避免刷屏）。
// 保留最后一次成功拉取的用户快照，前端可据此展示“API Offline”而非空白页。
func (c *TrojanClient) setOffline(err error) {
	c.mu.Lock()
	wasConnected := c.status.Connected
	shouldLog := wasConnected || time.Since(c.lastError) >= 30*time.Second
	c.status.Enabled = c.cfg.Enabled
	c.status.Connected = false
	c.status.Timestamp = time.Now()
	c.lastError = time.Now()
	c.mu.Unlock()
	if shouldLog {
		log.Printf("Trojan-Go API offline: %v", err)
	}
}

// snapshot 返回线程安全的 Trojan-Go 状态副本。
func (c *TrojanClient) snapshot() TrojanStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	status := c.status
	status.Users = append([]TrojanUser(nil), c.status.Users...)
	return status
}

// close 释放 gRPC 连接及后台刷新资源。
func (c *TrojanClient) close() error {
	c.closed.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// mapTrojanUser 将官方 UserStatus 映射为前端模型，使用官方 IpCurrent/IpLimit 字段。
func mapTrojanUser(status *service.UserStatus) TrojanUser {
	user := TrojanUser{IPCurrent: status.IpCurrent, IPLimit: status.IpLimit}
	if status.User != nil {
		user.Hash = status.User.Hash
	}
	if status.TrafficTotal != nil {
		user.UploadTotal = status.TrafficTotal.UploadTraffic
		user.DownloadTotal = status.TrafficTotal.DownloadTraffic
	}
	if status.SpeedCurrent != nil {
		user.UploadSpeed = status.SpeedCurrent.UploadSpeed
		user.DownloadSpeed = status.SpeedCurrent.DownloadSpeed
	}
	if status.SpeedLimit != nil {
		user.UploadLimit = status.SpeedLimit.UploadSpeed
		user.DownloadLimit = status.SpeedLimit.DownloadSpeed
	}
	// 在线判定：IpCurrent > 0 为权威信号；Trojan-Go v0.10.6 在 ip_limit=0（不限）时
	// 内存统计不会记录 IP，导致 IpCurrent 恒为 0，此时以实时速度兜底，避免
	// “客户端在跑流量但页面显示 Offline”的矛盾。
	user.Online = user.IPCurrent > 0 || user.UploadSpeed > 0 || user.DownloadSpeed > 0
	return user
}

// trojanHash 根据 Trojan-Go v0.10.6 规则计算密码 SHA-224 哈希。
func trojanHash(password string) string {
	hash := sha256.New224()
	_, _ = hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// setUser 调用官方 SetUsers 双向流式 RPC 执行增删改。
// 注意：v0.10.6 的 Modify 只支持修改限速/流量/IP 限制，不支持修改密码。
func (c *TrojanClient) setUser(ctx context.Context, req TrojanUserRequest, operation service.SetUsersRequest_Operation) error {
	conn, err := c.connection(ctx)
	if err != nil {
		return err
	}
	stream, err := service.NewTrojanServerServiceClient(conn).SetUsers(ctx)
	if err != nil {
		return err
	}
	hash := req.Hash
	if hash == "" {
		hash = trojanHash(req.Password)
	}
	user := &service.User{Hash: hash}
	if req.Password != "" {
		user.Password = req.Password
	}
	status := &service.UserStatus{User: user, IpLimit: req.IPLimit}
	// 注意：v0.10.6 服务端在 Add 时只有 SpeedLimit 非空才会应用 IpLimit，
	// 因此即使限速为 0 也必须显式携带 SpeedLimit。
	status.SpeedLimit = &service.Speed{UploadSpeed: req.UploadLimit, DownloadSpeed: req.DownloadLimit}
	if err := stream.Send(&service.SetUsersRequest{Status: status, Operation: operation}); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	response, err := stream.Recv()
	if err != nil {
		return err
	}
	if !response.Success {
		return fmt.Errorf("trojan-go: %s", response.Info)
	}
	return nil
}

// trojanStatusHandler 返回 Trojan-Go 当前状态快照。
func trojanStatusHandler(w http.ResponseWriter, r *http.Request) {
	if trojanClient == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Trojan-Go 客户端未初始化")
		return
	}
	writeJSON(w, http.StatusOK, "获取 Trojan-Go 状态成功", trojanClient.snapshot())
}

// trojanUsersHandler 返回 Trojan-Go 用户列表快照。
func trojanUsersHandler(w http.ResponseWriter, r *http.Request) {
	if trojanClient == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Trojan-Go 客户端未初始化")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), trojanClient.cfg.APITimeout)
	defer cancel()
	users, err := trojanClient.listUsers(ctx)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "获取 Trojan-Go 用户失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "获取 Trojan-Go 用户成功", users)
}

// trojanUserMutationHandler 根据 HTTP 方法调用 Trojan-Go 官方 SetUsers 流式 RPC。
func trojanUserMutationHandler(w http.ResponseWriter, r *http.Request) {
	if trojanClient == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Trojan-Go 客户端未初始化")
		return
	}
	var req TrojanUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	var operation service.SetUsersRequest_Operation
	switch r.Method {
	case http.MethodPost:
		if req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "添加用户必须提供 password")
			return
		}
		operation = service.SetUsersRequest_Add
	case http.MethodPut:
		if req.Hash == "" && req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "修改用户必须提供 hash 或 password")
			return
		}
		operation = service.SetUsersRequest_Modify
	case http.MethodDelete:
		if req.Hash == "" && req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "删除用户必须提供 hash 或 password")
			return
		}
		operation = service.SetUsersRequest_Delete
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), trojanClient.cfg.APITimeout)
	defer cancel()
	if err := trojanClient.setUser(ctx, req, operation); err != nil {
		writeJSONError(w, http.StatusBadGateway, "更新 Trojan-Go 用户失败: "+err.Error())
		return
	}
	// 保存完整档案（密码 + 限额），作为 Trojan-Go 重启后的恢复数据源
	if operation == service.SetUsersRequest_Add {
		hash := req.Hash
		if hash == "" {
			hash = trojanHash(req.Password)
		}
		if err := upsertTrojanUserRecord(hash, req.Password, req.IPLimit, req.UploadLimit, req.DownloadLimit); err != nil {
			log.Printf("Trojan credential save failed: %v", err)
		} else {
			log.Printf("Trojan user created: hash=%s", hash)
		}
	}
	// 修改限速/IP 限制时同步到本地档案，保证恢复时使用最新限额
	if operation == service.SetUsersRequest_Modify {
		hash := req.Hash
		if hash == "" {
			hash = trojanHash(req.Password)
		}
		if err := updateTrojanUserLimits(hash, req.IPLimit, req.UploadLimit, req.DownloadLimit); err != nil {
			log.Printf("Trojan limits persist failed: %v", err)
		}
	}
	// 删除用户时同步删除凭据
	if operation == service.SetUsersRequest_Delete {
		hash := req.Hash
		if hash == "" {
			hash = trojanHash(req.Password)
		}
		if err := deleteTrojanCredential(hash); err != nil {
			log.Printf("Trojan credential delete failed: %v", err)
		} else {
			log.Printf("Trojan user deleted: hash=%s", hash)
		}
	}
	trojanClient.refresh()
	// Trojan 用户变更高危操作，记录审计（detail 中不包含密码明文）
	auditAction(r, "trojan.user."+strings.ToLower(operation.String()),
		fmt.Sprintf("hash=%s ip_limit=%d", req.Hash, req.IPLimit))
	writeJSON(w, http.StatusOK, "Trojan-Go 用户更新成功", nil)
}

// TrojanConnectionInfo 返回给前端展示的连接信息。
type TrojanConnectionInfo struct {
	Name      string `json:"name"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	TLS       bool   `json:"tls"`
	SNI       string `json:"sni"`
	Transport string `json:"transport"`
	WSPath    string `json:"ws_path"`
	WSHost    string `json:"ws_host"`
	UDP       bool   `json:"udp"`
	LanCIDR   string `json:"lan_cidr"`
	TrojanURI string `json:"trojan_uri"`
	Clash     string `json:"clash"`
	Singbox   string `json:"singbox"`
}

// generateTrojanURI 生成符合客户端兼容格式的 Trojan URI。
// 密码中的特殊字符（@#?&% 空格中文等）需要 URL 编码。
func generateTrojanURI(name, server string, port int, password, sni, wsPath, wsHost string, tls, udp, wsEnabled bool) string {
	encodedPassword := url.QueryEscape(password)
	// QueryEscape 会把空格编码为 +，Trojan URI 需要 %20
	encodedPassword = strings.ReplaceAll(encodedPassword, "+", "%20")

	var uri strings.Builder
	uri.WriteString("trojan://")
	uri.WriteString(encodedPassword)
	uri.WriteString("@")

	// IPv6 地址需要加方括号
	if strings.Contains(server, ":") {
		uri.WriteString("[")
		uri.WriteString(server)
		uri.WriteString("]")
	} else {
		uri.WriteString(server)
	}
	uri.WriteString(":")
	uri.WriteString(strconv.Itoa(port))

	// 查询参数
	params := make([]string, 0, 6)
	if tls {
		params = append(params, "security=tls")
	}
	if sni != "" {
		params = append(params, "sni="+url.QueryEscape(sni))
	}
	if wsEnabled {
		params = append(params, "type=ws")
		if wsPath != "" {
			params = append(params, "path="+url.QueryEscape(wsPath))
		}
		if wsHost != "" {
			params = append(params, "host="+url.QueryEscape(wsHost))
		}
	}
	if udp {
		params = append(params, "udp=1")
	}

	if len(params) > 0 {
		uri.WriteString("?")
		uri.WriteString(strings.Join(params, "&"))
	}

	// fragment（名称）
	if name != "" {
		uri.WriteString("#")
		uri.WriteString(url.QueryEscape(name))
	}

	return uri.String()
}

// generateClashYAML 生成 Clash/Meta 兼容的 YAML 配置片段。
func generateClashYAML(name, server string, port int, password, sni, wsPath, wsHost, lanCIDR string, udp, wsEnabled bool) string {
	var buf strings.Builder
	buf.WriteString("proxies:\n")
	buf.WriteString(fmt.Sprintf("  - name: %q\n", name))
	buf.WriteString("    type: trojan\n")
	buf.WriteString(fmt.Sprintf("    server: %s\n", server))
	buf.WriteString(fmt.Sprintf("    port: %d\n", port))
	buf.WriteString(fmt.Sprintf("    password: %q\n", password))
	if sni != "" {
		buf.WriteString(fmt.Sprintf("    sni: %s\n", sni))
	}
	if udp {
		buf.WriteString("    udp: true\n")
	}
	if wsEnabled {
		buf.WriteString("    network: ws\n")
		buf.WriteString("    ws-opts:\n")
		if wsPath != "" {
			buf.WriteString(fmt.Sprintf("      path: %s\n", wsPath))
		}
		if wsHost != "" {
			buf.WriteString("      headers:\n")
			buf.WriteString(fmt.Sprintf("        Host: %s\n", wsHost))
		}
	}
	// 添加家庭局域网分流规则
	if lanCIDR != "" {
		buf.WriteString("\nrules:\n")
		buf.WriteString(fmt.Sprintf("  - IP-CIDR,%s,%s\n", lanCIDR, name))
		buf.WriteString(fmt.Sprintf("  - MATCH,%s\n", name))
	}
	return buf.String()
}

// generateSingboxJSON 生成 sing-box 兼容的 JSON 配置片段。
func generateSingboxJSON(name, server string, port int, password, sni, wsPath, wsHost string, udp, wsEnabled bool) string {
	outbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         name,
		"server":      server,
		"server_port": port,
		"password":    password,
	}
	if udp {
		outbound["udp"] = true
	}
	tlsConfig := map[string]interface{}{}
	if tlsConfig["enabled"] = true; sni != "" {
		tlsConfig["server_name"] = sni
	}
	outbound["tls"] = tlsConfig
	if wsEnabled {
		wsConfig := map[string]interface{}{
			"type": "ws",
		}
		if wsPath != "" {
			wsConfig["path"] = wsPath
		}
		if wsHost != "" {
			wsConfig["headers"] = map[string]interface{}{
				"Host": wsHost,
			}
		}
		outbound["transport"] = wsConfig
	}
	jsonData, err := json.MarshalIndent(outbound, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(jsonData)
}

// trojanConnectionHandler 返回指定用户的完整连接信息（受 RBAC 保护）。
// 密码仅在此受保护 API 中返回，不出现在用户列表和 WebSocket 中。
func trojanConnectionHandler(w http.ResponseWriter, r *http.Request) {
	if trojanClient == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Trojan-Go 客户端未初始化")
		return
	}
	hash := r.PathValue("hash")
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户 hash 参数")
		return
	}

	// 获取密码凭据
	password, ok := getTrojanCredential(hash)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "该用户缺少连接凭据，请重新创建用户")
		return
	}

	// 获取用户名（从缓存中找 hash）
	status := trojanClient.snapshot()
	userName := hash
	for _, u := range status.Users {
		if u.Hash == hash {
			userName = u.Hash
			break
		}
	}

	cfg := trojanClient.cfg.Connection
	conn := TrojanConnectionInfo{
		Name:      userName,
		Server:    cfg.Server,
		Port:      cfg.Port,
		Password:  password,
		TLS:       cfg.TLS,
		SNI:       cfg.SNI,
		Transport: "ws",
		WSPath:    cfg.WebSocket.Path,
		WSHost:    cfg.WebSocket.Host,
		UDP:       cfg.UDP,
		LanCIDR:   cfg.LanCIDR,
	}

	// 生成 Trojan URI
	conn.TrojanURI = generateTrojanURI(
		userName, cfg.Server, cfg.Port, password, cfg.SNI,
		cfg.WebSocket.Path, cfg.WebSocket.Host,
		cfg.TLS, cfg.UDP, cfg.WebSocket.Enabled,
	)

	// 生成 Clash 配置
	conn.Clash = generateClashYAML(
		userName, cfg.Server, cfg.Port, password, cfg.SNI,
		cfg.WebSocket.Path, cfg.WebSocket.Host, cfg.LanCIDR,
		cfg.UDP, cfg.WebSocket.Enabled,
	)

	// 生成 sing-box 配置
	conn.Singbox = generateSingboxJSON(
		userName, cfg.Server, cfg.Port, password, cfg.SNI,
		cfg.WebSocket.Path, cfg.WebSocket.Host,
		cfg.UDP, cfg.WebSocket.Enabled,
	)

	writeJSON(w, http.StatusOK, "获取连接信息成功", conn)
}

// trojanCredentialHandler 补录/更新用户密码凭据。
// 仅写入 server-status 的凭据存储（trojan_credentials.json），不调用 Trojan-Go。
// 用于解决历史用户缺少凭据、无法生成连接配置的问题，避免删除重建丢流量数据。
func trojanCredentialHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户 hash 参数")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "密码不能为空")
		return
	}
	// 校验 hash 与该密码匹配（Trojan-Go 用户 hash = SHA224(密码)），防止给错误用户写入错误密码
	if trojanHash(req.Password) != hash {
		writeJSONError(w, http.StatusBadRequest, "密码与用户不匹配，请填写该用户创建时设置的密码")
		return
	}
	if err := setTrojanCredential(hash, req.Password); err != nil {
		log.Printf("Trojan credential save failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "凭据保存失败")
		return
	}
	log.Printf("Trojan credential updated: hash=%s", hash)
	auditAction(r, "trojan.credential.update", "hash="+hash)
	writeJSON(w, http.StatusOK, "凭据已保存", nil)
}

// hasRouteToLAN 判断服务器是否存在到达 lanCIDR 的可用路由。
// 1) 本地网卡地址直接位于该网段（server-status/Trojan-Go 就在家庭局域网内）；
// 2) Linux /proc/net/route（IPv4）存在覆盖该网段的路由表项（含默认路由）。
// 返回 (是否有路由, 说明)。不伪造成功：未发现路由时返回明确提示句。
func hasRouteToLAN(lanCIDR string) (bool, string) {
	_, lanNet, err := net.ParseCIDR(lanCIDR)
	if err != nil {
		return false, "CIDR 无效: " + lanCIDR
	}
	// 1. 本地网卡是否直接位于该网段
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && lanNet.Contains(ip) {
					return true, "主机位于该网段"
				}
			}
		}
	}
	// 2. Linux IPv4 路由表（/proc/net/route）
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		if checkLinuxRouteTable(string(data), lanNet.IP) {
			return true, "存在路由表项"
		}
	}
	return false, "当前服务器没有发现到家庭局域网 " + lanCIDR + " 的可用路由"
}

// checkLinuxRouteTable 解析 /proc/net/route 文本，判断是否存在覆盖 targetIP 的路由表项。
// 字段均为小端十六进制：Destination(1)、Mask(7)。默认路由 0.0.0.0/0 也视为存在路由。
func checkLinuxRouteTable(content string, targetIP net.IP) bool {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // 表头
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		dest, err := strconv.ParseUint(fields[1], 16, 32)
		if err != nil {
			continue
		}
		maskVal, err := strconv.ParseUint(fields[7], 16, 32)
		if err != nil {
			continue
		}
		destIP := net.IPv4(byte(dest), byte(dest>>8), byte(dest>>16), byte(dest>>24))
		maskBytes := net.IPv4Mask(byte(maskVal), byte(maskVal>>8), byte(maskVal>>16), byte(maskVal>>24))
		routeNet := &net.IPNet{IP: destIP.Mask(maskBytes), Mask: maskBytes}
		if routeNet.Contains(targetIP) {
			return true
		}
	}
	return false
}

// trojanConnectionTestHandler 测试 Trojan-Go 连接状态。
func trojanConnectionTestHandler(w http.ResponseWriter, r *http.Request) {
	if trojanClient == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Trojan-Go 客户端未初始化")
		return
	}

	results := make([]map[string]interface{}, 0)

	// 1. 检查 Trojan-Go API 状态
	status := trojanClient.snapshot()
	apiOK := status.Connected
	results = append(results, map[string]interface{}{
		"name":    "Trojan-Go API",
		"status":  apiOK,
		"message": fmt.Sprintf("Trojan-Go API %s", map[bool]string{true: "正常", false: "离线"}[apiOK]),
	})

	// 2. 检查 Trojan-Go 服务状态
	serviceOK := status.Enabled
	results = append(results, map[string]interface{}{
		"name":    "Trojan-Go 服务",
		"status":  serviceOK,
		"message": fmt.Sprintf("Trojan-Go 服务 %s", map[bool]string{true: "运行中", false: "未启用"}[serviceOK]),
	})

	// 3. 检查端口监听（本地回环同时尝试 IPv4 与 IPv6，兼容 local_addr 绑定 "::" 的情况）
	portCheckOK := false
	port := trojanClient.cfg.Connection.Port
	for _, addr := range []string{"127.0.0.1", "[::1]"} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, port), 3*time.Second)
		if err == nil {
			conn.Close()
			portCheckOK = true
			break
		}
	}
	results = append(results, map[string]interface{}{
		"name":    "端口监听",
		"status":  portCheckOK,
		"message": fmt.Sprintf("端口 %d %s", port, map[bool]string{true: "正在监听", false: "未监听"}[portCheckOK]),
	})

	// 4. 检查到家庭局域网的路由（不伪造成功：未发现路由时明确提示）
	// 优先使用请求中的 lan_cidr（弹窗内自定义网段），否则回退到配置值
	lanCIDR := trojanClient.cfg.Connection.LanCIDR
	if cidr := r.URL.Query().Get("lan_cidr"); cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err == nil {
			lanCIDR = cidr
		} else {
			writeJSONError(w, http.StatusBadRequest, "家庭局域网 CIDR 无效")
			return
		}
	}
	lanOK := false
	lanMsg := "未配置家庭局域网"
	if lanCIDR != "" {
		lanOK, lanMsg = hasRouteToLAN(lanCIDR)
		if lanOK {
			lanMsg = "家庭局域网 " + lanCIDR + " 路由正常（" + lanMsg + "）"
		}
	}
	results = append(results, map[string]interface{}{
		"name":    "家庭局域网路由",
		"status":  lanOK,
		"message": lanMsg,
	})

	writeJSON(w, http.StatusOK, "连接测试完成", results)
}

// trojanClashDownloadHandler 下载 Clash 配置。
func trojanClashDownloadHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户 hash 参数")
		return
	}
	password, ok := getTrojanCredential(hash)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "该用户缺少连接凭据")
		return
	}
	cfg := trojanClient.cfg.Connection
	// 根据连接模式决定是否附加家庭局域网分流规则。
	// 优先使用请求中的 lan_cidr（弹窗内自定义网段），否则回退到配置 lan=true 逻辑。
	lanCIDR := ""
	if cidr := r.URL.Query().Get("lan_cidr"); cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err == nil {
			lanCIDR = cidr
		} else {
			writeJSONError(w, http.StatusBadRequest, "家庭局域网 CIDR 无效")
			return
		}
	} else if r.URL.Query().Get("lan") == "true" {
		lanCIDR = cfg.LanCIDR
	}
	clash := generateClashYAML(
		hash, cfg.Server, cfg.Port, password, cfg.SNI,
		cfg.WebSocket.Path, cfg.WebSocket.Host, lanCIDR,
		cfg.UDP, cfg.WebSocket.Enabled,
	)
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-clash.yaml"`, hash))
	_, _ = w.Write([]byte(clash))
}

// trojanSingboxDownloadHandler 下载 sing-box 配置。
func trojanSingboxDownloadHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户 hash 参数")
		return
	}
	password, ok := getTrojanCredential(hash)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "该用户缺少连接凭据")
		return
	}
	cfg := trojanClient.cfg.Connection
	singbox := generateSingboxJSON(
		hash, cfg.Server, cfg.Port, password, cfg.SNI,
		cfg.WebSocket.Path, cfg.WebSocket.Host,
		cfg.UDP, cfg.WebSocket.Enabled,
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-singbox.json"`, hash))
	_, _ = w.Write([]byte(singbox))
}
