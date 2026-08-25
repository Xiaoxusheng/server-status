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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/p4gefau1t/trojan-go/api/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TrojanConfig 定义 Trojan-Go API 客户端运行参数。
type TrojanConfig struct {
	Enabled         bool          `json:"enabled"`
	APIAddr         string        `json:"api_addr"`
	APITimeout      time.Duration `json:"-"`
	RefreshInterval time.Duration `json:"-"`
}

// TrojanFileConfig 对应 config.json 中 "trojan" 段（超时/间隔以秒为单位）。
type TrojanFileConfig struct {
	Enabled         *bool  `json:"enabled"`
	APIAddr         string `json:"api_addr"`
	APITimeout      int    `json:"api_timeout"`
	RefreshInterval int    `json:"refresh_interval"`
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

// loadTrojanConfig 依次从默认值、config.json、环境变量加载 Trojan-Go 配置。
// config.json 与 private_notes.json 使用同一根目录（SERVER_STATUS_HOME 或 /opt/server-status）。
func loadTrojanConfig() TrojanConfig {
	cfg := TrojanConfig{
		Enabled:         true,
		APIAddr:         "127.0.0.1:10000",
		APITimeout:      5 * time.Second,
		RefreshInterval: 2 * time.Second,
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
	wasConnected := c.status.Connected
	c.status = status
	c.mu.Unlock()
	if !wasConnected {
		log.Printf("Trojan-Go API connection restored")
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
	trojanClient.refresh()
	writeJSON(w, http.StatusOK, "Trojan-Go 用户更新成功", nil)
}
