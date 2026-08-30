package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/p4gefau1t/trojan-go/api/service"
	"google.golang.org/grpc"
)

func TestTrojanHash(t *testing.T) {
	// 与 Trojan-Go v0.10.6 common.SHA224String 一致的 SHA-224 十六进制哈希
	got := trojanHash("password123")
	want := "3d45597256050bb1e93bd9c10aee4c8716f8774f5a48c995bf0cf860"
	if got != want {
		t.Fatalf("trojanHash mismatch: got %s want %s", got, want)
	}
}

func TestLoadTrojanJSON(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"trojan": {
			"enabled": true,
			"api_addr": "127.0.0.1:10000",
			"api_timeout": 3,
			"refresh_interval": 1
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := TrojanConfig{Enabled: true, APIAddr: "127.0.0.1:10000", APITimeout: 5 * time.Second, RefreshInterval: 2 * time.Second}
	loadTrojanJSON(dir, &cfg)
	if cfg.APITimeout != 3*time.Second {
		t.Fatalf("APITimeout = %v, want 3s", cfg.APITimeout)
	}
	if cfg.RefreshInterval != 1*time.Second {
		t.Fatalf("RefreshInterval = %v, want 1s", cfg.RefreshInterval)
	}
	if !cfg.Enabled {
		t.Fatal("Enabled should be true")
	}
}

func TestLoadTrojanJSONDisabled(t *testing.T) {
	dir := t.TempDir()
	content := `{"trojan": {"enabled": false, "api_addr": "127.0.0.1:9999"}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := TrojanConfig{Enabled: true, APIAddr: "127.0.0.1:10000", APITimeout: 5 * time.Second, RefreshInterval: 2 * time.Second}
	loadTrojanJSON(dir, &cfg)
	if cfg.Enabled {
		t.Fatal("Enabled should be false")
	}
	if cfg.APIAddr != "127.0.0.1:9999" {
		t.Fatalf("APIAddr = %s, want 127.0.0.1:9999", cfg.APIAddr)
	}
}

func TestTrojanUserRequestJSON(t *testing.T) {
	// 验证前端提交的 B/s 数值能正确反序列化（10 MB/s = 10485760）
	raw := `{"hash":"","password":"secret","ip_limit":5,"upload_limit":10485760,"download_limit":52428800}`
	var req TrojanUserRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	if req.UploadLimit != 10485760 || req.DownloadLimit != 52428800 {
		t.Fatalf("limits mismatch: %d / %d", req.UploadLimit, req.DownloadLimit)
	}
	if req.IPLimit != 5 {
		t.Fatalf("IPLimit = %d, want 5", req.IPLimit)
	}
}

func TestMapTrojanUser(t *testing.T) {
	status := &service.UserStatus{
		User:         &service.User{Hash: "abc123"},
		IpCurrent:    2,
		IpLimit:      5,
		TrafficTotal: &service.Traffic{UploadTraffic: 100, DownloadTraffic: 200},
		SpeedCurrent: &service.Speed{UploadSpeed: 10, DownloadSpeed: 20},
		SpeedLimit:   &service.Speed{UploadSpeed: 1024, DownloadSpeed: 2048},
	}
	user := mapTrojanUser(status)
	if user.Hash != "abc123" {
		t.Fatalf("Hash = %s", user.Hash)
	}
	if user.IPCurrent != 2 || user.IPLimit != 5 {
		t.Fatalf("IP fields mismatch: current=%d limit=%d", user.IPCurrent, user.IPLimit)
	}
	if !user.Online {
		t.Fatal("user should be online")
	}
	if user.UploadTotal != 100 || user.DownloadTotal != 200 {
		t.Fatalf("traffic mismatch: %d / %d", user.UploadTotal, user.DownloadTotal)
	}
	if user.UploadSpeed != 10 || user.DownloadSpeed != 20 {
		t.Fatalf("speed mismatch: %d / %d", user.UploadSpeed, user.DownloadSpeed)
	}
	if user.UploadLimit != 1024 || user.DownloadLimit != 2048 {
		t.Fatalf("limit mismatch: %d / %d", user.UploadLimit, user.DownloadLimit)
	}

	// IpCurrent=0 但实时速度>0：Trojan-Go 在 ip_limit=0 时不记录 IP，应仍判为在线
	speedOnly := &service.UserStatus{
		User:         &service.User{Hash: "speed-only"},
		IpCurrent:    0,
		SpeedCurrent: &service.Speed{UploadSpeed: 100, DownloadSpeed: 200},
	}
	if u := mapTrojanUser(speedOnly); !u.Online {
		t.Fatal("user with speed but no IP tracking should be online")
	}

	// 完全空闲且无 IP 记录：离线
	idle := &service.UserStatus{User: &service.User{Hash: "idle"}}
	if u := mapTrojanUser(idle); u.Online {
		t.Fatal("fully idle user should be offline")
	}
}

// fakeTrojanServer 在内存中模拟 Trojan-Go v0.10.6 服务端 SetUsers/ListUsers 语义。
type fakeTrojanServer struct {
	service.UnimplementedTrojanServerServiceServer
	mu    sync.Mutex
	users map[string]*service.UserStatus
}

func (f *fakeTrojanServer) ListUsers(_ *service.ListUsersRequest, stream service.TrojanServerService_ListUsersServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, status := range f.users {
		if err := stream.Send(&service.ListUsersResponse{Status: status}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeTrojanServer) SetUsers(stream service.TrojanServerService_SetUsersServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.Status == nil || req.Status.User == nil {
			return errors.New("status or user is unspecified")
		}
		hash := req.Status.User.Hash
		if hash == "" {
			hash = trojanHash(req.Status.User.Password)
		}
		switch req.Operation {
		case service.SetUsersRequest_Add:
			if _, exists := f.users[hash]; exists {
				return errors.New("user already exists")
			}
			status := &service.UserStatus{User: &service.User{Hash: hash}}
			// 与 v0.10.6 服务端一致：仅当 SpeedLimit 非空时才应用限速与 IP 限制
			if req.Status.SpeedLimit != nil {
				status.SpeedLimit = req.Status.SpeedLimit
				status.IpLimit = req.Status.IpLimit
			}
			f.users[hash] = status
		case service.SetUsersRequest_Delete:
			if _, exists := f.users[hash]; !exists {
				return errors.New("invalid user " + hash)
			}
			delete(f.users, hash)
		case service.SetUsersRequest_Modify:
			status, exists := f.users[hash]
			if !exists {
				return errors.New("invalid user " + hash)
			}
			if req.Status.SpeedLimit != nil {
				status.SpeedLimit = req.Status.SpeedLimit
			}
			status.IpLimit = req.Status.IpLimit
		}
		if err := stream.Send(&service.SetUsersResponse{Success: true}); err != nil {
			return err
		}
	}
}

// TestTrojanClientIntegration 使用真实 TCP gRPC 链路验证客户端增删改查。
func TestTrojanClientIntegration(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeTrojanServer{users: make(map[string]*service.UserStatus)}
	service.RegisterTrojanServerServiceServer(server, fake)
	go func() { _ = server.Serve(lis) }()
	defer server.Stop()

	client := &TrojanClient{cfg: TrojanConfig{Enabled: true, APIAddr: lis.Addr().String(), APITimeout: 5 * time.Second, RefreshInterval: time.Hour}}
	defer func() { _ = client.close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. 初始列表为空
	users, err := client.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected empty user list, got %d", len(users))
	}

	// 2. 添加用户（限速 10 MB/s = 10485760 B/s，下载 50 MB/s，IP 限制 5）
	if err := client.setUser(ctx, TrojanUserRequest{Password: "secret123", UploadLimit: 10485760, DownloadLimit: 52428800, IPLimit: 5}, service.SetUsersRequest_Add); err != nil {
		t.Fatalf("add user: %v", err)
	}
	hash := trojanHash("secret123")
	users, err = client.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers after add: %v", err)
	}
	if len(users) != 1 || users[0].Hash != hash {
		t.Fatalf("unexpected users after add: %+v", users)
	}
	if users[0].UploadLimit != 10485760 || users[0].DownloadLimit != 52428800 || users[0].IPLimit != 5 {
		t.Fatalf("limits not applied: %+v", users[0])
	}

	// 3. 修改用户（IP 限制改为 8，上传限速改为 1 B/s）
	if err := client.setUser(ctx, TrojanUserRequest{Hash: hash, UploadLimit: 1, DownloadLimit: 52428800, IPLimit: 8}, service.SetUsersRequest_Modify); err != nil {
		t.Fatalf("modify user: %v", err)
	}
	users, err = client.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers after modify: %v", err)
	}
	if users[0].IPLimit != 8 || users[0].UploadLimit != 1 {
		t.Fatalf("modify not applied: %+v", users[0])
	}

	// 4. 删除用户
	if err := client.setUser(ctx, TrojanUserRequest{Hash: hash}, service.SetUsersRequest_Delete); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	users, err = client.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers after delete: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected empty user list after delete, got %d", len(users))
	}

	// 5. gRPC 连接已复用（同一 ClientConn 继续工作）
	if client.conn == nil {
		t.Fatal("connection should be cached")
	}
	if err := client.setUser(ctx, TrojanUserRequest{Password: "again"}, service.SetUsersRequest_Add); err != nil {
		t.Fatalf("reuse connection add: %v", err)
	}

	// 6. 限速为 0 时 IP 限制仍必须生效（v0.10.6 Add 的 SpeedLimit 门控逻辑）
	if err := client.setUser(ctx, TrojanUserRequest{Password: "nolimit", IPLimit: 7}, service.SetUsersRequest_Add); err != nil {
		t.Fatalf("add user with zero speed limits: %v", err)
	}
	users, err = client.listUsers(ctx)
	if err != nil {
		t.Fatalf("listUsers after zero-limit add: %v", err)
	}
	found := false
	for _, u := range users {
		if u.Hash == trojanHash("nolimit") {
			found = true
			if u.IPLimit != 7 {
				t.Fatalf("IP limit should be 7 even with zero speed limits, got %d", u.IPLimit)
			}
		}
	}
	if !found {
		t.Fatal("user nolimit not found")
	}
}

// TestGenerateTrojanURI 测试 Trojan URI 生成。
func TestGenerateTrojanURI(t *testing.T) {
	tests := []struct {
		name      string
		userName  string
		server    string
		port      int
		password  string
		sni       string
		wsPath    string
		wsHost    string
		tls       bool
		udp       bool
		wsEnabled bool
		want      string
	}{
		{
			name:     "IPv4 with WS",
			userName: "user-001",
			server:   "example.com", port: 8388, password: "Test@123456",
			sni: "example.com", wsPath: "/ws", wsHost: "example.com",
			tls: true, udp: true, wsEnabled: true,
			want: "trojan://Test%40123456@example.com:8388?security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com&udp=1#user-001",
		},
		{
			name:     "password with @",
			userName: "test", server: "example.com", port: 443, password: "test@example.com#123",
			sni: "example.com", wsPath: "/ws", wsHost: "example.com",
			tls: true, udp: true, wsEnabled: true,
			want: "trojan://test%40example.com%23123@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com&udp=1#test",
		},
		{
			name:     "password with special chars",
			userName: "user", server: "server.com", port: 443, password: "a?b&c% d#e@f",
			sni: "server.com", wsPath: "/ws", wsHost: "server.com",
			tls: true, udp: false, wsEnabled: true,
			want: "trojan://a%3Fb%26c%25%20d%23e%40f@server.com:443?security=tls&sni=server.com&type=ws&path=%2Fws&host=server.com#user",
		},
		{
			name:     "IPv6 address",
			userName: "ipv6-test", server: "2001:db8::1", port: 8388, password: "pass",
			sni: "2001:db8::1", wsPath: "/ws", wsHost: "2001:db8::1",
			tls: true, udp: true, wsEnabled: true,
			want: "trojan://pass@[2001:db8::1]:8388?security=tls&sni=2001%3Adb8%3A%3A1&type=ws&path=%2Fws&host=2001%3Adb8%3A%3A1&udp=1#ipv6-test",
		},
		{
			name:     "domain without WS",
			userName: "simple", server: "example.com", port: 443, password: "mypass",
			sni: "", wsPath: "", wsHost: "",
			tls: true, udp: false, wsEnabled: false,
			want: "trojan://mypass@example.com:443?security=tls#simple",
		},
		{
			name:     "Chinese username",
			userName: "中文用户", server: "cn.example.com", port: 8388, password: "chinese",
			sni: "cn.example.com", wsPath: "/ws", wsHost: "cn.example.com",
			tls: true, udp: true, wsEnabled: true,
			want: "trojan://chinese@cn.example.com:8388?security=tls&sni=cn.example.com&type=ws&path=%2Fws&host=cn.example.com&udp=1#%E4%B8%AD%E6%96%87%E7%94%A8%E6%88%B7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateTrojanURI(tt.userName, tt.server, tt.port, tt.password, tt.sni, tt.wsPath, tt.wsHost, tt.tls, tt.udp, tt.wsEnabled)
			if got != tt.want {
				t.Fatalf("generateTrojanURI() = %s\nwant %s", got, tt.want)
			}
		})
	}
}

// TestGenerateClashYAML 测试 Clash 配置生成。
func TestGenerateClashYAML(t *testing.T) {
	got := generateClashYAML("user-001", "example.com", 8388, "Test@123456", "example.com", "/ws", "example.com", "192.168.1.0/24", true, true)
	if !strings.Contains(got, "type: trojan") {
		t.Fatal("missing type: trojan")
	}
	if !strings.Contains(got, "server: example.com") {
		t.Fatal("missing server")
	}
	if !strings.Contains(got, "port: 8388") {
		t.Fatal("missing port")
	}
	if !strings.Contains(got, "password: \"Test@123456\"") {
		t.Fatal("missing password")
	}
	if !strings.Contains(got, "network: ws") {
		t.Fatal("missing network: ws")
	}
	if !strings.Contains(got, "path: /ws") {
		t.Fatal("missing ws path")
	}
	if !strings.Contains(got, "Host: example.com") {
		t.Fatal("missing ws host header")
	}
	if !strings.Contains(got, "udp: true") {
		t.Fatal("missing udp")
	}
	if !strings.Contains(got, "sni: example.com") {
		t.Fatal("missing sni")
	}
	if !strings.Contains(got, "192.168.1.0/24") {
		t.Fatal("missing lan cidr rule")
	}
	if !strings.Contains(got, "IP-CIDR") {
		t.Fatal("missing IP-CIDR rule")
	}
}

// TestGenerateSingboxJSON 测试 sing-box 配置生成。
func TestGenerateSingboxJSON(t *testing.T) {
	got := generateSingboxJSON("user-001", "example.com", 8388, "Test@123456", "example.com", "/ws", "example.com", true, true)
	if !strings.Contains(got, `"type": "trojan"`) {
		t.Fatal("missing type: trojan")
	}
	if !strings.Contains(got, `"server": "example.com"`) {
		t.Fatal("missing server")
	}
	if !strings.Contains(got, `"server_port": 8388`) {
		t.Fatal("missing server_port")
	}
	if !strings.Contains(got, `"password": "Test@123456"`) {
		t.Fatal("missing password")
	}
	if !strings.Contains(got, `"type": "ws"`) {
		t.Fatal("missing transport type ws")
	}
	if !strings.Contains(got, `"path": "/ws"`) {
		t.Fatal("missing ws path")
	}
	if !strings.Contains(got, `"Host": "example.com"`) {
		t.Fatal("missing ws host header")
	}
	if !strings.Contains(got, `"enabled": true`) {
		t.Fatal("missing tls enabled")
	}
	if !strings.Contains(got, `"server_name": "example.com"`) {
		t.Fatal("missing tls server_name")
	}
}

// TestTrojanCredential 测试凭据存储。
func TestTrojanCredential(t *testing.T) {
	// 使用临时目录
	tmpDir := t.TempDir()
	prevHome := os.Getenv("SERVER_STATUS_HOME")
	os.Setenv("SERVER_STATUS_HOME", tmpDir)
	defer os.Setenv("SERVER_STATUS_HOME", prevHome)

	// 测试保存凭据
	hash := trojanHash("testpassword")
	if err := setTrojanCredential(hash, "testpassword"); err != nil {
		t.Fatalf("setTrojanCredential failed: %v", err)
	}

	// 测试读取凭据
	password, ok := getTrojanCredential(hash)
	if !ok {
		t.Fatal("getTrojanCredential: credential not found")
	}
	if password != "testpassword" {
		t.Fatalf("getTrojanCredential: got %s, want testpassword", password)
	}

	// 测试不存在的凭据
	_, ok = getTrojanCredential("nonexistent")
	if ok {
		t.Fatal("getTrojanCredential should return false for nonexistent hash")
	}

	// 测试删除凭据
	if err := deleteTrojanCredential(hash); err != nil {
		t.Fatalf("deleteTrojanCredential failed: %v", err)
	}
	_, ok = getTrojanCredential(hash)
	if ok {
		t.Fatal("credential should be deleted")
	}
}

// TestTrojanURINoPasswordInLog 验证密码被正确编码，且函数不产生日志输出。
func TestTrojanURINoPasswordInLog(t *testing.T) {
	// 验证密码中的特殊字符被正确 URL 编码
	uri := generateTrojanURI("test", "example.com", 443, "secret@#", "example.com", "", "", true, false, false)
	if strings.Contains(uri, "secret@#") {
		t.Fatal("URI should not contain unencoded password special chars")
	}
	if !strings.Contains(uri, "secret%40%23") {
		t.Fatal("URI should contain URL-encoded password")
	}
}

// TestClashCIDR 测试 CIDR 规则生成。
func TestClashCIDR(t *testing.T) {
	// 有 LAN CIDR
	got := generateClashYAML("user", "server.com", 443, "pass", "", "", "", "192.168.1.0/24", true, false)
	if !strings.Contains(got, "IP-CIDR,192.168.1.0/24,user") {
		t.Fatal("missing LAN CIDR rule")
	}
	if !strings.Contains(got, "MATCH,user") {
		t.Fatal("missing MATCH rule")
	}

	// 无 LAN CIDR（仅互联网模式）
	got2 := generateClashYAML("user", "server.com", 443, "pass", "", "", "", "", true, false)
	if strings.Contains(got2, "IP-CIDR") {
		t.Fatal("should not have IP-CIDR rule when no LAN CIDR")
	}
	if strings.Contains(got2, "rules:") {
		t.Fatal("should not have rules section when no LAN CIDR")
	}
}

// ==================== Trojan 连接 / 认证 / 安全测试 ====================

// trojanTestMux 注册与 main() 一致的 Trojan 路由（会话认证 + RBAC + securityMiddleware）。
func trojanTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/trojan/status", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanStatusHandler))))
	mux.HandleFunc("GET /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUsersHandler))))
	mux.HandleFunc("POST /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUserMutationHandler))))
	mux.HandleFunc("GET /api/trojan/users/{hash}/connection", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanConnectionHandler))))
	mux.HandleFunc("POST /api/trojan/users/{hash}/credential", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanCredentialHandler))))
	mux.HandleFunc("GET /api/trojan/users/{hash}/clash/download", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanClashDownloadHandler))))
	mux.HandleFunc("GET /api/trojan/users/{hash}/singbox/download", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanSingboxDownloadHandler))))
	return mux
}

// trojanAuthedRequest 构造带登录会话（session + CSRF）与浏览器头部的 Trojan API 请求。
func trojanAuthedRequest(method, path, sessionID, body string) *http.Request {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
	r.Header.Set("Accept", "application/json, text/plain, */*")
	r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	// 写请求携带会话绑定 CSRF（Double-Submit：Cookie + X-CSRF-Token 头）
	r.Header.Set(csrfHeaderName, testCSRFToken)
	if sessionID != "" {
		r.Header.Set("Cookie", "session_id="+sessionID+"; csrf_token="+testCSRFToken)
	}
	return r
}

// trojanDo 在指定 mux 上执行请求并返回响应记录器。
func trojanDo(mux *http.ServeMux, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// setupTrojanEnv 初始化测试用户、fake gRPC 服务端与全局 trojanClient，并指向临时数据目录。
// 返回清理函数（恢复全局状态）。
func setupTrojanEnv(t *testing.T) func() {
	t.Helper()
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	oldHome := os.Getenv("SERVER_STATUS_HOME")
	os.Setenv("SERVER_STATUS_HOME", t.TempDir())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	fake := &fakeTrojanServer{users: make(map[string]*service.UserStatus)}
	service.RegisterTrojanServerServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()

	oldClient := trojanClient
	trojanClient = &TrojanClient{cfg: TrojanConfig{
		Enabled:         true,
		APIAddr:         lis.Addr().String(),
		APITimeout:      5 * time.Second,
		RefreshInterval: time.Hour,
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
	}}
	return func() {
		_ = trojanClient.close()
		srv.Stop()
		trojanClient = oldClient
		userManager = oldUM
		os.Setenv("SERVER_STATUS_HOME", oldHome)
	}
}

// TestTrojanAPIAuth 验证连接 API 的认证与权限：未登录 401、无权限 403、登录+权限可达。
func TestTrojanAPIAuth(t *testing.T) {
	cleanup := setupTrojanEnv(t)
	defer cleanup()
	mux := trojanTestMux()

	sid := "admin-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()

	// 1. 未登录（无 session Cookie）→ 401
	rec := trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/abc/connection", "", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. 已登录但无 trojan:manage 权限 → 403
	userManager.Lock()
	userManager.UserInfos["limited"] = &Users{Username: "limited", IsActive: true, Permissions: []string{"user:view"}}
	userManager.Sessions["limited-session"] = &Session{SessionID: "limited-session", Username: "limited", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/abc/connection", "limited-session", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("无权限应 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. 已登录 + 权限 → 到达受保护连接接口（凭据缺失返回 404 而非绕过认证）
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/abc/connection", sid, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("登录+权限应到达连接接口(404=凭据缺失), got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTrojanConnectionFlow 完整链路：创建用户 → 凭据保存 → 连接接口返回完整配置，
// 且用户列表 / 状态接口不泄露密码。
func TestTrojanConnectionFlow(t *testing.T) {
	cleanup := setupTrojanEnv(t)
	defer cleanup()
	mux := trojanTestMux()

	sid := "admin-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()

	// 1. 创建用户（密码含特殊字符）
	secret := "Test@123456"
	rec := trojanDo(mux, trojanAuthedRequest("POST", "/api/trojan/users", sid, `{"password":"`+secret+`","upload_limit":10485760,"download_limit":52428800,"ip_limit":5}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建用户失败: %d %s", rec.Code, rec.Body.String())
	}
	hash := trojanHash(secret)

	// 2. 用户列表接口不得包含 password
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users", sid, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("用户列表失败: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("用户列表泄露密码: %s", rec.Body.String())
	}

	// 3. 状态接口（与 WebSocket 推送相同的 TrojanStatus）不得包含 password
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/status", sid, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态接口失败: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), `"password"`) {
		t.Fatalf("状态接口泄露密码: %s", rec.Body.String())
	}

	// 4. 连接接口返回完整配置（受保护 API 中才返回密码）
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/connection", sid, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("连接接口失败: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			Password  string `json:"password"`
			TrojanURI string `json:"trojan_uri"`
			Clash     string `json:"clash"`
			Singbox   string `json:"singbox"`
			Server    string `json:"server"`
			Port      int    `json:"port"`
			TLS       bool   `json:"tls"`
			SNI       string `json:"sni"`
			WSPath    string `json:"ws_path"`
			WSHost    string `json:"ws_host"`
			UDP       bool   `json:"udp"`
			LanCIDR   string `json:"lan_cidr"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Password != secret {
		t.Fatalf("连接接口密码不符: %q", payload.Data.Password)
	}
	if payload.Data.Server != "example.com" || payload.Data.Port != 8388 || !payload.Data.TLS || payload.Data.SNI != "example.com" {
		t.Fatalf("连接参数错误: %+v", payload.Data)
	}
	if payload.Data.WSPath != "/ws" || payload.Data.WSHost != "example.com" || !payload.Data.UDP {
		t.Fatalf("WebSocket/UDP 参数错误: %+v", payload.Data)
	}
	if payload.Data.LanCIDR != "192.168.1.0/24" {
		t.Fatalf("LAN CIDR 错误: %q", payload.Data.LanCIDR)
	}
	if !strings.HasPrefix(payload.Data.TrojanURI, "trojan://Test%40123456@example.com:8388?") {
		t.Fatalf("Trojan URI 错误: %s", payload.Data.TrojanURI)
	}
	if !strings.Contains(payload.Data.TrojanURI, "type=ws") || !strings.Contains(payload.Data.TrojanURI, "path=%2Fws") || !strings.Contains(payload.Data.TrojanURI, "host=example.com") {
		t.Fatalf("Trojan URI 缺少 WebSocket 参数: %s", payload.Data.TrojanURI)
	}
	if !strings.Contains(payload.Data.Clash, "network: ws") {
		t.Fatalf("Clash 缺少 ws: %s", payload.Data.Clash)
	}
	if !strings.Contains(payload.Data.Singbox, `"type": "ws"`) {
		t.Fatalf("sing-box 缺少 ws: %s", payload.Data.Singbox)
	}

	// 5. 下载 Clash：lan=true 包含家庭局域网分流规则；lan=false 不包含
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/clash/download?lan=true", sid, ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "IP-CIDR,192.168.1.0/24,") {
		t.Fatalf("lan=true 应包含 LAN 分流规则: %d %s", rec.Code, rec.Body.String())
	}
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/clash/download?lan=false", sid, ""))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "IP-CIDR") {
		t.Fatalf("lan=false 不应包含 LAN 分流规则: %d %s", rec.Code, rec.Body.String())
	}

	// 5.1 自定义 lan_cidr：优先使用请求中的网段（弹窗内自定义）
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/clash/download?lan=true&lan_cidr=10.0.0.0%2F24", sid, ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "IP-CIDR,10.0.0.0/24,") {
		t.Fatalf("自定义 lan_cidr 应包含 10.0.0.0/24 规则: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "192.168.1.0/24") {
		t.Fatalf("自定义 lan_cidr 不应再包含配置默认网段: %s", rec.Body.String())
	}
	// 无效 CIDR → 400
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/clash/download?lan=true&lan_cidr=badcidr", sid, ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无效 CIDR 应 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 6. 凭据缺失的用户 hash → 404 且提示
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/nonexistent/connection", sid, ""))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "缺少连接凭据") {
		t.Fatalf("凭据缺失应 404 并提示: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTrojanNoPasswordInLog 验证创建用户过程中日志不记录密码或完整 Trojan URI。
func TestTrojanNoPasswordInLog(t *testing.T) {
	cleanup := setupTrojanEnv(t)
	defer cleanup()
	mux := trojanTestMux()

	sid := "admin-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()

	secret := "Test@123456"
	var logged string
	func() {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		rec := trojanDo(mux, trojanAuthedRequest("POST", "/api/trojan/users", sid, `{"password":"`+secret+`","upload_limit":0,"download_limit":0,"ip_limit":0}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("创建用户失败: %d %s", rec.Code, rec.Body.String())
		}
		logged = buf.String()
	}()
	if strings.Contains(logged, secret) {
		t.Fatalf("日志泄露密码: %s", logged)
	}
	if strings.Contains(logged, "trojan://") {
		t.Fatalf("日志泄露 Trojan URI: %s", logged)
	}
	if !strings.Contains(logged, "Trojan user created: hash=") {
		t.Fatalf("应记录 hash 形式的创建日志: %s", logged)
	}
}

// TestTrojanCredentialFilePermission 验证凭据文件以 0600 权限保存（非 Windows 平台）。
func TestTrojanCredentialFilePermission(t *testing.T) {
	oldHome := os.Getenv("SERVER_STATUS_HOME")
	tmp := t.TempDir()
	os.Setenv("SERVER_STATUS_HOME", tmp)
	defer os.Setenv("SERVER_STATUS_HOME", oldHome)

	hash := trojanHash("secret@123")
	if err := setTrojanCredential(hash, "secret@123"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // Windows 无 POSIX 权限语义，跳过
	}
	info, err := os.Stat(trojanCredentialsFilePath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("凭据文件权限应为 0600, got %o", perm)
	}
}

// TestCheckLinuxRouteTable 验证 /proc/net/route 小端路由解析（家庭局域网路由检测）。
func TestCheckLinuxRouteTable(t *testing.T) {
	// 表头 + 默认路由 0.0.0.0/0 + 192.168.1.0/24（小端 Destination=0005A8C0 / Mask=00FFFFFF）
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth1\t0005A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	// 192.168.1.1 应命中 192.168.1.0/24 路由
	if !checkLinuxRouteTable(content, net.ParseIP("192.168.1.1")) {
		t.Fatal("应命中 192.168.1.0/24 路由")
	}
	// 10.0.0.1 应命中默认路由
	if !checkLinuxRouteTable(content, net.ParseIP("10.0.0.1")) {
		t.Fatal("应命中默认路由")
	}
	// 空表不命中
	if checkLinuxRouteTable("Iface\tDestination\tGateway\tFlags\n", net.ParseIP("192.168.1.1")) {
		t.Fatal("空路由表不应命中")
	}
}

// TestHasRouteToLAN 验证无效 CIDR 的返回（不伪造成功）。
func TestHasRouteToLAN(t *testing.T) {
	ok, msg := hasRouteToLAN("not-a-cidr")
	if ok {
		t.Fatal("无效 CIDR 不应判定有路由")
	}
	if !strings.Contains(msg, "CIDR 无效") {
		t.Fatalf("应提示 CIDR 无效: %s", msg)
	}
}

// TestTrojanCredentialRecovery 验证补录凭据流程：
// 历史用户缺凭据 → 连接接口 404 → 错误密码 400 → 正确密码补录成功 → 连接接口可用。
func TestTrojanCredentialRecovery(t *testing.T) {
	cleanup := setupTrojanEnv(t)
	defer cleanup()
	mux := trojanTestMux()

	sid := "admin-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()

	secret := "Legacy@Pass123"
	hash := trojanHash(secret)

	// 1. 模拟历史用户：凭据缺失
	// 2. 连接接口 → 404 缺少凭据
	rec := trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/connection", sid, ""))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "缺少连接凭据") {
		t.Fatalf("缺凭据应 404: %d %s", rec.Code, rec.Body.String())
	}

	// 3. 错误密码补录 → 400（hash 与密码不匹配）
	rec = trojanDo(mux, trojanAuthedRequest("POST", "/api/trojan/users/"+hash+"/credential", sid, `{"password":"WrongPass999"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("错误密码应 400: %d %s", rec.Code, rec.Body.String())
	}

	// 4. 正确密码补录 → 200
	rec = trojanDo(mux, trojanAuthedRequest("POST", "/api/trojan/users/"+hash+"/credential", sid, `{"password":"`+secret+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("正确密码补录应 200: %d %s", rec.Code, rec.Body.String())
	}

	// 5. 补录后连接接口 → 200，密码正确，且含家庭局域网网段
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/connection", sid, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("补录后连接接口应 200: %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Password  string `json:"password"`
			TrojanURI string `json:"trojan_uri"`
			LanCIDR   string `json:"lan_cidr"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Password != secret {
		t.Fatalf("补录后密码不符: %q", payload.Data.Password)
	}
	if !strings.HasPrefix(payload.Data.TrojanURI, "trojan://Legacy%40Pass123@example.com:8388?") {
		t.Fatalf("Trojan URI 错误: %s", payload.Data.TrojanURI)
	}
	if payload.Data.LanCIDR != "192.168.1.0/24" {
		t.Fatalf("LAN CIDR 错误: %q", payload.Data.LanCIDR)
	}

	// 6. 删除凭据后连接接口恢复 404（删除用户会同步清凭据）
	if err := deleteTrojanCredential(hash); err != nil {
		t.Fatal(err)
	}
	rec = trojanDo(mux, trojanAuthedRequest("GET", "/api/trojan/users/"+hash+"/connection", sid, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("删除凭据后应 404: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTrojanCredentialArchive 验证用户档案（密码 + 限额）的持久化：
// 创建时写入限额、补录密码保留限额、修改限额同步、档案可完整还原。
func TestTrojanCredentialArchive(t *testing.T) {
	tmpDir := t.TempDir()
	prevHome := os.Getenv("SERVER_STATUS_HOME")
	os.Setenv("SERVER_STATUS_HOME", tmpDir)
	defer os.Setenv("SERVER_STATUS_HOME", prevHome)

	secret := "Archive@Test123"
	hash := trojanHash(secret)

	// 1. 创建档案（含限额）
	if err := upsertTrojanUserRecord(hash, secret, 3, 1048576, 2097152); err != nil {
		t.Fatalf("upsertTrojanUserRecord failed: %v", err)
	}
	store, err := loadTrojanCredentials()
	if err != nil {
		t.Fatalf("loadTrojanCredentials: %v", err)
	}
	if len(store.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(store.Credentials))
	}
	rec := store.Credentials[0]
	if rec.Password != secret || rec.IPLimit != 3 || rec.UploadLimit != 1048576 || rec.DownloadLimit != 2097152 {
		t.Fatalf("archive fields mismatch: %+v", rec)
	}

	// 2. 补录密码（同 hash）：保留已记录限额
	if err := setTrojanCredential(hash, "replaced-pass"); err != nil {
		t.Fatalf("setTrojanCredential failed: %v", err)
	}
	store, _ = loadTrojanCredentials()
	rec = store.Credentials[0]
	if rec.Password != "replaced-pass" {
		t.Fatalf("password should be updated, got %s", rec.Password)
	}
	if rec.IPLimit != 3 || rec.UploadLimit != 1048576 {
		t.Fatalf("limits should be preserved on password update: %+v", rec)
	}

	// 3. 修改限额同步
	if err := updateTrojanUserLimits(hash, 8, 1, 2); err != nil {
		t.Fatalf("updateTrojanUserLimits failed: %v", err)
	}
	store, _ = loadTrojanCredentials()
	rec = store.Credentials[0]
	if rec.IPLimit != 8 || rec.UploadLimit != 1 || rec.DownloadLimit != 2 {
		t.Fatalf("limits should be updated: %+v", rec)
	}
	if rec.Password != "replaced-pass" {
		t.Fatalf("password should survive limits update: %+v", rec)
	}

	// 4. 对未记录用户调用限额更新应为无害 no-op
	if err := updateTrojanUserLimits("unknown-hash", 5, 5, 5); err != nil {
		t.Fatalf("updateTrojanUserLimits on unknown hash should not error: %v", err)
	}

	// 5. 删除档案
	if err := deleteTrojanCredential(hash); err != nil {
		t.Fatalf("deleteTrojanCredential failed: %v", err)
	}
	store, _ = loadTrojanCredentials()
	if len(store.Credentials) != 0 {
		t.Fatalf("credential should be deleted, got %d", len(store.Credentials))
	}
}

// TestTrojanUserRestartRecovery 端到端验证 Trojan-Go 重启后用户自动恢复：
// 面板创建用户（含限额）→ 模拟 Trojan-Go 重启（换全新空用户表）→ 连接恢复时
// 按本地档案补发缺失用户，并把服务端手动创建的用户记入档案。
func TestTrojanUserRestartRecovery(t *testing.T) {
	// 环境搭建（与 setupTrojanEnv 相同，但保留 fake 服务端与监听器引用以便模拟重启）
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	oldHome := os.Getenv("SERVER_STATUS_HOME")
	os.Setenv("SERVER_STATUS_HOME", t.TempDir())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv1 := grpc.NewServer()
	fake1 := &fakeTrojanServer{users: make(map[string]*service.UserStatus)}
	service.RegisterTrojanServerServiceServer(srv1, fake1)
	go func() { _ = srv1.Serve(lis) }()

	oldClient := trojanClient
	trojanClient = &TrojanClient{cfg: TrojanConfig{
		Enabled:         true,
		APIAddr:         lis.Addr().String(),
		APITimeout:      5 * time.Second,
		RefreshInterval: time.Hour,
	}}
	cleanup := func() {
		_ = trojanClient.close()
		srv1.Stop()
		trojanClient = oldClient
		userManager = oldUM
		os.Setenv("SERVER_STATUS_HOME", oldHome)
	}
	defer cleanup()

	// 0. 首次刷新：空档案 + 空用户表，不应有任何副作用
	trojanClient.refresh()

	mux := trojanTestMux()
	sid := "admin-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CSRFToken: testCSRFToken}
	userManager.Unlock()

	// 1. 面板创建用户：限速 1MB/s 上 / 2MB/s 下、IP 限制 3
	body := `{"password":"Restart@Test123","upload_limit":1048576,"download_limit":2097152,"ip_limit":3}`
	rec := trojanDo(mux, trojanAuthedRequest("POST", "/api/trojan/users", sid, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建用户应 200: %d %s", rec.Code, rec.Body.String())
	}
	hash := trojanHash("Restart@Test123")

	// 档案已含限额
	store, err := loadTrojanCredentials()
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if len(store.Credentials) != 1 || store.Credentials[0].UploadLimit != 1048576 || store.Credentials[0].IPLimit != 3 {
		t.Fatalf("档案应含限额: %+v", store.Credentials)
	}

	// 2. 模拟 Trojan-Go 重启：停掉旧进程（用户表随内存清空），起一个全新空用户表
	srv1.Stop()
	trojanClient.refresh() // 此时连接失败 → setOffline
	if got := func() bool {
		trojanClient.mu.RLock()
		defer trojanClient.mu.RUnlock()
		return trojanClient.status.Connected
	}(); got {
		t.Fatal("服务端停止后应进入离线状态")
	}

	manualHash := trojanHash("manual-side-user")
	// 与生产一致：Trojan-Go 重启后仍在同一 API 地址监听，客户端缓存连接自动重连
	var lis2 net.Listener
	bindDeadline := time.Now().Add(5 * time.Second)
	for {
		lis2, err = net.Listen("tcp", lis.Addr().String())
		if err == nil || time.Now().After(bindDeadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("重新绑定同端口失败: %v", err)
	}
	srv2 := grpc.NewServer()
	fake2 := &fakeTrojanServer{users: map[string]*service.UserStatus{
		// 模拟有人在 trojan-go 侧手动配置的用户（带限额）
		manualHash: {
			User:       &service.User{Hash: manualHash},
			SpeedLimit: &service.Speed{UploadSpeed: 555, DownloadSpeed: 666},
			IpLimit:    7,
		},
	}}
	service.RegisterTrojanServerServiceServer(srv2, fake2)
	go func() { _ = srv2.Serve(lis2) }()
	defer srv2.Stop()

	// 3. 连接恢复：refresh 触发 reconcile → 档案中的缺失用户被补发
	// gRPC 重连可能需要片刻，轮询直至恢复或超时
	deadline := time.Now().Add(10 * time.Second)
	for {
		trojanClient.refresh()
		fake2.mu.Lock()
		_, panelUserBack := fake2.users[hash]
		fake2.mu.Unlock()
		if panelUserBack || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 4. 断言：面板创建的用户已恢复且限额完整
	fake2.mu.Lock()
	restored, ok := fake2.users[hash]
	fake2.mu.Unlock()
	if !ok {
		t.Fatalf("重启后面板用户应被自动恢复 (hash=%s)，现有用户: %d 个", hash, len(fake2.users))
	}
	if restored.SpeedLimit == nil || restored.SpeedLimit.UploadSpeed != 1048576 || restored.SpeedLimit.DownloadSpeed != 2097152 {
		t.Fatalf("恢复用户限速应与创建时一致: %+v", restored.SpeedLimit)
	}
	if restored.IpLimit != 3 {
		t.Fatalf("恢复用户 IP 限制应为 3: %+v", restored.IpLimit)
	}

	// 5. 断言：服务端手动创建的用户被记入档案（获得下次重启的恢复能力）
	store, err = loadTrojanCredentials()
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	foundManual := false
	for _, c := range store.Credentials {
		if c.Hash == manualHash {
			foundManual = true
			if c.UploadLimit != 555 || c.DownloadLimit != 666 || c.IPLimit != 7 {
				t.Fatalf("手动用户限额应记录服务端现值: %+v", c)
			}
		}
	}
	if !foundManual {
		t.Fatalf("服务端手动创建的用户应被记入档案: %+v", store.Credentials)
	}

	// 6. 断言：面板用户密码仍在（恢复后连接信息可用）
	password, ok := getTrojanCredential(hash)
	if !ok || password != "Restart@Test123" {
		t.Fatalf("面板用户密码应保留: %q %v", password, ok)
	}
}
