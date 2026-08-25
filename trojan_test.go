package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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
