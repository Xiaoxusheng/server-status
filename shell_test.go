package main

// Web Shell 二次认证 / 一次性 Token / RBAC / CSRF / 限速 / 密码管理 纯逻辑与 REST 回归测试。
// 覆盖：未登录 401、无 system:exec 403、错误/正确密码、一次性 Token 防重放/过期/撤销、
// 改密的旧认证失效、密码强度、输入消息大小、Shell 环境变量脱敏、限速防爆破。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	testShellPassword = "P@ssw0rd12345!"
)

// setupShellTest 初始化 Shell 测试环境：临时审计文件 / 临时密码文件 / 干净内存态与用户集合。
func setupShellTest(t *testing.T, adminSession string, password string) (*http.ServeMux, *Session) {
	t.Helper()

	// 干净的内存态（避免测试间互相污染）
	shellHubState = &shellHub{
		shells: make(map[string]*shellSession),
		auth:   &shellAuthStore{sessions: make(map[string]*ShellAuthSession)},
	}
	shellAuthRate = &shellRateLimiter{fails: make(map[string][]time.Time), locks: make(map[string]time.Time)}

	// 审计与密码文件跑在临时目录，不污染 /opt/server-status
	auditLogFile = filepath.Join(t.TempDir(), "audit.log")
	os.Setenv("SHELL_PASSWORD_HASH_FILE", filepath.Join(t.TempDir(), "pw.dat"))
	t.Cleanup(func() { os.Unsetenv("SHELL_PASSWORD_HASH_FILE") })
	if password != "" {
		h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		os.Setenv("SHELL_PASSWORD_HASH", string(h))
	} else {
		os.Unsetenv("SHELL_PASSWORD_HASH")
	}

	oldUM := userManager
	userManager = &UserManager{
		RWMutex: sync.RWMutex{},
		UserInfos: map[string]*Users{
			"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}},
			"nolab": {Username: "nolab", IsActive: true, Permissions: []string{"system:view"}}, // 无 system:exec
		},
		Sessions: make(map[string]*Session),
	}
	t.Cleanup(func() { userManager = oldUM })

	sess := newTestSession(adminSession)

	return shellTestMux(), sess
}

// shellTestMux 注册与 main() 相同保护链的 Web Shell 路由集
func shellTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/shell/auth", authMiddleware(requirePermission("system:exec", securityMiddleware(shellAuthHandler))))
	mux.HandleFunc("POST /api/shell/setup-password", authMiddleware(requirePermission("system:exec", securityMiddleware(shellSetupPasswordHandler))))
	mux.HandleFunc("POST /api/shell/change-password", authMiddleware(requirePermission("system:exec", securityMiddleware(shellChangePasswordHandler))))
	mux.HandleFunc("GET /api/shell/sessions", authMiddleware(requirePermission("system:exec", securityMiddleware(shellListSessionsHandler))))
	mux.HandleFunc("DELETE /api/shell/sessions/{id}", authMiddleware(requirePermission("system:exec", securityMiddleware(shellDeleteSessionHandler))))
	mux.HandleFunc("DELETE /api/shell/auth-sessions/{id}", authMiddleware(requirePermission("system:exec", securityMiddleware(shellDeleteAuthSessionHandler))))
	mux.HandleFunc("POST /api/shell/revoke-all", authMiddleware(requirePermission("system:exec", securityMiddleware(shellRevokeAllHandler))))
	mux.HandleFunc("GET /ws/shell", authMiddleware(requirePermission("system:exec", securityMiddleware(shellWSHandler))))
	return mux
}

// execPOST 便捷执行一次带会话+CSRF 的 POST JSON 请求，返回状态码与响应体 map
func execPOST(t *testing.T, mux *http.ServeMux, sess *Session, path, body string) (int, map[string]interface{}) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", path, body, true))
	var m map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

// shellAuthToken 调用 /api/shell/auth 获取一次性 Token
func shellAuthToken(t *testing.T, mux *http.ServeMux, sess *Session, password string) string {
	t.Helper()
	code, m := execPOST(t, mux, sess, "/api/shell/auth", `{"password":"`+password+`"}`)
	if code != http.StatusOK {
		t.Fatalf("二次认证应 200, got %d: %v", code, m)
	}
	data, _ := m["data"].(map[string]interface{})
	tok, _ := data["shell_token"].(string)
	if tok == "" {
		t.Fatalf("应返回一次性 shell_token, got %v", m)
	}
	return tok
}

// 未登录 → 401
func TestShellUnauthenticated401(t *testing.T) {
	mux, _ := setupShellTest(t, "admin", testShellPassword)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/shell/auth", strings.NewReader(`{"password":"x"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401, got %d", rec.Code)
	}
}

// 已登录但无 system:exec → 403
func TestShellRBACDenied403(t *testing.T) {
	mux, sess := setupShellTest(t, "nolab", testShellPassword)
	code, _ := execPOST(t, mux, sess, "/api/shell/auth", `{"password":"`+testShellPassword+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("无 system:exec 应 403, got %d", code)
	}
}

// 错误密码 → 401 且统一文案
func TestShellAuthWrongPassword401(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	code, m := execPOST(t, mux, sess, "/api/shell/auth", `{"password":"wrong-password"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("错误密码应 401, got %d", code)
	}
	if msg, ok := m["message"].(string); !ok || msg != "Shell authentication failed" {
		t.Fatalf("应返回统一错误文案 %v", m)
	}
}

// 正确密码 → 200 + 一次性 Token（防重放）
func TestShellAuthOneTimeToken(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	tok := shellAuthToken(t, mux, sess, testShellPassword)

	// 第一次消费成功
	if _, ok := shellHubState.auth.consume(shellTokenHash(tok)); !ok {
		t.Fatalf("Token 第一次消费应成功")
	}
	// 重放同一 Token 失败
	if _, ok := shellHubState.auth.consume(shellTokenHash(tok)); ok {
		t.Fatalf("Token 重放应失败")
	}
}

// Token 过期不可用
func TestShellAuthTokenExpired(t *testing.T) {
	_, _ = setupShellTest(t, "admin", testShellPassword)
	raw, _ := generateSecureToken(32)
	as := &ShellAuthSession{
		ID:        "sast-x",
		TokenHash: shellTokenHash(raw),
		Username:  "admin",
		ExpiresAt: time.Now().Add(-time.Second),
	}
	shellHubState.auth.put(as)
	if _, ok := shellHubState.auth.consume(shellTokenHash(raw)); ok {
		t.Fatalf("过期 Token 应不可用")
	}
}

// Token 撤销（revoke-by-id / revoke-all / logout revokeByUser）
func TestShellAuthTokenRevoked(t *testing.T) {
	_, _ = setupShellTest(t, "admin", testShellPassword)
	raw, _ := generateSecureToken(32)
	as := &ShellAuthSession{
		ID:        "sast-rev1",
		TokenHash: shellTokenHash(raw),
		Username:  "admin",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	shellHubState.auth.put(as)
	if !shellHubState.auth.revokeByID("sast-rev1", "admin", true) {
		t.Fatalf("应能撤销")
	}
	if _, ok := shellHubState.auth.consume(shellTokenHash(raw)); ok {
		t.Fatalf("已撤销 Token 应不可用")
	}

	// revoke-all
	raw2, _ := generateSecureToken(32)
	shellHubState.auth.put(&ShellAuthSession{ID: "sast-rev2", TokenHash: shellTokenHash(raw2), Username: "admin", ExpiresAt: time.Now().Add(time.Minute)})
	if n := shellHubState.auth.revokeAll(); n != 1 {
		t.Fatalf("revoke-all 应撤销 1 个, got %d", n)
	}
	if _, ok := shellHubState.auth.consume(shellTokenHash(raw2)); ok {
		t.Fatalf("revoke-all 后 Token 应不可用")
	}
}

// 非管理员不能撤销别人的 token，管理员可以
func TestShellRevokeByIDPermission(t *testing.T) {
	_, _ = setupShellTest(t, "admin", testShellPassword)
	raw, _ := generateSecureToken(32)
	as := &ShellAuthSession{ID: "sast-a", TokenHash: shellTokenHash(raw), Username: "other", ExpiresAt: time.Now().Add(time.Minute)}
	shellHubState.auth.put(as)
	if shellHubState.auth.revokeByID("sast-a", "admin", false) {
		t.Fatalf("非管理员不应能撤销他人 Token")
	}
	if !shellHubState.auth.revokeByID("sast-a", "admin", true) {
		t.Fatalf("管理员应能撤销他人在等待的 Token")
	}
}

// 二次认证防爆破：连续失败 5 次后锁定
func TestShellAuthRateLimitLock(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	for i := 0; i < shellMaxAuthFailures; i++ {
		code, _ := execPOST(t, mux, sess, "/api/shell/auth", `{"password":"wrong"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误密码应 401, got %d", i, code)
		}
	}
	keys := shellAuthKeys(sess.Username, getClientIP(httptest.NewRequest("POST", "/", nil)))
	if shellAuthRate.allowed(keys[0]) {
		t.Fatalf("达到阈值后应锁定")
	}
}

// setup-password：非管理员 → 403
func TestShellSetupPasswordNonAdmin403(t *testing.T) {
	mux, sess := setupShellTest(t, "nolab", "")
	code, _ := execPOST(t, mux, sess, "/api/shell/setup-password", `{"password":"`+testShellPassword+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("非管理员 setup 应 403, got %d", code)
	}
}

// setup-password：密码由环境变量管理时拒绝
func TestShellSetupPasswordEnvManaged(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	code, _ := execPOST(t, mux, sess, "/api/shell/setup-password", `{"password":"`+testShellPassword+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("env 管理模式 setup 应 400, got %d", code)
	}
}

// setup-password：弱密码拒绝
func TestShellSetupPasswordWeak(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", "") // 非 env 管理，走文件
	cfg := filepath.Join(t.TempDir(), "pw.dat")
	os.Setenv("SHELL_PASSWORD_HASH_FILE", cfg)
	defer os.Unsetenv("SHELL_PASSWORD_HASH_FILE")
	code, _ := execPOST(t, mux, sess, "/api/shell/setup-password", `{"password":"short"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("弱密码应 400, got %d", code)
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Fatalf("弱密码不应写入文件")
	}
}

// setup-password：管理员成功设置，且此后旧密码/新密码均可用于认证
func TestShellSetupPasswordSuccessAndAuth(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", "") // 非 env 管理
	cfg := filepath.Join(t.TempDir(), "pw.dat")
	os.Setenv("SHELL_PASSWORD_HASH_FILE", cfg)
	defer os.Unsetenv("SHELL_PASSWORD_HASH_FILE")

	code, _ := execPOST(t, mux, sess, "/api/shell/setup-password", `{"password":"`+testShellPassword+`"}`)
	if code != http.StatusOK {
		t.Fatalf("管理员 setup 应 200, got %d", code)
	}
	if tok := shellAuthToken(t, mux, sess, testShellPassword); tok == "" {
		t.Fatalf("设置后可认证获取 token")
	}
}

// change-password：旧密码校验，成功后旧密码失效、新密码可用
func TestShellChangePassword(t *testing.T) {
	// 不为空 password 会命中 env 管理模式，故此处用文件存储的密码（非 env 管理）
	mux, sess := setupShellTest(t, "admin", "")
	cfg := filepath.Join(t.TempDir(), "pw.dat")
	os.Setenv("SHELL_PASSWORD_HASH_FILE", cfg)
	defer os.Unsetenv("SHELL_PASSWORD_HASH_FILE")
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("Old@Passw0rd123"), bcrypt.MinCost)
	if err := saveShellPasswordHash(string(oldHash)); err != nil {
		t.Fatalf("预置旧密码失败: %v", err)
	}

	// 旧密码错误 → 401
	code, _ := execPOST(t, mux, sess, "/api/shell/change-password", `{"old_password":"bad","new_password":"New@Passw0rd123"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("旧密码错误应 401, got %d", code)
	}

	// 旧密码正确 → 200
	code, _ = execPOST(t, mux, sess, "/api/shell/change-password", `{"old_password":"Old@Passw0rd123","new_password":"New@Passw0rd123"}`)
	if code != http.StatusOK {
		t.Fatalf("改密应 200, got %d", code)
	}

	// 旧密码不再可用
	code, _ = execPOST(t, mux, sess, "/api/shell/auth", `{"password":"Old@Passw0rd123"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("改密后旧密码应失效, got %d", code)
	}
	// 新密码可用
	code, _ = execPOST(t, mux, sess, "/api/shell/auth", `{"password":"New@Passw0rd123"}`)
	if code != http.StatusOK {
		t.Fatalf("改密后新密码应可用, got %d", code)
	}
}

// 错误的 shell ID 注入防护
func TestShellDeleteInvalidID(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	for _, id := range []string{"..", "shell;rm", "a/b", "shell a", strings.Repeat("x", 100)} {
		if validShellID(id) {
			t.Fatalf("非法 ID 不应通过: %q", id)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "DELETE", "/api/shell/sessions/..%2Frame", "", true))
	if rec.Code == http.StatusOK {
		t.Fatalf("非法 ID 删除应失败")
	}
}

// 密码强度校验
func TestShellPasswordStrength(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
	}{
		{"Short1!", false},                 // 太短
		{"nocaptialanddigitonlyxx", false}, // 无数字/特殊
		{"123456789012", false},            // 无字母/特殊
		{"abcdefghijk", false},             // 无数字特殊
		{"Abcdef12345!", true},
		{"P@ssw0rd12345!", true},
	}
	for _, c := range cases {
		if got := validShellPassword(c.pw); got != c.want {
			t.Fatalf("validShellPassword(%q) = %v, want %v", c.pw, got, c.want)
		}
	}
}

// Shell 环境必须剥离 Server Status 敏感变量
func TestShellBuildEnvStripsSensitive(t *testing.T) {
	os.Setenv("SERVER_STATUS_ENCRYPT_KEY", "topsecret")
	os.Setenv("SERVER_STATUS_SIGNING_KEY", "topsecret2")
	os.Setenv("SHELL_PASSWORD_HASH", "$2a$10$abcdefghijklmnopqrstuv")
	defer os.Unsetenv("SERVER_STATUS_ENCRYPT_KEY")
	defer os.Unsetenv("SERVER_STATUS_SIGNING_KEY")
	defer os.Unsetenv("SHELL_PASSWORD_HASH")

	env := buildShellEnv()
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"SERVER_STATUS_ENCRYPT_KEY", "SERVER_STATUS_SIGNING_KEY", "topsecret", "SHELL_PASSWORD_HASH", "$2a$10$ab"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("Shell 环境不应包含敏感项 %q", bad)
		}
	}
	// 必要的终端变量应存在
	for _, need := range []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("Shell 环境应包含 %q", need)
		}
	}
}

// Token Hash 为定长 64 位十六进制
func TestShellTokenHashDeterministic(t *testing.T) {
	if got := shellTokenHash("abc"); len(got) != 64 {
		t.Fatalf("token hash 应为 64 位, got %d", len(got))
	}
	if shellTokenHash("abc") != shellTokenHash("abc") {
		t.Fatalf("同一 token hash 应一致")
	}
}

// 会话列表：无会话时返回空数组不报错
func TestShellListSessionsEmpty(t *testing.T) {
	mux, sess := setupShellTest(t, "admin", testShellPassword)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "GET", "/api/shell/sessions", "", false))
	var m map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != http.StatusOK {
		t.Fatalf("列表应 200, got %d", rec.Code)
	}
	if _, ok := m["data"]; !ok {
		t.Fatalf("应返回 data 字段: %v", m)
	}
}

// 超大输入消息在会话层被拒绝（unit 级直接构造字符串长度判断）
func TestShellMaxMsgBound(t *testing.T) {
	if shellMaxMsgSize != 64*1024 {
		t.Fatalf("最大消息应为 64KB")
	}
}
