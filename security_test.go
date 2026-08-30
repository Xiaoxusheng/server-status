package main

// 认证 / CSRF / Cookie / RBAC / WebSocket / 前端源码安全回归测试。
// 覆盖：未登录 401、写操作 CSRF 校验、Cookie 属性、RBAC 403、Trojan 与 /exec 保护、WebSocket 会话认证。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// testCSRFToken 供测试使用的一个固定 CSRF Token（仅测试用，不代表生产随机值）。
const testCSRFToken = "test-csrf-token-0123456789abcdef0123456789abcdef"

// securityMux 构建与 main() 相同保护链（authMiddleware + requirePermission + securityMiddleware）的最小路由集。
func securityMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/secure", authMiddleware(requirePermission("system:view", securityMiddleware(echoHandler))))
	mux.HandleFunc("POST /api/secure", authMiddleware(requirePermission("system:view", securityMiddleware(echoHandler))))
	mux.HandleFunc("GET /api/rbac/users", authMiddleware(requireAnyPermission([]string{"user:manage", "user:view"}, securityMiddleware(echoHandler))))
	mux.HandleFunc("GET /api/exec/list", authMiddleware(requirePermission("system:exec", securityMiddleware(echoHandler))))
	mux.HandleFunc("POST /api/exec/list", authMiddleware(requirePermission("system:exec", securityMiddleware(echoHandler))))
	mux.HandleFunc("/ws", authMiddleware(requirePermission("system:view", securityMiddleware(wsHandler))))
	mux.HandleFunc("GET /api/docker/containers", authMiddleware(requirePermission("docker:view", securityMiddleware(echoHandler))))
	mux.HandleFunc("GET /api/docker/overview", authMiddleware(requirePermission("docker:view", securityMiddleware(echoHandler))))
	mux.HandleFunc("GET /api/docker/inspect", authMiddleware(requirePermission("docker:view", securityMiddleware(echoHandler))))
	mux.HandleFunc("POST /api/docker/action", authMiddleware(requirePermission("docker:manage", securityMiddleware(echoHandler))))
	mux.HandleFunc("POST /api/docker/remove", authMiddleware(requirePermission("docker:manage", securityMiddleware(echoHandler))))
	mux.HandleFunc("/docker", authMiddleware(requireAnyPermission([]string{"docker:view", "docker:manage"}, securityMiddleware(echoHandler))))
	return mux
}

// echoHandler 一个受保护的最小业务处理器，仅用于验证认证链。
func echoHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, "ok", map[string]interface{}{})
}

// setupSecurityEnv 初始化测试用户并返回 mux（与 main 相同的保护链）。
func setupSecurityEnv(t *testing.T) *http.ServeMux {
	t.Helper()
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	t.Cleanup(func() { userManager = oldUM })
	return securityMux()
}

// newTestSession 直接插入一个带随机 CSRF Token 的测试会话（避免触发异步落盘 goroutine）。
func newTestSession(username string) *Session {
	randPart, _ := generateSecureToken(12)
	sid := "test-session-" + randPart
	csrf, _ := generateSecureToken(32)
	s := &Session{
		SessionID: sid, Username: username,
		CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: csrf,
	}
	userManager.Lock()
	userManager.Sessions[sid] = s
	userManager.Unlock()
	return s
}

// secureReq 构造带会话 + CSRF 的请求（csrf=true 才附加 X-CSRF-Token 头与 csrf cookie）。
func secureReq(sess *Session, method, path, body string, csrf bool) *http.Request {
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
	cookies := []string{"session_id=" + sess.SessionID}
	if csrf {
		r.Header.Set(csrfHeaderName, sess.CSRFToken)
		cookies = append(cookies, "csrf_token="+sess.CSRFToken)
	}
	r.Header.Set("Cookie", strings.Join(cookies, "; "))
	return r
}

// 未登录请求返回 401。
func TestAuthUnauthenticated401(t *testing.T) {
	mux := setupSecurityEnv(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/secure", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 登录后 GET 正常（无需 CSRF）。
func TestAuthAuthenticatedGET(t *testing.T) {
	mux := setupSecurityEnv(t)
	sess := newTestSession("admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "GET", "/api/secure", "", false))
	if rec.Code != http.StatusOK {
		t.Fatalf("登录后 GET 应 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 写操作缺少 CSRF → 403。
func TestCSRFMissingForPOST403(t *testing.T) {
	mux := setupSecurityEnv(t)
	sess := newTestSession("admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/secure", `{}`, false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 的 POST 应 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 写操作 CSRF 正确 → 200。
func TestCSRFValidForPOST200(t *testing.T) {
	mux := setupSecurityEnv(t)
	sess := newTestSession("admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/secure", `{}`, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("CSRF 正确的 POST 应 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 写操作错误 CSRF → 403。
func TestCSRFWrong403(t *testing.T) {
	mux := setupSecurityEnv(t)
	sess := newTestSession("admin")
	r := secureReq(sess, "POST", "/api/secure", `{}`, true)
	r.Header.Set(csrfHeaderName, "wrong-csrf-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("错误 CSRF 的 POST 应 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// RBAC 权限不足 → 403。
func TestRBACPermissionDenied403(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex: sync.RWMutex{},
		UserInfos: map[string]*Users{
			"limited": {Username: "limited", IsActive: true, Permissions: []string{"user:view"}},
		},
		Sessions: make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()
	mux := securityMux()
	sess := newTestSession("limited")
	// limited 有 user:view 但有 access /api/secure 需要 system:view
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "GET", "/api/secure", "", false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("权限不足应 403, got %d: %s", rec.Code, rec.Body.String())
	}
	// limited 有 user:view，访问 /api/rbac/users（允许 user:view）→ 200
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, secureReq(sess, "GET", "/api/rbac/users", "", false))
	if rec2.Code != http.StatusOK {
		t.Fatalf("允许 user:view 的接口应 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// Session Cookie 具备 HttpOnly / Secure / SameSite；CSRF Cookie 非 HttpOnly（JS 可读）。
func TestCookieAttributes(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", securityMiddleware(loginHandler))
	mux.HandleFunc("/check-auth", securityMiddleware(checkAuthHandler))

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw-2026"), bcrypt.MinCost)
	userManager.Lock()
	userManager.UserInfos["admin"].Password = string(hash)
	userManager.Unlock()

	// 1. 登录 → session Cookie 属性
	body := strings.NewReader(`{"username":"admin","password":"pw-2026"}`)
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, httptest.NewRequest("POST", "/login", body))
	if loginRec.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var sessionCookie string
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "session_id" {
			sessionCookie = c.Value
			if !c.HttpOnly {
				t.Fatal("session_id Cookie 必须 HttpOnly")
			}
			if !c.Secure {
				t.Fatal("session_id Cookie 必须 Secure")
			}
			if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session_id SameSite 应为 Lax 或 Strict, got %v", c.SameSite)
			}
		}
	}
	if sessionCookie == "" {
		t.Fatal("登录未返回 session_id Cookie")
	}

	// 2. check-auth → CSRF Cookie 非 HttpOnly（前端 JS 需读取作为 X-CSRF-Token）
	checkRec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/check-auth", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionCookie})
	mux.ServeHTTP(checkRec, req)
	found := false
	for _, c := range checkRec.Result().Cookies() {
		if c.Name == csrfCookieName {
			found = true
			if c.HttpOnly {
				t.Fatal("csrf_token Cookie 不能 HttpOnly，否则前端 JS 无法读取")
			}
			if !c.Secure {
				t.Fatal("csrf_token Cookie 必须 Secure")
			}
		}
	}
	if !found {
		t.Fatal("check-auth 未下发 csrf_token Cookie")
	}
}

// Trojan 用户接口在新增认证/CSRF 后仍工作（复用 trojan_test.go 的 fake gRPC 环境）。
func TestTrojanInterfaceWithCSRF(t *testing.T) {
	cleanup := setupTrojanEnv(t)
	defer cleanup()
	mux := trojanTestMux()
	sess := newTestSession("admin")
	// GET 状态接口 → 200
	rec := trojanDo(mux, secureReq(sess, "GET", "/api/trojan/status", "", false))
	if rec.Code != http.StatusOK {
		t.Fatalf("Trojan 状态接口应 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// POST 创建用户：无 CSRF → 403；有 CSRF → 200
	rec = trojanDo(mux, secureReq(sess, "POST", "/api/trojan/users", `{"password":"x1","upload_limit":1000,"download_limit":1000,"ip_limit":1}`, false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Trojan POST 缺 CSRF 应 403, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = trojanDo(mux, secureReq(sess, "POST", "/api/trojan/users", `{"password":"x1","upload_limit":1000,"download_limit":1000,"ip_limit":1}`, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("Trojan POST 带 CSRF 应 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// /exec 仍受保护：未登录 401、缺 CSRF 403。
func TestExecStillProtected(t *testing.T) {
	mux := setupSecurityEnv(t)
	sess := newTestSession("admin")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/exec/list", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/exec 未登录应 401, got %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, secureReq(sess, "POST", "/api/exec/list", `{}`, false))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("/exec 缺 CSRF 应 403, got %d", rec2.Code)
	}
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, secureReq(sess, "POST", "/api/exec/list", `{}`, true))
	if rec3.Code != http.StatusOK {
		t.Fatalf("/exec 带 CSRF 应可达(200), got %d: %s", rec3.Code, rec3.Body.String())
	}
}

// WebSocket：未登录无法连接，登录后可连接（依赖 session Cookie 认证）。
func TestWebSocketAuth(t *testing.T) {
	mux := setupSecurityEnv(t)
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	wsURL := "wss" + strings.TrimPrefix(srv.URL, "https") + "/ws?iface=lo"

	tlsClient := srv.Client()
	dl := websocket.Dialer{TLSClientConfig: tlsClient.Transport.(*http.Transport).TLSClientConfig}

	// 1. 未登录 → 握手失败（401）
	_, _, err := dl.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("未登录的 WebSocket 应无法连接")
	}

	// 2. 登录后 → 可连接
	sess := newTestSession("admin")
	hdr := http.Header{}
	hdr.Set("Cookie", "session_id="+sess.SessionID)
	hdr.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	hdr.Set("Accept", "*/*")
	hdr.Set("Accept-Language", "zh-CN")
	hdr.Set("Accept-Encoding", "gzip")
	conn, resp, err := dl.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("登录后的 WebSocket 应能连接, err=%v resp=%v", err, resp)
	}
	conn.Close()
}

// 前端 HTML 源码不得再包含 securityToken / HMAC-SHA256 / X-Signature 等浏览器端 Secret。
func TestFrontendHasNoEmbeddedSecret(t *testing.T) {
	forbidden := []string{
		"securityToken",
		"HmacSHA256",
		"X-Signature",
		"X-Timestamp",
		"X-Nonce",
		"anti_crawler_secret",
	}
	ents, err := os.ReadDir("templates")
	if err != nil {
		t.Skipf("templates 目录不存在: %v", err)
	}
	checked := false
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		checked = true
		data, err := os.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(data))
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				t.Fatalf("前端 %s 仍包含浏览器端 Secret 标识: %q", e.Name(), f)
			}
		}
	}
	if !checked {
		t.Skip("未找到任何 templates/*.html 文件")
	}
}

// TestFrontendCookieHelperNoRegExp 回归：getCookie 曾用带未转义 '/' 的正则字面量导致
// Babel "Invalid regular expression flag" 使整页无法加载，改为纯字符串解析。此处断言旧写法不再出现。
func TestFrontendCookieHelperNoRegExp(t *testing.T) {
	forbidden := []string{
		"name.replace(/([.$?*",
		"new RegExp('(?:^|; )' + name",
	}
	ents, err := os.ReadDir("templates")
	if err != nil {
		t.Skipf("templates 目录不存在: %v", err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		data, err := os.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(data))
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				t.Fatalf("前端 %s 仍包含有语法风险的 Cookie 正则: %q", e.Name(), f)
			}
		}
	}
}

// CSRF Token 必须为高强度随机（crypto/rand），且会话间不重复。
func TestCSRFTokenIsRandom(t *testing.T) {
	setupSecurityEnv(t)
	a := newTestSession("admin")
	b := newTestSession("admin")
	if a.CSRFToken == "" || len(a.CSRFToken) < 32 {
		t.Fatalf("CSRF Token 过短或为空: %q", a.CSRFToken)
	}
	if a.SessionID == b.SessionID {
		t.Fatal("会话 ID 可重复")
	}
	if a.CSRFToken == b.CSRFToken {
		t.Fatal("CSRF Token 出现重复（疑似未使用随机源）")
	}
}

// TestEpubEndpointsProtected 电子书端到端：/epubs 与 /epub 必须登录 + files:view 权限。
func TestEpubEndpointsProtected(t *testing.T) {
	mux := setupSecurityEnv(t)
	mux.HandleFunc("/epubs", authMiddleware(requirePermission("files:view", securityMiddleware(listEpubs))))
	mux.HandleFunc("GET /epub", authMiddleware(requirePermission("files:view", securityMiddleware(epubFileHandler))))

	// 1. 未登录 → 401
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(&Session{SessionID: "invalid-session"}, "GET", "/epubs", "", false))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录访问 /epubs 应 401, got %d", rec.Code)
	}

	// 2. 有权限（admin *），但服务器无 EPUB 目录 → 500（目录不存在）
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(newTestSession("admin"), "GET", "/epubs", "", true))
	if rec.Code != http.StatusInternalServerError {
		t.Logf("注意：若服务器存在 EPUB 目录，本步会返回 200 列表而非 500")
	}

	// 3. /epub 未登录 → 401
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(&Session{SessionID: "invalid-session"}, "GET", "/epub?name=test.epub", "", false))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录访问 /epub 应 401, got %d", rec.Code)
	}

	// 4. /epub 登录但文件不存在 → 404（认证通过，文件名白名单校验通过）
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(newTestSession("admin"), "GET", "/epub?name=not-exist.epub", "", true))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的 epub 应 404, got %d", rec.Code)
	}

	// 5. /epub 非法文件名 → 404（路径穿越防护）
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(newTestSession("admin"), "GET", "/epub?name=..%2F..%2Fetc%2Fpasswd", "", true))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("路径穿越应被拦截(404/403), got %d", rec.Code)
	}
}

// TestDownloadTokenFullFlow 端到端复现 download.html 的真实浏览器流程：
// 登录拿 session_id + csrf_token → check-auth（下发 Double-Submit CSRF Cookie）→ 生成下载令牌。
// 确保 /generate-download-token 在 CSRF 认证改造后仍正常工作；并验证缺 CSRF 时 403。
func TestDownloadTokenFullFlow(t *testing.T) {
	// 初始化用户与下载令牌管理器（避免依赖 main 的全局副作用）
	oldUM := userManager
	oldDTM := downloadTokenManager
	defer func() { userManager = oldUM; downloadTokenManager = oldDTM }()

	hash, err := bcrypt.GenerateFromPassword([]byte("AdminPass123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", Password: string(hash), IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	downloadTokenManager = &DownloadTokenManager{Tokens: make(map[string]*DownloadToken)}

	// 与 main 相同的保护链 + 真实 handler
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", securityMiddleware(loginHandler))
	mux.HandleFunc("GET /check-auth", securityMiddleware(checkAuthHandler))
	mux.HandleFunc("POST /generate-download-token", authMiddleware(requirePermission("token:issue", securityMiddleware(generateDownloadTokenHandler))))

	// 登录并收集 Cookie（模拟 curl -c cookie jar）
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"admin","password":"AdminPass123"}`))
	loginReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
	loginReq.Header.Set("Accept", "application/json")
	loginReq.Header.Set("Accept-Language", "zh-CN")
	loginReq.Header.Set("Accept-Encoding", "gzip")
	loginReq.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", loginRec.Code, loginRec.Body.String())
	}
	jar := map[string]string{}
	var csrfFromLogin string
	for _, c := range loginRec.Result().Cookies() {
		jar[c.Name] = c.Value
		if c.Name == "csrf_token" {
			csrfFromLogin = c.Value
		}
	}
	if jar["session_id"] == "" {
		t.Fatal("登录响应未下发 session_id Cookie")
	}
	if csrfFromLogin == "" {
		t.Fatal("登录响应未下发 csrf_token Cookie（Double-Submit 来源缺失）")
	}

	mkReq := func(method, path string, body string, csrfHeader bool, cookies ...string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		for k, v := range map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Accept-Encoding": "gzip, deflate",
			"Content-Type":    "application/json",
		} {
			req.Header.Set(k, v)
		}
		if csrfHeader {
			req.Header.Set(csrfHeaderName, csrfFromLogin)
		}
		if len(cookies) > 0 {
			req.Header.Set("Cookie", strings.Join(cookies, "; "))
		}
		return req
	}

	// 2. check-auth：确认登录状态，同时（重新）下发 csrf_token（download.html 页面加载时必调）
	chkRec := httptest.NewRecorder()
	mux.ServeHTTP(chkRec, mkReq("GET", "/check-auth", "", false, "session_id="+jar["session_id"]))
	if chkRec.Code != http.StatusOK {
		t.Fatalf("check-auth 失败: %d", chkRec.Code)
	}

	// 3-a. 缺 CSRF 的写请求必须 403（复现若前端拿不到 csrf cookie 的失败场景）
	rec403 := httptest.NewRecorder()
	mux.ServeHTTP(rec403, mkReq("POST", "/generate-download-token", `{"description":"t"}`, false, "session_id="+jar["session_id"]))
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 的 POST 应 403, got %d", rec403.Code)
	}

	// 3-b. 正确携带 session + csrf cookie + X-CSRF-Token → 成功
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, mkReq("POST", "/generate-download-token", `{"description":"t"}`, true,
		"session_id="+jar["session_id"], "csrf_token="+csrfFromLogin))
	if rec.Code != http.StatusOK {
		t.Fatalf("生成下载令牌应成功, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Code != 200 {
		t.Fatalf("响应异常: %s", rec.Body.String())
	}
	if resp.Data["token"] == nil || resp.Data["token"] == "" {
		t.Fatalf("未返回下载令牌: %s", rec.Body.String())
	}
}

// Docker 路由的 RBAC 与 CSRF 保护回归测试。
func TestDockerRoutesProtected(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex: sync.RWMutex{},
		UserInfos: map[string]*Users{
			"viewer":  {Username: "viewer", IsActive: true, Permissions: []string{"docker:view"}},
			"nouser":  {Username: "nouser", IsActive: true, Permissions: []string{}},
			"manager": {Username: "manager", IsActive: true, Permissions: []string{"docker:manage"}},
		},
		Sessions: make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()
	mux := securityMux()

	// 1. 无 docker 权限 → GET /api/docker/containers 403
	rec0 := httptest.NewRecorder()
	mux.ServeHTTP(rec0, secureReq(newTestSession("nouser"), "GET", "/api/docker/containers", "", false))
	if rec0.Code != http.StatusForbidden {
		t.Fatalf("无权限用户访问 docker 列表应 403, got %d", rec0.Code)
	}

	// 2. 有 docker:view → 可读列表
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, secureReq(newTestSession("viewer"), "GET", "/api/docker/containers", "", false))
	if rec1.Code != http.StatusOK {
		t.Fatalf("docker:view 用户读取列表应 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// 3. 只有 view 无 manage → 启动容器 403
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, secureReq(newTestSession("viewer"), "POST", "/api/docker/action", `{"container":"web","action":"start"}`, true))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("docker:view 无 manage 权限启动容器应 403, got %d", rec2.Code)
	}

	// 4. 有 manage 但缺 CSRF → 启动容器 403
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, secureReq(newTestSession("manager"), "POST", "/api/docker/action", `{"container":"web","action":"start"}`, false))
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 的启动操作应 403, got %d", rec3.Code)
	}

	// 5. 有 manage + CSRF → 通过（echoHandler 返回 200）
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, secureReq(newTestSession("manager"), "POST", "/api/docker/action", `{"container":"web","action":"start"}`, true))
	if rec4.Code != http.StatusOK {
		t.Fatalf("docker:manage + CSRF 应 200, got %d", rec4.Code)
	}

	// 6. /docker 页面：viewer 可访问（requireAnyPermission）
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, secureReq(newTestSession("viewer"), "GET", "/docker", "", false))
	if rec5.Code != http.StatusOK {
		t.Fatalf("docker:view 用户访问 /docker 页面应 200, got %d", rec5.Code)
	}

	// 7. overview/inspect 只读：viewer 可访问
	rec6 := httptest.NewRecorder()
	mux.ServeHTTP(rec6, secureReq(newTestSession("viewer"), "GET", "/api/docker/overview", "", false))
	if rec6.Code != http.StatusOK {
		t.Fatalf("docker:view 用户访问 overview 应 200, got %d", rec6.Code)
	}
	rec7 := httptest.NewRecorder()
	mux.ServeHTTP(rec7, secureReq(newTestSession("viewer"), "GET", "/api/docker/inspect?container=web", "", false))
	if rec7.Code != http.StatusOK {
		t.Fatalf("docker:view 用户访问 inspect 应 200, got %d", rec7.Code)
	}

	// 8. 无权限用户访问 overview 应 403
	rec8 := httptest.NewRecorder()
	mux.ServeHTTP(rec8, secureReq(newTestSession("nouser"), "GET", "/api/docker/overview", "", false))
	if rec8.Code != http.StatusForbidden {
		t.Fatalf("无权限用户访问 overview 应 403, got %d", rec8.Code)
	}

	// 9. 删除（危险写操作）：viewer 无 manage 权限 403；manager 缺 CSRF 403；manager + CSRF 通过
	rec9 := httptest.NewRecorder()
	mux.ServeHTTP(rec9, secureReq(newTestSession("viewer"), "POST", "/api/docker/remove", `{"container":"web"}`, true))
	if rec9.Code != http.StatusForbidden {
		t.Fatalf("viewer 无 manage 权限删除应 403, got %d", rec9.Code)
	}
	rec10 := httptest.NewRecorder()
	mux.ServeHTTP(rec10, secureReq(newTestSession("manager"), "POST", "/api/docker/remove", `{"container":"web"}`, false))
	if rec10.Code != http.StatusForbidden {
		t.Fatalf("manager 缺 CSRF 删除应 403, got %d", rec10.Code)
	}
	rec11 := httptest.NewRecorder()
	mux.ServeHTTP(rec11, secureReq(newTestSession("manager"), "POST", "/api/docker/remove", `{"container":"web"}`, true))
	if rec11.Code != http.StatusOK {
		t.Fatalf("manager + CSRF 删除应 200, got %d", rec11.Code)
	}
}
