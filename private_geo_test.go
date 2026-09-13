package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 端到端验证 regeo 服务端代理：key 不经 session 下发浏览器、双层认证后才可调用、
// 高德响应透传、未配置 key 返回 status=0、坐标参数校验。
func TestPrivateRegeoProxy(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()

	oldStore := privateStore
	st := newTestStore(t)
	if err := st.SetupPrivatePassword("secret-2026"); err != nil {
		t.Fatal(err)
	}
	st.config.Geo.AmapKey = "test-amap-key"
	privateStore = st
	defer func() { privateStore = oldStore }()

	// 桩高德：校验代理转发的是服务端 key，且 location 原样透传
	var stubGot url.Values
	oldURL := amapRegeoURL
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stubGot = r.URL.Query()
		io.WriteString(w, `{"status":"1","regeocode":{"formatted_address":"湖北省随州市随县小林镇"}}`)
	}))
	defer stub.Close()
	amapRegeoURL = stub.URL
	defer func() { amapRegeoURL = oldURL }()

	mux := http.NewServeMux()
	registerPrivateRoutes(mux)

	sid := "test-session-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	userManager.Lock()
	userManager.Sessions[sid] = &Session{
		SessionID: sid, Username: "admin", CreatedAt: time.Now(),
		LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: testCSRFToken,
	}
	userManager.Unlock()

	var privateCookie string
	newReq := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
		r.Header.Set("Accept", "application/json, text/plain, */*")
		r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate")
		r.Header.Set(csrfHeaderName, testCSRFToken)
		cookies := []string{"session_id=" + sid, "csrf_token=" + testCSRFToken}
		if privateCookie != "" {
			cookies = append(cookies, "private_session="+privateCookie)
		}
		r.Header.Set("Cookie", strings.Join(cookies, "; "))
		return r
	}
	do := func(r *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// 1. 未解锁（无 private_session）→ 403，防止匿名盗刷配额
	if rec := do(newReq("GET", "/api/private/geo/regeo?location=113.736009,32.313893")); rec.Code != http.StatusForbidden {
		t.Fatalf("未解锁应返回 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. 解锁拿到 private_session
	{
		r := httptest.NewRequest("POST", "/api/private/unlock", strings.NewReader(`{"password":"secret-2026"}`))
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Accept-Language", "zh-CN")
		r.Header.Set("Accept-Encoding", "gzip")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(csrfHeaderName, testCSRFToken)
		r.Header.Set("Cookie", "session_id="+sid+"; csrf_token="+testCSRFToken)
		rec := do(r)
		if rec.Code != http.StatusOK {
			t.Fatalf("解锁应成功, got %d: %s", rec.Code, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == "private_session" {
				privateCookie = c.Value
			}
		}
		if privateCookie == "" {
			t.Fatal("解锁响应未包含 private_session Cookie")
		}
	}

	// 3. session 响应不得再包含 amap_key（本泄漏修复的核心断言）
	var sess struct {
		Data map[string]interface{} `json:"data"`
	}
	if rec := do(newReq("GET", "/api/private/session")); rec.Code != http.StatusOK {
		t.Fatalf("session 应 200, got %d", rec.Code)
	} else if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatalf("session 响应解析失败: %s", rec.Body.String())
	}
	if _, leak := sess.Data["amap_key"]; leak {
		t.Fatal("session 接口仍在下发 amap_key，key 已泄漏到浏览器")
	}

	// 4. 正常调用：200 + 高德响应原样透传，且带的是服务端 key
	rec := do(newReq("GET", "/api/private/geo/regeo?location=113.736009,32.313893"))
	if rec.Code != http.StatusOK {
		t.Fatalf("regeo 代理应 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "小林镇") {
		t.Fatalf("regeo 响应未透传高德结果: %s", rec.Body.String())
	}
	if stubGot == nil {
		t.Fatal("代理未向高德发起请求")
	}
	if stubGot.Get("key") != "test-amap-key" {
		t.Fatalf("代理应使用服务端 key, got %q", stubGot.Get("key"))
	}
	if stubGot.Get("location") != "113.736009,32.313893" {
		t.Fatalf("location 应原样透传, got %q", stubGot.Get("location"))
	}

	// 5. 未配置 key → 200 + status=0（前端据此回退 nominatim）
	st.config.Geo.AmapKey = ""
	rec = do(newReq("GET", "/api/private/geo/regeo?location=113.736009,32.313893"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"0"`) {
		t.Fatalf("未配置 key 应返回 status=0, got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. 非法坐标 → 400
	st.config.Geo.AmapKey = "test-amap-key"
	for _, bad := range []string{"113.736009", "abc", "113.736009,32.313893,1.0"} {
		if rec := do(newReq("GET", "/api/private/geo/regeo?location="+url.QueryEscape(bad))); rec.Code != http.StatusBadRequest {
			t.Fatalf("非法 location %q 应 400, got %d: %s", bad, rec.Code, rec.Body.String())
		}
	}
}
