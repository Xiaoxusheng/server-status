package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 端到端验证私人空间 HTTP 层：双层认证、手记、卡片、分享、锁定。
func TestPrivateHTTPFlow(t *testing.T) {
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
	privateStore = st
	defer func() { privateStore = oldStore }()

	mux := http.NewServeMux()
	registerPrivateRoutes(mux)

	// 手工创建普通登录 session（避免触发异步落盘）
	sid := "test-session-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	userManager.Lock()
	userManager.Sessions[sid] = &Session{
		SessionID: sid, Username: "admin", CreatedAt: time.Now(),
		LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	userManager.Unlock()

	var privateCookie string
	newReq := func(method, path, body string, cookies ...string) *http.Request {
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
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "testnonce" + ts
		pathOnly := strings.Split(path, "?")[0]
		r.Header.Set("X-Timestamp", ts)
		r.Header.Set("X-Nonce", nonce)
		r.Header.Set("X-Signature", generateHMACSignature(ts+"|"+nonce+"|"+pathOnly+"|"+securityToken))
		cookies = append(cookies, "session_id="+sid)
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
	decode := func(rec *httptest.ResponseRecorder) map[string]interface{} {
		var d map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatalf("响应不是 JSON: %s", rec.Body.String())
		}
		return d
	}
	cookiesOf := func(rec *httptest.ResponseRecorder) []*http.Cookie {
		return rec.Result().Cookies()
	}

	// 1. 未登录（无 session cookie）→ 401
	r := httptest.NewRequest("GET", "/api/private/session", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Language", "zh-CN")
	r.Header.Set("Accept-Encoding", "gzip")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r.Header.Set("X-Timestamp", ts)
	r.Header.Set("X-Nonce", "n")
	r.Header.Set("X-Signature", generateHMACSignature(ts+"|n|/api/private/session|"+securityToken))
	if rec := do(r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应返回 401, got %d", rec.Code)
	}

	// 2. 密码错误 → 403
	rec := do(newReq("POST", "/api/private/unlock", `{"password":"wrong"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("错误密码应返回 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. 正确密码 → 200 + private_session Cookie
	rec = do(newReq("POST", "/api/private/unlock", `{"password":"secret-2026"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("解锁应成功, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range cookiesOf(rec) {
		if c.Name == "private_session" {
			privateCookie = c.Value
		}
	}
	if privateCookie == "" {
		t.Fatal("解锁响应未包含 private_session Cookie")
	}

	// 4. session 状态
	rec = do(newReq("GET", "/api/private/session", ""))
	d := decode(rec)
	if d["code"].(float64) != 200 || d["data"].(map[string]interface{})["unlocked"] != true {
		t.Fatalf("session 应已解锁: %s", rec.Body.String())
	}

	// 5. 创建手记
	rec = do(newReq("POST", "/api/private/notes", `{"title":"东京出差","content":"今天去东京站办事。","location_name":"东京站","latitude":35.68,"longitude":139.76,"tags":["生活","东京"]}`))
	d = decode(rec)
	if d["code"].(float64) != 200 {
		t.Fatalf("创建手记失败: %s", rec.Body.String())
	}
	note := d["data"].(map[string]interface{})
	noteID := note["id"].(string)

	// 6. 搜索
	rec = do(newReq("GET", "/api/private/search?q=东京", ""))
	d = decode(rec)
	if d["code"].(float64) != 200 || len(d["data"].([]interface{})) != 1 {
		t.Fatalf("搜索失败: %s", rec.Body.String())
	}

	// 6.5 上传图片并回读（验证带图卡片的图片链路）
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, image.NewRGBA(image.Rect(0, 0, 8, 8))); err != nil {
		t.Fatal(err)
	}
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", `form-data; name="file"; filename="test.png"`)
	partHeader.Set("Content-Type", "image/png")
	fw, _ := mw.CreatePart(partHeader)
	fw.Write(pngBuf.Bytes())
	mw.Close()
	upReq := httptest.NewRequest("POST", "/api/private/notes/"+noteID+"/images", &mp)
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	upReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	upReq.Header.Set("Accept", "*/*")
	upReq.Header.Set("Accept-Language", "zh-CN")
	upReq.Header.Set("Accept-Encoding", "gzip")
	upReq.Header.Set("Cookie", "session_id="+sid+"; private_session="+privateCookie)
	ts2 := strconv.FormatInt(time.Now().Unix(), 10)
	upReq.Header.Set("X-Timestamp", ts2)
	upReq.Header.Set("X-Nonce", "up1")
	upReq.Header.Set("X-Signature", generateHMACSignature(ts2+"|up1|/api/private/notes/"+noteID+"/images|"+securityToken))
	rec = do(upReq)
	d = decode(rec)
	if d["code"].(float64) != 200 {
		t.Fatalf("图片上传失败: %s", rec.Body.String())
	}
	imgID := d["data"].(map[string]interface{})["id"].(string)
	imgFileURL := "/api/private/notes/" + noteID + "/images/" + imgID + "/file"
	rec = do(newReq("GET", imgFileURL, ""))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "image/") {
		t.Fatalf("图片回读失败: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}

	// 7. 生成卡片（提交前端渲染的 PNG）
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	cardBody := `{"note_id":"` + noteID + `","template":"simple","width":1080,"height":1080,"title":"东京出差","image":"data:image/png;base64,` + base64.StdEncoding.EncodeToString(buf.Bytes()) + `"}`
	rec = do(newReq("POST", "/api/private/cards", cardBody))
	d = decode(rec)
	if d["code"].(float64) != 200 {
		t.Fatalf("创建卡片失败: %s", rec.Body.String())
	}
	cardID := d["data"].(map[string]interface{})["id"].(string)

	// 8. 无 private session 访问卡片图片 → 403
	r2 := newReq("GET", "/api/private/cards/"+cardID+"/image", "")
	r2.Header.Set("Cookie", "session_id="+sid)
	if rec := do(r2); rec.Code != http.StatusForbidden {
		t.Fatalf("未解锁访问卡片图片应 403, got %d", rec.Code)
	}

	// 9. 创建分享（带密码）
	rec = do(newReq("POST", "/api/private/cards/"+cardID+"/share", `{"expires_in":"1h","password":"abc123","allow_download":true}`))
	d = decode(rec)
	if d["code"].(float64) != 200 {
		t.Fatalf("创建分享失败: %s", rec.Body.String())
	}
	shareData := d["data"].(map[string]interface{})
	token := shareData["token"].(string)
	if !strings.HasPrefix(shareData["url"].(string), "http") {
		t.Fatalf("分享 URL 非法: %v", shareData["url"])
	}

	// 10. 公开分享数据
	rec = do(newReq("GET", "/api/share/"+token+"/data", ""))
	d = decode(rec)
	if d["code"].(float64) != 200 || d["data"].(map[string]interface{})["has_password"] != true {
		t.Fatalf("分享数据异常: %s", rec.Body.String())
	}

	// 11. 未验证密码访问图片 → 403
	r3 := newReq("GET", "/api/share/"+token+"/image", "")
	r3.Header.Del("Cookie")
	if rec := do(r3); rec.Code != http.StatusForbidden {
		t.Fatalf("密码分享未验证应 403, got %d", rec.Code)
	}

	// 12. 错误密码验证 → 403
	rec = do(newReq("POST", "/api/share/"+token+"/verify", `{"password":"bad"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("错误分享密码应 403, got %d", rec.Code)
	}

	// 13. 正确密码验证 → 200 + 分享 Cookie
	rec = do(newReq("POST", "/api/share/"+token+"/verify", `{"password":"abc123"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("分享密码验证失败: %s", rec.Body.String())
	}
	var shareCookie string
	for _, c := range cookiesOf(rec) {
		if strings.HasPrefix(c.Name, "share_ok_") {
			shareCookie = c.Name + "=" + c.Value
		}
	}
	if shareCookie == "" {
		t.Fatal("验证通过后应设置分享 Cookie")
	}
	r4 := newReq("GET", "/api/share/"+token+"/image", "", shareCookie)
	r4.Header.Del("Cookie")
	r4.Header.Set("Cookie", shareCookie)
	if rec := do(r4); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("验证后应能访问分享图片: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}

	// 14. 二维码
	rec = do(newReq("GET", "/api/share/"+token+"/qr", ""))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("二维码生成失败: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}

	// 15. 锁定 → 私人 API 403
	rec = do(newReq("POST", "/api/private/lock", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("锁定失败: %d", rec.Code)
	}
	privateCookie = ""
	rec = do(newReq("GET", "/api/private/notes", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("锁定后应 403, got %d", rec.Code)
	}

	// 16. 撤销分享后公开访问失效
	privateCookie = ""
	rec = do(newReq("POST", "/api/private/unlock", `{"password":"secret-2026"}`))
	for _, c := range cookiesOf(rec) {
		if c.Name == "private_session" {
			privateCookie = c.Value
		}
	}
	rec = do(newReq("POST", "/api/private/shares/"+token+"/revoke", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("撤销分享失败: %s", rec.Body.String())
	}
	r5 := newReq("GET", "/api/share/"+token+"/data", "")
	r5.Header.Del("Cookie")
	var r5rec *httptest.ResponseRecorder
	if r5rec = do(r5); r5rec.Code != http.StatusOK {
		t.Fatalf("撤销后 data 应仍可查询: %d", r5rec.Code)
	}
	d = decode(r5rec)
	if d["data"] == nil {
		t.Fatalf("撤销后 data 响应缺少 data: %s", r5rec.Body.String())
	}
	if d["data"].(map[string]interface{})["invalid"] != true {
		t.Fatalf("撤销后分享应标记 invalid: %s", r5rec.Body.String())
	}
}

// 未解锁时私人 API 必须 403（双层认证缺失第二层）
func TestPrivateAPINeedsDoubleAuth(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true}},
		Sessions:  make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()
	oldStore := privateStore
	st := newTestStore(t)
	privateStore = st
	defer func() { privateStore = oldStore }()

	mux := http.NewServeMux()
	registerPrivateRoutes(mux)

	sid := "auth-test-session"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{SessionID: sid, Username: "admin", CreatedAt: time.Now(), LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	userManager.Unlock()

	r := httptest.NewRequest("GET", "/api/private/notes", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Language", "zh-CN")
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("Cookie", "session_id="+sid)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r.Header.Set("X-Timestamp", ts)
	r.Header.Set("X-Nonce", "n1")
	r.Header.Set("X-Signature", generateHMACSignature(ts+"|n1|/api/private/notes|"+securityToken))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("仅普通登录未解锁应 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 直接输入网址打开 /private.html 必须被拦截（隐藏入口 Cookie 缺失 → 跳回首页）
func TestPrivatePageEntryGate(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"admin": {Username: "admin", IsActive: true}},
		Sessions:  make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()

	mux := http.NewServeMux()
	registerPrivateRoutes(mux)

	// 1. 无任何 Cookie 直接访问 → 302 跳回 index.html
	r := httptest.NewRequest("GET", "/private.html", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "zh-CN")
	r.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusFound {
		t.Fatalf("直接访问 /private.html 应 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/index.html" {
		t.Fatalf("应跳回 /index.html, got %s", loc)
	}

	// 2. 有入口 Cookie 但没有登录 session → 仍应 302
	r2 := httptest.NewRequest("GET", "/private.html", nil)
	r2.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	r2.Header.Set("Accept", "text/html")
	r2.Header.Set("Accept-Language", "zh-CN")
	r2.Header.Set("Accept-Encoding", "gzip")
	r2.AddCookie(&http.Cookie{Name: "pv_entry", Value: hmacSign("pv_entry")})
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("入口 Cookie 但未登录应 302, got %d", rec2.Code)
	}

	// 3. 未登录调用入口接口 → 401
	r3 := httptest.NewRequest("POST", "/api/private/entry", nil)
	r3.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	r3.Header.Set("Accept", "application/json")
	r3.Header.Set("Accept-Language", "zh-CN")
	r3.Header.Set("Accept-Encoding", "gzip")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r3.Header.Set("X-Timestamp", ts)
	r3.Header.Set("X-Nonce", "n2")
	r3.Header.Set("X-Signature", generateHMACSignature(ts+"|n2|/api/private/entry|"+securityToken))
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("未登录调用入口接口应 401, got %d", rec3.Code)
	}
}
