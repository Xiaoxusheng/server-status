package main

// 静态页面访问控制回归测试。
// 背景：注册在 "/" 的兜底路由若不设限，会把 rbac / security / trojan / services 等
// 后台页面外壳连同 API 路径与权限结构一并暴露给未登录访客（实测曾有 39/40 个模板可读）。
// 本测试锁定该行为，防止后续重构把访问控制丢掉。

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readBody 取出响应正文；serveTemplateCached 在 Accept-Encoding 含 gzip 时会返回预压缩内容，
// 因此断言页面内容前必须先解压，否则会误判为"没有返回页面"。
func readBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	raw := rec.Body.Bytes()
	if rec.Header().Get("Content-Encoding") != "gzip" {
		return string(raw)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip 解压失败: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip 读取失败: %v", err)
	}
	return string(out)
}

// useRealTemplatesDir 把 indexPath 指向仓库内的 templates/，让测试能真正命中模板缓存或磁盘文件。
func useRealTemplatesDir(t *testing.T) {
	t.Helper()
	old := indexPath
	indexPath = "templates"
	t.Cleanup(func() { indexPath = old })
}

// staticPageReq 构造浏览器式 GET 请求；sess 非 nil 时附带会话 Cookie。
func staticPageReq(sess *Session, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	if sess != nil {
		r.Header.Set("Cookie", "session_id="+sess.SessionID)
	}
	return r
}

// 未登录访问后台页面必须跳回首页，且不得返回任何页面内容。
func TestStaticPageUnauthenticatedPanelPagesRedirect(t *testing.T) {
	setupSecurityEnv(t)
	useRealTemplatesDir(t)
	h := staticFileHandler()

	panelPages := []string{
		"/docker.html", "/rbac.html", "/security.html", "/security-events.html",
		"/trojan.html", "/services.html", "/files.html", "/log.html",
		"/github.html", "/backup.html", "/process.html", "/tasks.html",
		"/task-history.html", "/remediation.html", "/ip-panel.html",
		"/ebooks.html", "/video.html", "/location.html",
		"/pv-c.html", "/pv-preview.html", "/pv-pw2.html",
	}
	for _, p := range panelPages {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staticPageReq(nil, p))
		if rec.Code != http.StatusFound {
			t.Errorf("%s 未登录应 302 跳回首页，实际 %d", p, rec.Code)
			continue
		}
		if loc := rec.Header().Get("Location"); loc != "/index.html" {
			t.Errorf("%s 跳转目标应为 /index.html，实际 %q", p, loc)
		}
		if body := readBody(t, rec); strings.Contains(body, "<html") {
			t.Errorf("%s 未登录却返回了页面内容", p)
		}
	}
}

// 登录入口与对外分享/下载页必须保持公开，否则未登录访客连登录页和分享链接都打不开。
func TestStaticPagePublicPagesRemainOpen(t *testing.T) {
	setupSecurityEnv(t)
	useRealTemplatesDir(t)
	h := staticFileHandler()

	publicPaths := []string{
		"/", "/index.html", "/share.html", "/dl.html", "/download.html",
		"/audio-share.html", "/pv-share.html", "/pv-share-pw.html", "/pv-share-bad.html",
		"/mqtt-screen.html",
		"/ui.css",
	}
	for _, p := range publicPaths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staticPageReq(nil, p))
		if rec.Code != http.StatusOK {
			t.Errorf("%s 应允许未登录访问，实际 %d", p, rec.Code)
		}
	}
}

// 已登录用户访问后台页面必须正常放行——访问控制只挡未登录，不能把功能改坏。
func TestStaticPageAuthenticatedPanelPagesAllowed(t *testing.T) {
	setupSecurityEnv(t)
	useRealTemplatesDir(t)
	h := staticFileHandler()
	sess := newTestSession("admin")

	for _, p := range []string{"/docker.html", "/rbac.html", "/trojan.html", "/files.html", "/pv-c.html"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staticPageReq(sess, p))
		if rec.Code != http.StatusOK {
			t.Errorf("%s 已登录应 200，实际 %d", p, rec.Code)
			continue
		}
		if !strings.Contains(readBody(t, rec), "<html") {
			t.Errorf("%s 已登录但未返回页面内容", p)
		}
	}
}

// 会话无效（伪造/过期）时按未登录处理，不能因为带了 Cookie 就放行。
func TestStaticPageInvalidSessionRejected(t *testing.T) {
	setupSecurityEnv(t)
	useRealTemplatesDir(t)
	h := staticFileHandler()

	rec := httptest.NewRecorder()
	r := staticPageReq(nil, "/rbac.html")
	r.Header.Set("Cookie", "session_id=forged-session-id-not-in-store")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusFound {
		t.Errorf("伪造会话应 302 跳回首页，实际 %d", rec.Code)
	}
}

// 敏感后缀拦截为既有防线，防止本次改动误伤。
func TestStaticFileSensitiveSuffixStillBlocked(t *testing.T) {
	setupSecurityEnv(t)
	h := staticFileHandler()

	for _, p := range []string{
		"/users.json", "/config.json", "/rbac.json", "/main.go",
		"/deploy.sh", "/tls/key.pem", "/app.log", "/private_notes.db",
		"/index.html.bak", "/index.html~",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staticPageReq(nil, p))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s 应 404，实际 %d", p, rec.Code)
		}
	}
}

// publicTemplatePages 与 registerPrivateRoutes / shell.go 的显式路由不应冲突：
// shell.html 与 private.html 必须留在"需要认证"一侧，不得被误登记为公开页。
func TestPublicTemplatePagesExcludesGatedPages(t *testing.T) {
	for _, name := range []string{"shell.html", "private.html"} {
		if publicTemplatePages[name] {
			t.Errorf("%s 由更具体的路由接管并要求认证，不应登记为公开页", name)
		}
	}
	// 登录入口必须公开，否则未登录访客拿不到登录表单。
	if !publicTemplatePages["index.html"] {
		t.Error("index.html 是登录入口，必须保持公开")
	}
	// 设备定位大屏要直接投屏展示，必须无需登录。
	if !publicTemplatePages["mqtt-screen.html"] {
		t.Error("mqtt-screen.html 是公开投屏页，必须登记为公开页")
	}
}

// 设备定位大屏：页面本身与其地图资源都必须未登录可访问，
// 且页面里不得内联任何凭据（数据只能从公开裁剪接口取）。
func TestMqttScreenPagePublicAndCredentialFree(t *testing.T) {
	setupSecurityEnv(t)
	useRealTemplatesDir(t)
	h := staticFileHandler()

	// leaflet 是本页的地图依赖，若被访问控制拦住大屏会白屏
	for _, p := range []string{"/mqtt-screen.html", "/leaflet.js", "/leaflet.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staticPageReq(nil, p))
		if rec.Code != http.StatusOK {
			t.Errorf("%s 应允许未登录访问，实际 %d", p, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, staticPageReq(nil, "/mqtt-screen.html"))
	body := readBody(t, rec)
	if !strings.Contains(body, "<html") {
		t.Fatal("大屏页未返回页面内容")
	}
	if !strings.Contains(body, "/api/public/mqtt/screen") {
		t.Error("大屏页应从公开接口 /api/public/mqtt/screen 取数")
	}
	for _, bad := range []string{"amap_key", "securityJsCode", "mqtt_password", "127.0.0.1:7777"} {
		if strings.Contains(body, bad) {
			t.Errorf("大屏页不应出现 %q（凭据或上游地址不得进入公开页面）", bad)
		}
	}
}
