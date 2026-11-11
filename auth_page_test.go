package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// 未登录时：页面导航跳登录页，接口调用返回带 charset 的 401 JSON。
func TestRejectUnauthenticatedPageVsAPI(t *testing.T) {
	// 1) 手机/浏览器地址栏导航
	req := httptest.NewRequest("GET", "/alerts", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	rejectUnauthenticated(rec, req)

	if rec.Code != 302 {
		t.Fatalf("页面导航应 302，实际 %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/index.html" {
		t.Errorf("跳转地址 = %q", loc)
	}

	// 2) 前端 fetch（Accept: */*）
	req2 := httptest.NewRequest("GET", "/api/alerts/rules", nil)
	req2.Header.Set("Accept", "*/*")
	rec2 := httptest.NewRecorder()
	rejectUnauthenticated(rec2, req2)

	if rec2.Code != 401 {
		t.Fatalf("接口应 401，实际 %d", rec2.Code)
	}
	ct := rec2.Header().Get("Content-Type")
	if !strings.Contains(ct, "charset=utf-8") {
		t.Errorf("Content-Type 缺 charset，手机浏览器会乱码: %q", ct)
	}
	if !strings.Contains(rec2.Body.String(), "请先登录") {
		t.Errorf("响应体中文未按 UTF-8 输出: %q", rec2.Body.String())
	}

	// 3) 带 text/html 的 API 请求不能被误判成页面
	req3 := httptest.NewRequest("GET", "/api/alerts/rules", nil)
	req3.Header.Set("Accept", "text/html")
	rec3 := httptest.NewRecorder()
	rejectUnauthenticated(rec3, req3)
	if rec3.Code != 401 {
		t.Errorf("/api/ 前缀即使 Accept 是 html 也应 401，实际 %d", rec3.Code)
	}

	// 4) POST 表单提交不当作页面导航（避免把接口错误变成跳转）
	req4 := httptest.NewRequest("POST", "/login", nil)
	req4.Header.Set("Accept", "text/html")
	rec4 := httptest.NewRecorder()
	rejectUnauthenticated(rec4, req4)
	if rec4.Code != 401 {
		t.Errorf("POST 不应跳转，实际 %d", rec4.Code)
	}
}

func TestIsPageNavigation(t *testing.T) {
	cases := []struct {
		method, path, accept string
		want                 bool
	}{
		{"GET", "/alerts", "text/html,application/xhtml+xml", true},
		{"GET", "/docker", "text/html", true},
		{"GET", "/alerts", "*/*", false},
		{"GET", "/api/alerts/rules", "text/html", false},
		{"POST", "/alerts", "text/html", false},
		{"HEAD", "/security", "text/html", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set("Accept", c.accept)
		if got := isPageNavigation(r); got != c.want {
			t.Errorf("%s %s accept=%q → %v, want %v", c.method, c.path, c.accept, got, c.want)
		}
	}
}
