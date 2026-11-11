package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// /healthz 必须始终给出可解析的 JSON，且状态码与 status 字段自洽。
func TestHealthzResponseShape(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	healthzHandler(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json; charset=utf-8") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var rep healthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("响应不是合法 JSON: %v (body=%s)", err, rec.Body.String())
	}

	if rep.Version == "" {
		t.Error("version 不应为空")
	}
	if rep.CheckedAt == "" {
		t.Error("checked_at 不应为空")
	}
	// 四项检查必须齐全，缺项说明 handler 提前 return 了
	for _, k := range []string{"database", "templates", "media", "docker"} {
		if _, ok := rep.Checks[k]; !ok {
			t.Errorf("缺少检查项 %q", k)
		}
	}

	switch rep.Status {
	case "ok":
		if rec.Code != 200 {
			t.Errorf("status=ok 但 HTTP %d", rec.Code)
		}
	case "degraded":
		if rec.Code != 503 {
			t.Errorf("status=degraded 但 HTTP %d", rec.Code)
		}
	default:
		t.Errorf("未知 status %q", rep.Status)
	}
}

// 未初始化 store 时必须判为不健康（宁可误报，不可漏报）
func TestHealthzWithoutStoreIsDegraded(t *testing.T) {
	prev := opsStore
	opsStore = nil
	defer func() { opsStore = prev }()

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	healthzHandler(rec, req)

	if rec.Code != 503 {
		t.Fatalf("HTTP = %d, want 503", rec.Code)
	}
	var rep healthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Checks["database"].OK {
		t.Error("database 检查应为 false")
	}
}
