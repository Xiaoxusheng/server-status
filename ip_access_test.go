package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetIPAccess 测试前后清空全局追踪器，避免用例间串扰
func resetIPAccess(t *testing.T) {
	t.Helper()
	savedStats := ipAccess.stats
	savedRecords := ipAccess.records
	t.Cleanup(func() {
		ipAccess.mu.Lock()
		ipAccess.stats = savedStats
		ipAccess.records = savedRecords
		ipAccess.mu.Unlock()
	})
	ipAccess.mu.Lock()
	ipAccess.stats = make(map[string]*ipAccessStat)
	ipAccess.records = nil
	ipAccess.mu.Unlock()
}

// TestIPInfoHandlerLocal 验证 /api/ipinfo 本地单路由的三种响应形态
// （列表数组 / 单 IP {stats, records} / 未记录 IP 纯文本），字段与旧 8081 服务对齐
func TestIPInfoHandlerLocal(t *testing.T) {
	resetIPAccess(t)

	// 经过中间件记一笔 200 与一笔 404
	mw := ipAccessMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/some-page", nil)
	req.RemoteAddr = "203.0.113.7:12345"
	mw.ServeHTTP(httptest.NewRecorder(), req)
	req2 := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req2.RemoteAddr = "203.0.113.7:12345"
	mw.ServeHTTP(httptest.NewRecorder(), req2)

	// 列表模式：无 ip 参数 → 统计数组
	rec := httptest.NewRecorder()
	ipinfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ipinfo", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("列表模式状态码 = %d, 期望 200", rec.Code)
	}
	var list []ipAccessStat
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("列表模式应返回 JSON 数组: %v", err)
	}
	if len(list) != 1 || list[0].IP != "203.0.113.7" || list[0].TotalAccess != 2 {
		t.Fatalf("列表统计不符: %+v", list)
	}
	if list[0].StatusCounts["200"] != 1 || list[0].StatusCounts["404"] != 1 {
		t.Fatalf("状态码分布不符: %+v", list[0].StatusCounts)
	}

	// 详情模式：?ip= → {stats, records}
	rec = httptest.NewRecorder()
	ipinfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ipinfo?ip=203.0.113.7", nil))
	var detail struct {
		Stats   ipAccessStat     `json:"stats"`
		Records []ipAccessRecord `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("详情模式应返回 {stats, records}: %v", err)
	}
	if detail.Stats.TotalAccess != 2 || len(detail.Records) != 2 {
		t.Fatalf("详情数据不符: stats=%+v records=%d", detail.Stats, len(detail.Records))
	}
	if detail.Records[0].URL != "/missing" {
		t.Fatalf("明细应按时间倒序，最新在前: %+v", detail.Records)
	}

	// 未记录 IP：纯文本 "IP not found"（与旧服务一致，前端据此提示）
	rec = httptest.NewRecorder()
	ipinfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ipinfo?ip=198.51.100.1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "IP not found") {
		t.Fatalf("未记录 IP 应返回 IP not found, got %d %q", rec.Code, rec.Body.String())
	}

	// 非法 IP 参数
	rec = httptest.NewRecorder()
	ipinfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/ipinfo?ip=not-an-ip", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 IP 应 400, got %d", rec.Code)
	}
}

// TestIPAccessMiddlewareSkipsSelf IP 面板轮询 /api/ipinfo 自身不应计入统计
func TestIPAccessMiddlewareSkipsSelf(t *testing.T) {
	resetIPAccess(t)

	handler := ipAccessMiddleware(http.HandlerFunc(ipinfoHandler))
	req := httptest.NewRequest(http.MethodGet, "/api/ipinfo", nil)
	req.RemoteAddr = "203.0.113.9:999"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ipAccess.mu.RLock()
	_, exists := ipAccess.stats["203.0.113.9"]
	ipAccess.mu.RUnlock()
	if exists {
		t.Fatal("/api/ipinfo 自身请求不应被记账")
	}
}

// TestIPAccessRecordPersistenceRoundTrip 统计落盘后应能完整恢复
func TestIPAccessRecordPersistenceRoundTrip(t *testing.T) {
	resetIPAccess(t)

	// 落盘文件指向临时目录，避免污染真实数据根目录
	savedFile := ipAccessFile
	ipAccessFile = filepath.Join(t.TempDir(), "ip_access.json")
	t.Cleanup(func() { ipAccessFile = savedFile })

	ipAccess.mu.Lock()
	ipAccess.stats["198.51.100.42"] = &ipAccessStat{
		IP:           "198.51.100.42",
		TotalAccess:  3,
		FirstAccess:  time.Now().Add(-time.Hour),
		LastAccess:   time.Now(),
		StatusCounts: map[string]int64{"200": 2, "403": 1},
	}
	ipAccess.mu.Unlock()

	saveIPAccess()
	defer func() {
		ipAccess.mu.Lock()
		delete(ipAccess.stats, "198.51.100.42")
		ipAccess.mu.Unlock()
	}()

	// 模拟重启：清空后重新加载
	ipAccess.mu.Lock()
	ipAccess.stats = make(map[string]*ipAccessStat)
	ipAccess.records = nil
	ipAccess.mu.Unlock()
	loadIPAccess()

	st, _, ok := ipAccess.lookup("198.51.100.42")
	if !ok || st.TotalAccess != 3 || st.StatusCounts["403"] != 1 {
		t.Fatalf("重启恢复数据不符: ok=%v stats=%+v", ok, st)
	}
}
