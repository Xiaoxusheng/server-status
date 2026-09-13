package main

// 安全中心回归测试：
//   - 扫描编排：发现写入/合并/自动恢复、评分、事件、并发扫描互斥
//   - HTTP 层：登录 + RBAC + CSRF 保护链（与全站一致）

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeChecker 可控的测试检查器
type fakeChecker struct {
	id       string
	name     string
	category string
	result   SecurityCheckResult
	block    chan struct{} // 非 nil 时 Check 会阻塞直到关闭
}

func (c *fakeChecker) ID() string          { return c.id }
func (c *fakeChecker) Name() string        { return c.name }
func (c *fakeChecker) Category() string    { return c.category }
func (c *fakeChecker) Description() string { return "测试检查器" }
func (c *fakeChecker) Check(ctx context.Context) SecurityCheckResult {
	if c.block != nil {
		<-c.block
	}
	return c.result
}

func setupSecurityCenterTest(t *testing.T, checkers []SecurityChecker) (*OpsStore, *SecurityCenter) {
	t.Helper()
	store := newTestOpsStore(t)
	oldStore, oldCenter, oldRemStore := opsStore, opsCenter, remEngine.store
	opsStore = store
	opsCenter = newSecurityCenter(store, checkers)
	remEngine.store = store
	t.Cleanup(func() {
		opsStore, opsCenter, remEngine.store = oldStore, oldCenter, oldRemStore
	})
	return store, opsCenter
}

func TestSecurityScanCreatesFindingsAndScore(t *testing.T) {
	store, center := setupSecurityCenterTest(t, []SecurityChecker{
		&fakeChecker{id: "ck_a", name: "检查A", category: "分类A", result: SecurityCheckResult{
			Status: "fail", Summary: "有风险",
			Findings: []SecurityFinding{
				{DedupeKey: "ka", Severity: "high", Title: "风险A"},
				{DedupeKey: "kb", Severity: "low", Title: "风险B"},
			},
		}},
		&fakeChecker{id: "ck_b", name: "检查B", category: "分类B", result: SecurityCheckResult{
			Status: "pass", Summary: "正常",
		}},
	})
	center.runScan("test") // 同步执行便于断言

	findings, total, err := store.ListFindings(FindingFilter{Status: []string{"open"}, Limit: 10})
	if err != nil || total != 2 {
		t.Fatalf("应有 2 条 open 发现: total=%d err=%v", total, err)
	}
	for _, f := range findings {
		if f.CheckID != "ck_a" || f.Category != "分类A" {
			t.Fatalf("发现归属检查器失败: %+v", f)
		}
	}
	// 评分：100 - 15(high) - 3(low) = 82
	ov := center.overview()
	if score, ok := ov["score"].(*int); !ok || *score != 82 {
		t.Fatalf("评分应为 82, got %v", ov["score"])
	}
	if ov["score_level"] != "注意" {
		t.Fatalf("82 分档位应为 注意, got %v", ov["score_level"])
	}
	// 事件：2 条 finding.open + 1 条 scan.completed
	events, total, _ := store.ListEvents("", "", 50, 0)
	if total < 3 {
		t.Fatalf("事件数不足: %d (%+v)", total, events)
	}
}

func TestSecurityScanMergesAndAutoResolves(t *testing.T) {
	resultA := SecurityCheckResult{Status: "warn", Findings: []SecurityFinding{
		{DedupeKey: "ka", Severity: "high", Title: "风险A"},
	}}
	ck := &fakeChecker{id: "ck_a", name: "A", category: "C", result: resultA}
	store, center := setupSecurityCenterTest(t, []SecurityChecker{ck})

	center.runScan("test")
	center.runScan("test") // 同一风险再次出现 → 合并不新增
	list, total, _ := store.ListFindings(FindingFilter{Limit: 10})
	if total != 1 || list[0].Occurrences != 2 {
		t.Fatalf("重复扫描应合并: total=%d occ=%d", total, list[0].Occurrences)
	}
	// 第二次扫描风险消失 → 自动 resolved + 事件
	ck.result = SecurityCheckResult{Status: "pass", Summary: "ok"}
	center.runScan("test")
	got, _ := store.GetFinding(list[0].ID)
	if got.Status != "resolved" || got.ResolvedAt == nil {
		t.Fatalf("风险消失应自动恢复, got %+v", got)
	}
	events, _, _ := store.ListEvents("", "finding.resolved", 10, 0)
	if len(events) != 1 {
		t.Fatalf("应有 1 条恢复事件, got %d", len(events))
	}
}

func TestSecurityScanIgnoredStaysIgnored(t *testing.T) {
	ck := &fakeChecker{id: "ck_a", name: "A", category: "C", result: SecurityCheckResult{
		Status: "warn", Findings: []SecurityFinding{{DedupeKey: "ka", Severity: "medium", Title: "风险A"}},
	}}
	store, center := setupSecurityCenterTest(t, []SecurityChecker{ck})
	center.runScan("test")
	list, _, _ := store.ListFindings(FindingFilter{Limit: 10})
	store.UpdateFindingStatus(list[0].ID, "ignored", "")
	// 再次扫描：ignored 不复活、不重复计数
	center.runScan("test")
	list2, total, _ := store.ListFindings(FindingFilter{Limit: 10})
	if total != 1 || list2[0].Status != "ignored" || list2[0].Occurrences != 2 {
		t.Fatalf("ignored 应保持: %+v total=%d", list2[0], total)
	}
	open, _, _ := store.ListFindings(FindingFilter{Status: []string{"open"}, Limit: 10})
	if len(open) != 0 {
		t.Fatalf("ignored 不应计入 open")
	}
}

func TestSecurityConcurrentScanBlocked(t *testing.T) {
	_, center := setupSecurityCenterTest(t, []SecurityChecker{
		&fakeChecker{id: "ck", name: "C", category: "C", result: SecurityCheckResult{Status: "pass"}},
	})
	// 直接置为 running 模拟扫描进行中（不依赖异步 goroutine）
	center.mu.Lock()
	center.state.Status = "running"
	center.mu.Unlock()
	if err := center.StartScan(); err == nil {
		t.Fatal("扫描进行中再次启动应被拒绝")
	}
	if err := center.StartScanWithTrigger("test"); err == nil {
		t.Fatal("StartScanWithTrigger 同样应被拒绝")
	}
	center.mu.Lock()
	center.state.Status = "idle"
	center.mu.Unlock()
	if err := center.StartScan(); err != nil {
		t.Fatalf("空闲状态应可启动扫描: %v", err)
	}
	// 等待异步扫描收尾（fake checker 立即返回），避免清理时仍在写库
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if center.ScanStatusSnapshot().Status != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
}

func TestComputeSecurityScoreLevels(t *testing.T) {
	cases := []struct {
		counts map[string]int
		want   int
		level  string
	}{
		{map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}, 100, "良好"},
		{map[string]int{"critical": 0, "high": 1, "medium": 0, "low": 0}, 85, "注意"},
		{map[string]int{"critical": 0, "high": 3, "medium": 0, "low": 0}, 55, "风险"},
		{map[string]int{"critical": 2, "high": 3, "medium": 0, "low": 0}, 5, "严重"},
	}
	for _, c := range cases {
		got := computeSecurityScore(c.counts)
		if *got != c.want || scoreLevel(*got) != c.level {
			t.Fatalf("counts=%v: want %d/%s got %d/%s", c.counts, c.want, c.level, *got, scoreLevel(*got))
		}
	}
}

// 评分可解释性：扣分明细与最终分一致
func TestScoreBreakdown(t *testing.T) {
	// 100 - 1*25(critical) - 2*15(high) - 3*8(medium) = 21
	bd, score := computeScoreBreakdown(map[string]int{"critical": 1, "high": 2, "medium": 3}, time.Now())
	if *score != 21 {
		t.Fatalf("最终分不符: %d", *score)
	}
	if bd.BaseScore != 100 || bd.RuleVersion != "v1" || bd.UpdatedAt == "" {
		t.Fatalf("基础分/规则版本/更新时间缺失: %+v", bd)
	}
	total := 0
	for _, d := range bd.Deductions {
		total += d.Points
		if d.Count <= 0 || d.Points != d.Count*map[string]int{"严重风险": 25, "高风险": 15, "中风险": 8, "低风险": 3}[d.Reason] {
			t.Fatalf("扣分项异常: %+v", d)
		}
	}
	if bd.FinalScore != 100-total {
		t.Fatalf("扣分合计与最终分不一致: %d vs %d", total, bd.FinalScore)
	}
	// 触底钳制：扣分超过 100 时评分不为负
	bd2, score2 := computeScoreBreakdown(map[string]int{"critical": 2, "high": 5, "medium": 16}, time.Now())
	if *score2 != 0 || bd2.FinalScore != 0 {
		t.Fatalf("超限扣分应钳制为 0, got %d", *score2)
	}
	if got := scoreStatusKey(95); got != "good" {
		t.Fatalf("95 应为 good, got %s", got)
	}
	if got := scoreStatusKey(30); got != "critical" {
		t.Fatalf("30 应为 critical, got %s", got)
	}
}

// 风险趋势：按发现/解决时间重建每日未解决数
func TestSecurityTrend(t *testing.T) {
	store, center := setupSecurityCenterTest(t, []SecurityChecker{})
	old := &SecurityFinding{CheckID: "ck", DedupeKey: "old", Severity: "low", Title: "旧风险"}
	store.UpsertFinding(old)
	store.db.Exec(`UPDATE security_findings SET detected_at = ? WHERE id = ?`,
		time.Now().AddDate(0, 0, -5).Format(time.RFC3339Nano), old.ID)
	fresh := &SecurityFinding{CheckID: "ck", DedupeKey: "fresh", Severity: "low", Title: "新风险"}
	store.UpsertFinding(fresh)

	trend := center.securityTrend()
	if len(trend) != 7 {
		t.Fatalf("应为 7 天趋势, got %d", len(trend))
	}
	// 4 天前：只有 old（fresh 是今天发现的）
	if n := trend[2]["open"].(int); n != 1 {
		t.Fatalf("4 天前应为 1, got %v", trend[2])
	}
	// 今天：两个都在
	if n := trend[6]["open"].(int); n != 2 {
		t.Fatalf("今天应为 2, got %v", trend[6])
	}
	// 解决 old 后，昨天的点仍是 1（当时未解决），今天变为 1
	store.UpdateFindingStatus(old.ID, "resolved", "")
	trend2 := center.securityTrend()
	if n := trend2[5]["open"].(int); n != 1 {
		t.Fatalf("昨天（old 尚未解决）应为 1, got %v", trend2[5])
	}
	if n := trend2[6]["open"].(int); n != 1 {
		t.Fatalf("今天解决后应为 1, got %v", trend2[6])
	}
}

// 处置优先级：严重+公网+可修复排在最前，而非简单按时间
func TestPriorityFindings(t *testing.T) {
	store, center := setupSecurityCenterTest(t, []SecurityChecker{})

	// mk 插入发现并把 detected_at 回拨到指定时间（Upsert 会刷新为当前时间）
	mk := func(key, sev, check string, remediable bool, age time.Duration, occ int) *SecurityFinding {
		f := &SecurityFinding{CheckID: check, DedupeKey: key, Severity: sev, Title: "风险" + key,
			Remediable: remediable, Occurrences: occ}
		store.UpsertFinding(f)
		store.db.Exec(`UPDATE security_findings SET detected_at = ? WHERE id = ?`,
			time.Now().Add(-age).Format(time.RFC3339Nano), f.ID)
		return f
	}
	mk("a", "medium", "file_permissions", false, 72*time.Hour, 1)       // 低优先
	mk("b", "high", "service_health", true, 30*24*time.Hour, 5)         // 高+可修复+多次出现，但陈旧
	mk("c", "critical", "open_ports", true, 2*time.Hour, 3)             // 应排第一
	d := mk("d", "high", "open_ports", false, 2*time.Hour, 1)           // 公网但不可修复，初始略低于 b
	list := center.priorityFindings(3)
	if len(list) != 3 {
		t.Fatalf("应返回 3 条, got %d", len(list))
	}
	if list[0].DedupeKey != "c" {
		t.Fatalf("严重+公网+可修复应排第一, got %s", list[0].DedupeKey)
	}
	// failed 状态加权：d 置为 failed 后应超过陈旧的 b（排进前二）
	store.UpdateFindingStatus(d.ID, "failed", "模拟失败")
	list2 := center.priorityFindings(5)
	if list2[0].DedupeKey != "c" {
		t.Fatalf("c 应仍排第一, got %s", list2[0].DedupeKey)
	}
	posD := -1
	for i, f := range list2 {
		if f.DedupeKey == "d" {
			posD = i
		}
	}
	if posD == -1 || posD > 1 {
		t.Fatalf("failed 状态的 d 应排进前二, pos=%d list=%+v", posD, list2)
	}
}

// 停用检查器：扫描跳过、检查器清单标记 enabled=false
func TestDisabledCheckersSkipped(t *testing.T) {
	ckA := &fakeChecker{id: "ck_on", name: "启用项", category: "C", result: SecurityCheckResult{Status: "pass"}}
	ckB := &fakeChecker{id: "ck_off", name: "停用项", category: "C", result: SecurityCheckResult{
		Status: "warn", Findings: []SecurityFinding{{DedupeKey: "kb", Severity: "high", Title: "不应产生的风险"}},
	}}
	store, center := setupSecurityCenterTest(t, []SecurityChecker{ckA, ckB})
	store.SetSetting("security.disabled_checkers", `["ck_off"]`)

	center.runScan("test")
	_, total, _ := store.ListFindings(FindingFilter{Limit: 10})
	if total != 0 {
		t.Fatalf("停用检查器不应产生发现, got %d", total)
	}
	steps := center.ScanStatusSnapshot().Steps
	if len(steps) != 2 || steps[1].Status != "skipped" {
		t.Fatalf("停用项应有 skipped 步骤: %+v", steps)
	}
	if center.disabledCheckers()["ck_off"] != true {
		t.Fatal("disabledCheckers 读取失败")
	}
}

// TestCronParseAndNext 覆盖 cron 解析与下次触发时间计算（调度器核心）
func TestCronParseAndNext(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.Local) // 周日
	cases := []struct {
		expr string
		want time.Time
	}{
		{"0 3 * * *", time.Date(2026, 9, 14, 3, 0, 0, 0, time.Local)},      // 明天 03:00
		{"*/15 * * * *", time.Date(2026, 9, 13, 12, 15, 0, 0, time.Local)}, // 12:15
		{"30 4 * * 1", time.Date(2026, 9, 14, 4, 30, 0, 0, time.Local)},    // 下周一
		// 12:00 整点的触发刚刚过去（Next 严格大于 after）→ 下一次是明天 12:00
		{"0 12 * * *", time.Date(2026, 9, 14, 12, 0, 0, 0, time.Local)},
	}
	for _, c := range cases {
		expr, err := ParseCron(c.expr)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", c.expr, err)
		}
		got := expr.Next(base)
		if !got.Equal(c.want) {
			t.Fatalf("%s Next(%v) = %v, want %v", c.expr, base, got, c.want)
		}
	}
	for _, bad := range []string{"", "abc", "0 3 * *", "61 * * * *", "0 25 * * *", "* * * * * *"} {
		if _, err := ParseCron(bad); err == nil {
			t.Fatalf("非法 cron 未被拒绝: %q", bad)
		}
	}
	if _, err := ParseCron("@daily"); err != nil {
		t.Fatalf("@daily 应可解析: %v", err)
	}
}

// ==================== HTTP 保护链测试 ====================

func opsTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/security/overview", authMiddleware(requireAnyPermission([]string{"security:view", "remediation:view"}, securityMiddleware(securityOverviewHandler))))
	mux.HandleFunc("POST /api/security/scan", authMiddleware(requirePermission("security:scan", securityMiddleware(securityScanStartHandler))))
	mux.HandleFunc("GET /api/security/findings", authMiddleware(requirePermission("security:view", securityMiddleware(securityFindingsHandler))))
	mux.HandleFunc("POST /api/security/findings/{id}/ignore", authMiddleware(requirePermission("security:manage", securityMiddleware(securityFindingIgnoreHandler))))
	mux.HandleFunc("POST /api/security/findings/{id}/remediate", authMiddleware(requirePermission("remediation:execute", securityMiddleware(securityFindingRemediateHandler))))
	mux.HandleFunc("GET /api/tasks", authMiddleware(requirePermission("task:view", securityMiddleware(tasksListHandler))))
	mux.HandleFunc("POST /api/tasks", authMiddleware(requirePermission("task:manage", securityMiddleware(taskCreateHandler))))
	mux.HandleFunc("POST /api/tasks/{id}/run", authMiddleware(requirePermission("task:execute", securityMiddleware(taskRunNowHandler))))
	return mux
}

func setupOpsHTTPTenv(t *testing.T) (*http.ServeMux, *OpsStore) {
	t.Helper()
	mux := func() *http.ServeMux {
		oldUM := userManager
		userManager = &UserManager{
			RWMutex:   sync.RWMutex{},
			UserInfos: map[string]*Users{
				"admin": {Username: "admin", IsActive: true, Permissions: []string{"*"}},
				"guest": {Username: "guest", IsActive: true, Permissions: []string{}},
			},
			Sessions: make(map[string]*Session),
		}
		t.Cleanup(func() { userManager = oldUM })
		return opsTestMux()
	}()
	store := newTestOpsStore(t)
	oldStore, oldCenter, oldRemStore := opsStore, opsCenter, remEngine.store
	// 用立即返回的假检查器，避免 HTTP 测试里跑真实检查（Windows/CI 环境不稳定）
	opsStore = store
	opsCenter = newSecurityCenter(store, []SecurityChecker{
		&fakeChecker{id: "ck_fast", name: "快速检查", category: "C", result: SecurityCheckResult{Status: "pass", Summary: "ok"}},
	})
	remEngine.store = store
	t.Cleanup(func() {
		opsStore, opsCenter, remEngine.store = oldStore, oldCenter, oldRemStore
	})
	return mux, store
}

func waitScanIdle(t *testing.T, center *SecurityCenter) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if center.ScanStatusSnapshot().Status != "running" {
			time.Sleep(150 * time.Millisecond) // 等待 goroutine 收尾写入
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Log("扫描未在 5 秒内结束（不影响断言）")
}

func TestOpsHTTPAuthChain(t *testing.T) {
	mux, _ := setupOpsHTTPTenv(t)

	// 未登录 → 401
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/security/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401, got %d", rec.Code)
	}

	sess := newTestSession("admin")

	// 无 CSRF 的写操作 → 403
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/security/scan", "", false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("写操作缺 CSRF 应 403, got %d", rec.Code)
	}

	// 带 CSRF → 200（扫描已启动，异步执行）
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/security/scan", "", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("带 CSRF 应 200, got %d: %s", rec.Code, rec.Body.String())
	}
	waitScanIdle(t, opsCenter)

	// RBAC：guest 无权限 → 403
	guest := newTestSession("guest")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(guest, "GET", "/api/security/findings", "", false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("无权限应 403, got %d", rec.Code)
	}

	// remediate 权限粒度：guest 即便拿到 CSRF 也不能执行修复
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(guest, "POST", "/api/security/findings/xxx/remediate", "{}", true))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest 修复应 403, got %d", rec.Code)
	}

	// task:manage 与 task:execute 分离：guest 创建任务 403
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(guest, "POST", "/api/tasks", `{"name":"x"}`, true))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest 创建任务应 403, got %d", rec.Code)
	}
}

func TestOpsTaskValidationRejects(t *testing.T) {
	mux, _ := setupOpsHTTPTenv(t)
	sess := newTestSession("admin")
	cases := []struct {
		name string
		body string
	}{
		{"非法 Cron", `{"name":"t1","type":"cron","schedule":"a b c d e","action_id":"security_scan"}`},
		{"过短周期", `{"name":"t2","type":"interval","interval_seconds":5,"action_id":"security_scan"}`},
		{"非法 Action", `{"name":"t3","type":"cron","schedule":"0 3 * * *","action_id":"run_shell"}`},
		{"过去时间", `{"name":"t4","type":"once","run_at":"2020-01-01T00:00:00Z","action_id":"security_scan"}`},
		{"未知事件类型", `{"name":"t5","type":"event","trigger":{"type":"boom"},"action_id":"security_scan"}`},
		// 服务名注入：start_service 的 Validate 必须拦截带元字符的服务名
		{"服务名注入", `{"name":"t7","type":"cron","schedule":"0 3 * * *","action_id":"start_service","parameters":{"service":"nginx; rm -rf /"}}`},
		// 路径穿越：rotate_log 只允许数据目录 log/ 下的文件
		{"日志路径穿越", `{"name":"t8","type":"cron","schedule":"0 3 * * *","action_id":"rotate_log","parameters":{"path":"/etc/passwd"}}`},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/tasks", c.body, true))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400, got %d: %s", c.name, rec.Code, rec.Body.String())
		}
	}
}

func TestOpsFindingIgnoreFlow(t *testing.T) {
	mux, store := setupOpsHTTPTenv(t)
	sess := newTestSession("admin")
	f := &SecurityFinding{CheckID: "ck", DedupeKey: "k", Severity: "low", Title: "测试风险"}
	store.UpsertFinding(f)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, secureReq(sess, "POST", "/api/security/findings/"+f.ID+"/ignore", "", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("忽略应 200, got %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := store.GetFinding(f.ID)
	if got.Status != "ignored" {
		t.Fatalf("状态应为 ignored, got %s", got.Status)
	}
	if !strings.Contains(rec.Body.String(), "code\":200") {
		t.Fatalf("响应应使用统一封装: %s", rec.Body.String())
	}
}
