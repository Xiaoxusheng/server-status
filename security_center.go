package main

// ==================== 安全中心 ====================
//
// 职责：编排安全检查器（异步扫描）、合并风险发现、计算安全评分、
// 记录安全事件、按计划定时扫描，并把新风险交给自动修复引擎。
// 扫描完全异步，绝不阻塞 HTTP；同一时刻只允许一个扫描在跑。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SecurityChecker 安全检查器接口：以后新增检查项只需实现并注册，不污染主逻辑
type SecurityChecker interface {
	ID() string
	Name() string
	Category() string
	Description() string
	Check(ctx context.Context) SecurityCheckResult
}

// SecurityCheckResult 检查器返回值
type SecurityCheckResult struct {
	Status   string            `json:"status"` // pass/warn/fail/error
	Summary  string            `json:"summary"`
	Findings []SecurityFinding `json:"findings"`
	Detail   map[string]any    `json:"detail,omitempty"`
}

// ScanStep 单个检查器的扫描进度
type ScanStep struct {
	CheckerID   string `json:"checker_id"`
	CheckerName string `json:"checker_name"`
	Category    string `json:"category"`
	Status      string `json:"status"` // pending/running/pass/warn/fail/error
	Findings    int    `json:"findings"`
	Summary     string `json:"summary"`
	DurationMS  int64  `json:"duration_ms"`
}

// ScanState 一次扫描的状态快照（内存中仅保留最近一次）
type ScanState struct {
	Status            string     `json:"status"` // idle/running/success/failed
	Trigger           string     `json:"trigger,omitempty"`
	StartedAt         time.Time  `json:"started_at,omitempty"`
	FinishedAt        *time.Time `json:"finished_at,omitempty"`
	Steps             []ScanStep `json:"steps,omitempty"`
	Total             int        `json:"total"`
	NewFindings       int        `json:"new_findings"`
	ResolvedFindings  int        `json:"resolved_findings"`
	OpenAfterScan     int        `json:"open_after_scan"`
	Score             *int       `json:"score,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// SecurityCenter 安全中心
type SecurityCenter struct {
	mu       sync.Mutex
	scanMu   sync.Mutex // 同一时间只允许一个扫描（TryLock 语义）
	store    *OpsStore
	checkers []SecurityChecker
	state    ScanState
	started  time.Time // 进程启动时间（首次计划扫描用）
}

var (
	opsStore  *OpsStore
	opsCenter *SecurityCenter
)

const (
	checkerTimeout = 90 * time.Second
	scanTotalCap   = 10 * time.Minute
)

// newSecurityCenter 组装安全中心（测试可注入自定义检查器）
func newSecurityCenter(store *OpsStore, checkers []SecurityChecker) *SecurityCenter {
	return &SecurityCenter{store: store, checkers: checkers, started: time.Now()}
}

// StartScan 异步启动一次全量扫描；已有扫描进行中时返回错误
func (c *SecurityCenter) StartScan() error {
	if c == nil || c.store == nil {
		return fmt.Errorf("安全中心未初始化")
	}
	c.mu.Lock()
	if c.state.Status == "running" {
		c.mu.Unlock()
		return fmt.Errorf("安全扫描正在进行中，请稍后再试")
	}
	c.state = ScanState{
		Status:    "running",
		StartedAt: time.Now(),
		Total:     len(c.checkers),
		Steps:     make([]ScanStep, 0, len(c.checkers)),
	}
	c.mu.Unlock()

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("安全扫描 panic: %v", rec)
				c.mu.Lock()
				c.state.Status = "failed"
				c.state.Error = fmt.Sprintf("内部错误: %v", rec)
				now := time.Now()
				c.state.FinishedAt = &now
				c.mu.Unlock()
			}
		}()
		c.runScan("manual")
	}()
	return nil
}

// StartScanWithTrigger 带触发来源的启动入口（schedule/task）
func (c *SecurityCenter) StartScanWithTrigger(trigger string) error {
	if c == nil || c.store == nil {
		return fmt.Errorf("安全中心未初始化")
	}
	c.mu.Lock()
	running := c.state.Status == "running"
	c.mu.Unlock()
	if running {
		return fmt.Errorf("安全扫描正在进行中，请稍后再试")
	}
	c.mu.Lock()
	c.state = ScanState{Status: "running", StartedAt: time.Now(), Total: len(c.checkers), Steps: make([]ScanStep, 0, len(c.checkers))}
	c.mu.Unlock()
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("安全扫描 panic: %v", rec)
			}
		}()
		c.runScan(trigger)
	}()
	return nil
}

// ScanStatusSnapshot 读取当前扫描状态（供 API 与动作 Verify 使用）
func (c *SecurityCenter) ScanStatusSnapshot() ScanState {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := c.state
	// 深拷贝 steps，避免调用方并发读
	cp.Steps = append([]ScanStep(nil), c.state.Steps...)
	return cp
}

// runScan 执行扫描流水线
func (c *SecurityCenter) runScan(trigger string) {
	c.mu.Lock()
	c.state.Trigger = trigger
	c.mu.Unlock()

	totalStart := time.Now()
	newFindings := make([]SecurityFinding, 0, 8)
	resolvedCount := 0
	disabled := c.disabledCheckers()

	for i, checker := range c.checkers {
		if disabled[checker.ID()] {
			c.appendStep(i, ScanStep{CheckerID: checker.ID(), CheckerName: checker.Name(), Category: checker.Category(), Status: "skipped", Summary: "已在扫描设置中停用"})
			continue
		}
		if time.Since(totalStart) > scanTotalCap {
			log.Printf("安全扫描总时长超限，剩余检查器跳过")
			break
		}
		step := ScanStep{CheckerID: checker.ID(), CheckerName: checker.Name(), Category: checker.Category(), Status: "running"}
		c.appendStep(i, step)

		ctx, cancel := context.WithTimeout(context.Background(), checkerTimeout)
		result := checker.Check(ctx)
		cancel()

		step.DurationMS = time.Since(totalStart).Milliseconds() // 累计无妨，仅展示
		switch result.Status {
		case "warn":
			step.Status = "warn"
		case "fail":
			step.Status = "fail"
		case "error":
			step.Status = "error"
		default:
			step.Status = "pass"
		}
		step.Summary = result.Summary
		step.Findings = len(result.Findings)

		// 写入/合并发现
		for j := range result.Findings {
			f := result.Findings[j]
			f.CheckID = checker.ID()
			f.Category = checker.Category()
			created, reopened, err := c.store.UpsertFinding(&f)
			if err != nil {
				log.Printf("写入安全发现失败: %v", err)
				continue
			}
			if created {
				newFindings = append(newFindings, f)
				c.store.AddEvent(&SecurityEvent{
					Level:  severityEventLevel(f.Severity),
					Type:   "finding.open",
					Title:  fmt.Sprintf("发现风险：%s", f.Title),
					Source: checker.Name(), RefID: f.ID,
					Detail: f.Description,
				})
				opsHub.broadcast(map[string]any{"type": "finding.open", "finding": f})
			} else if reopened {
				newFindings = append(newFindings, f)
				c.store.AddEvent(&SecurityEvent{
					Level:  severityEventLevel(f.Severity),
					Type:   "finding.open",
					Title:  fmt.Sprintf("风险回归：%s", f.Title),
					Source: checker.Name(), RefID: f.ID,
					Detail: "此前已解决的风险再次出现",
				})
				opsHub.broadcast(map[string]any{"type": "finding.open", "finding": f})
			}
		}
		// 本检查下未再发现的风险自动恢复
		liveKeys := map[string]bool{}
		for j := range result.Findings {
			liveKeys[result.Findings[j].DedupeKey] = true
		}
		resolved, _ := c.store.ResolveFindingsNotIn(checker.ID(), liveKeys)
		for _, r := range resolved {
			resolvedCount++
			c.store.AddEvent(&SecurityEvent{
				Level: "info", Type: "finding.resolved",
				Title:  fmt.Sprintf("风险恢复：%s", r.Title),
				Source: checker.Name(), RefID: r.ID,
				Detail: "最近一次扫描未再检测到该风险，已自动标记为已解决",
			})
			opsHub.broadcast(map[string]any{"type": "finding.resolved", "finding_id": r.ID, "title": r.Title})
		}

		// 更新 remediable 标记（该检查下是否有可用规则）
		c.markRemediable(checker.ID())
		c.appendStep(i, step)
	}

	// 汇总
	openCounts := c.store.CountOpenFindingsBySeverity()
	now := time.Now()
	breakdown, scorePtr := computeScoreBreakdown(openCounts, now)
	openTotal := 0
	for _, n := range openCounts {
		openTotal += n
	}

	c.mu.Lock()
	c.state.Status = "success"
	c.state.FinishedAt = &now
	c.state.NewFindings = len(newFindings)
	c.state.ResolvedFindings = resolvedCount
	c.state.OpenAfterScan = openTotal
	c.state.Score = scorePtr
	c.mu.Unlock()

	durationMS := time.Since(totalStart).Milliseconds()
	summary := map[string]any{
		"time": now.Format(time.RFC3339), "score": breakdown.FinalScore, "counts": openCounts,
		"new": len(newFindings), "resolved": resolvedCount, "status": "success",
		"duration_ms": durationMS, "checks_total": len(c.checkers),
		"breakdown": breakdown,
	}
	if b, err := json.Marshal(summary); err == nil {
		c.store.SetSetting("security.last_scan_summary", string(b))
	}

	c.store.AddEvent(&SecurityEvent{
		Level: "info", Type: "scan.completed",
		Title: fmt.Sprintf("安全扫描完成：新增 %d / 恢复 %d / 待处理 %d", len(newFindings), resolvedCount, openTotal),
		Source: "安全中心",
		Detail: fmt.Sprintf("安全评分 %d，耗时 %s，触发方式 %s", breakdown.FinalScore, time.Duration(durationMS)*time.Millisecond, trigger),
	})
	opsHub.broadcast(map[string]any{
		"type": "security.scan.completed", "score": breakdown.FinalScore,
		"new": len(newFindings), "resolved": resolvedCount, "open": openTotal,
	})
	log.Printf("🛡️ 安全扫描完成（%s）：新增 %d，恢复 %d，待处理 %d，评分 %d",
		trigger, len(newFindings), resolvedCount, openTotal, breakdown.FinalScore)

	// 闭环：新产生 / 回归的风险交给自动修复引擎（引擎内部有全部安全闸门）
	remEngine.AutoRemediateAfterScan(newFindings)
}

func (c *SecurityCenter) appendStep(index int, step ScanStep) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Steps == nil {
		c.state.Steps = make([]ScanStep, 0, len(c.checkers))
	}
	for len(c.state.Steps) <= index {
		c.state.Steps = append(c.state.Steps, ScanStep{Status: "pending"})
	}
	c.state.Steps[index] = step
	opsHub.broadcast(map[string]any{"type": "security.scan.progress", "step": step, "index": index, "total": len(c.checkers)})
}

// markRemediable 回填 remediable 标记：该检查下存在匹配的启用规则即可修复
func (c *SecurityCenter) markRemediable(checkID string) {
	findings, _, err := c.store.ListFindings(FindingFilter{CheckID: checkID, Limit: 200})
	if err != nil {
		return
	}
	for i := range findings {
		f := findings[i]
		if f.Status == "resolved" {
			continue
		}
		rules := remEngine.MatchRules(&f)
		if (len(rules) > 0) != f.Remediable {
			// Upsert 一条空变更太重，这里直接 UPDATE
			c.store.db.Exec(`UPDATE security_findings SET remediable=? WHERE id=?`, boolToInt(len(rules) > 0), f.ID)
		}
	}
}

// severityEventLevel 风险严重级 → 事件级别
func severityEventLevel(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "info"
	}
}

// ScoreDeduction 单条评分扣分项（评分可解释性：前端展示扣分原因）
type ScoreDeduction struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
	Points int    `json:"points"`
}

// SecurityScoreBreakdown 评分构成（基础分 - 扣分 = 最终分）
type SecurityScoreBreakdown struct {
	BaseScore   int              `json:"base_score"`
	Deductions  []ScoreDeduction `json:"deductions"`
	FinalScore  int              `json:"final_score"`
	RuleVersion string           `json:"rule_version"`
	UpdatedAt   string           `json:"updated_at,omitempty"`
}

// scoreRuleVersion 评分规则版本（规则变更时递增，前端展示用）
const scoreRuleVersion = "v1"

// computeScoreBreakdown 按未解决风险计算评分并给出扣分明细。
// 权重与历史版本保持一致：critical 25 / high 15 / medium 8 / low 3 / info 0。
func computeScoreBreakdown(counts map[string]int, updatedAt time.Time) (*SecurityScoreBreakdown, *int) {
	b := &SecurityScoreBreakdown{BaseScore: 100, RuleVersion: scoreRuleVersion, Deductions: []ScoreDeduction{}}
	add := func(sev, label string, weight int) {
		if n := counts[sev]; n > 0 {
			b.Deductions = append(b.Deductions, ScoreDeduction{Reason: label, Count: n, Points: n * weight})
		}
	}
	add("critical", "严重风险", 25)
	add("high", "高风险", 15)
	add("medium", "中风险", 8)
	add("low", "低风险", 3)
	total := 0
	for _, d := range b.Deductions {
		total += d.Points
	}
	score := 100 - total
	if score < 0 {
		score = 0
	}
	b.FinalScore = score
	if !updatedAt.IsZero() {
		b.UpdatedAt = updatedAt.Format("01-02 15:04")
	}
	return b, &score
}

// computeSecurityScore 评分：100 起步，按未解决风险扣分
// critical 25 / high 15 / medium 8 / low 3 / info 0
func computeSecurityScore(counts map[string]int) *int {
	_, score := computeScoreBreakdown(counts, time.Time{})
	return score
}

// scoreLevel 评分档位
func scoreLevel(score int) string {
	switch {
	case score >= 90:
		return "良好"
	case score >= 70:
		return "注意"
	case score >= 40:
		return "风险"
	default:
		return "严重"
	}
}

// scoreStatusKey 评分档位的英文状态键（前端状态点着色用）
func scoreStatusKey(score int) string {
	switch {
	case score >= 90:
		return "good"
	case score >= 70:
		return "warning"
	case score >= 40:
		return "risk"
	default:
		return "critical"
	}
}

// ---------------- 处置优先级 ----------------

// priorityScoreOf 风险处置优先级打分（不简单按时间或严重度排序）：
//   严重等级基数（critical 40 / high 30 / medium 20 / low 10）
// + 公网暴露类风险加权 +15（open_ports 检查只对公网监听产出发现）
// + 可自动修复 +10（处理成本低，优先消化）
// + 曾经修复失败 +8（已尝试且未成功，需要尽快人工介入）
// + 反复出现次数（每次 +2，封顶 +10）
// + 新鲜度（1 小时内 +5，24 小时内 +2）
func priorityScoreOf(f *SecurityFinding) int {
	base := map[string]int{"critical": 40, "high": 30, "medium": 20, "low": 10}[f.Severity]
	score := base
	if f.CheckID == "open_ports" {
		score += 15
	}
	if f.Remediable {
		score += 10
	}
	if f.Status == "failed" {
		score += 8
	}
	occ := f.Occurrences
	if occ > 5 {
		occ = 5
	}
	score += occ * 2
	age := time.Since(f.DetectedAt)
	switch {
	case age < time.Hour:
		score += 5
	case age < 24*time.Hour:
		score += 2
	}
	return score
}

// priorityFindings 返回待处理风险中建议优先处理的 Top N
func (c *SecurityCenter) priorityFindings(n int) []SecurityFinding {
	list, _, err := c.store.ListFindings(FindingFilter{Status: []string{"open", "failed"}, Limit: 300})
	if err != nil {
		return nil
	}
	sort.SliceStable(list, func(i, j int) bool {
		pi, pj := priorityScoreOf(&list[i]), priorityScoreOf(&list[j])
		if pi != pj {
			return pi > pj
		}
		return list[i].DetectedAt.After(list[j].DetectedAt)
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

// ---------------- 风险趋势 ----------------

// securityTrend 近 7 天待处理风险数量趋势（按发现/解决时间近似重建每日未解决数）
func (c *SecurityCenter) securityTrend() []map[string]any {
	out := make([]map[string]any, 0, 7)
	now := time.Now()
	prev := 0
	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dayEnd := time.Date(day.Year(), day.Month(), day.Day(), 23, 59, 59, 0, day.Location())
		n := c.store.CountFindingsOpenAt(dayEnd)
		out = append(out, map[string]any{
			"date":  day.Format("01-02"),
			"open":  n,
			"delta": n - prev,
		})
		prev = n
	}
	return out
}

// ---------------- 停用检查器 ----------------

// disabledCheckers 已在扫描设置中停用的检查器集合
func (c *SecurityCenter) disabledCheckers() map[string]bool {
	out := map[string]bool{}
	if c.store == nil {
		return out
	}
	var list []string
	if err := json.Unmarshal([]byte(c.store.GetSetting("security.disabled_checkers", "")), &list); err == nil {
		for _, id := range list {
			out[id] = true
		}
	}
	return out
}

// ---------------- 扫描计划调度 ----------------

// ScanSchedule 扫描计划配置（持久化在 ops_settings）
type ScanSchedule struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"` // hourly/daily/weekly/cron
	Minute  int    `json:"minute"`
	Hour    int    `json:"hour"`
	Weekday int    `json:"weekday"` // 0=周日
	Cron    string `json:"cron,omitempty"`
}

// defaultScanSchedule 默认每天 05:30 扫描一次
func defaultScanSchedule() ScanSchedule {
	return ScanSchedule{Enabled: true, Type: "daily", Minute: 30, Hour: 5, Weekday: 1}
}

func (c *SecurityCenter) loadSchedule() ScanSchedule {
	raw := c.store.GetSetting("security.scan_schedule", "")
	if raw == "" {
		return defaultScanSchedule()
	}
	var s ScanSchedule
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return defaultScanSchedule()
	}
	return s
}

func (c *SecurityCenter) saveSchedule(s ScanSchedule) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return c.store.SetSetting("security.scan_schedule", string(b))
}

// nextScheduleRun 计算计划扫描的下次触发时间（以 lastRun 为基准）
func nextScheduleRun(s ScanSchedule, lastRun time.Time) time.Time {
	if !s.Enabled {
		return time.Time{}
	}
	now := time.Now()
	base := lastRun
	if base.IsZero() {
		// 从未扫描过：启动 2 分钟后跑首次扫描
		return time.Now().Add(2 * time.Minute)
	}
	switch s.Type {
	case "hourly":
		next := time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), s.Minute%60, 0, 0, base.Location())
		if !next.After(base) {
			next = next.Add(time.Hour)
		}
		for next.Before(now) {
			next = next.Add(time.Hour)
		}
		return next
	case "daily":
		next := time.Date(base.Year(), base.Month(), base.Day(), s.Hour%24, s.Minute%60, 0, 0, base.Location())
		if !next.After(base) {
			next = next.AddDate(0, 0, 1)
		}
		for next.Before(now) {
			next = next.AddDate(0, 0, 1)
		}
		return next
	case "weekly":
		next := time.Date(base.Year(), base.Month(), base.Day(), s.Hour%24, s.Minute%60, 0, 0, base.Location())
		for {
			// 前进到目标星期
			for int(next.Weekday()) != s.Weekday%7 {
				next = next.AddDate(0, 0, 1)
			}
			if next.After(base) && next.After(now) {
				return next
			}
			next = next.AddDate(0, 0, 1)
		}
	case "cron":
		expr, err := ParseCron(s.Cron)
		if err != nil {
			return time.Time{}
		}
		return expr.NextAfter(base, now)
	default:
		return time.Time{}
	}
}

// scanScheduleLoop 计划扫描守护协程（每 30 秒检查一次是否到点）
func (c *SecurityCenter) scanScheduleLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s := c.loadSchedule()
		if !s.Enabled {
			continue
		}
		var lastRun time.Time
		if raw := c.store.GetSetting("security.last_scan_summary", ""); raw != "" {
			var m map[string]any
			if json.Unmarshal([]byte(raw), &m) == nil {
				if ts, ok := m["time"].(string); ok {
					lastRun = parseDBTime(ts)
				}
			}
		}
		next := nextScheduleRun(s, lastRun)
		if next.IsZero() || time.Now().Before(next) {
			continue
		}
		log.Printf("⏰ 到达计划扫描时间，自动启动安全扫描（%s）", s.Type)
		c.store.AddEvent(&SecurityEvent{Level: "info", Type: "scan.started", Title: "计划扫描已启动", Source: "安全中心"})
		if err := c.StartScanWithTrigger("schedule"); err != nil {
			log.Printf("计划扫描启动失败: %v", err)
		}
	}
}

// ---------------- 运维事件 WebSocket 推送 ----------------

type opsEventHub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

var opsHub = &opsEventHub{clients: map[*websocket.Conn]bool{}}

func (h *opsEventHub) broadcast(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.clients {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			delete(h.clients, conn)
			conn.Close()
		}
	}
}

// opsEventsWSHandler GET /ws/ops-events：向具备安全/修复/任务任一查看权限的客户端推送实时事件
func opsEventsWSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("运维事件 WebSocket 升级失败:", err)
		return
	}
	opsHub.mu.Lock()
	opsHub.clients[conn] = true
	opsHub.mu.Unlock()
	defer func() {
		opsHub.mu.Lock()
		delete(opsHub.clients, conn)
		opsHub.mu.Unlock()
		conn.Close()
	}()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// ---------------- Overview 汇总 ----------------

// overview 安全中心首页汇总（一次请求带回评分/分布/趋势/优先处理/最近事件，减少前端并发请求）
func (c *SecurityCenter) overview() map[string]any {
	out := map[string]any{
		"available": true,
	}
	if c == nil || c.store == nil {
		out["available"] = false
		return out
	}
	counts := c.store.CountOpenFindingsBySeverity()
	openTotal := 0
	for _, n := range counts {
		openTotal += n
	}

	// 最近扫描时间作为评分更新时间
	var lastSummary map[string]any
	if raw := c.store.GetSetting("security.last_scan_summary", ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &lastSummary)
	}
	var lastScanAt time.Time
	if lastSummary != nil {
		if ts, ok := lastSummary["time"].(string); ok {
			lastScanAt = parseDBTime(ts)
		}
	}
	breakdown, scorePtr := computeScoreBreakdown(counts, lastScanAt)
	out["score"] = scorePtr
	out["score_breakdown"] = breakdown
	if scorePtr != nil {
		out["score_level"] = scoreLevel(*scorePtr)
		out["status"] = scoreStatusKey(*scorePtr)
	}
	out["counts"] = counts
	out["open_total"] = openTotal
	out["pending"] = openTotal
	out["last_scan_summary"] = lastSummary

	st := c.ScanStatusSnapshot()
	if st.Status == "running" {
		out["scan"] = map[string]any{"status": "running", "steps": st.Steps, "total": st.Total}
	} else {
		out["scan"] = map[string]any{"status": "idle"}
	}
	sched := c.loadSchedule()
	out["schedule"] = sched
	if next := nextScheduleRun(sched, lastScanAt); !next.IsZero() {
		out["next_scan_at"] = next
	}
	// 检查器清单（含最近一次扫描状态与启用状态，供扫描设置与检查项展示）
	checkers := make([]map[string]any, 0, len(c.checkers))
	stepBy := map[string]ScanStep{}
	for _, s := range st.Steps {
		stepBy[s.CheckerID] = s
	}
	disabled := c.disabledCheckers()
	for _, ck := range c.checkers {
		m := map[string]any{
			"id": ck.ID(), "name": ck.Name(), "category": ck.Category(),
			"description": ck.Description(), "enabled": !disabled[ck.ID()],
		}
		if s, ok := stepBy[ck.ID()]; ok {
			m["last_status"] = s.Status
			m["last_summary"] = s.Summary
			m["last_findings"] = s.Findings
		}
		checkers = append(checkers, m)
	}
	out["checkers"] = checkers
	out["trend"] = c.securityTrend()
	out["priority_findings"] = c.priorityFindings(5)
	if events, _, err := c.store.ListEvents("", "", 8, 0); err == nil {
		out["recent_events"] = events
	}
	return out
}

func strAny(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// ---------------- 初始化 ----------------

// initOpsCenter 在 main() 中调用：打开存储、装配检查器、预置策略、启动调度
func initOpsCenter() {
	store, err := NewOpsStore(filepath.Join(dataRoot(), "ops_center.db"))
	if err != nil {
		log.Printf("⚠️ 运维中心存储不可用，安全中心/自动修复/运维任务未启用: %v", err)
		return
	}
	opsStore = store
	remEngine.store = store
	opsCenter = newSecurityCenter(store, defaultSecurityCheckers())
	remEngine.seedDefaultRules()
	go opsCenter.scanScheduleLoop()
	go opsMaintenanceLoop()
	log.Println("✅ 安全中心 / 自动修复 / 运维任务已启用（ops_center.db）")
}

// opsMaintenanceLoop 每日清理过期流水，防止数据库无限膨胀
func opsMaintenanceLoop() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if opsStore != nil {
			opsStore.CleanupOldRecords(2000, 2000)
		}
	}
}

// sortFindings 展示排序（severity 优先）——供 handler 使用
func sortFindings(fs []SecurityFinding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return fs[i].DetectedAt.After(fs[j].DetectedAt)
	})
}
