package main

// ==================== 自动修复引擎 ====================
//
// 核心原则（架构红线）：
//   检测 ≠ 修复，修复 ≠ Shell，任务 ≠ Shell。
//   所有修复动作必须来自白名单 Registry，禁止任何用户输入直接拼接 shell。
//   流程：Finding → Rule → Action Preview → 权限/CSRF → 确认 → Execute → Verify → Audit。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ActionParam 动作参数说明（供前端动态渲染表单，杜绝自由文本命令）
type ActionParam struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // string/int/enum/duration
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
	Default  any      `json:"default,omitempty"`
	Help     string   `json:"help,omitempty"`
}

// ActionPreview 修复预览（确认弹窗内容）
type ActionPreview struct {
	Title     string   `json:"title"`
	Action    string   `json:"action"`
	ActionName string  `json:"action_name"`
	Steps     []string `json:"steps"`
	Impact    string   `json:"impact"`
	Risk      string   `json:"risk"`
	RiskLevel string   `json:"risk_level"`
	// CommandHint 仅描述内部受控机制（如 "systemctl start <unit>"），不是可编辑命令
	CommandHint string `json:"command_hint"`
}

// ActionResult 动作执行结果
type ActionResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
}

// VerifyResult 修复后验证结果
type VerifyResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// RemediationAction 白名单修复动作接口
type RemediationAction interface {
	ID() string
	Name() string
	Description() string
	RiskLevel() string // low/medium/high（动作本身的风险）
	AllowAuto() bool   // 是否允许配置为自动执行（高风险动作必须人工确认）
	ParamSpec() []ActionParam
	Validate(params map[string]any) error
	Preview(ctx context.Context, params map[string]any) (*ActionPreview, error)
	Execute(ctx context.Context, params map[string]any) (*ActionResult, error)
	Verify(ctx context.Context, params map[string]any) (*VerifyResult, error)
}

// ---------------- Action Registry ----------------

var (
	remediationRegistryMu sync.RWMutex
	remediationRegistry   = map[string]RemediationAction{}
)

func registerRemediationAction(a RemediationAction) {
	remediationRegistryMu.Lock()
	defer remediationRegistryMu.Unlock()
	remediationRegistry[a.ID()] = a
}

// unregisterRemediationAction 仅供测试注入假动作使用
func unregisterRemediationAction(id string) {
	remediationRegistryMu.Lock()
	defer remediationRegistryMu.Unlock()
	delete(remediationRegistry, id)
}

func getRemediationAction(id string) (RemediationAction, bool) {
	remediationRegistryMu.RLock()
	defer remediationRegistryMu.RUnlock()
	a, ok := remediationRegistry[id]
	return a, ok
}

// listRemediationActions 列出全部白名单动作（按 ID 排序，前端展示用）
func listRemediationActions() []map[string]any {
	remediationRegistryMu.RLock()
	defer remediationRegistryMu.RUnlock()
	ids := make([]string, 0, len(remediationRegistry))
	for id := range remediationRegistry {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		a := remediationRegistry[id]
		out = append(out, map[string]any{
			"id":          a.ID(),
			"name":        a.Name(),
			"description": a.Description(),
			"risk_level":  a.RiskLevel(),
			"allow_auto":  a.AllowAuto(),
			"params":      a.ParamSpec(),
		})
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---------------- 修复引擎 ----------------

type RemediationEngine struct {
	mu       sync.Mutex
	store    *OpsStore
	inFlight map[string]bool // findingID → 修复进行中（同一风险不并发修复）
}

var remEngine = &RemediationEngine{
	store:    nil,
	inFlight: map[string]bool{},
}

// actionTimeout 单个动作执行超时
const actionTimeout = 2 * time.Minute

// severityRank 严重级排序权重（critical 最高）
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// MatchRules 找出适用于某发现的所有已启用规则（按模式排序，auto 优先）
func (e *RemediationEngine) MatchRules(finding *SecurityFinding) []*RemediationRule {
	if e.store == nil || finding == nil {
		return nil
	}
	rules, err := e.store.ListRules()
	if err != nil {
		return nil
	}
	out := make([]*RemediationRule, 0)
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.CheckID != finding.CheckID {
			continue
		}
		if r.DedupeKey != "" && r.DedupeKey != finding.DedupeKey {
			continue
		}
		if severityRank(finding.Severity) < severityRank(r.MinSeverity) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// resolveParams 组装动作参数：规则参数为基础，值为 "$finding" 的键由发现上下文提供
func resolveParams(rule *RemediationRule, finding *SecurityFinding) (map[string]any, error) {
	params := map[string]any{}
	for k, v := range rule.Parameters {
		params[k] = v
	}
	if finding == nil {
		return params, nil
	}
	for k, v := range params {
		if s, ok := v.(string); ok && s == "$finding" {
			if finding.Context == nil {
				return nil, fmt.Errorf("规则参数 %s 需要从风险上下文取值，但该风险未提供上下文", k)
			}
			cv, ok := finding.Context[k]
			if !ok {
				return nil, fmt.Errorf("风险上下文缺少参数 %s，无法执行该规则", k)
			}
			params[k] = cv
		}
	}
	return params, nil
}

// sanitizeParamsForLog 输出参数摘要时剔除敏感值
func sanitizeParamsForLog(params map[string]any) string {
	safe := map[string]any{}
	for k, v := range params {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "key") {
			safe[k] = "***"
			continue
		}
		safe[k] = v
	}
	b, _ := json.Marshal(safe)
	if len(b) > 300 {
		b = append(b[:300], []byte("...")...)
	}
	return string(b)
}

// PreviewForFinding 生成修复预览（不执行）
func (e *RemediationEngine) PreviewForFinding(findingID, ruleID string) (*ActionPreview, *RemediationRule, error) {
	if e.store == nil {
		return nil, nil, fmt.Errorf("运维中心存储未就绪")
	}
	finding, err := e.store.GetFinding(findingID)
	if err != nil {
		return nil, nil, fmt.Errorf("风险不存在或已被清理")
	}
	rule, err := e.pickRule(finding, ruleID)
	if err != nil {
		return nil, nil, err
	}
	params, err := resolveParams(rule, finding)
	if err != nil {
		return nil, rule, err
	}
	action, ok := getRemediationAction(rule.ActionID)
	if !ok {
		return nil, rule, fmt.Errorf("修复动作 %s 不在白名单中", rule.ActionID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pv, err := action.Preview(ctx, params)
	if err != nil {
		return nil, rule, err
	}
	pv.Action = action.ID()
	pv.ActionName = action.Name()
	pv.RiskLevel = action.RiskLevel()
	return pv, rule, nil
}

// pickRule 选择规则：显式指定 ruleID 时校验匹配；否则取第一条匹配规则
func (e *RemediationEngine) pickRule(finding *SecurityFinding, ruleID string) (*RemediationRule, error) {
	rules := e.MatchRules(finding)
	if ruleID != "" {
		for _, r := range rules {
			if r.ID == ruleID {
				return r, nil
			}
		}
		return nil, fmt.Errorf("指定的修复策略与该风险不匹配或未启用")
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("没有适用于该风险的修复策略")
	}
	return rules[0], nil
}

// RunManual 人工确认后执行修复（HTTP 入口，operator 来自会话，r 用于审计取 IP）
func (e *RemediationEngine) RunManual(findingID, ruleID, operator string, r *http.Request) (*RemediationExecution, error) {
	if e.store == nil {
		return nil, fmt.Errorf("运维中心存储未就绪")
	}
	finding, err := e.store.GetFinding(findingID)
	if err != nil {
		return nil, fmt.Errorf("风险不存在或已被清理")
	}
	if finding.Status == "resolved" {
		return nil, fmt.Errorf("该风险已解决，无需修复")
	}
	rule, err := e.pickRule(finding, ruleID)
	if err != nil {
		return nil, err
	}
	// 人工执行不受 action.AllowAuto 限制，但 critical 风险必须二次确认由前端 Modal 保证，
	// 服务端强制记录审计并要求 remediation:execute 权限（由路由中间件完成）
	return e.execute(rule, finding, "manual", operator, r)
}

// RunAuto 扫描后自动修复入口：全部安全闸门通过后才真正执行
// 返回 nil, nil 表示被安全策略跳过（属正常情况，不是错误）
func (e *RemediationEngine) RunAuto(finding *SecurityFinding) (*RemediationExecution, error) {
	if e.store == nil {
		return nil, nil
	}
	// 全局自动修复总开关（自动修复页可关）
	if e.store.GetSetting("remediation.auto_enabled", "1") != "1" {
		return nil, nil
	}
	rules := e.MatchRules(finding)
	for _, rule := range rules {
		exec, err := e.tryAutoOnce(rule, finding)
		if err != nil {
			return exec, err
		}
		if exec != nil {
			return exec, nil
		}
	}
	return nil, nil
}

// tryAutoOnce 单条规则的自动执行闸门检查
func (e *RemediationEngine) tryAutoOnce(rule *RemediationRule, finding *SecurityFinding) (*RemediationExecution, error) {
	if rule.Mode != "auto" {
		return nil, nil
	}
	action, ok := getRemediationAction(rule.ActionID)
	if !ok {
		return nil, nil
	}
	// §24 禁止自动执行的场景：critical 风险 / 高危动作（删除文件、chmod、停服务等由 AllowAuto 声明）
	if finding.Severity == "critical" {
		log.Printf("[自动修复] 跳过 critical 风险 %s（必须人工确认）", finding.Title)
		return nil, nil
	}
	if !action.AllowAuto() {
		return nil, nil
	}

	e.mu.Lock()
	busy := e.inFlight[finding.ID]
	e.mu.Unlock()
	if busy {
		return nil, nil // 同一风险已在修复中，静默跳过
	}

	now := time.Now()
	cooldown := time.Duration(rule.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		cooldown = 15 * time.Minute
	}
	maxAttempts := rule.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	// 冷却期内不再执行，防止死循环
	if n, _ := e.store.CountRemediationExecutionsSince(rule.ID, finding.ID, now.Add(-cooldown)); n > 0 {
		return nil, nil
	}
	// 本轮发现周期内执行次数达到上限：转入人工处理并发出高优先级事件（1 小时内同一风险只提醒一次）
	attempts, _ := e.store.CountRemediationExecutionsSince(rule.ID, finding.ID, finding.DetectedAt)
	if attempts >= maxAttempts {
		if !e.needsManualAlertedRecently(finding.ID) {
			e.store.AddEvent(&SecurityEvent{
				Level: "error", Type: "remediation.needs_manual",
				Title: fmt.Sprintf("自动修复已达最大重试次数：%s", rule.Name),
				Source: "自动修复", RefID: finding.ID,
				Detail: fmt.Sprintf("风险「%s」自动修复 %d 次未成功，已转入人工处理", finding.Title, attempts),
			})
			opsHub.broadcast(map[string]any{"type": "remediation.needs_manual", "finding_id": finding.ID, "rule": rule.Name})
		}
		return nil, nil
	}
	return e.execute(rule, finding, "auto", "system", nil)
}

// needsManualAlertedRecently 查重：同一风险 1 小时内已发过 needs_manual 事件则不重复提醒
func (e *RemediationEngine) needsManualAlertedRecently(findingID string) bool {
	events, _, err := e.store.ListEvents("", "remediation.needs_manual", 20, 0)
	if err != nil {
		return false
	}
	for _, ev := range events {
		if ev.RefID == findingID && time.Since(ev.Time) < time.Hour {
			return true
		}
	}
	return false
}

// execute 核心执行流程：preview → execute → verify → finding 状态流转 → 事件 + 审计
func (e *RemediationEngine) execute(rule *RemediationRule, finding *SecurityFinding, trigger, operator string, r *http.Request) (*RemediationExecution, error) {
	action, ok := getRemediationAction(rule.ActionID)
	if !ok {
		return nil, fmt.Errorf("修复动作 %s 不在白名单中", rule.ActionID)
	}
	params, err := resolveParams(rule, finding)
	if err != nil {
		return nil, err
	}
	if err := action.Validate(params); err != nil {
		return nil, fmt.Errorf("参数校验失败: %w", err)
	}

	e.mu.Lock()
	if e.inFlight[finding.ID] {
		e.mu.Unlock()
		return nil, fmt.Errorf("该风险正在修复中，请勿重复提交")
	}
	e.inFlight[finding.ID] = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.inFlight, finding.ID)
		e.mu.Unlock()
	}()

	exec := &RemediationExecution{
		ID:           genOpsID("rem"),
		FindingID:    finding.ID,
		RuleID:       rule.ID,
		ActionID:     action.ID(),
		Trigger:      trigger,
		Operator:     operator,
		ParamsDigest: sanitizeParamsForLog(params),
		Status:       "running",
		Steps:        map[string]string{},
		StartedAt:    time.Now(),
	}
	if err := e.store.AddRemediationExecution(exec); err != nil {
		return nil, fmt.Errorf("写入执行记录失败: %w", err)
	}

	finish := func(status, message string) *RemediationExecution {
		now := time.Now()
		exec.Status = status
		exec.Message = message
		exec.FinishedAt = &now
		exec.DurationMS = now.Sub(exec.StartedAt).Milliseconds()
		if err := e.store.UpdateRemediationExecution(exec); err != nil {
			log.Printf("更新修复执行记录失败: %v", err)
		}
		// 审计：绝不记录敏感参数
		detail := fmt.Sprintf("rule=%s action=%s finding=%q trigger=%s result=%s 耗时=%dms",
			rule.Name, action.ID(), finding.Title, trigger, status, exec.DurationMS)
		if trigger == "auto" {
			writeAuditEntry("system", "", "remediation.auto", detail)
		} else {
			clientIP := ""
			if r != nil {
				clientIP = getClientIP(r)
			}
			writeAuditEntry(operator, clientIP, "remediation.execute", detail)
		}
		opsHub.broadcast(map[string]any{
			"type": "remediation." + map[string]string{"success": "success", "failed": "failed", "timeout": "failed"}[status],
			"execution_id": exec.ID, "finding_id": finding.ID, "action": action.ID(), "status": status,
		})
		return exec
	}

	// finding 进入 fixing
	if err := e.store.UpdateFindingStatus(finding.ID, "fixing", ""); err != nil {
		log.Printf("更新风险状态为 fixing 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	// 1) Preview 记录（供执行历史展示）
	if pv, err := action.Preview(ctx, params); err == nil && pv != nil {
		exec.Steps["preview"] = pv.Title + "：" + strings.Join(pv.Steps, "；")
	}

	// 2) Execute
	result, execErr := action.Execute(ctx, params)
	if execErr != nil {
		result = &ActionResult{Success: false, Message: execErr.Error()}
	}
	if result != nil {
		exec.Steps["execute"] = result.Message
		if result.Output != "" {
			exec.Steps["execute"] += " | " + truncateString(result.Output, 500)
		}
	}
	if execErr != nil || result == nil || !result.Success {
		msg := "执行失败"
		if execErr != nil {
			msg = execErr.Error()
		} else if result != nil && result.Message != "" {
			msg = result.Message
		}
		e.store.UpdateFindingStatus(finding.ID, "failed", truncateString(msg, 300))
		done := finish("failed", msg)
		e.store.AddEvent(&SecurityEvent{
			Level: "error", Type: "remediation.failed",
			Title:  fmt.Sprintf("修复失败：%s", rule.Name),
			Source: "自动修复", RefID: finding.ID,
			Detail: fmt.Sprintf("风险「%s」修复失败：%s", finding.Title, truncateString(msg, 200)),
		})
		return done, fmt.Errorf("%s", msg)
	}

	// 3) Verify：不能只看 exec success，必须验证最终状态
	vr, verifyErr := action.Verify(ctx, params)
	if verifyErr != nil {
		vr = &VerifyResult{OK: false, Message: verifyErr.Error()}
	}
	if vr != nil {
		exec.Steps["verify"] = vr.Message
	}
	if verifyErr != nil || vr == nil || !vr.OK {
		msg := "修复后验证未通过"
		if verifyErr != nil {
			msg = "验证出错: " + verifyErr.Error()
		} else if vr != nil && vr.Message != "" {
			msg = vr.Message
		}
		e.store.UpdateFindingStatus(finding.ID, "failed", truncateString(msg, 300))
		done := finish("failed", msg)
		e.store.AddEvent(&SecurityEvent{
			Level: "error", Type: "remediation.failed",
			Title:  fmt.Sprintf("修复验证失败：%s", rule.Name),
			Source: "自动修复", RefID: finding.ID,
			Detail: fmt.Sprintf("风险「%s」执行成功但验证未通过：%s", finding.Title, truncateString(msg, 200)),
		})
		return done, fmt.Errorf("%s", msg)
	}

	// 4) 成功：finding → resolved
	e.store.UpdateFindingStatus(finding.ID, "resolved", "")
	done := finish("success", "修复成功并已通过验证")
	triggerText := "人工确认执行"
	if trigger == "auto" {
		triggerText = "自动执行"
	}
	e.store.AddEvent(&SecurityEvent{
		Level: "info", Type: "remediation.success",
		Title:  fmt.Sprintf("修复成功：%s", rule.Name),
		Source: "自动修复", RefID: finding.ID,
		Detail: fmt.Sprintf("风险「%s」已修复并通过验证（%s）", finding.Title, triggerText),
	})
	return done, nil
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// seedDefaultRules 首次启动时预置默认修复策略（全部 manual 模式，需用户确认后才可切 auto）
func (e *RemediationEngine) seedDefaultRules() {
	if e.store == nil {
		return
	}
	if n, err := e.store.CountRules(); err != nil || n > 0 {
		return
	}
	if e.store.GetSetting("remediation.seeded", "") == "1" {
		return
	}
	now := time.Now()
	defaults := []*RemediationRule{
		{
			ID: "rule_service_restart", Name: "关键服务停止自动恢复",
			Description: "被监控的 systemd 服务停止后，可一键（或自动）执行启动并验证 active 状态",
			CheckID: "service_health", MinSeverity: "high", Mode: "manual", Enabled: true,
			RequireConfirm: true, ActionID: "start_service",
			Parameters: map[string]any{"service": "$finding"},
			MaxAttempts: 3, CooldownSeconds: 900, CreatedBy: "system",
		},
		{
			ID: "rule_file_perm", Name: "敏感文件权限收紧",
			Description: "数据目录内敏感文件权限过宽时，收紧到 0600（仅限受控路径）",
			CheckID: "file_permissions", MinSeverity: "medium", Mode: "manual", Enabled: true,
			RequireConfirm: true, ActionID: "chmod_sensitive_file",
			Parameters: map[string]any{"path": "$finding", "mode": "0600"},
			MaxAttempts: 3, CooldownSeconds: 900, CreatedBy: "system",
		},
		{
			ID: "rule_docker_restart", Name: "异常容器重启",
			Description: "容器异常退出（非 0 退出码 / 重启循环）时执行 docker restart 并验证 running",
			CheckID: "docker_security", MinSeverity: "medium", Mode: "manual", Enabled: true,
			RequireConfirm: true, ActionID: "docker_restart",
			Parameters: map[string]any{"container": "$finding"},
			MaxAttempts: 3, CooldownSeconds: 900, CreatedBy: "system",
		},
	}
	for _, r := range defaults {
		r.CreatedAt = now
		if err := e.store.SaveRule(r); err != nil {
			log.Printf("预置修复策略失败: %v", err)
			return
		}
	}
	e.store.SetSetting("remediation.seeded", "1")
	log.Printf("已预置 %d 条默认修复策略（均为人工确认模式）", len(defaults))
}

// AutoRemediateAfterScan 扫描完成后对新产生/回归的风险尝试自动修复
func (e *RemediationEngine) AutoRemediateAfterScan(findings []SecurityFinding) {
	for i := range findings {
		f := findings[i]
		if f.Status != "open" {
			continue
		}
		// 只对声明了可修复的风险尝试
		if !f.Remediable {
			continue
		}
		exec, err := e.RunAuto(&f)
		if err != nil {
			log.Printf("[自动修复] %s: %v", f.Title, err)
		}
		_ = exec
	}
}

// ---------------- 参数校验公共工具 ----------------

var safeUnitNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@\\-]{0,99}(\.service|\.timer|\.socket)?$`)

func paramServiceName(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("缺少参数 %s", key)
	}
	name, ok := v.(string)
	if !ok || strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("参数 %s 必须是非空字符串", key)
	}
	name = strings.TrimSpace(name)
	if !safeUnitNameRe.MatchString(name) {
		return "", fmt.Errorf("参数 %s 含非法字符", key)
	}
	return name, nil
}
