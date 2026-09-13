package main

// ==================== 安全中心 / 自动修复 / 运维任务 HTTP 层 ====================
//
// 所有接口统一走：authMiddleware（登录 + CSRF）→ requirePermission（RBAC）→ securityMiddleware。
// 响应统一使用项目既有 {code, message, data} 封装（writeJSON / writeJSONError），错误码即 HTTP 状态码。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// requireOpsReady 统一守卫：存储未启用时返回 503
func requireOpsReady(w http.ResponseWriter) bool {
	if opsStore == nil || opsCenter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "安全中心/运维任务存储未启用（初始化 ops_center.db 失败），请检查数据目录权限")
		return false
	}
	return true
}

// decodeOpsBody 解析 JSON 请求体（限制大小防滥用）
func decodeOpsBody(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(v)
}

func sessionUsername(r *http.Request) string {
	if s, ok := getSessionFromRequest(r); ok {
		return s.Username
	}
	return ""
}

// ==================== 安全中心 ====================

// securityOverviewHandler GET /api/security/overview
func securityOverviewHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, "获取安全概览成功", opsCenter.overview())
}

// securityScanStartHandler POST /api/security/scan —— 异步启动扫描
func securityScanStartHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	if err := opsCenter.StartScan(); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	auditAction(r, "security.scan.start", "手动触发全量安全扫描")
	writeJSON(w, http.StatusOK, "安全扫描已启动", nil)
}

// securityScanStatusHandler GET /api/security/scan/status
func securityScanStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	st := opsCenter.ScanStatusSnapshot()
	if st.Status == "idle" || st.Status == "" {
		writeJSON(w, http.StatusOK, "当前没有扫描任务", map[string]any{"status": "idle"})
		return
	}
	writeJSON(w, http.StatusOK, "获取扫描状态成功", st)
}

// securityFindingsHandler GET /api/security/findings?status=&severity=&category=&limit=&offset=
func securityFindingsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	q := r.URL.Query()
	f := FindingFilter{
		Severity: q.Get("severity"),
		Category: q.Get("category"),
		CheckID:  q.Get("check_id"),
	}
	if s := q.Get("status"); s != "" {
		for _, st := range strings.Split(s, ",") {
			st = strings.TrimSpace(st)
			if st != "" {
				f.Status = append(f.Status, st)
			}
		}
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	list, total, err := opsStore.ListFindings(f)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取风险列表失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "获取风险列表成功", map[string]any{
		"findings": list, "total": total,
		"counts": opsStore.CountOpenFindingsBySeverity(),
	})
}

// securityFindingDetailHandler GET /api/security/findings/{id}
func securityFindingDetailHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	f, err := opsStore.GetFinding(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "风险不存在或已被清理")
		return
	}
	auditAction(r, "security.finding.view", fmt.Sprintf("finding=%q check=%s", f.Title, f.CheckID))
	// 附带可用修复策略（供详情 Drawer 展示）
	rules := remEngine.MatchRules(f)
	ruleViews := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleViews = append(ruleViews, map[string]any{
			"id": rule.ID, "name": rule.Name, "action_id": rule.ActionID,
			"mode": rule.Mode, "require_confirm": rule.RequireConfirm,
		})
	}
	writeJSON(w, http.StatusOK, "获取风险详情成功", map[string]any{"finding": f, "rules": ruleViews})
}

// securityFindingIgnoreHandler POST /api/security/findings/{id}/ignore
func securityFindingIgnoreHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	f, err := opsStore.GetFinding(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "风险不存在或已被清理")
		return
	}
	if err := opsStore.UpdateFindingStatus(id, "ignored", ""); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "更新状态失败")
		return
	}
	auditAction(r, "security.finding.ignore", fmt.Sprintf("finding=%q check=%s", f.Title, f.CheckID))
	opsStore.AddEvent(&SecurityEvent{
		Level: "info", Type: "finding.ignored",
		Title:  fmt.Sprintf("风险已忽略：%s", f.Title),
		Source: "安全中心", RefID: id,
		Detail: "操作人: " + sessionUsername(r),
	})
	writeJSON(w, http.StatusOK, "已忽略该风险，后续扫描不会再提醒", nil)
}

// securityFindingRemediateHandler POST /api/security/findings/{id}/remediate
// body: {"rule_id": "..."}（可选；缺省取第一条匹配规则）
func securityFindingRemediateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	var body struct {
		RuleID string `json:"rule_id"`
	}
	_ = decodeOpsBody(r, &body)
	exec, err := remEngine.RunManual(r.PathValue("id"), body.RuleID, sessionUsername(r), r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "修复已执行", exec)
}

// securityEventsHandler GET /api/security/events?level=&type=&limit=&offset=
func securityEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	list, total, err := opsStore.ListEvents(q.Get("level"), q.Get("type"), limit, offset)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取安全事件失败")
		return
	}
	writeJSON(w, http.StatusOK, "获取安全事件成功", map[string]any{"events": list, "total": total})
}

// securityCheckersHandler GET /api/security/checkers
func securityCheckersHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	out := make([]map[string]any, 0, len(opsCenter.checkers))
	for _, c := range opsCenter.checkers {
		out = append(out, map[string]any{
			"id": c.ID(), "name": c.Name(), "category": c.Category(), "description": c.Description(),
		})
	}
	writeJSON(w, http.StatusOK, "获取检查器清单成功", out)
}

// securitySettingsHandler GET /api/security/settings
func securitySettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, "获取扫描设置成功", map[string]any{
		"schedule":          opsCenter.loadSchedule(),
		"watched_services":  splitWatchedServices(opsStore.GetSetting("security.watched_services", "")),
		"disabled_checkers": disabledCheckersList(),
		"auto_remediation":  opsStore.GetSetting("remediation.auto_enabled", "1") == "1",
	})
}

// disabledCheckersList 停用的检查器 ID 列表
func disabledCheckersList() []string {
	var list []string
	if err := json.Unmarshal([]byte(opsStore.GetSetting("security.disabled_checkers", "")), &list); err != nil {
		return []string{}
	}
	return list
}

// securitySettingsUpdateHandler POST /api/security/settings
func securitySettingsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	var body struct {
		Schedule         *ScanSchedule `json:"schedule"`
		WatchedServices  []string      `json:"watched_services"`
		DisabledCheckers []string      `json:"disabled_checkers"`
	}
	if err := decodeOpsBody(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if body.Schedule != nil {
		s := *body.Schedule
		switch s.Type {
		case "hourly":
			if s.Minute < 0 || s.Minute > 59 {
				writeJSONError(w, http.StatusBadRequest, "每小时模式的分钟取值 0-59")
				return
			}
		case "daily":
			if s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 {
				writeJSONError(w, http.StatusBadRequest, "每天模式的时间取值无效")
				return
			}
		case "weekly":
			if s.Weekday < 0 || s.Weekday > 6 || s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 {
				writeJSONError(w, http.StatusBadRequest, "每周模式的时间取值无效")
				return
			}
		case "cron":
			if err := ValidateCronExpr(s.Cron); err != nil {
				writeJSONError(w, http.StatusBadRequest, "Cron 表达式无效: "+err.Error())
				return
			}
		default:
			writeJSONError(w, http.StatusBadRequest, "扫描频率类型无效")
			return
		}
		if err := opsCenter.saveSchedule(s); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存扫描计划失败")
			return
		}
	}
	if body.WatchedServices != nil {
		cleaned := make([]string, 0, len(body.WatchedServices))
		for _, s := range body.WatchedServices {
			s = strings.TrimSuffix(strings.TrimSpace(s), ".service")
			if s == "" {
				continue
			}
			if len(s) > 64 || strings.ContainsAny(s, " /\\;|&$`") {
				writeJSONError(w, http.StatusBadRequest, "服务名 "+s+" 含非法字符")
				return
			}
			cleaned = append(cleaned, s)
		}
		b, _ := json.Marshal(cleaned)
		if err := opsStore.SetSetting("security.watched_services", string(b)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存监控清单失败")
			return
		}
	}
	if body.DisabledCheckers != nil {
		known := map[string]bool{}
		for _, ck := range opsCenter.checkers {
			known[ck.ID()] = true
		}
		cleaned := make([]string, 0, len(body.DisabledCheckers))
		for _, id := range body.DisabledCheckers {
			if !known[id] {
				writeJSONError(w, http.StatusBadRequest, "未知检查项: "+id)
				return
			}
			cleaned = append(cleaned, id)
		}
		b, _ := json.Marshal(cleaned)
		if err := opsStore.SetSetting("security.disabled_checkers", string(b)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存检查项配置失败")
			return
		}
	}
	auditAction(r, "security.settings.update", "更新安全中心扫描设置")
	writeJSON(w, http.StatusOK, "扫描设置已保存", nil)
}

func splitWatchedServices(raw string) []string {
	if raw == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil
	}
	return list
}

// ==================== 自动修复 ====================

// remediationRulesHandler GET /api/remediation/rules
func remediationRulesHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	rules, err := opsStore.ListRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取修复策略失败")
		return
	}
	// 最近一次执行时间（按策略 ID 索引，避免污染规则本体字段）
	lastExec := map[string]string{}
	for i := range rules {
		execs, _, _ := opsStore.ListRemediationExecutions(rules[i].ID, "", 1, 0)
		if len(execs) > 0 {
			lastExec[rules[i].ID] = execs[0].StartedAt.Format(time.RFC3339)
		}
	}
	writeJSON(w, http.StatusOK, "获取修复策略成功", map[string]any{
		"rules": rules,
		"last_exec":    lastExec,
		"auto_enabled": opsStore.GetSetting("remediation.auto_enabled", "1") == "1",
	})
}

// validateRuleInput 规则创建/更新校验
func validateRuleInput(rule *RemediationRule) error {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" || len(rule.Name) > 100 {
		return fmt.Errorf("策略名称必填且不超过 100 字")
	}
	if rule.CheckID == "" {
		return fmt.Errorf("必须选择触发检查器")
	}
	if _, ok := getRemediationAction(rule.ActionID); !ok {
		return fmt.Errorf("修复动作 %s 不在白名单中", rule.ActionID)
	}
	if rule.Mode != "manual" && rule.Mode != "suggest" && rule.Mode != "auto" {
		return fmt.Errorf("模式仅支持 manual / suggest / auto")
	}
	action, _ := getRemediationAction(rule.ActionID)
	if rule.Mode == "auto" && !action.AllowAuto() {
		return fmt.Errorf("动作「%s」风险较高，不允许配置为自动执行", action.Name())
	}
	if rule.MinSeverity == "" {
		rule.MinSeverity = "medium"
	}
	if severityRank(rule.MinSeverity) == 0 {
		return fmt.Errorf("风险等级下限无效")
	}
	if rule.MaxAttempts <= 0 {
		rule.MaxAttempts = 3
	}
	if rule.MaxAttempts > 10 {
		return fmt.Errorf("最大尝试次数不能超过 10")
	}
	if rule.CooldownSeconds <= 0 {
		rule.CooldownSeconds = 900
	}
	if len(rule.Parameters) == 0 {
		rule.Parameters = map[string]any{}
	}
	return nil
}

// remediationRuleCreateHandler POST /api/remediation/rules
func remediationRuleCreateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	var rule RemediationRule
	if err := decodeOpsBody(r, &rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := validateRuleInput(&rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 参数必须能通过动作校验（把 "$finding" 占位保留：引擎执行时解析）
	if rule.ActionID != "" {
		if a, ok := getRemediationAction(rule.ActionID); ok {
			testParams := map[string]any{}
			for k, v := range rule.Parameters {
				if s, isStr := v.(string); isStr && s == "$finding" {
					continue // 占位符在执行期解析
				}
				testParams[k] = v
			}
			// 只校验非占位参数的类型合法性由动作 Validate 完成时可能因缺参失败，这里做宽松校验：
			// 必填参数要么有值要么是占位符
			for _, p := range a.ParamSpec() {
				if !p.Required {
					continue
				}
				v, ok := rule.Parameters[p.Name]
				if !ok {
					writeJSONError(w, http.StatusBadRequest, "缺少必填参数: "+p.Label)
					return
				}
				if s, isStr := v.(string); isStr && s == "$finding" {
					continue
				}
			}
		}
	}
	rule.ID = genOpsID("rule")
	rule.CreatedBy = sessionUsername(r)
	if err := opsStore.SaveRule(&rule); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存修复策略失败")
		return
	}
	auditAction(r, "remediation.rule.create", fmt.Sprintf("rule=%q check=%s action=%s mode=%s", rule.Name, rule.CheckID, rule.ActionID, rule.Mode))
	writeJSON(w, http.StatusOK, "修复策略已创建", rule)
}

// remediationRuleUpdateHandler PUT /api/remediation/rules/{id}
func remediationRuleUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	old, err := opsStore.GetRule(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "修复策略不存在")
		return
	}
	var rule RemediationRule
	if err := decodeOpsBody(r, &rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := validateRuleInput(&rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.ID = id
	rule.CreatedBy = old.CreatedBy
	rule.CreatedAt = old.CreatedAt
	if err := opsStore.SaveRule(&rule); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存修复策略失败")
		return
	}
	auditAction(r, "remediation.rule.update", fmt.Sprintf("rule=%q mode=%s enabled=%v", rule.Name, rule.Mode, rule.Enabled))
	writeJSON(w, http.StatusOK, "修复策略已更新", rule)
}

// remediationRuleDeleteHandler DELETE /api/remediation/rules/{id}
func remediationRuleDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	rule, err := opsStore.GetRule(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "修复策略不存在")
		return
	}
	if err := opsStore.DeleteRule(id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "删除修复策略失败")
		return
	}
	auditAction(r, "remediation.rule.delete", fmt.Sprintf("rule=%q", rule.Name))
	writeJSON(w, http.StatusOK, "修复策略已删除", nil)
}

// remediationActionsHandler GET /api/remediation/actions —— 动作白名单清单
func remediationActionsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, "获取修复动作清单成功", listRemediationActions())
}

// remediationPreviewHandler POST /api/remediation/preview  body: {"finding_id": "...", "rule_id": "..."}
func remediationPreviewHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	var body struct {
		FindingID string `json:"finding_id"`
		RuleID    string `json:"rule_id"`
	}
	if err := decodeOpsBody(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	pv, rule, err := remEngine.PreviewForFinding(body.FindingID, body.RuleID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "生成修复预览成功", map[string]any{
		"preview": pv,
		"rule_id": rule.ID, "rule_name": rule.Name,
		"require_confirm": rule.RequireConfirm,
	})
}

// remediationExecutionsHandler GET /api/remediation/executions?rule_id=&finding_id=&limit=&offset=
func remediationExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	list, total, err := opsStore.ListRemediationExecutions(q.Get("rule_id"), q.Get("finding_id"), limit, offset)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取修复执行记录失败")
		return
	}
	totalToday, successToday, failedToday, _ := opsStore.CountRemediationToday()
	writeJSON(w, http.StatusOK, "获取修复执行记录成功", map[string]any{
		"executions": list, "total": total,
		"today": map[string]int{"total": totalToday, "success": successToday, "failed": failedToday},
	})
}

// remediationSettingsHandler GET/POST /api/remediation/settings —— 全局自动修复开关
func remediationSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			AutoEnabled *bool `json:"auto_enabled"`
		}
		if err := decodeOpsBody(r, &body); err != nil || body.AutoEnabled == nil {
			writeJSONError(w, http.StatusBadRequest, "请求体需包含 auto_enabled")
			return
		}
		v := "0"
		if *body.AutoEnabled {
			v = "1"
		}
		if err := opsStore.SetSetting("remediation.auto_enabled", v); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存设置失败")
			return
		}
		auditAction(r, "remediation.settings.update", fmt.Sprintf("auto_enabled=%v", *body.AutoEnabled))
		writeJSON(w, http.StatusOK, "自动修复开关已更新", map[string]any{"auto_enabled": *body.AutoEnabled})
		return
	}
	writeJSON(w, http.StatusOK, "获取自动修复设置成功", map[string]any{
		"auto_enabled": opsStore.GetSetting("remediation.auto_enabled", "1") == "1",
	})
}

// ==================== 运维任务 ====================

// tasksListHandler GET /api/tasks
func tasksListHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	tasks, err := opsStore.ListTasks()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取任务列表失败")
		return
	}
	for i := range tasks {
		if id, ok := taskExecutor.RunningExecutionID(tasks[i].ID); ok {
			tasks[i].LastStatus = "running"
			_ = id
		}
	}
	upcoming := taskScheduler.upcoming(6)
	writeJSON(w, http.StatusOK, "获取任务列表成功", map[string]any{
		"tasks":    tasks,
		"upcoming": upcoming,
		"running":  taskExecutor.RunningCount(),
	})
}

// validateTaskInput 任务创建/更新校验（Cron 注入 / 非法 Action / 参数校验都在这里拦截）
func validateTaskInput(t *Task) error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" || len(t.Name) > 100 {
		return fmt.Errorf("任务名称必填且不超过 100 字")
	}
	switch t.Type {
	case "cron":
		if err := ValidateCronExpr(t.Schedule); err != nil {
			return err
		}
	case "interval":
		if t.IntervalSec < 60 {
			return fmt.Errorf("周期任务最小间隔 60 秒，防止任务堆积")
		}
		if t.IntervalSec > 365*24*3600 {
			return fmt.Errorf("周期任务间隔过大")
		}
	case "once":
		if t.RunAt == nil || t.RunAt.Before(time.Now()) {
			return fmt.Errorf("一次性任务的执行时间必须是未来时间")
		}
	case "event":
		if t.Trigger == nil {
			return fmt.Errorf("事件触发任务必须配置触发条件")
		}
		switch t.Trigger.Type {
		case "cpu_high", "disk_high", "ip_abnormal":
			if t.Trigger.Threshold < 0 || t.Trigger.Threshold > 100 {
				return fmt.Errorf("事件阈值取值 0-100")
			}
		case "service_stopped", "docker_container_exit", "security_finding":
			if len(t.Trigger.Match) > 100 || strings.ContainsAny(t.Trigger.Match, " \t\n;|&$`") {
				return fmt.Errorf("事件匹配条件含非法字符")
			}
		default:
			return fmt.Errorf("不支持的事件触发类型: %s", t.Trigger.Type)
		}
	default:
		return fmt.Errorf("任务类型仅支持 once / cron / interval / event")
	}
	action, ok := getRemediationAction(t.ActionID)
	if !ok {
		return fmt.Errorf("动作 %s 不在白名单中", t.ActionID)
	}
	if t.Parameters == nil {
		t.Parameters = map[string]any{}
	}
	if err := action.Validate(t.Parameters); err != nil {
		return fmt.Errorf("任务参数校验失败: %w", err)
	}
	t.TimeoutSec = clampInt(defaultInt(t.TimeoutSec, 600), 30, 3600)
	t.MaxAttempts = clampInt(defaultInt(t.MaxAttempts, 1), 1, 5)
	t.RetryBackoffSec = clampInt(defaultInt(t.RetryBackoffSec, 60), 0, 3600)
	return nil
}

func defaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// taskCreateHandler POST /api/tasks
func taskCreateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	var t Task
	if err := decodeOpsBody(r, &t); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := validateTaskInput(&t); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	t.ID = genOpsID("task")
	t.Enabled = true
	t.CreatedBy = sessionUsername(r)
	if next := taskScheduler.computeNextRun(&t, time.Now()); next != nil {
		t.NextRunAt = next
	}
	if err := opsStore.SaveTask(&t); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存任务失败")
		return
	}
	auditAction(r, "task.create", fmt.Sprintf("task=%q type=%s action=%s", t.Name, t.Type, t.ActionID))
	writeJSON(w, http.StatusOK, "任务已创建", t)
}

// taskGetHandler GET /api/tasks/{id}
func taskGetHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	t, err := opsStore.GetTask(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "任务不存在")
		return
	}
	execs, _, _ := opsStore.ListTaskExecutions(TaskExecutionFilter{TaskID: t.ID, Limit: 10})
	if _, running := taskExecutor.RunningExecutionID(t.ID); running {
		t.LastStatus = "running"
	}
	writeJSON(w, http.StatusOK, "获取任务详情成功", map[string]any{"task": t, "executions": execs})
}

// taskUpdateHandler PUT /api/tasks/{id}
func taskUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	old, err := opsStore.GetTask(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "任务不存在")
		return
	}
	var t Task
	if err := decodeOpsBody(r, &t); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := validateTaskInput(&t); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	t.ID = id
	t.CreatedBy = old.CreatedBy
	t.CreatedAt = old.CreatedAt
	t.LastRunAt = old.LastRunAt
	t.LastStatus = old.LastStatus
	if next := taskScheduler.computeNextRun(&t, time.Now()); next != nil {
		t.NextRunAt = next
	} else {
		t.NextRunAt = nil
	}
	if err := opsStore.SaveTask(&t); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存任务失败")
		return
	}
	auditAction(r, "task.update", fmt.Sprintf("task=%q type=%s action=%s enabled=%v", t.Name, t.Type, t.ActionID, t.Enabled))
	writeJSON(w, http.StatusOK, "任务已更新", t)
}

// taskDeleteHandler DELETE /api/tasks/{id}
func taskDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	t, err := opsStore.GetTask(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "任务不存在")
		return
	}
	if _, running := taskExecutor.RunningExecutionID(id); running {
		writeJSONError(w, http.StatusConflict, "任务正在执行中，请先取消执行再删除")
		return
	}
	if err := opsStore.DeleteTask(id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "删除任务失败")
		return
	}
	auditAction(r, "task.delete", fmt.Sprintf("task=%q action=%s", t.Name, t.ActionID))
	writeJSON(w, http.StatusOK, "任务已删除", nil)
}

// taskRunNowHandler POST /api/tasks/{id}/run
func taskRunNowHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	execID, err := taskScheduler.RunNow(r.PathValue("id"), sessionUsername(r), r)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	auditAction(r, "task.run_now", fmt.Sprintf("task_id=%s exec=%s", r.PathValue("id"), execID))
	writeJSON(w, http.StatusOK, "任务已开始执行", map[string]any{"execution_id": execID})
}

// taskCancelHandler POST /api/tasks/{id}/cancel
func taskCancelHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	execID, ok := taskExecutor.RunningExecutionID(id)
	if !ok {
		writeJSONError(w, http.StatusConflict, "任务当前没有正在执行的轮次")
		return
	}
	if err := taskExecutor.Cancel(execID); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	auditAction(r, "task.cancel", fmt.Sprintf("task_id=%s exec=%s", id, execID))
	writeJSON(w, http.StatusOK, "已发送取消指令", nil)
}

// taskToggleHandler POST /api/tasks/{id}/toggle  body: {"enabled": true}
func taskToggleHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	id := r.PathValue("id")
	t, err := opsStore.GetTask(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "任务不存在")
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeOpsBody(r, &body); err != nil || body.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "请求体需包含 enabled")
		return
	}
	t.Enabled = *body.Enabled
	if t.Enabled {
		if next := taskScheduler.computeNextRun(t, time.Now()); next != nil {
			t.NextRunAt = next
		}
	} else {
		t.NextRunAt = nil
	}
	if err := opsStore.SaveTask(t); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存任务失败")
		return
	}
	auditAction(r, "task.toggle", fmt.Sprintf("task=%q enabled=%v", t.Name, t.Enabled))
	writeJSON(w, http.StatusOK, "任务状态已更新", t)
}

// taskExecutionsHandler GET /api/tasks/{id}/executions
func taskExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	list, total, err := opsStore.ListTaskExecutions(TaskExecutionFilter{TaskID: r.PathValue("id"), Status: q.Get("status"), Limit: limit, Offset: offset})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取执行历史失败")
		return
	}
	writeJSON(w, http.StatusOK, "获取执行历史成功", map[string]any{"executions": list, "total": total})
}

// taskExecutionsAllHandler GET /api/task/executions?task_id=&status=&range=&limit=&offset=
func taskExecutionsAllHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	q := r.URL.Query()
	f := TaskExecutionFilter{TaskID: q.Get("task_id"), Status: q.Get("status")}
	switch q.Get("range") {
	case "today":
		since := time.Now().Add(-24 * time.Hour)
		f.Since = &since
	case "7d":
		since := time.Now().AddDate(0, 0, -7)
		f.Since = &since
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	list, total, err := opsStore.ListTaskExecutions(f)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取执行历史失败")
		return
	}
	// 任务下拉选项
	tasks, _ := opsStore.ListTasks()
	taskOpts := make([]map[string]string, 0, len(tasks))
	for _, t := range tasks {
		taskOpts = append(taskOpts, map[string]string{"id": t.ID, "name": t.Name})
	}
	writeJSON(w, http.StatusOK, "获取执行历史成功", map[string]any{
		"executions": list, "total": total, "tasks": taskOpts,
	})
}

// taskExecutionDetailHandler GET /api/task/executions/{id}
func taskExecutionDetailHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	e, err := opsStore.GetTaskExecution(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "执行记录不存在")
		return
	}
	writeJSON(w, http.StatusOK, "获取执行详情成功", e)
}

// taskTemplatesHandler GET /api/task/templates
func taskTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, "获取任务模板成功", taskTemplates())
}

// taskStatsHandler GET /api/task/stats
func taskStatsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireOpsReady(w) {
		return
	}
	running, scheduled, failed24h, doneToday, err := opsStore.TaskStats()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取任务统计失败")
		return
	}
	if running == 0 {
		running = taskExecutor.RunningCount()
	}
	writeJSON(w, http.StatusOK, "获取任务统计成功", map[string]any{
		"running": running, "scheduled": scheduled,
		"failed_24h": failed24h, "done_today": doneToday,
	})
}

// ==================== 页面路由 ====================

func securityPageHandler(w http.ResponseWriter, r *http.Request)      { serveOpsPage(w, r, "security.html") }
func securityEventsPageHandler(w http.ResponseWriter, r *http.Request) { serveOpsPage(w, r, "security-events.html") }
func remediationPageHandler(w http.ResponseWriter, r *http.Request)   { serveOpsPage(w, r, "remediation.html") }
func tasksPageHandler(w http.ResponseWriter, r *http.Request)         { serveOpsPage(w, r, "tasks.html") }
func taskHistoryPageHandler(w http.ResponseWriter, r *http.Request)   { serveOpsPage(w, r, "task-history.html") }

// serveOpsPage 与 trojanPageHandler/dockerPageHandler 相同的模板伺服方式
func serveOpsPage(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if serveTemplateCached(w, r, name) {
		return
	}
	data, err := os.ReadFile(filepath.Join(indexPath, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}
