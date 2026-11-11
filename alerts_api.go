package main

// alerts_api.go —— 告警中心的 HTTP 接口与页面入口

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// alertsOverviewHandler GET /api/alerts/overview —— 顶部统计卡
func alertsOverviewHandler(w http.ResponseWriter, r *http.Request) {
	cfg := opsStore.GetAlertsConfig()
	rules, err := opsStore.ListAlertRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取规则失败")
		return
	}
	enabled := 0
	for _, x := range rules {
		if x.Enabled {
			enabled++
		}
	}
	emailReady := false
	if cfg.Email != nil && cfg.Email.Host != "" && len(cfg.Email.To) > 0 {
		emailReady = true
	} else if g := loadDockerGuardConfig(); g.AlertEmail != nil && g.AlertEmail.Host != "" {
		emailReady = true
	}
	writeJSON(w, http.StatusOK, "ok", map[string]any{
		"enabled":            cfg.Enabled,
		"interval_sec":       cfg.IntervalSec,
		"mute_start":         cfg.MuteStart,
		"mute_end":           cfg.MuteEnd,
		"rules_total":        len(rules),
		"rules_enabled":      enabled,
		"firing_count":       opsStore.CountFiringAlerts(),
		"events_today":       opsStore.CountAlertEventsSince(time.Now().Truncate(24 * time.Hour)),
		"email_configured":   emailReady,
		"webhook_configured": strings.TrimSpace(cfg.WebhookURL) != "",
	})
}

// alertsRulesHandler GET /api/alerts/rules
func alertsRulesHandler(w http.ResponseWriter, r *http.Request) {
	rules, err := opsStore.ListAlertRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取规则失败")
		return
	}
	writeJSON(w, http.StatusOK, "ok", map[string]any{"rules": rules})
}

// alertsSaveRuleHandler POST /api/alerts/rules —— 带 id 则更新，否则新建
func alertsSaveRuleHandler(w http.ResponseWriter, r *http.Request) {
	var in AlertRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "规则名称不能为空")
		return
	}
	switch in.Metric {
	case alertMetricCPU, alertMetricMem, alertMetricDisk, alertMetricCert, alertMetricService:
	default:
		writeJSONError(w, http.StatusBadRequest, "未知的监控指标")
		return
	}
	if in.Op != "gt" && in.Op != "lt" {
		in.Op = "gt"
	}
	if in.DurationSec < 0 {
		in.DurationSec = 0
	}
	if in.DurationSec > 86400 {
		in.DurationSec = 86400
	}
	if in.CooldownSec < 0 {
		in.CooldownSec = 0
	}
	if in.CooldownSec > 86400*7 {
		in.CooldownSec = 86400 * 7
	}
	if in.Severity == "" {
		in.Severity = "warning"
	}
	if len(in.Channels) == 0 {
		in.Channels = []string{"email"}
	}

	saved, err := opsStore.SaveAlertRule(&in)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	auditAction(r, "alerts.rule.save", "规则 "+saved.Name)
	writeJSON(w, http.StatusOK, "已保存", saved)
}

// alertsDeleteRuleHandler DELETE /api/alerts/rules/{id}
func alertsDeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/rules/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少规则 ID")
		return
	}
	rule, _ := opsStore.GetAlertRule(id)
	if err := opsStore.DeleteAlertRule(id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "删除失败")
		return
	}
	name := id
	if rule != nil {
		name = rule.Name
	}
	auditAction(r, "alerts.rule.delete", "规则 "+name)
	writeJSON(w, http.StatusOK, "已删除", map[string]any{"id": id})
}

// alertsEventsHandler GET /api/alerts/events?limit=100&status=firing
func alertsEventsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	events, err := opsStore.ListAlertEvents(limit, status)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取事件失败")
		return
	}
	writeJSON(w, http.StatusOK, "ok", map[string]any{"events": events})
}

// alertsConfigHandler GET/POST /api/alerts/config
func alertsConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg := opsStore.GetAlertsConfig()
		out := cfg
		if out.Email != nil {
			cp := *out.Email
			// 有管理权限的人看明文（面板是自用的，授权码本来就写在 config.json 里）；
			// 只有查看权限的账号仍然打码，避免顺手泄露凭据。
			if cp.Password != "" && !hasPermissionFromRequest(r, "alerts:manage") {
				cp.Password = "******"
			}
			out.Email = &cp
		}
		writeJSON(w, http.StatusOK, "ok", out)
		return
	}

	if !hasPermissionFromRequest(r, "alerts:manage") {
		writeJSONError(w, http.StatusForbidden, "需要告警管理权限")
		return
	}

	prev := opsStore.GetAlertsConfig()
	var in alertsConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	if in.IntervalSec < 10 {
		in.IntervalSec = 10
	}
	if in.IntervalSec > 3600 {
		in.IntervalSec = 3600
	}
	// 密码留空或仍是掩码时，沿用原密码
	if in.Email != nil && (in.Email.Password == "" || in.Email.Password == "******") {
		if prev.Email != nil {
			in.Email.Password = prev.Email.Password
		}
	}
	if in.Email != nil && in.Email.From == "" {
		in.Email.From = in.Email.Username
	}
	if err := opsStore.SaveAlertsConfig(in); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存失败")
		return
	}
	auditAction(r, "alerts.config.save", fmt.Sprintf("enabled=%v interval=%ds", in.Enabled, in.IntervalSec))
	writeJSON(w, http.StatusOK, "已保存", map[string]any{"enabled": in.Enabled})
}

// alertsTestHandler POST /api/alerts/test —— 发一条测试通知，验证渠道是否配通
func alertsTestHandler(w http.ResponseWriter, r *http.Request) {
	cfg := opsStore.GetAlertsConfig()
	ev := &AlertEvent{
		RuleName:  "测试告警",
		Metric:    alertMetricDisk,
		Severity:  "info",
		Status:    "firing",
		Value:     88.6,
		Threshold: 85,
		Message:   "这是一条测试通知，收到即说明告警渠道配置正确。",
		CreatedAt: time.Now(),
	}

	channels := []string{"email", "webhook"}
	var raw struct {
		Channels []string `json:"channels"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&raw)
	}
	if len(raw.Channels) > 0 {
		channels = raw.Channels
	}

	results := map[string]string{}
	for _, ch := range channels {
		rule := &AlertRule{Name: "测试告警", Channels: []string{ch}}
		ok, errMsg := sendAlertNotification(cfg, rule, ev)
		if ok {
			results[ch] = "ok"
		} else {
			results[ch] = errMsg
		}
	}
	auditAction(r, "alerts.test", "测试通知")
	writeJSON(w, http.StatusOK, "测试完成", map[string]any{"results": results})
}

// alertsPageHandler 渲染告警中心页面
func alertsPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if serveTemplateCached(w, r, "alerts.html") {
		return
	}
	htmlData, err := os.ReadFile(filepath.Join(indexPath, "alerts.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取告警页面: %v", err), http.StatusInternalServerError)
		log.Printf("读取 alerts.html 失败: %v", err)
		return
	}
	_, _ = w.Write(htmlData)
}

// hasPermissionFromRequest 从当前会话里判断权限（页面级 handler 用）
func hasPermissionFromRequest(r *http.Request, perm string) bool {
	session, ok := getSessionFromRequest(r)
	if !ok || session == nil {
		return false
	}
	return hasPermission(session.Username, perm)
}
