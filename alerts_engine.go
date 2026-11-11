package main

// alerts_engine.go —— 阈值告警引擎
//
// 每 interval 秒采样一次指标，对每条启用规则做状态机判定：
//   ok → pending（条件刚成立，开始计时）→ firing（持续够 duration_sec，发通知）
//   firing → resolved（条件不再成立，补一条恢复通知）
// 触发后按规则的 cooldown_sec 抑制重复通知；静默窗口内只落事件、不发通知。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type alertRuleState struct {
	since      time.Time
	firing     bool
	lastValue  float64
	lastDetail string
}

type alertEngine struct {
	mu        sync.Mutex
	state     map[string]*alertRuleState
	lastRun   time.Time
	certCache certSample
	certAt    time.Time
}

type certSample struct {
	days     float64
	ok       bool
	notAfter time.Time
}

var alertEng = &alertEngine{state: make(map[string]*alertRuleState)}

// StartAlertsEngine 启动后台采样循环（进程内单例，重复调用无副作用）
func StartAlertsEngine(ctx context.Context) {
	go func() {
		// 启动后稍等，避开启动瞬间的初始化高峰
		time.Sleep(20 * time.Second)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cfg := opsStore.GetAlertsConfig()
				interval := time.Duration(cfg.IntervalSec) * time.Second
				if interval < 10*time.Second {
					interval = 30 * time.Second
				}
				alertEng.mu.Lock()
				due := alertEng.lastRun.IsZero() || now.Sub(alertEng.lastRun) >= interval
				if due {
					alertEng.lastRun = now
				}
				alertEng.mu.Unlock()
				if !due {
					continue
				}
				alertEng.evaluateOnce(cfg)
			}
		}
	}()
}

// evaluateOnce 采样一轮并推进每条规则的状态机
func (e *alertEngine) evaluateOnce(cfg alertsConfig) {
	if !cfg.Enabled {
		return
	}
	rules, err := opsStore.ListAlertRules()
	if err != nil {
		log.Printf("告警规则读取失败: %v", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	metrics := e.collectMetrics(rules)

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		val, ok, detail := metricValue(r, metrics)
		if !ok {
			continue
		}

		st := e.state[r.ID]
		if st == nil {
			st = &alertRuleState{}
			e.state[r.ID] = st
		}

		met := (r.Op == "gt" && val > r.Threshold) || (r.Op == "lt" && val < r.Threshold)

		if met {
			if st.since.IsZero() {
				st.since = now
			}
			st.lastValue, st.lastDetail = val, detail
			if !st.firing && now.Sub(st.since) >= time.Duration(r.DurationSec)*time.Second {
				st.firing = true
				e.emit(cfg, r, val, detail, false, now)
			}
			continue
		}

		// 条件不再成立
		if st.firing {
			e.emit(cfg, r, val, detail, true, now)
		}
		st.since = time.Time{}
		st.firing = false
		st.lastValue, st.lastDetail = val, detail
	}
}

// emit 落一条事件并按渠道通知（resolved=true 表示恢复）
func (e *alertEngine) emit(cfg alertsConfig, r *AlertRule, val float64, detail string, resolved bool, now time.Time) {
	muted := inAlertMuteWindow(now, r, cfg)

	ev := &AlertEvent{
		RuleID:    r.ID,
		RuleName:  r.Name,
		Metric:    r.Metric,
		Severity:  r.Severity,
		Value:     val,
		Threshold: r.Threshold,
		Muted:     muted,
		CreatedAt: now,
	}
	label := alertMetricLabels[r.Metric]
	if label == "" {
		label = r.Metric
	}
	opText := "高于"
	if r.Op == "lt" {
		opText = "低于"
	}

	if resolved {
		ev.Status = "resolved"
		ev.Message = fmt.Sprintf("%s 已恢复：当前 %s，低于触发阈值 %s", label, formatAlertValue(r.Metric, val), formatAlertValue(r.Metric, r.Threshold))
	} else {
		ev.Status = "firing"
		// 持续时长 <= 1 秒视为"立即触发"，别写成"（持续 1 秒）"这种别扭文案
		lasting := ""
		if r.DurationSec > 1 {
			lasting = fmt.Sprintf("（持续 %s）", humanDurationCN(r.DurationSec))
		}
		ev.Message = fmt.Sprintf("%s %s：当前 %s，阈值 %s%s",
			label, opText, formatAlertValue(r.Metric, val), formatAlertValue(r.Metric, r.Threshold), lasting)
		if detail != "" {
			ev.Message += "，" + detail
		}
	}

	// 冷却：同一规则冷却期内不重复发通知（恢复通知不受限制，否则用户以为还没好）
	if !resolved && r.LastFiredAt != nil && r.CooldownSec > 0 {
		if now.Sub(*r.LastFiredAt) < time.Duration(r.CooldownSec)*time.Second {
			ev.Notified = false
			ev.NotifyErr = "冷却期内，已抑制通知"
			_ = opsStore.AddAlertEvent(ev)
			return
		}
	}

	if muted {
		ev.NotifyErr = "静默窗口内，仅记录"
		_ = opsStore.AddAlertEvent(ev)
		return
	}

	notified, errMsg := sendAlertNotification(cfg, r, ev)
	ev.Notified = notified
	ev.NotifyErr = errMsg
	if err := opsStore.AddAlertEvent(ev); err != nil {
		log.Printf("告警事件落库失败: %v", err)
	}

	if notified && !resolved {
		_ = opsStore.TouchAlertRuleFired(r.ID, now)
	}
	// 通知成功后更新内存里的 last fired，避免冷却判断依赖下次读库
	if notified && !resolved {
		t := now
		r.LastFiredAt = &t
	}
}

// ---------- 指标采集 ----------

type alertMetrics struct {
	cpu, mem, disk float64
	certDays       float64
	certOK         bool
	certDetail     string
	downServices   []string
	serviceChecked bool
}

func (e *alertEngine) collectMetrics(rules []AlertRule) alertMetrics {
	m := alertMetrics{}

	needSystem := false
	needCert := false
	needService := false
	for _, r := range rules {
		switch r.Metric {
		case alertMetricCPU, alertMetricMem, alertMetricDisk:
			needSystem = true
		case alertMetricCert:
			needCert = true
		case alertMetricService:
			needService = true
		}
	}

	if needSystem {
		if st, err := getServerStatus(""); err == nil && st != nil {
			m.cpu = st.CPUUsage
			m.mem = st.MemoryUsage
			m.disk = st.DiskUsage
		}
	}

	if needCert {
		// 证书 5 分钟内不会变，缓存一下，避免每轮都做 TLS 握手
		if time.Since(e.certAt) > 5*time.Minute || e.certAt.IsZero() {
			cert, err := probeLiveCertificate()
			if err != nil {
				cert, err = loadFileCertificate()
			}
			sample := certSample{}
			if err == nil && cert != nil {
				sample.ok = true
				sample.notAfter = cert.NotAfter
				sample.days = time.Until(cert.NotAfter).Hours() / 24
			}
			e.certCache = sample
			e.certAt = time.Now()
		}
		m.certDays = e.certCache.days
		m.certOK = e.certCache.ok
		if !e.certCache.notAfter.IsZero() {
			m.certDetail = "到期时间 " + e.certCache.notAfter.Format("2006-01-02 15:04")
		}
	}

	if needService {
		m.serviceChecked = true
		watched := (&serviceHealthChecker{}).watched()
		for _, name := range watched {
			if !systemdServiceActive(name) {
				m.downServices = append(m.downServices, name)
			}
		}
	}

	return m
}

// metricValue 取规则对应的指标值；ok=false 表示本轮拿不到数据（跳过，宁可漏报也不误报）
func metricValue(r *AlertRule, m alertMetrics) (float64, bool, string) {
	switch r.Metric {
	case alertMetricCPU:
		return m.cpu, true, ""
	case alertMetricMem:
		return m.mem, true, ""
	case alertMetricDisk:
		return m.disk, true, ""
	case alertMetricCert:
		if !m.certOK {
			return 0, false, ""
		}
		return m.certDays, true, m.certDetail
	case alertMetricService:
		if !m.serviceChecked {
			return 0, false, ""
		}
		down := m.downServices
		if r.Target != "" {
			down = nil
			for _, s := range m.downServices {
				if s == r.Target {
					down = append(down, s)
				}
			}
		}
		detail := ""
		if len(down) > 0 {
			detail = "掉线：" + strings.Join(down, "、")
		}
		return float64(len(down)), true, detail
	}
	return 0, false, ""
}

func formatAlertValue(metric string, v float64) string {
	switch metric {
	case alertMetricCert:
		return fmt.Sprintf("%.1f 天", v)
	case alertMetricService:
		return fmt.Sprintf("%.0f 个", v)
	default:
		return fmt.Sprintf("%.1f%%", v)
	}
}

// systemdServiceActive 判断服务是否处于 active；不存在也按掉线处理（配置写错时能暴露出来）
func systemdServiceActive(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", name).Output()
	if err != nil {
		return strings.TrimSpace(string(out)) == "active"
	}
	return strings.TrimSpace(string(out)) == "active"
}

// ---------- 静默窗口 ----------

func parseHHMM(s string) (int, int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d", &h, &m); err != nil {
		return 0, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// inAlertMuteWindow 规则级窗口优先，其次全局；支持跨零点（如 23:00-08:00）
func inAlertMuteWindow(now time.Time, r *AlertRule, cfg alertsConfig) bool {
	start, end := r.MuteStart, r.MuteEnd
	if start == "" || end == "" {
		start, end = cfg.MuteStart, cfg.MuteEnd
	}
	sh, sm, ok1 := parseHHMM(start)
	eh, em, ok2 := parseHHMM(end)
	if !ok1 || !ok2 {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	s, e := sh*60+sm, eh*60+em
	if s == e {
		return false
	}
	if s < e {
		return cur >= s && cur < e
	}
	return cur >= s || cur < e
}

// ---------- 通知 ----------

func sendAlertNotification(cfg alertsConfig, r *AlertRule, ev *AlertEvent) (bool, string) {
	var errs []string
	sent := false

	for _, ch := range r.Channels {
		switch ch {
		case "email":
			mail := cfg.Email
			if mail == nil || mail.Host == "" {
				// 回退：沿用容器守护里配好的 SMTP，用户不用重复填
				if g := loadDockerGuardConfig(); g.AlertEmail != nil {
					mail = g.AlertEmail
				}
			}
			if mail == nil || mail.Host == "" || len(mail.To) == 0 {
				errs = append(errs, "邮件未配置")
				continue
			}
			subject, htmlBody := renderAlertEmail(ev, r)
			if err := sendAlertEmail(mail, subject, htmlBody); err != nil {
				errs = append(errs, "邮件发送失败: "+err.Error())
			} else {
				sent = true
			}
		case "webhook":
			if cfg.WebhookURL == "" {
				errs = append(errs, "Webhook 未配置")
				continue
			}
			if err := postAlertWebhook(cfg.WebhookURL, ev); err != nil {
				errs = append(errs, "Webhook 失败: "+err.Error())
			} else {
				sent = true
			}
		}
	}

	return sent, strings.Join(errs, "; ")
}

func alertEmailSubject(ev *AlertEvent) string {
	if ev.Status == "resolved" {
		return fmt.Sprintf("[已恢复] %s", ev.RuleName)
	}
	return fmt.Sprintf("[%s] %s", severityLabel(ev.Severity), ev.RuleName)
}

func severityLabel(s string) string {
	switch s {
	case "critical":
		return "严重告警"
	case "warning":
		return "警告"
	case "info":
		return "提示"
	}
	return "告警"
}

// postAlertWebhook 发送 webhook：企业微信机器人走 markdown 格式，其它按通用 JSON
func postAlertWebhook(url string, ev *AlertEvent) error {
	var payload any
	if strings.Contains(url, "qyapi.weixin.qq.com") {
		content := fmt.Sprintf("**%s**\n> 规则：%s\n> 状态：%s\n> 详情：%s\n> 时间：%s",
			alertEmailSubject(ev), ev.RuleName, map[bool]string{true: "已恢复", false: "触发中"}[ev.Status == "resolved"],
			ev.Message, ev.CreatedAt.Format("2006-01-02 15:04:05"))
		payload = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": content}}
	} else {
		payload = ev
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
