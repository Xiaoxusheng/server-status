package main

// alerts_store.go —— 告警中心的规则 / 事件存储（复用 ops_center.db，与安全中心同库不同表）
//
// 规则是"条件 + 持续时间 + 通知渠道"的组合，引擎每 interval 秒采样一次，
// 条件持续满足 duration_sec 才触发，避免瞬时毛刺刷屏；恢复时补一条 resolved 事件。

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AlertRule 一条告警规则
type AlertRule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Metric      string     `json:"metric"` // cpu_percent / mem_percent / disk_percent / cert_days / service_down
	Op          string     `json:"op"`     // gt / lt
	Threshold   float64    `json:"threshold"`
	DurationSec int        `json:"duration_sec"`
	Severity    string     `json:"severity"` // critical / warning / info
	Channels    []string   `json:"channels"` // email / webhook
	Enabled     bool       `json:"enabled"`
	Target      string     `json:"target,omitempty"` // service_down 时指定服务名（空=全部被监控服务）
	CooldownSec int        `json:"cooldown_sec"`
	MuteStart   string     `json:"mute_start,omitempty"` // HH:MM，空则跟随全局静默窗口
	MuteEnd     string     `json:"mute_end,omitempty"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// AlertEvent 一次触发 / 恢复记录
type AlertEvent struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Metric    string    `json:"metric"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"` // firing / resolved
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Message   string    `json:"message"`
	Notified  bool      `json:"notified"`
	Muted     bool      `json:"muted"`
	NotifyErr string    `json:"notify_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// alertsConfig 告警中心全局配置（存 ops_settings 的 alerts.config 键）
type alertsConfig struct {
	Enabled     bool              `json:"enabled"`
	IntervalSec int               `json:"interval_sec"`
	MuteStart   string            `json:"mute_start"`
	MuteEnd     string            `json:"mute_end"`
	Email       *alertEmailConfig `json:"email,omitempty"`
	WebhookURL  string            `json:"webhook_url"`
}

const (
	alertsConfigKey = "alerts.config"

	alertMetricCPU     = "cpu_percent"
	alertMetricMem     = "mem_percent"
	alertMetricDisk    = "disk_percent"
	alertMetricCert    = "cert_days"
	alertMetricService = "service_down"
)

// alertMetricLabels 指标的中文名（通知与页面共用）
var alertMetricLabels = map[string]string{
	alertMetricCPU:     "CPU 使用率",
	alertMetricMem:     "内存使用率",
	alertMetricDisk:    "磁盘使用率",
	alertMetricCert:    "SSL 证书剩余天数",
	alertMetricService: "关键服务掉线",
}

func newAlertID(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func nowRFC3339Str() string { return time.Now().Format(time.RFC3339) }

func parseRFC3339Loose(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ---------- 规则读写 ----------

func (s *OpsStore) ListAlertRules() ([]AlertRule, error) {
	rows, err := s.db.Query(`SELECT id,name,metric,op,threshold,duration_sec,severity,channels,enabled,
		target,cooldown_sec,mute_start,mute_end,last_fired_at,created_at,updated_at
		FROM alert_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]AlertRule, 0, 8)
	for rows.Next() {
		var r AlertRule
		var channels, enabled intOrStr
		var lastFired sql.NullString
		var created, updated string
		if err := rows.Scan(&r.ID, &r.Name, &r.Metric, &r.Op, &r.Threshold, &r.DurationSec,
			&r.Severity, &channels, &enabled, &r.Target, &r.CooldownSec, &r.MuteStart,
			&r.MuteEnd, &lastFired, &created, &updated); err != nil {
			return nil, err
		}
		r.Channels = splitChannels(string(channels))
		r.Enabled = string(enabled) == "1" || string(enabled) == "true"
		if lastFired.Valid && lastFired.String != "" {
			t := parseRFC3339Loose(lastFired.String)
			r.LastFiredAt = &t
		}
		r.CreatedAt = parseRFC3339Loose(created)
		r.UpdatedAt = parseRFC3339Loose(updated)
		list = append(list, r)
	}
	return list, rows.Err()
}

// intOrStr 兼容 channels 列（TEXT）被 scan 到 int 变量的历史写法
type intOrStr string

func (v *intOrStr) Scan(src any) error {
	switch t := src.(type) {
	case string:
		*v = intOrStr(t)
	case []byte:
		*v = intOrStr(string(t))
	case int64:
		*v = intOrStr(fmt.Sprintf("%d", t))
	case nil:
		*v = ""
	default:
		*v = intOrStr(fmt.Sprint(t))
	}
	return nil
}

func splitChannels(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinChannels(ch []string) string { return strings.Join(ch, ",") }

func (s *OpsStore) GetAlertRule(id string) (*AlertRule, error) {
	list, err := s.ListAlertRules()
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

// SaveAlertRule 插入或更新（按 ID 判定），返回落库后的规则
func (s *OpsStore) SaveAlertRule(r *AlertRule) (*AlertRule, error) {
	now := nowRFC3339Str()
	if r.ID == "" {
		r.ID = newAlertID("ar")
		r.CreatedAt = time.Now()
	}
	r.UpdatedAt = time.Now()
	// 只兜负值：0 是合法语义（"条件一满足就触发" / "不冷却"），不能被默认值吃掉
	if r.DurationSec < 0 {
		r.DurationSec = 300
	}
	if r.CooldownSec < 0 {
		r.CooldownSec = 1800
	}
	if r.Severity == "" {
		r.Severity = "warning"
	}
	if r.Op != "lt" {
		r.Op = "gt"
	}
	if len(r.Channels) == 0 {
		r.Channels = []string{"email"}
	}

	var lastFired any
	if r.LastFiredAt != nil && !r.LastFiredAt.IsZero() {
		lastFired = r.LastFiredAt.Format(time.RFC3339)
	}

	_, err := s.db.Exec(`INSERT INTO alert_rules
		(id,name,metric,op,threshold,duration_sec,severity,channels,enabled,target,cooldown_sec,
		 mute_start,mute_end,last_fired_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, metric=excluded.metric, op=excluded.op, threshold=excluded.threshold,
			duration_sec=excluded.duration_sec, severity=excluded.severity, channels=excluded.channels,
			enabled=excluded.enabled, target=excluded.target, cooldown_sec=excluded.cooldown_sec,
			mute_start=excluded.mute_start, mute_end=excluded.mute_end,
			last_fired_at=excluded.last_fired_at, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Metric, r.Op, r.Threshold, r.DurationSec, r.Severity,
		joinChannels(r.Channels), boolToInt(r.Enabled), r.Target, r.CooldownSec,
		r.MuteStart, r.MuteEnd, lastFired, now, now)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *OpsStore) DeleteAlertRule(id string) error {
	_, err := s.db.Exec(`DELETE FROM alert_rules WHERE id = ?`, id)
	return err
}

func (s *OpsStore) TouchAlertRuleFired(id string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE alert_rules SET last_fired_at = ?, updated_at = ? WHERE id = ?`,
		at.Format(time.RFC3339), nowRFC3339Str(), id)
	return err
}

// ---------- 事件读写 ----------

func (s *OpsStore) AddAlertEvent(e *AlertEvent) error {
	if e.ID == "" {
		e.ID = newAlertID("ae")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO alert_events
		(id,rule_id,rule_name,metric,severity,status,value,threshold,message,notified,muted,notify_error,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.RuleID, e.RuleName, e.Metric, e.Severity, e.Status,
		e.Value, e.Threshold, e.Message, boolToInt(e.Notified), boolToInt(e.Muted),
		e.NotifyErr, e.CreatedAt.Format(time.RFC3339Nano))
	return err
}

// ListAlertEvents 按时间倒序取事件；status 为空则不过滤
func (s *OpsStore) ListAlertEvents(limit int, status string) ([]AlertEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,rule_id,rule_name,metric,severity,status,value,threshold,message,notified,muted,notify_error,created_at
		FROM alert_events`
	args := []any{}
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	// rowid 兜底：同一秒内的多条事件时间戳可能相同，只按时间排序顺序不确定
	q += ` ORDER BY created_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]AlertEvent, 0, limit)
	for rows.Next() {
		var e AlertEvent
		var notified, muted intOrStr
		var created string
		if err := rows.Scan(&e.ID, &e.RuleID, &e.RuleName, &e.Metric, &e.Severity, &e.Status,
			&e.Value, &e.Threshold, &e.Message, &notified, &muted, &e.NotifyErr, &created); err != nil {
			return nil, err
		}
		e.Notified = string(notified) == "1"
		e.Muted = string(muted) == "1"
		e.CreatedAt = parseRFC3339Loose(created)
		list = append(list, e)
	}
	return list, rows.Err()
}

func (s *OpsStore) CountFiringAlerts() int {
	var n int
	// 取每条规则最后一条事件（按 rowid，避免同秒时间戳并列）判断是否仍处于 firing
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alert_events e
		WHERE e.rowid = (SELECT MAX(rowid) FROM alert_events x WHERE x.rule_id = e.rule_id)
		AND e.status = 'firing'`).Scan(&n)
	return n
}

func (s *OpsStore) CountAlertEventsSince(t time.Time) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alert_events WHERE created_at >= ?`,
		t.Format(time.RFC3339)).Scan(&n)
	return n
}

// ---------- 配置读写 ----------

func (s *OpsStore) GetAlertsConfig() alertsConfig {
	cfg := alertsConfig{Enabled: false, IntervalSec: 30, MuteStart: "23:00", MuteEnd: "08:00"}
	if raw := s.GetSetting(alertsConfigKey, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	} else if g := loadDockerGuardConfig(); g.AlertEmail != nil && g.AlertEmail.Host != "" {
		// 首次使用告警中心：把容器守护里已经配好的 SMTP 直接带过来，用户不用重填
		cfg.Email = g.AlertEmail
	}
	if cfg.IntervalSec < 10 {
		cfg.IntervalSec = 10
	}
	return cfg
}

func (s *OpsStore) SaveAlertsConfig(cfg alertsConfig) error {
	if cfg.IntervalSec < 10 {
		cfg.IntervalSec = 10
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.SetSetting(alertsConfigKey, string(raw))
}

// ensureDefaultAlertRules 首次启动（表为空）时写入四条基础规则。
// 邮件沿用 docker_guard 的 SMTP 配置，避免用户再填一遍。
func (s *OpsStore) ensureDefaultAlertRules() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_rules`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	defaults := []AlertRule{
		{Name: "磁盘空间不足", Metric: alertMetricDisk, Op: "gt", Threshold: 85, DurationSec: 300,
			Severity: "warning", Channels: []string{"email"}, Enabled: true, CooldownSec: 3600},
		{Name: "内存占用过高", Metric: alertMetricMem, Op: "gt", Threshold: 90, DurationSec: 300,
			Severity: "warning", Channels: []string{"email"}, Enabled: true, CooldownSec: 1800},
		{Name: "SSL 证书即将到期", Metric: alertMetricCert, Op: "lt", Threshold: 14, DurationSec: 1,
			Severity: "critical", Channels: []string{"email"}, Enabled: true, CooldownSec: 86400},
		{Name: "关键服务掉线", Metric: alertMetricService, Op: "gt", Threshold: 0, DurationSec: 60,
			Severity: "critical", Channels: []string{"email"}, Enabled: true, CooldownSec: 1800},
	}
	for i := range defaults {
		if _, err := s.SaveAlertRule(&defaults[i]); err != nil {
			return err
		}
	}
	return nil
}
