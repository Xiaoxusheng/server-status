package main

// ==================== 安全中心 / 自动修复 / 运维任务 统一存储层 ====================
//
// 沿用私人空间的 SQLite 方案（modernc.org/sqlite，纯 Go 无 CGO），
// 单文件库 ops_center.db，独立于 private_notes.db，互不影响。
// 单连接 + WAL，写入串行化，避免锁冲突；所有时间以 RFC3339 TEXT 存储。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SecurityFinding 一条安全风险发现（跨扫描通过 check_id + dedupe_key 合并）
type SecurityFinding struct {
	ID             string     `json:"id"`
	CheckID        string     `json:"check_id"`
	DedupeKey      string     `json:"dedupe_key"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"` // critical/high/medium/low/info
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Evidence       string     `json:"evidence"`
	Recommendation string     `json:"recommendation"`
	Status         string     `json:"status"` // open/ignored/fixing/resolved/failed
	DetectedAt     time.Time  `json:"detected_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	Remediable     bool       `json:"remediable"`
	Occurrences    int        `json:"occurrences"`
	LastExecError  string     `json:"last_exec_error,omitempty"`
	Context        map[string]any `json:"context,omitempty"` // 检查器附带的动作参数上下文（service/ip/port 等），持久化
}

// SecurityEvent 安全事件流水（风险产生/恢复、扫描、修复动作等）
type SecurityEvent struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`  // info/warning/error/critical
	Type   string    `json:"type"`   // finding.open / finding.resolved / scan.completed / remediation.* / task.*
	Title  string    `json:"title"`
	Source string    `json:"source"` // 来源检查器或模块
	RefID  string    `json:"ref_id,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// RemediationRule 修复策略：把某类 Finding 映射到白名单 Action
type RemediationRule struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	CheckID         string         `json:"check_id"`
	DedupeKey       string         `json:"dedupe_key,omitempty"` // 空=匹配该检查下全部发现
	MinSeverity     string         `json:"min_severity"`         // 适用风险下限，低于该级别不匹配
	Mode            string         `json:"mode"`                 // manual/suggest/auto
	Enabled         bool           `json:"enabled"`
	RequireConfirm  bool           `json:"require_confirm"`
	ActionID        string         `json:"action_id"`
	Parameters      map[string]any `json:"parameters"`
	MaxAttempts     int            `json:"max_attempts"`
	CooldownSeconds int            `json:"cooldown_seconds"`
	CreatedBy       string         `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// RemediationExecution 一次修复动作的执行记录
type RemediationExecution struct {
	ID           string            `json:"id"`
	FindingID    string            `json:"finding_id,omitempty"`
	RuleID       string            `json:"rule_id,omitempty"`
	ActionID     string            `json:"action_id"`
	Trigger      string            `json:"trigger"`   // manual/auto
	Operator     string            `json:"operator"`  // 用户名或 system
	ParamsDigest string            `json:"params_digest,omitempty"`
	Status       string            `json:"status"` // running/success/failed/timeout
	Message      string            `json:"message,omitempty"`
	Steps        map[string]string `json:"steps,omitempty"` // preview/execute/verify 阶段输出摘要
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   *time.Time        `json:"finished_at,omitempty"`
	DurationMS   int64             `json:"duration_ms"`
}

// Task 运维任务（一次性 / Cron / 周期 / 事件触发）
type Task struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Type            string         `json:"type"` // once/cron/interval/event
	Schedule        string         `json:"schedule,omitempty"`
	IntervalSec     int            `json:"interval_seconds,omitempty"`
	RunAt           *time.Time     `json:"run_at,omitempty"`
	Trigger         *TaskTrigger   `json:"trigger,omitempty"`
	ActionID        string         `json:"action_id"`
	Parameters      map[string]any `json:"parameters"`
	Enabled         bool           `json:"enabled"`
	TimeoutSec      int            `json:"timeout_seconds"`
	MaxAttempts     int            `json:"max_attempts"`
	RetryBackoffSec int            `json:"retry_backoff_seconds"`
	NextRunAt       *time.Time     `json:"next_run_at,omitempty"`
	LastRunAt       *time.Time     `json:"last_run_at,omitempty"`
	LastStatus      string         `json:"last_status,omitempty"`
	CreatedBy       string         `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// TaskTrigger 事件触发条件
type TaskTrigger struct {
	Type      string `json:"type"`                 // cpu_high/disk_high/service_stopped/security_finding/docker_container_exit/ip_abnormal
	Threshold int    `json:"threshold,omitempty"`  // 阈值（百分比/个数）
	Match     string `json:"match,omitempty"`      // 过滤：服务名 / 容器名 / 最低严重级
	CooldownSec int  `json:"cooldown_sec,omitempty"` // 触发冷却，防止重复触发
}

// TaskExecution 任务执行历史（一条 = 一次触发，含重试）
type TaskExecution struct {
	ID           string            `json:"id"`
	TaskID       string            `json:"task_id"`
	TaskName     string            `json:"task_name"`
	Status       string            `json:"status"` // queued/running/success/failed/cancelled/timeout/skipped
	TriggerType  string            `json:"trigger_type"` // schedule/manual/event/retry
	Attempt      int               `json:"attempt"`
	MaxAttempts  int               `json:"max_attempts"`
	Operator     string            `json:"operator,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Steps        map[string]string `json:"steps,omitempty"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	FinishedAt   *time.Time        `json:"finished_at,omitempty"`
	DurationMS   int64             `json:"duration_ms"`
	CreatedAt    time.Time         `json:"created_at"`
}

// OpsStore 运维中心统一存储
type OpsStore struct {
	db *sql.DB
}

// NewOpsStore 打开（必要时创建）运维中心 SQLite 库并执行迁移
func NewOpsStore(path string) (*OpsStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &OpsStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *OpsStore) Close() error {
	if s != nil && s.db != nil {
		return s.db.Close()
	}
	return nil
}

// migrate 建表（幂等）
func (s *OpsStore) migrate() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS security_findings (
			id TEXT PRIMARY KEY,
			check_id TEXT NOT NULL,
			dedupe_key TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			recommendation TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open',
			detected_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			resolved_at TEXT,
			remediable INTEGER NOT NULL DEFAULT 0,
			occurrences INTEGER NOT NULL DEFAULT 1,
			last_exec_error TEXT NOT NULL DEFAULT '',
			context_json TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_key ON security_findings(check_id, dedupe_key)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status ON security_findings(status, severity)`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id TEXT PRIMARY KEY,
			time TEXT NOT NULL,
			level TEXT NOT NULL,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			ref_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(time DESC)`,
		`CREATE TABLE IF NOT EXISTS remediation_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			check_id TEXT NOT NULL,
			dedupe_key TEXT NOT NULL DEFAULT '',
			min_severity TEXT NOT NULL DEFAULT 'medium',
			mode TEXT NOT NULL DEFAULT 'manual',
			enabled INTEGER NOT NULL DEFAULT 1,
			require_confirm INTEGER NOT NULL DEFAULT 1,
			action_id TEXT NOT NULL,
			parameters TEXT NOT NULL DEFAULT '{}',
			max_attempts INTEGER NOT NULL DEFAULT 3,
			cooldown_seconds INTEGER NOT NULL DEFAULT 900,
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS remediation_executions (
			id TEXT PRIMARY KEY,
			finding_id TEXT NOT NULL DEFAULT '',
			rule_id TEXT NOT NULL DEFAULT '',
			action_id TEXT NOT NULL,
			trigger TEXT NOT NULL,
			operator TEXT NOT NULL DEFAULT '',
			params_digest TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			message TEXT NOT NULL DEFAULT '',
			steps TEXT NOT NULL DEFAULT '{}',
			started_at TEXT NOT NULL,
			finished_at TEXT,
			duration_ms INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_remexec_time ON remediation_executions(started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL,
			schedule TEXT NOT NULL DEFAULT '',
			interval_seconds INTEGER NOT NULL DEFAULT 0,
			run_at TEXT,
			trigger_json TEXT NOT NULL DEFAULT '',
			action_id TEXT NOT NULL,
			parameters TEXT NOT NULL DEFAULT '{}',
			enabled INTEGER NOT NULL DEFAULT 1,
			timeout_seconds INTEGER NOT NULL DEFAULT 600,
			max_attempts INTEGER NOT NULL DEFAULT 1,
			retry_backoff_seconds INTEGER NOT NULL DEFAULT 60,
			next_run_at TEXT,
			last_run_at TEXT,
			last_status TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_next ON tasks(enabled, next_run_at)`,
		`CREATE TABLE IF NOT EXISTS task_executions (
			id TEXT PRIMARY KEY,
			task_id TEXT NOT NULL,
			task_name TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			trigger_type TEXT NOT NULL DEFAULT 'schedule',
			attempt INTEGER NOT NULL DEFAULT 1,
			max_attempts INTEGER NOT NULL DEFAULT 1,
			operator TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			steps TEXT NOT NULL DEFAULT '{}',
			started_at TEXT,
			finished_at TEXT,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_taskexec_task ON task_executions(task_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_taskexec_time ON task_executions(created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS ops_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
	}
	for _, stmt := range schema {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("运维中心建表失败: %w", err)
		}
	}
	return nil
}

// GetSetting 读取设置（key 不存在返回 def）
func (s *OpsStore) GetSetting(key, def string) string {
	var v string
	err := s.db.QueryRow(`SELECT value FROM ops_settings WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

// SetSetting 写入设置
func (s *OpsStore) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO ops_settings(key, value, updated_at) VALUES(?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, nowRFC3339())
	return err
}

func nowRFC3339() string { return time.Now().Format(time.RFC3339Nano) }

func parseDBTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func nullTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.Format(time.RFC3339Nano)
}

func scanNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := parseDBTime(ns.String)
	if t.IsZero() {
		return nil
	}
	return &t
}

// ---------------- 安全发现 ----------------

// UpsertFinding 按索引写入或合并一条发现；created=true 表示全新发现
// 合并规则：
//   - 不存在 → 新建 open
//   - open/failed/fixing → 更新内容、累计次数、刷新检测时间
//   - ignored → 仅刷新内容，不复活状态（用户已明确忽略）
//   - resolved → 重新打开（风险回归），计入新事件
func (s *OpsStore) UpsertFinding(f *SecurityFinding) (created bool, reopened bool, err error) {
	now := time.Now()
	f.UpdatedAt = now
	var (
		id          string
		status      string
		occ         int
		detectedStr string
	)
	err = s.db.QueryRow(`SELECT id, status, occurrences, detected_at FROM security_findings
		WHERE check_id = ? AND dedupe_key = ?`, f.CheckID, f.DedupeKey).Scan(&id, &status, &occ, &detectedStr)
	switch {
	case err == sql.ErrNoRows:
		f.ID = genOpsID("fnd")
		f.Status = "open"
		f.DetectedAt = now
		f.Occurrences = 1
		ctxJSON := marshalFindingContext(f.Context)
		_, err = s.db.Exec(`INSERT INTO security_findings
			(id, check_id, dedupe_key, category, severity, title, description, evidence, recommendation,
			 status, detected_at, updated_at, remediable, occurrences, last_exec_error, context_json)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			f.ID, f.CheckID, f.DedupeKey, f.Category, f.Severity, f.Title, f.Description,
			f.Evidence, f.Recommendation, f.Status, nowRFC3339(), nowRFC3339(), boolToInt(f.Remediable), 1, "", ctxJSON)
		return err == nil, false, err
	case err != nil:
		return false, false, err
	}
	prevDetected := parseDBTime(detectedStr)
	newStatus := status
	reopened = false
	switch status {
	case "resolved":
		newStatus = "open"
		reopened = true
	case "ignored", "fixing", "open", "failed":
		// 保持原状态
	default:
		newStatus = "open"
	}
	f.ID = id
	f.Status = newStatus
	f.Occurrences = occ + 1
	f.DetectedAt = now
	_, err = s.db.Exec(`UPDATE security_findings SET
		category=?, severity=?, title=?, description=?, evidence=?, recommendation=?,
		status=?, detected_at=?, updated_at=?, resolved_at=NULL, occurrences=?, remediable=?, context_json=?
		WHERE id=?`,
		f.Category, f.Severity, f.Title, f.Description, f.Evidence, f.Recommendation,
		newStatus, nowRFC3339(), nowRFC3339(), f.Occurrences, boolToInt(f.Remediable),
		marshalFindingContext(f.Context), id)
	_ = prevDetected
	return false, reopened, err
}

func marshalFindingContext(ctx map[string]any) string {
	if len(ctx) == 0 {
		return ""
	}
	b, err := json.Marshal(ctx)
	if err != nil {
		return ""
	}
	return string(b)
}

func unmarshalFindingContext(s string) map[string]any {
	if s == "" {
		return nil
	}
	m := map[string]any{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// ResolveFindingsNotIn 批量恢复：当前扫描未再发现且仍处于未解决的条目置为 resolved
func (s *OpsStore) ResolveFindingsNotIn(checkID string, liveKeys map[string]bool) ([]SecurityFinding, error) {
	rows, err := s.db.Query(`SELECT id, dedupe_key, title, severity FROM security_findings
		WHERE check_id = ? AND status IN ('open','failed','fixing')`, checkID)
	if err != nil {
		return nil, err
	}
	type staleRow struct {
		id, key, title, sev string
	}
	var stale []staleRow
	for rows.Next() {
		var r staleRow
		if err := rows.Scan(&r.id, &r.key, &r.title, &r.sev); err == nil {
			stale = append(stale, r)
		}
	}
	rows.Close()
	now := time.Now()
	out := make([]SecurityFinding, 0)
	for _, r := range stale {
		if liveKeys[r.key] {
			continue
		}
		if _, err := s.db.Exec(`UPDATE security_findings SET status='resolved', resolved_at=?, updated_at=? WHERE id=?`,
			nowRFC3339(), nowRFC3339(), r.id); err != nil {
			continue
		}
		out = append(out, SecurityFinding{ID: r.id, CheckID: checkID, DedupeKey: r.key, Title: r.title, Severity: r.sev, Status: "resolved", ResolvedAt: &now})
	}
	return out, nil
}

// FindingFilter 发现列表过滤条件
type FindingFilter struct {
	Status   []string
	Severity string
	Category string
	CheckID  string
	Limit    int
	Offset   int
}

func (s *OpsStore) ListFindings(f FindingFilter) ([]SecurityFinding, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if len(f.Status) > 0 {
		where += " AND status IN ("
		for i, st := range f.Status {
			if i > 0 {
				where += ","
			}
			where += "?"
			args = append(args, st)
		}
		where += ")"
	}
	if f.Severity != "" {
		where += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Category != "" {
		where += " AND category = ?"
		args = append(args, f.Category)
	}
	if f.CheckID != "" {
		where += " AND check_id = ?"
		args = append(args, f.CheckID)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM security_findings"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := f.Limit, f.Offset
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT id, check_id, dedupe_key, category, severity, title, description, evidence, recommendation,
		status, detected_at, updated_at, resolved_at, remediable, occurrences, last_exec_error, context_json
		FROM security_findings` + where + ` ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		detected_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := make([]SecurityFinding, 0, 32)
	for rows.Next() {
		var fo SecurityFinding
		var detected, updated string
		var resolved sql.NullString
		var remediable int
		var ctxJSON string
		if err := rows.Scan(&fo.ID, &fo.CheckID, &fo.DedupeKey, &fo.Category, &fo.Severity, &fo.Title,
			&fo.Description, &fo.Evidence, &fo.Recommendation, &fo.Status, &detected, &updated, &resolved,
			&remediable, &fo.Occurrences, &fo.LastExecError, &ctxJSON); err != nil {
			continue
		}
		fo.DetectedAt = parseDBTime(detected)
		fo.UpdatedAt = parseDBTime(updated)
		fo.ResolvedAt = scanNullTime(resolved)
		fo.Remediable = remediable == 1
		fo.Context = unmarshalFindingContext(ctxJSON)
		list = append(list, fo)
	}
	return list, total, nil
}

func (s *OpsStore) GetFinding(id string) (*SecurityFinding, error) {
	row := s.db.QueryRow(`SELECT id, check_id, dedupe_key, category, severity, title, description, evidence,
		recommendation, status, detected_at, updated_at, resolved_at, remediable, occurrences, last_exec_error, context_json
		FROM security_findings WHERE id = ?`, id)
	var fo SecurityFinding
	var detected, updated string
	var resolved sql.NullString
	var remediable int
	var ctxJSON string
	if err := row.Scan(&fo.ID, &fo.CheckID, &fo.DedupeKey, &fo.Category, &fo.Severity, &fo.Title, &fo.Description,
		&fo.Evidence, &fo.Recommendation, &fo.Status, &detected, &updated, &resolved, &remediable,
		&fo.Occurrences, &fo.LastExecError, &ctxJSON); err != nil {
		return nil, err
	}
	fo.DetectedAt = parseDBTime(detected)
	fo.UpdatedAt = parseDBTime(updated)
	fo.ResolvedAt = scanNullTime(resolved)
	fo.Remediable = remediable == 1
	fo.Context = unmarshalFindingContext(ctxJSON)
	return &fo, nil
}

// UpdateFindingStatus 状态机流转（open/ignored/fixing/resolved/failed）
func (s *OpsStore) UpdateFindingStatus(id, status string, execErr string) error {
	sets := `status=?, updated_at=?`
	args := []any{status, nowRFC3339()}
	if status == "resolved" {
		sets += ", resolved_at=?, last_exec_error=''"
		args = append(args, nowRFC3339())
	} else {
		if status != "fixing" {
			sets += ", resolved_at=NULL"
		}
		sets += ", last_exec_error=?"
		args = append(args, execErr)
	}
	args = append(args, id)
	_, err := s.db.Exec(`UPDATE security_findings SET `+sets+` WHERE id=?`, args...)
	return err
}

// CountOpenFindingsBySeverity 统计 open/failed/fixing 发现数量（评分用）
func (s *OpsStore) CountOpenFindingsBySeverity() map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM security_findings
		WHERE status IN ('open','failed','fixing') GROUP BY severity`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err == nil {
			out[sev] = n
		}
	}
	return out
}

// CountFindingsOpenAt 统计某时刻仍处于未解决状态的风险数（趋势重建用，忽略态不计）
func (s *OpsStore) CountFindingsOpenAt(ts time.Time) int {
	t := ts.Format(time.RFC3339Nano)
	var n int
	// 当时已存在（detected_at <= ts），且现在仍未解决，或之后才被标记解决
	err := s.db.QueryRow(`SELECT COUNT(*) FROM security_findings
		WHERE detected_at <= ? AND (status IN ('open','failed','fixing')
			OR (status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at > ?))`, t, t).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// ---------------- 安全事件 ----------------

func (s *OpsStore) AddEvent(e *SecurityEvent) error {
	if e.ID == "" {
		e.ID = genOpsID("evt")
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO security_events(id, time, level, type, title, source, ref_id, detail)
		VALUES(?,?,?,?,?,?,?,?)`,
		e.ID, e.Time.Format(time.RFC3339Nano), e.Level, e.Type, e.Title, e.Source, e.RefID, e.Detail)
	return err
}

func (s *OpsStore) ListEvents(level, evType string, limit, offset int) ([]SecurityEvent, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if level != "" {
		where += " AND level=?"
		args = append(args, level)
	}
	if evType != "" {
		where += " AND type=?"
		args = append(args, evType)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM security_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(`SELECT id, time, level, type, title, source, ref_id, detail
		FROM security_events`+where+` ORDER BY time DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]SecurityEvent, 0, 32)
	for rows.Next() {
		var e SecurityEvent
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Type, &e.Title, &e.Source, &e.RefID, &e.Detail); err == nil {
			e.Time = parseDBTime(ts)
			out = append(out, e)
		}
	}
	return out, total, nil
}

// ---------------- 修复策略 ----------------

func (s *OpsStore) ListRules() ([]RemediationRule, error) {
	rows, err := s.db.Query(`SELECT id, name, description, check_id, dedupe_key, min_severity, mode, enabled,
		require_confirm, action_id, parameters, max_attempts, cooldown_seconds, created_by, created_at, updated_at
		FROM remediation_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RemediationRule, 0, 8)
	for rows.Next() {
		r, err := scanRemediationRule(rows)
		if err != nil {
			continue
		}
		out = append(out, *r)
	}
	return out, nil
}

func scanRemediationRule(rows *sql.Rows) (*RemediationRule, error) {
	var r RemediationRule
	var enabled, confirm int
	var params string
	var created, updated string
	if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CheckID, &r.DedupeKey, &r.MinSeverity, &r.Mode,
		&enabled, &confirm, &r.ActionID, &params, &r.MaxAttempts, &r.CooldownSeconds, &r.CreatedBy,
		&created, &updated); err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	r.RequireConfirm = confirm == 1
	r.Parameters = map[string]any{}
	_ = json.Unmarshal([]byte(params), &r.Parameters)
	r.CreatedAt = parseDBTime(created)
	r.UpdatedAt = parseDBTime(updated)
	return &r, nil
}

func (s *OpsStore) GetRule(id string) (*RemediationRule, error) {
	row := s.db.QueryRow(`SELECT id, name, description, check_id, dedupe_key, min_severity, mode, enabled,
		require_confirm, action_id, parameters, max_attempts, cooldown_seconds, created_by, created_at, updated_at
		FROM remediation_rules WHERE id=?`, id)
	r, err := scanRemediationRuleRows(row)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRemediationRuleRows(row rowScanner) (*RemediationRule, error) {
	// 借助临时 sql.Rows 形态：这里直接手工扫描
	var r RemediationRule
	var enabled, confirm int
	var params string
	var created, updated string
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CheckID, &r.DedupeKey, &r.MinSeverity, &r.Mode,
		&enabled, &confirm, &r.ActionID, &params, &r.MaxAttempts, &r.CooldownSeconds, &r.CreatedBy,
		&created, &updated); err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	r.RequireConfirm = confirm == 1
	r.Parameters = map[string]any{}
	_ = json.Unmarshal([]byte(params), &r.Parameters)
	r.CreatedAt = parseDBTime(created)
	r.UpdatedAt = parseDBTime(updated)
	return &r, nil
}

func (s *OpsStore) SaveRule(r *RemediationRule) error {
	params, _ := json.Marshal(r.Parameters)
	if params == nil {
		params = []byte("{}")
	}
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	_, err := s.db.Exec(`INSERT INTO remediation_rules
		(id, name, description, check_id, dedupe_key, min_severity, mode, enabled, require_confirm,
		 action_id, parameters, max_attempts, cooldown_seconds, created_by, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, description=excluded.description, check_id=excluded.check_id,
			dedupe_key=excluded.dedupe_key, min_severity=excluded.min_severity, mode=excluded.mode,
			enabled=excluded.enabled, require_confirm=excluded.require_confirm, action_id=excluded.action_id,
			parameters=excluded.parameters, max_attempts=excluded.max_attempts,
			cooldown_seconds=excluded.cooldown_seconds, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Description, r.CheckID, r.DedupeKey, r.MinSeverity, r.Mode, boolToInt(r.Enabled),
		boolToInt(r.RequireConfirm), r.ActionID, string(params), r.MaxAttempts, r.CooldownSeconds,
		r.CreatedBy, r.CreatedAt.Format(time.RFC3339Nano), r.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *OpsStore) DeleteRule(id string) error {
	_, err := s.db.Exec(`DELETE FROM remediation_rules WHERE id=?`, id)
	return err
}

func (s *OpsStore) CountRules() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM remediation_rules`).Scan(&n)
	return n, err
}

// ---------------- 修复执行记录 ----------------

func (s *OpsStore) AddRemediationExecution(e *RemediationExecution) error {
	steps, _ := json.Marshal(e.Steps)
	if steps == nil {
		steps = []byte("{}")
	}
	_, err := s.db.Exec(`INSERT INTO remediation_executions
		(id, finding_id, rule_id, action_id, trigger, operator, params_digest, status, message, steps, started_at, finished_at, duration_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.FindingID, e.RuleID, e.ActionID, e.Trigger, e.Operator, e.ParamsDigest, e.Status,
		e.Message, string(steps), e.StartedAt.Format(time.RFC3339Nano), nullTime(e.FinishedAt), e.DurationMS)
	return err
}

func (s *OpsStore) UpdateRemediationExecution(e *RemediationExecution) error {
	steps, _ := json.Marshal(e.Steps)
	_, err := s.db.Exec(`UPDATE remediation_executions SET status=?, message=?, steps=?, finished_at=?, duration_ms=? WHERE id=?`,
		e.Status, e.Message, string(steps), nullTime(e.FinishedAt), e.DurationMS, e.ID)
	return err
}

func scanRemExecution(row rowScanner) (*RemediationExecution, error) {
	var e RemediationExecution
	var started string
	var finished sql.NullString
	var steps string
	if err := row.Scan(&e.ID, &e.FindingID, &e.RuleID, &e.ActionID, &e.Trigger, &e.Operator, &e.ParamsDigest,
		&e.Status, &e.Message, &steps, &started, &finished, &e.DurationMS); err != nil {
		return nil, err
	}
	e.StartedAt = parseDBTime(started)
	e.FinishedAt = scanNullTime(finished)
	e.Steps = map[string]string{}
	_ = json.Unmarshal([]byte(steps), &e.Steps)
	return &e, nil
}

const remExecCols = `id, finding_id, rule_id, action_id, trigger, operator, params_digest, status, message, steps, started_at, finished_at, duration_ms`

func (s *OpsStore) GetRemediationExecution(id string) (*RemediationExecution, error) {
	return scanRemExecution(s.db.QueryRow(`SELECT `+remExecCols+` FROM remediation_executions WHERE id=?`, id))
}

func (s *OpsStore) ListRemediationExecutions(ruleID, findingID string, limit, offset int) ([]RemediationExecution, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if ruleID != "" {
		where += " AND rule_id=?"
		args = append(args, ruleID)
	}
	if findingID != "" {
		where += " AND finding_id=?"
		args = append(args, findingID)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM remediation_executions"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(`SELECT `+remExecCols+` FROM remediation_executions`+where+` ORDER BY started_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]RemediationExecution, 0, 32)
	for rows.Next() {
		if e, err := scanRemExecution(rows); err == nil {
			out = append(out, *e)
		}
	}
	return out, total, nil
}

// CountRemediationExecutionsSince 统计某规则对某发现的执行次数（冷却/最大次数用）
func (s *OpsStore) CountRemediationExecutionsSince(ruleID, findingID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM remediation_executions
		WHERE rule_id=? AND finding_id=? AND started_at >= ?`,
		ruleID, findingID, since.Format(time.RFC3339Nano)).Scan(&n)
	return n, err
}

// CountRemediationToday 今日修复执行统计
func (s *OpsStore) CountRemediationToday() (total, success, failed int, err error) {
	today := time.Now().Format("2006-01-02")
	err = s.db.QueryRow(`SELECT COUNT(*),
			SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),
			SUM(CASE WHEN status IN ('failed','timeout') THEN 1 ELSE 0 END)
		FROM remediation_executions WHERE started_at >= ?`, today).Scan(&total, &success, &failed)
	return
}

// ---------------- 运维任务 ----------------

func (s *OpsStore) ListTasks() ([]Task, error) {
	rows, err := s.db.Query(`SELECT id, name, description, type, schedule, interval_seconds, run_at, trigger_json,
		action_id, parameters, enabled, timeout_seconds, max_attempts, retry_backoff_seconds,
		next_run_at, last_run_at, last_status, created_by, created_at, updated_at
		FROM tasks ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Task, 0, 8)
	for rows.Next() {
		if t, err := scanTask(rows); err == nil {
			out = append(out, *t)
		}
	}
	return out, nil
}

func scanTask(row rowScanner) (*Task, error) {
	var t Task
	var schedule, triggerJSON, params string
	var runAt, nextRun, lastRun sql.NullString
	var enabled int
	var created, updated string
	if err := row.Scan(&t.ID, &t.Name, &t.Description, &t.Type, &schedule, &t.IntervalSec, &runAt, &triggerJSON,
		&t.ActionID, &params, &enabled, &t.TimeoutSec, &t.MaxAttempts, &t.RetryBackoffSec,
		&nextRun, &lastRun, &t.LastStatus, &t.CreatedBy, &created, &updated); err != nil {
		return nil, err
	}
	t.Schedule = schedule
	t.Enabled = enabled == 1
	t.RunAt = scanNullTime(runAt)
	t.NextRunAt = scanNullTime(nextRun)
	t.LastRunAt = scanNullTime(lastRun)
	t.Parameters = map[string]any{}
	_ = json.Unmarshal([]byte(params), &t.Parameters)
	if triggerJSON != "" && triggerJSON != "{}" {
		var tg TaskTrigger
		if err := json.Unmarshal([]byte(triggerJSON), &tg); err == nil {
			t.Trigger = &tg
		}
	}
	t.CreatedAt = parseDBTime(created)
	t.UpdatedAt = parseDBTime(updated)
	return &t, nil
}

func (s *OpsStore) GetTask(id string) (*Task, error) {
	return scanTask(s.db.QueryRow(`SELECT id, name, description, type, schedule, interval_seconds, run_at, trigger_json,
		action_id, parameters, enabled, timeout_seconds, max_attempts, retry_backoff_seconds,
		next_run_at, last_run_at, last_status, created_by, created_at, updated_at
		FROM tasks WHERE id=?`, id))
}

func (s *OpsStore) SaveTask(t *Task) error {
	params, _ := json.Marshal(t.Parameters)
	if params == nil {
		params = []byte("{}")
	}
	triggerJSON := ""
	if t.Trigger != nil {
		if b, err := json.Marshal(t.Trigger); err == nil {
			triggerJSON = string(b)
		}
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	_, err := s.db.Exec(`INSERT INTO tasks
		(id, name, description, type, schedule, interval_seconds, run_at, trigger_json, action_id, parameters,
		 enabled, timeout_seconds, max_attempts, retry_backoff_seconds, next_run_at, last_run_at, last_status,
		 created_by, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, description=excluded.description, type=excluded.type, schedule=excluded.schedule,
			interval_seconds=excluded.interval_seconds, run_at=excluded.run_at, trigger_json=excluded.trigger_json,
			action_id=excluded.action_id, parameters=excluded.parameters, enabled=excluded.enabled,
			timeout_seconds=excluded.timeout_seconds, max_attempts=excluded.max_attempts,
			retry_backoff_seconds=excluded.retry_backoff_seconds, updated_at=excluded.updated_at`,
		t.ID, t.Name, t.Description, t.Type, t.Schedule, t.IntervalSec, nullTime(t.RunAt), triggerJSON,
		t.ActionID, string(params), boolToInt(t.Enabled), t.TimeoutSec, t.MaxAttempts, t.RetryBackoffSec,
		nullTime(t.NextRunAt), nullTime(t.LastRunAt), t.LastStatus, t.CreatedBy,
		t.CreatedAt.Format(time.RFC3339Nano), t.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *OpsStore) DeleteTask(id string) error {
	_, err := s.db.Exec(`DELETE FROM tasks WHERE id=?`, id)
	return err
}

// UpdateTaskRuntime 调度回写：下次执行 / 最近执行 / 最近状态
func (s *OpsStore) UpdateTaskRuntime(id string, nextRun *time.Time, lastRun *time.Time, lastStatus string) error {
	_, err := s.db.Exec(`UPDATE tasks SET next_run_at=?, last_run_at=?, last_status=?, updated_at=? WHERE id=?`,
		nullTime(nextRun), nullTime(lastRun), lastStatus, nowRFC3339(), id)
	return err
}

// UpdateTaskLastRun 执行器回写最近一次执行结果（不动 next_run_at，归调度器管）
func (s *OpsStore) UpdateTaskLastRun(id string, lastRun time.Time, status string) error {
	_, err := s.db.Exec(`UPDATE tasks SET last_run_at=?, last_status=?, updated_at=? WHERE id=?`,
		lastRun.Format(time.RFC3339Nano), status, nowRFC3339(), id)
	return err
}

// ---------------- 任务执行历史 ----------------

const taskExecCols = `id, task_id, task_name, status, trigger_type, attempt, max_attempts, operator, error_message, steps, started_at, finished_at, duration_ms, created_at`

func scanTaskExecution(row rowScanner) (*TaskExecution, error) {
	var e TaskExecution
	var started, finished, created sql.NullString
	var steps string
	if err := row.Scan(&e.ID, &e.TaskID, &e.TaskName, &e.Status, &e.TriggerType, &e.Attempt, &e.MaxAttempts,
		&e.Operator, &e.ErrorMessage, &steps, &started, &finished, &e.DurationMS, &created); err != nil {
		return nil, err
	}
	e.StartedAt = scanNullTime(started)
	e.FinishedAt = scanNullTime(finished)
	e.CreatedAt = parseDBTime(created.String)
	e.Steps = map[string]string{}
	_ = json.Unmarshal([]byte(steps), &e.Steps)
	return &e, nil
}

func (s *OpsStore) AddTaskExecution(e *TaskExecution) error {
	steps, _ := json.Marshal(e.Steps)
	if steps == nil {
		steps = []byte("{}")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO task_executions
		(id, task_id, task_name, status, trigger_type, attempt, max_attempts, operator, error_message, steps, started_at, finished_at, duration_ms, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TaskID, e.TaskName, e.Status, e.TriggerType, e.Attempt, e.MaxAttempts, e.Operator,
		e.ErrorMessage, string(steps), nullTime(e.StartedAt), nullTime(e.FinishedAt), e.DurationMS,
		e.CreatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *OpsStore) UpdateTaskExecution(e *TaskExecution) error {
	steps, _ := json.Marshal(e.Steps)
	_, err := s.db.Exec(`UPDATE task_executions SET status=?, attempt=?, error_message=?, steps=?, started_at=?, finished_at=?, duration_ms=? WHERE id=?`,
		e.Status, e.Attempt, e.ErrorMessage, string(steps), nullTime(e.StartedAt), nullTime(e.FinishedAt), e.DurationMS, e.ID)
	return err
}

func (s *OpsStore) GetTaskExecution(id string) (*TaskExecution, error) {
	return scanTaskExecution(s.db.QueryRow(`SELECT `+taskExecCols+` FROM task_executions WHERE id=?`, id))
}

// TaskExecutionFilter 执行历史过滤
type TaskExecutionFilter struct {
	TaskID string
	Status string
	Since  *time.Time
	Limit  int
	Offset int
}

func (s *OpsStore) ListTaskExecutions(f TaskExecutionFilter) ([]TaskExecution, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if f.TaskID != "" {
		where += " AND task_id=?"
		args = append(args, f.TaskID)
	}
	if f.Status != "" {
		where += " AND status=?"
		args = append(args, f.Status)
	}
	if f.Since != nil {
		where += " AND created_at >= ?"
		args = append(args, f.Since.Format(time.RFC3339Nano))
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM task_executions"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(`SELECT `+taskExecCols+` FROM task_executions`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]TaskExecution, 0, 32)
	for rows.Next() {
		if e, err := scanTaskExecution(rows); err == nil {
			out = append(out, *e)
		}
	}
	return out, total, nil
}

// CountRunningTaskExecutions 统计仍在运行的任务执行数（可选按任务过滤）
func (s *OpsStore) CountRunningTaskExecutions(taskID string) (int, error) {
	q := `SELECT COUNT(*) FROM task_executions WHERE status IN ('queued','running')`
	args := []any{}
	if taskID != "" {
		q += " AND task_id=?"
		args = append(args, taskID)
	}
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}

// TaskStats 运维任务首页统计
func (s *OpsStore) TaskStats() (running, scheduled, failed24h, doneToday int, err error) {
	today := time.Now().Format("2006-01-02")
	dayAgo := time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM task_executions WHERE status IN ('queued','running')`).Scan(&running); err != nil {
		return
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE enabled=1`).Scan(&scheduled); err != nil {
		return
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM task_executions WHERE status IN ('failed','timeout') AND created_at >= ?`, dayAgo).Scan(&failed24h); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT COUNT(*) FROM task_executions WHERE status='success' AND created_at >= ?`, today).Scan(&doneToday)
	return
}

// CleanupOldRecords 清理过期流水（事件 / 执行历史保留条数），防止库无限膨胀
func (s *OpsStore) CleanupOldRecords(keepEvents, keepExecs int) {
	if keepEvents < 100 {
		keepEvents = 100
	}
	if keepExecs < 100 {
		keepExecs = 100
	}
	if _, err := s.db.Exec(`DELETE FROM security_events WHERE id NOT IN
		(SELECT id FROM security_events ORDER BY time DESC LIMIT ?)`, keepEvents); err != nil {
		log.Printf("清理安全事件失败: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM task_executions WHERE id NOT IN
		(SELECT id FROM task_executions ORDER BY created_at DESC LIMIT ?)`, keepExecs); err != nil {
		log.Printf("清理任务执行历史失败: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM remediation_executions WHERE id NOT IN
		(SELECT id FROM remediation_executions ORDER BY started_at DESC LIMIT ?)`, keepExecs); err != nil {
		log.Printf("清理修复执行历史失败: %v", err)
	}
}

// ---------------- 公共小工具 ----------------

var opsIDCounter = int64(0)

// genOpsID 生成运维中心内部 ID（前缀 + 时间 + 序列 + 随机尾）
func genOpsID(prefix string) string {
	opsIDCounter++
	return fmt.Sprintf("%s_%d_%04x", prefix, time.Now().UnixNano(), opsIDCounter&0xffff)
}
