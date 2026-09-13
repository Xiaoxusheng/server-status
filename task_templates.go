package main

// ==================== 任务模板 ====================
//
// 模板只是配置预设，不直接执行；用户「使用模板 → 填参数 → 创建任务」。

import "path/filepath"

// TaskTemplate 任务模板（参数字段来自 Action Registry 的 ParamSpec，前端动态渲染）
type TaskTemplate struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Type        string         `json:"type"`
	Schedule    string         `json:"schedule,omitempty"`
	IntervalSec int            `json:"interval_seconds,omitempty"`
	Trigger     *TaskTrigger   `json:"trigger,omitempty"`
	ActionID    string         `json:"action_id"`
	Parameters  map[string]any `json:"parameters"`
	TimeoutSec  int            `json:"timeout_seconds"`
	MaxAttempts int            `json:"max_attempts"`
}

// taskTemplates 预置模板清单
// 说明：备份由 /etc/cron.d/pv-backup（云备份页）负责执行，属于「任务 ≠ Shell」边界外的既有机制，
// 这里不提供会执行任意脚本的备份模板。
func taskTemplates() []TaskTemplate {
	serverLog := filepath.Join(dataRoot(), "log", "server.log")
	return []TaskTemplate{
		{
			ID: "tpl_daily_scan", Name: "每日安全扫描",
			Description: "每天凌晨异步执行一次全量安全扫描（含登录安全、端口、防火墙、TLS、文件权限、服务、Docker 检查）",
			Type:        "cron", Schedule: "30 5 * * *", ActionID: "security_scan",
			Parameters: map[string]any{}, TimeoutSec: 600, MaxAttempts: 1,
		},
		{
			ID: "tpl_weekly_check", Name: "每周系统检查",
			Description: "每周一凌晨执行一次全量安全扫描并输出评分趋势",
			Type:        "cron", Schedule: "0 4 * * 1", ActionID: "security_scan",
			Parameters: map[string]any{}, TimeoutSec: 600, MaxAttempts: 1,
		},
		{
			ID: "tpl_ssl_check", Name: "SSL 证书检查",
			Description: "每日检查 TLS 证书有效期 / 域名匹配（作为安全扫描的一部分高频关注证书项）",
			Type:        "cron", Schedule: "0 9 * * *", ActionID: "security_scan",
			Parameters: map[string]any{}, TimeoutSec: 600, MaxAttempts: 1,
		},
		{
			ID: "tpl_service_health", Name: "服务健康检查",
			Description: "定时核查监控清单与托管服务运行状态，异常停止时联动修复策略",
			Type:        "cron", Schedule: "0 */6 * * *", ActionID: "security_scan",
			Parameters: map[string]any{}, TimeoutSec: 600, MaxAttempts: 1,
		},
		{
			ID: "tpl_docker_health", Name: "Docker 健康检查",
			Description: "定时核查容器状态与安全配置（特权 / host 网络 / socket 挂载 / 异常退出）",
			Type:        "cron", Schedule: "0 6 * * *", ActionID: "security_scan",
			Parameters: map[string]any{}, TimeoutSec: 600, MaxAttempts: 1,
		},
		{
			ID: "tpl_log_rotate", Name: "日志轮转",
			Description: "对运行日志执行 copytruncate 轮转（超过指定体积才执行，保留最近 3 份 gzip 归档）",
			Type: "cron", Schedule: "0 4 * * *", ActionID: "rotate_log",
			Parameters: map[string]any{"path": serverLog, "size_mb": 20},
			TimeoutSec: 120, MaxAttempts: 2,
		},
		{
			ID: "tpl_temp_cleanup", Name: "临时文件清理",
			Description: "每周清理数据目录 tmp/ 内超过 7 天的临时文件（仅白名单目录，人工确认执行）",
			Type: "cron", Schedule: "0 3 * * 6", ActionID: "cleanup_temp",
			Parameters: map[string]any{"max_age_hours": 168},
			TimeoutSec: 300, MaxAttempts: 1,
		},
		{
			ID: "tpl_service_event", Name: "服务停止自动拉起",
			Description: "监控的服务停止时触发启动动作（请填写具体服务名，服务须在允许操作清单内）",
			Type: "event", Trigger: &TaskTrigger{Type: "service_stopped", CooldownSec: 900},
			ActionID: "start_service", Parameters: map[string]any{"service": "nginx"},
			TimeoutSec: 120, MaxAttempts: 2,
		},
		{
			ID: "tpl_docker_event", Name: "容器异常退出自动重启",
			Description: "容器异常退出（非 0 退出码）时自动重启（请填写容器名；动作默认需人工确认，可在自动修复页调整）",
			Type: "event", Trigger: &TaskTrigger{Type: "docker_container_exit", CooldownSec: 900},
			ActionID: "docker_restart", Parameters: map[string]any{"container": "my-container"},
			TimeoutSec: 180, MaxAttempts: 2,
		},
	}
}
