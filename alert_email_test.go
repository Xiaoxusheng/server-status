package main

import (
	"strings"
	"testing"
	"time"
)

func sampleAlertEvent(status, severity, metric string, value, threshold float64) *AlertEvent {
	return &AlertEvent{
		RuleName:  "磁盘空间不足",
		Metric:    metric,
		Severity:  severity,
		Status:    status,
		Value:     value,
		Threshold: threshold,
		Message:   "磁盘使用率 高于：当前 88.6%，阈值 85.0%（持续 300 秒）",
		CreatedAt: time.Date(2026, 11, 11, 15, 54, 46, 0, time.Local),
	}
}

func TestRenderAlertEmailFiring(t *testing.T) {
	ev := sampleAlertEvent("firing", "warning", alertMetricDisk, 88.6, 85)
	rule := &AlertRule{Metric: alertMetricDisk, Op: "gt", Threshold: 85, DurationSec: 300}

	subject, body := renderAlertEmail(ev, rule)

	if !strings.Contains(subject, "磁盘空间不足") {
		t.Errorf("主题缺少规则名: %q", subject)
	}
	// 必须是完整的 HTML 邮件，且带 600 宽卡片
	for _, want := range []string{"<!DOCTYPE html>", "width=\"600\"", "磁盘空间不足", "88.6%", "85.0%", "5 分钟", "打开告警中心"} {
		if !strings.Contains(body, want) {
			t.Errorf("正文缺少 %q", want)
		}
	}
	// 触发态应画进度条（88.6 四舍五入 89%）
	if !strings.Contains(body, "width=\"89%\"") {
		t.Error("触发态百分比指标应渲染进度条")
	}
	// 警告色
	if !strings.Contains(body, "#dc6803") {
		t.Error("警告级别应使用橙色主色")
	}
	// 不含外部资源（避免被拦截成空白）
	if strings.Contains(body, "<img") || strings.Contains(body, "http://") {
		t.Error("邮件正文不应依赖外部图片或 http 资源")
	}
}

func TestRenderAlertEmailResolved(t *testing.T) {
	ev := sampleAlertEvent("resolved", "warning", alertMetricMem, 62.4, 90)
	rule := &AlertRule{Metric: alertMetricMem, Op: "gt", Threshold: 90, DurationSec: 300}

	subject, body := renderAlertEmail(ev, rule)

	if !strings.Contains(subject, "已恢复") {
		t.Errorf("恢复邮件主题应含「已恢复」: %q", subject)
	}
	if !strings.Contains(body, "已恢复") || !strings.Contains(body, "#039855") {
		t.Error("恢复邮件应使用绿色主题与「已恢复」徽标")
	}
	// 恢复通知不画进度条，避免被误读成指标仍处高位
	if strings.Contains(body, "border-radius:4px;font-size:0") {
		t.Error("恢复邮件不应渲染进度条")
	}
}

func TestRenderAlertEmailEscapesAndNonPercent(t *testing.T) {
	ev := sampleAlertEvent("firing", "critical", alertMetricCert, 9.5, 14)
	ev.RuleName = `证书 <script>alert(1)</script>`
	ev.Message = "证书剩余 9.5 天"
	rule := &AlertRule{Metric: alertMetricCert, Op: "lt", Threshold: 14, DurationSec: 0}

	_, body := renderAlertEmail(ev, rule)

	if strings.Contains(body, "<script>") {
		t.Error("规则名未做 HTML 转义，存在注入风险")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("转义后的规则名应保留为可见文本")
	}
	// 非百分比指标不画进度条，且单位是"天"
	if strings.Contains(body, "border-radius:4px;font-size:0") {
		t.Error("证书天数指标不应渲染百分比进度条")
	}
	if !strings.Contains(body, "9.5 天") || !strings.Contains(body, "14.0 天") {
		t.Error("证书指标应带「天」单位")
	}
	// 严重级别用红色
	if !strings.Contains(body, "#d92d20") {
		t.Error("严重级别应使用红色主色")
	}
}

func TestHumanDurationCN(t *testing.T) {
	cases := map[int]string{
		0: "立即", 30: "30 秒", 60: "1 分钟", 90: "1 分 30 秒",
		3600: "1 小时", 3900: "1 小时 5 分", 86400: "24 小时",
	}
	for in, want := range cases {
		if got := humanDurationCN(in); got != want {
			t.Errorf("humanDurationCN(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestAlertPanelURL(t *testing.T) {
	u := alertPanelURL()
	if !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, "/alerts") {
		t.Errorf("面板地址不合法: %q", u)
	}
}
