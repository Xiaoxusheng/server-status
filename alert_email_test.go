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
		Message:   "磁盘使用率 高于：当前 88.6%，阈值 85.0%（持续 5 分钟）",
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
	for _, want := range []string{
		"<!DOCTYPE html>", `width="600"`, "server-status", "磁盘空间不足",
		"警告", "88.6%", "85.0%", "磁盘使用率 高于：当前 88.6%", "查看详情", "/alerts",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("正文缺少 %q", want)
		}
	}
	// 警告档使用土黄状态色，且只出现在细线与状态词两处
	if strings.Count(body, "#d08a1e") != 1 || strings.Count(body, "#9a6512") != 1 {
		t.Error("状态色应只用一次（细线 / 状态词）")
	}
	// 朴素通知不该有卡片、按钮、图片、进度条
	for _, unwanted := range []string{"<img", "border-radius", "<button", "background:#f9fafb"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("邮件里不应出现 %q（模板感太重）", unwanted)
		}
	}
	if strings.Contains(body, "http://") {
		t.Error("邮件正文不应引用 http 资源")
	}
}

func TestRenderAlertEmailResolved(t *testing.T) {
	ev := sampleAlertEvent("resolved", "warning", alertMetricMem, 62.4, 90)
	rule := &AlertRule{Metric: alertMetricMem, Op: "gt", Threshold: 90, DurationSec: 300}

	subject, body := renderAlertEmail(ev, rule)

	if !strings.Contains(subject, "已恢复") {
		t.Errorf("恢复邮件主题应含「已恢复」: %q", subject)
	}
	if !strings.Contains(body, "已恢复") || !strings.Contains(body, "#2f9e6f") {
		t.Error("恢复邮件应使用绿色状态色与「已恢复」字样")
	}
}

func TestRenderAlertEmailEscapesAndUnits(t *testing.T) {
	ev := sampleAlertEvent("firing", "critical", alertMetricCert, 9.5, 14)
	ev.RuleName = `证书 <script>alert(1)</script>`
	ev.Message = "SSL 证书剩余天数 低于：当前 9.5 天，阈值 14.0 天。"
	rule := &AlertRule{Metric: alertMetricCert, Op: "lt", Threshold: 14, DurationSec: 0}

	_, body := renderAlertEmail(ev, rule)

	if strings.Contains(body, "<script>") {
		t.Error("规则名未做 HTML 转义，存在注入风险")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("转义后的规则名应保留为可见文本")
	}
	if !strings.Contains(body, "9.5 天") || !strings.Contains(body, "14.0 天") {
		t.Error("证书指标应带「天」单位")
	}
	if !strings.Contains(body, "#c9382c") {
		t.Error("严重级别应使用红色状态色")
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
