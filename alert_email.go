package main

// alert_email.go —— 系统邮件模板（告警中心 + 容器守护共用一套视觉）
//
// 设计约束（邮件客户端不是浏览器）：
//   - 只用 table 布局 + 内联样式，不用 flex/grid，Outlook 桌面版才认；
//   - 不依赖外部图片与 CSS，纯色块 + 文字，避免被拦截导致"空一片"；
//   - 卡片固定 600px（移动端自适应），字号最小 11px，QQ/163/Gmail 均可读；
//   - 顶部隐藏 preheader，收件箱列表里能直接看到关键信息。
//
// 视觉：严重度决定主色（红/橙/蓝），恢复通知整封转绿，一眼能分辨。

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// emailTheme 一封邮件的主色方案
type emailTheme struct {
	Accent string // 主色：色条、数值、进度条
	Soft   string // 徽标背景
	Border string // 徽标边框
	Text   string // 徽标文字（保证对比度）
}

func alertEmailTheme(sev string, resolved bool) emailTheme {
	if resolved {
		return emailTheme{Accent: "#039855", Soft: "#ecfdf3", Border: "#a6f4c5", Text: "#027a48"}
	}
	switch sev {
	case "critical":
		return emailTheme{Accent: "#d92d20", Soft: "#fef3f2", Border: "#fecdca", Text: "#b42318"}
	case "warning":
		return emailTheme{Accent: "#dc6803", Soft: "#fffaeb", Border: "#fedf89", Text: "#b54708"}
	default:
		return emailTheme{Accent: "#1570ef", Soft: "#eff8ff", Border: "#b2ddff", Text: "#175cd3"}
	}
}

// emailStat 指标卡里的一格（最多三格）
type emailStat struct {
	Label string
	Value string
	Color string // 留空则用中性色
}

// emailDoc 一封邮件的结构化内容，由 renderEmailDocument 渲染成 HTML
type emailDoc struct {
	DocTitle string // <title>
	Host     string // 右上角主机标识
	Badge    string // 状态徽标文字
	Theme    emailTheme
	Title    string // 主标题
	Summary  string // 标题下的摘要（也用作 preheader）
	Stats    []emailStat
	Progress int         // 进度条百分比，<0 不画
	Rows     [][2]string // 详情键值对
	CTA      string      // 按钮文案，空则不显示
	CTAHref  string
	Footer   string
}

// panelBaseURL 面板根地址（https://域名:端口），拿不到域名时退回主机名
func panelBaseURL() string {
	host := strings.TrimSpace(tlsDomain)
	if host == "" || host == "localhost" {
		if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
			host = strings.TrimSpace(h)
		}
	}
	if strings.Contains(host, ":") {
		return "https://" + host
	}
	port := listenPort()
	if port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}

// alertPanelURL 告警中心地址，供邮件按钮跳转
func alertPanelURL() string { return panelBaseURL() + "/alerts" }

// humanDurationCN 秒数转中文时长（90 → 1 分 30 秒）
func humanDurationCN(sec int) string {
	if sec <= 0 {
		return "立即"
	}
	if sec < 60 {
		return fmt.Sprintf("%d 秒", sec)
	}
	if sec < 3600 {
		m, s := sec/60, sec%60
		if s == 0 {
			return fmt.Sprintf("%d 分钟", m)
		}
		return fmt.Sprintf("%d 分 %d 秒", m, s)
	}
	h, m := sec/3600, sec%3600/60
	if m == 0 {
		return fmt.Sprintf("%d 小时", h)
	}
	return fmt.Sprintf("%d 小时 %d 分", h, m)
}

// alertProgressPercent 百分比型指标换算进度条宽度；非百分比指标返回 -1（不画条）
func alertProgressPercent(metric string, value float64) int {
	switch metric {
	case alertMetricCPU, alertMetricMem, alertMetricDisk:
		if value < 0 {
			return 0
		}
		if value > 100 {
			return 100
		}
		return int(value + 0.5)
	}
	return -1
}

const emailFont = "-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',Roboto,Helvetica,Arial,sans-serif"

// renderEmailDocument 把结构化内容渲染为整封 HTML 邮件
func renderEmailDocument(d emailDoc) string {
	esc := html.EscapeString
	th := d.Theme

	statCells := ""
	if len(d.Stats) > 0 {
		var cells strings.Builder
		for i, s := range d.Stats {
			border := ""
			if i > 0 {
				border = "border-left:1px solid #eaecf0;"
			}
			color := s.Color
			if color == "" {
				color = "#344054"
			}
			size, lineHeight := "20px", "28px"
			weight := "600"
			if i == 0 {
				size, lineHeight, weight = "26px", "32px", "700"
			}
			fmt.Fprintf(&cells, `
            <td width="33%%" style="padding:16px 18px;%s">
              <div style="font-family:%s;font-size:12px;line-height:18px;color:#667085;">%s</div>
              <div style="margin-top:2px;font-family:%s;font-size:%s;line-height:%s;font-weight:%s;color:%s;">%s</div>
            </td>`, border, emailFont, esc(s.Label), emailFont, size, lineHeight, weight, color, esc(s.Value))
		}
		statCells = fmt.Sprintf(`
      <tr><td style="padding:20px 28px 0;">
        <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:#f9fafb;border:1px solid #eaecf0;border-radius:12px;">
          <tr>%s
          </tr>
        </table>
      </td></tr>`, cells.String())
	}

	barRow := ""
	if d.Progress >= 0 {
		var bar strings.Builder
		pct := d.Progress
		if pct > 100 {
			pct = 100
		}
		fmt.Fprintf(&bar, `
      <tr><td style="padding:10px 28px 2px;">
        <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="height:8px;">
          <tr>
            <td width="%d%%" height="8" style="background:%s;height:8px;border-radius:4px;font-size:0;line-height:0;">&nbsp;</td>
            <td width="%d%%" height="8" style="background:#eaecf0;height:8px;border-radius:4px;font-size:0;line-height:0;">&nbsp;</td>
          </tr>
        </table>
      </td></tr>`, pct, th.Accent, 100-pct)
		barRow = bar.String()
	}

	var rows strings.Builder
	for _, kv := range d.Rows {
		fmt.Fprintf(&rows, `
          <tr>
            <td style="padding:10px 0 0;font-size:13px;line-height:20px;color:#667085;width:96px;">%s</td>
            <td style="padding:10px 0 0;font-size:13px;line-height:20px;color:#101828;">%s</td>
          </tr>`, esc(kv[0]), esc(kv[1]))
	}

	cta := ""
	if d.CTA != "" && d.CTAHref != "" {
		cta = fmt.Sprintf(`
      <tr><td style="padding:22px 28px 4px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr><td style="background:#101828;border-radius:9px;">
            <a href="%s" style="display:inline-block;padding:11px 20px;font-family:%s;font-size:14px;font-weight:600;line-height:20px;color:#ffffff;text-decoration:none;">%s &rarr;</a>
          </td></tr>
        </table>
      </td></tr>`, esc(d.CTAHref), emailFont, esc(d.CTA))
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only">
<title>%s</title>
</head>
<body style="margin:0;padding:0;background:#f2f4f7;-webkit-text-size-adjust:100%%;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">%s</div>
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:#f2f4f7;">
  <tr><td align="center" style="padding:28px 12px;">

    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;background:#ffffff;border:1px solid #eaecf0;border-radius:14px;overflow:hidden;">

      <tr><td height="4" style="height:4px;background:%s;font-size:0;line-height:0;">&nbsp;</td></tr>

      <tr><td style="padding:22px 28px 0;">
        <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td style="font-family:%s;font-size:15px;font-weight:700;color:#101828;letter-spacing:-0.2px;">server-status</td>
            <td align="right" style="font-family:%s;font-size:12px;color:#98a2b3;">%s</td>
          </tr>
        </table>
      </td></tr>

      <tr><td style="padding:18px 28px 0;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr><td style="background:%s;border:1px solid %s;border-radius:999px;padding:4px 11px;font-family:%s;font-size:12px;font-weight:600;line-height:16px;color:%s;">%s</td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:12px 28px 0;">
        <h1 style="margin:0;font-family:%s;font-size:22px;line-height:30px;font-weight:600;color:#101828;">%s</h1>`,
		esc(d.DocTitle), esc(d.Summary),
		th.Accent,
		emailFont, emailFont, esc(d.Host),
		th.Soft, th.Border, emailFont, th.Text, esc(d.Badge),
		emailFont, esc(d.Title))

	if d.Summary != "" {
		fmt.Fprintf(&b, `
        <p style="margin:8px 0 0;font-family:%s;font-size:14px;line-height:22px;color:#475467;">%s</p>`, emailFont, esc(d.Summary))
	}
	b.WriteString(`
      </td></tr>`)
	b.WriteString(statCells)
	b.WriteString(barRow)
	b.WriteString(`
      <tr><td style="padding:18px 28px 0;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`)
	b.WriteString(rows.String())
	b.WriteString(`
        </table>
      </td></tr>`)
	b.WriteString(cta)
	fmt.Fprintf(&b, `
      <tr><td style="padding:18px 28px 0;">
        <div style="height:1px;background:#eaecf0;font-size:0;line-height:0;">&nbsp;</div>
      </td></tr>
      <tr><td style="padding:14px 28px 24px;">
        <p style="margin:0;font-family:%s;font-size:12px;line-height:19px;color:#98a2b3;">%s</p>
      </td></tr>

    </table>

    <div style="margin-top:14px;font-family:%s;font-size:11px;line-height:16px;color:#98a2b3;">server-status %s</div>

  </td></tr>
</table>
</body>
</html>`, emailFont, esc(d.Footer), emailFont, esc(version))

	return b.String()
}

// renderAlertEmail 渲染告警中心的通知邮件，返回 (主题, HTML)
func renderAlertEmail(ev *AlertEvent, rule *AlertRule) (string, string) {
	subject := alertEmailSubject(ev)
	resolved := ev.Status == "resolved"
	th := alertEmailTheme(ev.Severity, resolved)

	host, _ := os.Hostname()
	if host == "" {
		host = "server"
	}

	badge := severityLabel(ev.Severity)
	if resolved {
		badge = "已恢复"
	}

	opText := "高于"
	if rule != nil && rule.Op == "lt" {
		opText = "低于"
	}
	metricName := alertMetricLabels[ev.Metric]
	if metricName == "" {
		metricName = ev.Metric
	}

	durText := "—"
	if rule != nil && rule.DurationSec > 0 {
		durText = humanDurationCN(rule.DurationSec)
	}

	rows := [][2]string{
		{"触发条件", fmt.Sprintf("%s %s %s", metricName, opText, formatAlertValue(ev.Metric, ev.Threshold))},
	}
	if rule != nil && strings.TrimSpace(rule.Target) != "" {
		rows = append(rows, [2]string{"监控对象", rule.Target})
	}
	rows = append(rows,
		[2]string{"主机", host},
		[2]string{"时间", ev.CreatedAt.Format("2006-01-02 15:04:05")},
		[2]string{"规则", ev.RuleName + " · " + severityLabel(ev.Severity)},
	)

	progress := -1
	if !resolved {
		progress = alertProgressPercent(ev.Metric, ev.Value)
	}

	footer := "本邮件由 server-status 告警中心自动发送，请勿直接回复。可在「告警中心 → 设置」调整通知渠道与静默窗口。"
	if resolved {
		footer = "该告警已恢复，无需处理。本邮件由 server-status 告警中心自动发送。"
	}

	htmlBody := renderEmailDocument(emailDoc{
		DocTitle: subject,
		Host:     host,
		Badge:    badge,
		Theme:    th,
		Title:    ev.RuleName,
		Summary:  ev.Message,
		Stats: []emailStat{
			{Label: "当前值", Value: formatAlertValue(ev.Metric, ev.Value), Color: th.Accent},
			{Label: "阈值", Value: formatAlertValue(ev.Metric, ev.Threshold)},
			{Label: "持续时长", Value: durText},
		},
		Progress: progress,
		Rows:     rows,
		CTA:      "打开告警中心",
		CTAHref:  alertPanelURL(),
		Footer:   footer,
	})
	return subject, htmlBody
}

// renderContainerAlertEmail 容器守护的告警邮件，复用同一套视觉
func renderContainerAlertEmail(name, state, status string, maxRestarts int, cooldown time.Duration) (string, string) {
	host, _ := os.Hostname()
	if host == "" {
		host = "server"
	}
	subject := fmt.Sprintf("[严重告警] 容器 %s 反复重启未恢复", name)
	th := alertEmailTheme("critical", false)
	coolText := humanDurationCN(int(cooldown.Seconds()))

	htmlBody := renderEmailDocument(emailDoc{
		DocTitle: subject,
		Host:     host,
		Badge:    "容器异常",
		Theme:    th,
		Title:    fmt.Sprintf("容器 %s 反复重启未能恢复", name),
		Summary: fmt.Sprintf("异常停止后已自动重启 %d 次仍未能拉起，守护已暂停对该容器的自动重启，冷却 %s 后重新接管。",
			maxRestarts, coolText),
		Stats: []emailStat{
			{Label: "重启次数", Value: fmt.Sprintf("%d 次", maxRestarts), Color: th.Accent},
			{Label: "当前状态", Value: state},
			{Label: "冷却时长", Value: coolText},
		},
		Progress: -1,
		Rows: [][2]string{
			{"容器", name},
			{"状态详情", status},
			{"主机", host},
			{"时间", time.Now().Format("2006-01-02 15:04:05")},
		},
		CTA:     "查看容器日志",
		CTAHref: panelBaseURL() + "/docker.html",
		Footer:  "请登录面板查看容器日志并排查根因。本邮件由容器守护自动发送，请勿回复。",
	})
	return subject, htmlBody
}
