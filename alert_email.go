package main

// alert_email.go —— 系统邮件模板（告警中心 + 容器守护共用）
//
// 风格取向：像"监控系统自己发的通知"，不像营销邮件。
//   - 不做彩色卡片、徽标胶囊、大号数字块、行动按钮——那些一眼就是模板；
//   - 白底 + 一条 3px 状态色线 + 紧凑的键值行，信息密度接近 SSH 告警 / cron 通知；
//   - 颜色只用在两处：顶部细线和状态词，其余全是灰度；
//   - 只用 table 布局 + 内联样式（Outlook 桌面版才认），不引用外部图片/CSS。

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// emailTheme 状态色（只用于顶部细线与状态词）
type emailTheme struct {
	Line string
	Word string
}

func alertEmailTheme(sev string, resolved bool) emailTheme {
	if resolved {
		return emailTheme{Line: "#2f9e6f", Word: "#1f7a55"}
	}
	switch sev {
	case "critical":
		return emailTheme{Line: "#c9382c", Word: "#a92e24"}
	case "warning":
		return emailTheme{Line: "#d08a1e", Word: "#9a6512"}
	default:
		return emailTheme{Line: "#3b7dd8", Word: "#2a5fa8"}
	}
}

// emailDoc 一封邮件的内容，由 renderEmailDocument 渲染
type emailDoc struct {
	DocTitle string // <title>，同时用作 preheader
	Host     string
	Status   string // 状态词：警告 / 严重告警 / 已恢复 / 容器异常
	Theme    emailTheme
	Title    string // 主标题（规则名 / 容器名）
	Summary  string // 一句话说明
	Rows     [][2]string
	LinkHref string
	Footer   string
}

// emailHostName 邮件里展示的主机标识：优先域名，其次主机名
func emailHostName() string {
	if d := strings.TrimSpace(tlsDomain); d != "" && d != "localhost" {
		return d
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	return "server"
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

// alertPanelURL 告警中心地址
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

const (
	emailFont  = "-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',Roboto,Helvetica,Arial,sans-serif"
	emailInk   = "#1f2328" // 主文字
	emailBody  = "#4a5058" // 正文
	emailMuted = "#8a8f98" // 标签与页脚
	emailRule  = "#e8eaed" // 分隔线
	emailLink  = "#0b62d6"
)

// renderEmailDocument 渲染整封 HTML
func renderEmailDocument(d emailDoc) string {
	esc := html.EscapeString
	host := d.Host
	if host == "" {
		host = "server"
	}

	var rows strings.Builder
	for _, kv := range d.Rows {
		fmt.Fprintf(&rows, `
        <tr>
          <td width="88" style="width:88px;padding:7px 12px 0 0;font-family:%s;font-size:13px;line-height:21px;color:%s;vertical-align:top;">%s</td>
          <td style="padding:7px 0 0;font-family:%s;font-size:13px;line-height:21px;color:%s;">%s</td>
        </tr>`, emailFont, emailMuted, esc(kv[0]), emailFont, emailInk, esc(kv[1]))
	}

	linkRow := ""
	if strings.TrimSpace(d.LinkHref) != "" {
		var lb strings.Builder
		fmt.Fprintf(&lb, `
    <tr><td style="padding:16px 0 0;border-top:1px solid %s;font-family:%s;font-size:13px;line-height:21px;color:%s;">
      查看详情：<a href="%s" style="color:%s;text-decoration:none;">%s</a>
    </td></tr>`, emailRule, emailFont, emailBody, esc(d.LinkHref), emailLink, esc(d.LinkHref))
		linkRow = lb.String()
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
<body style="margin:0;padding:0;background:#ffffff;-webkit-text-size-adjust:100%%;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">%s</div>
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;">
  <tr><td align="center" style="padding:24px 16px 36px;">
    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;">

      <tr><td style="padding:0 0 0 0;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr><td height="3" width="40" style="height:3px;width:40px;background:%s;font-size:0;line-height:0;">&nbsp;</td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:16px 0 0;font-family:%s;font-size:12px;line-height:18px;color:%s;">server-status</td></tr>

      <tr><td style="padding:6px 0 0;font-family:%s;font-size:18px;line-height:27px;font-weight:600;color:%s;">
        <span style="color:%s;">%s</span> · %s
      </td></tr>

      <tr><td style="padding:8px 0 0;font-family:%s;font-size:14px;line-height:23px;color:%s;">%s</td></tr>

      <tr><td style="padding:14px 0 0;">
        <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="border-top:1px solid %s;">%s
        </table>
      </td></tr>`,
		esc(d.DocTitle), esc(d.Summary),
		d.Theme.Line,
		emailFont, emailMuted,
		emailFont, emailInk, d.Theme.Word, esc(d.Status), esc(d.Title),
		emailFont, emailBody, esc(d.Summary),
		emailRule, rows.String())

	b.WriteString(linkRow)

	fmt.Fprintf(&b, `
    <tr><td style="padding:14px 0 0;font-family:%s;font-size:12px;line-height:19px;color:%s;">%s</td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>`, emailFont, emailMuted, esc(d.Footer))

	return b.String()
}

// renderAlertEmail 告警中心的通知邮件，返回 (主题, HTML)
func renderAlertEmail(ev *AlertEvent, rule *AlertRule) (string, string) {
	subject := alertEmailSubject(ev)
	resolved := ev.Status == "resolved"
	th := alertEmailTheme(ev.Severity, resolved)

	host := emailHostName()

	status := severityLabel(ev.Severity)
	if resolved {
		status = "已恢复"
	}

	rows := [][2]string{}
	if rule != nil && strings.TrimSpace(rule.Target) != "" {
		rows = append(rows, [2]string{"监控对象", rule.Target})
	}
	// 触发条件已写在摘要里（自然语言），这里不再重复一行
	rows = append(rows,
		[2]string{"主机", host},
		[2]string{"时间", ev.CreatedAt.Format("2006-01-02 15:04:05")},
	)

	footer := "本邮件由 server-status 告警中心自动发送，请勿回复。可在「告警中心 → 设置」调整规则与静默窗口。"
	if resolved {
		footer = "该告警已恢复，无需处理。本邮件由 server-status 告警中心自动发送。"
	}

	htmlBody := renderEmailDocument(emailDoc{
		DocTitle: subject,
		Host:     host,
		Status:   status,
		Theme:    th,
		Title:    ev.RuleName,
		Summary:  ev.Message,
		Rows:     rows,
		LinkHref: alertPanelURL(),
		Footer:   footer,
	})
	return subject, htmlBody
}

// renderContainerAlertEmail 容器守护的告警邮件，同一套排版
func renderContainerAlertEmail(name, state, status string, maxRestarts int, cooldown time.Duration) (string, string) {
	host := emailHostName()
	subject := fmt.Sprintf("[严重告警] 容器 %s 反复重启未恢复", name)
	coolText := humanDurationCN(int(cooldown.Seconds()))

	htmlBody := renderEmailDocument(emailDoc{
		DocTitle: subject,
		Host:     host,
		Status:   "容器异常",
		Theme:    alertEmailTheme("critical", false),
		Title:    name,
		Summary: fmt.Sprintf("异常停止后已自动重启 %d 次仍未能拉起，守护已暂停自动重启，%s后重新接管。",
			maxRestarts, coolText),
		Rows: [][2]string{
			{"容器", name},
			{"当前状态", state},
			{"状态详情", status},
			{"主机", host},
			{"时间", time.Now().Format("2006-01-02 15:04:05")},
		},
		LinkHref: panelBaseURL() + "/docker.html",
		Footer:   "请登录面板查看容器日志并排查根因。本邮件由容器守护自动发送，请勿回复。",
	})
	return subject, htmlBody
}
