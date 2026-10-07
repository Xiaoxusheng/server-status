// docker_guard.go -- Docker 容器守护：异常停止自动重启 + 超限邮件告警
//
// 工作方式（后台轮询，无需 docker events 依赖）：
//   1. 每 check_interval 秒执行 `docker ps -a` 快照全部容器状态；
//   2. 服务启动时已处于停止状态的容器记入基线（视为用户有意停止），永不干预；
//   3. 运行中容器出现异常停止（退出码非 0/143 的 exited、dead 状态）时执行 `docker start` 自动拉起；
//   4. 滑动窗口内自动重启达到 max_restarts 仍异常 → 发送告警邮件并暂停重启，冷却期满后清零重新守护；
//   5. 正常退出（退出码 0/143，即手动 stop/优雅停止）只记入基线，不重启不告警。
//
// 配置：config.json 的 "docker_guard" 段（SMTP 凭据等敏感值不入库日志，失败仅记录错误摘要）。
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dockerGuardFileConfig 对应 config.json 中 "docker_guard" 段（Enabled 用指针区分「未配置」与「配置为 false」）
type dockerGuardFileConfig struct {
	Enabled        *bool             `json:"enabled"`          // 是否启用守护（默认 false，需显式开启）
	CheckInterval  int               `json:"check_interval"`   // 状态检查间隔（秒），默认 30
	MaxRestarts    int               `json:"max_restarts"`     // 窗口内最大自动重启次数，超过则告警并暂停，默认 3
	WindowMinutes  int               `json:"window_minutes"`   // 重启计数滑动窗口（分钟），默认 60
	CooldownMin    int               `json:"cooldown_minutes"` // 告警邮件冷却（分钟），默认 30
	Exclude        []string          `json:"exclude"`          // 排除的容器名（精确匹配，不守护不告警）
	ExcludePatterns []string         `json:"exclude_patterns"` // 排除的容器名模式（glob，如 "temp-*"）
	AlertEmail     *alertEmailConfig `json:"alert_email"`      // 告警邮箱 SMTP 配置
}

// alertEmailConfig 告警邮件 SMTP 配置（凭据仅用于发送，不打日志）
type alertEmailConfig struct {
	Host     string   `json:"host"`     // SMTP 服务器，如 smtp.qq.com
	Port     int      `json:"port"`     // 端口：465=隐式 TLS，587=STARTTLS，25=明文（内网 relay）
	Username string   `json:"username"` // 认证用户名（通常为发件邮箱）
	Password string   `json:"password"` // 认证密码/授权码
	From     string   `json:"from"`     // 发件人（为空时取 Username）
	To       []string `json:"to"`       // 收件人列表
}

// dockerGuardFileWrapper 仅解析 config.json 的 "docker_guard" 段
type dockerGuardFileWrapper struct {
	Guard *dockerGuardFileConfig `json:"docker_guard"`
}

// dockerGuardConfig 运行时配置（默认值 + config.json 合并结果）
type dockerGuardConfig struct {
	Enabled       bool
	CheckInterval time.Duration
	MaxRestarts   int
	Window        time.Duration
	Cooldown      time.Duration
	Exclude       map[string]bool
	ExcludePats   []string
	AlertEmail    *alertEmailConfig
}

// loadDockerGuardConfig 从 config.json "docker_guard" 段加载守护配置（默认值兜底）
func loadDockerGuardConfig() dockerGuardConfig {
	cfg := dockerGuardConfig{
		Enabled:       false,
		CheckInterval: 30 * time.Second,
		MaxRestarts:   3,
		Window:        60 * time.Minute,
		Cooldown:      30 * time.Minute,
		Exclude:       map[string]bool{},
	}
	data, err := os.ReadFile(filepath.Join(privateRoot(), "config.json"))
	if err != nil {
		return cfg
	}
	var fileCfg dockerGuardFileWrapper
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		log.Printf("⚠️ config.json 解析失败，容器守护使用默认配置: %v", err)
		return cfg
	}
	g := fileCfg.Guard
	if g == nil {
		return cfg
	}
	if g.Enabled != nil {
		cfg.Enabled = *g.Enabled
	}
	if g.CheckInterval > 0 {
		cfg.CheckInterval = time.Duration(g.CheckInterval) * time.Second
	}
	if g.MaxRestarts > 0 {
		cfg.MaxRestarts = g.MaxRestarts
	}
	if g.WindowMinutes > 0 {
		cfg.Window = time.Duration(g.WindowMinutes) * time.Minute
	}
	if g.CooldownMin > 0 {
		cfg.Cooldown = time.Duration(g.CooldownMin) * time.Minute
	}
	for _, name := range g.Exclude {
		if name = strings.TrimSpace(name); name != "" {
			cfg.Exclude[name] = true
		}
	}
	for _, pat := range g.ExcludePatterns {
		if pat = strings.TrimSpace(pat); pat != "" {
			cfg.ExcludePats = append(cfg.ExcludePats, pat)
		}
	}
	if g.AlertEmail != nil && len(g.AlertEmail.To) > 0 && g.AlertEmail.Host != "" {
		if g.AlertEmail.Port <= 0 {
			g.AlertEmail.Port = 465
		}
		if g.AlertEmail.From == "" {
			g.AlertEmail.From = g.AlertEmail.Username
		}
		cfg.AlertEmail = g.AlertEmail
	}
	return cfg
}

// isExcludedContainer 判断容器是否被排除规则命中（精确名或 glob 模式）
func (c *dockerGuardConfig) isExcludedContainer(name string) bool {
	if c.Exclude[name] {
		return true
	}
	for _, pat := range c.ExcludePats {
		if matched, err := filepath.Match(pat, name); err == nil && matched {
			return true
		}
	}
	return false
}

// containerGuardState 单个容器的守护状态（重启计数 + 告警冷却）
type containerGuardState struct {
	restarts  []time.Time // 窗口内的自动重启时间戳
	lastAlert time.Time   // 上次告警邮件发送时间（冷却判定）
}

// dockerGuard 容器守护器（持全局状态，单 goroutine 串行访问，字段加锁仅为测试并发安全）
type dockerGuard struct {
	mu      sync.Mutex
	cfg     dockerGuardConfig
	states  map[string]*containerGuardState // 容器名 -> 守护状态
	baseline map[string]bool                // 启动时已停止/守护期间正常停止的容器（不干预）
}

// 全局守护器（dockerGuardLoop 启动时加载配置，dockerActionHandler 手动操作后可联动）
var containerGuard = &dockerGuard{
	states:   map[string]*containerGuardState{},
	baseline: map[string]bool{},
}

// dockerGuardLoop 守护主循环：加载配置并首轮建立基线后按配置间隔轮询（在 main 中以 goroutine 启动）
// Docker daemon 不可用时空转等待，恢复后自动继续守护。
func dockerGuardLoop() {
	g := containerGuard
	g.cfg = loadDockerGuardConfig()
	if !g.cfg.Enabled {
		log.Println("容器守护未启用（config.json docker_guard.enabled=false），跳过")
		return
	}
	log.Printf("🐕 容器守护已启动: 检查间隔=%s 窗口内最大重启=%d 告警冷却=%s",
		g.cfg.CheckInterval, g.cfg.MaxRestarts, g.cfg.Cooldown)

	// 首轮扫描建立基线：启动时已停止的容器视为用户有意停止，不自动拉起
	g.scanOnce(true)

	ticker := time.NewTicker(g.cfg.CheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		g.scanOnce(false)
	}
}

// scanOnce 执行一轮容器状态扫描；first=true 时仅记录基线不做任何干预
func (g *dockerGuard) scanOnce(first bool) {
	type item struct {
		name   string
		state  string
		status string
	}
	var items []item
	for _, line := range g.dockerPsLines() {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		items = append(items, item{name: parts[0], state: parts[1], status: parts[2]})
	}
	if items == nil {
		// docker 命令失败（daemon 未运行/未安装）：仅首轮打日志，避免每 30 秒刷屏
		if first {
			log.Println("⚠️ 容器守护：docker ps 不可用，等待 daemon 恢复后继续")
		}
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for _, it := range items {
		if g.cfg.isExcludedContainer(it.name) {
			continue
		}
		// 运行中：清理窗口外的重启计数（稳定运行超过窗口即视为彻底恢复）
		if it.state == "running" {
			if st := g.states[it.name]; st != nil {
				st.restarts = pruneRestarts(st.restarts, now, g.cfg.Window)
			}
			continue
		}
		// 非运行状态：基线内（启动即停止/正常停止）不干预
		if g.baseline[it.name] {
			continue
		}
		// 正常退出（手动 stop 的 0/143 等）：记入基线，之后不再打扰
		if it.state == "exited" && isNormalExitStatus(it.status) {
			g.baseline[it.name] = true
			log.Printf("容器 %s 正常停止（%s），已记入基线不再自动拉起", it.name, it.status)
			continue
		}
		// 异常停止（退出码非 0/143 的 exited、dead 等）：首轮不干预（只记基线），后续轮自动重启
		if first {
			g.baseline[it.name] = true
			log.Printf("容器守护基线: %s 启动时即为 %s 状态，不自动拉起", it.name, it.state)
			continue
		}
		g.handleAbnormalLocked(it.name, it.state, it.status, now)
	}
}

// handleAbnormalLocked 处理异常停止的容器：窗口内未超限则自动重启，超限则告警并暂停（调用方需持 g.mu）
func (g *dockerGuard) handleAbnormalLocked(name, state, status string, now time.Time) {
	st := g.states[name]
	if st == nil {
		st = &containerGuardState{}
		g.states[name] = st
	}
	st.restarts = pruneRestarts(st.restarts, now, g.cfg.Window)

	// 窗口内重启次数已达上限：告警 + 暂停重启；冷却期满则清零重新开始新一轮守护
	if len(st.restarts) >= g.cfg.MaxRestarts {
		if now.Sub(st.lastAlert) >= g.cfg.Cooldown {
			st.lastAlert = now
			st.restarts = st.restarts[:0] // 清零，冷却期满后重新开始一轮守护
			log.Printf("🚨 容器 %s 异常（%s / %s）: 自动重启 %d 次仍失败，已发送告警并暂停重启", name, state, status, g.cfg.MaxRestarts)
			g.sendAlert(name, state, status)
		}
		return
	}

	// 未超限：自动重启拉起
	if err := g.startContainer(name); err != nil {
		log.Printf("⚠️ 容器 %s 自动重启失败: %v", name, err)
		return // 失败不计入次数，下一轮继续尝试重启
	}
	st.restarts = append(st.restarts, now)
	log.Printf("容器 %s 异常停止（%s / %s），已自动重启（窗口内第 %d/%d 次）", name, state, status, len(st.restarts), g.cfg.MaxRestarts)
	invalidateDockerCaches() // 让面板立刻反映最新状态
}

// startContainer 执行 docker start 拉起容器
func (g *dockerGuard) startContainer(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "start", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// dockerPsLines 执行 docker ps -a 并按行返回 "名称|状态|原始状态文本"，失败返回 nil
func (g *dockerGuard) dockerPsLines() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--no-trunc",
		"--format", "{{.Names}}|{{.State}}|{{.Status}}").Output()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// exitCodeStatusRe 从 docker 状态文本中提取退出码，如 "Exited (137) 2 minutes ago" -> 137
var exitCodeStatusRe = regexp.MustCompile(`Exited \((\d+)\)`)

// isNormalExitStatus 判断容器是否为正常停止：手动 stop（SIGTERM→143）与进程自身优雅退出（0）
func isNormalExitStatus(status string) bool {
	m := exitCodeStatusRe.FindStringSubmatch(status)
	if m == nil {
		return false
	}
	code, err := strconv.Atoi(m[1])
	if err != nil {
		return false
	}
	return code == 0 || code == 143
}

// pruneRestarts 清理滑动窗口之外的重启时间戳
func pruneRestarts(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	return kept
}

// sendAlert 发送容器异常告警邮件（SMTP 未配置时仅打日志提示）
func (g *dockerGuard) sendAlert(name, state, status string) {
	mail := g.cfg.AlertEmail
	if mail == nil {
		log.Printf("⚠️ 容器 %s 达到重启上限但未配置告警邮箱（docker_guard.alert_email），仅记录日志", name)
		return
	}
	host, _ := os.Hostname()
	subject := fmt.Sprintf("【server-status】容器异常告警: %s 自动重启 %d 次失败", name, g.cfg.MaxRestarts)
	body := fmt.Sprintf(`<div style="font-family:-apple-system,'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
<div style="background:#dc2626;color:#fff;padding:14px 20px;font-size:16px;font-weight:600">🚨 Docker 容器异常告警</div>
<div style="padding:20px;color:#374151;font-size:14px;line-height:1.8">
<p>容器 <b style="color:#111">%s</b> 异常停止后已自动重启 <b>%d</b> 次仍未能恢复运行，守护进程已暂停对该容器的自动重启（冷却 %s 后将重新开始守护）。</p>
<table style="border-collapse:collapse;margin:12px 0">
<tr><td style="padding:4px 16px 4px 0;color:#6b7280">主机</td><td>%s</td></tr>
<tr><td style="padding:4px 16px 4px 0;color:#6b7280">容器</td><td>%s</td></tr>
<tr><td style="padding:4px 16px 4px 0;color:#6b7280">当前状态</td><td>%s</td></tr>
<tr><td style="padding:4px 16px 4px 0;color:#6b7280">状态详情</td><td>%s</td></tr>
<tr><td style="padding:4px 16px 4px 0;color:#6b7280">检测时间</td><td>%s</td></tr>
</table>
<p style="color:#9ca3af;font-size:12px">请登录 server-status 面板查看容器日志并排查根因。本邮件由容器守护自动发送，请勿回复。</p>
</div></div>`, name, g.cfg.MaxRestarts, g.cfg.Cooldown, host, name, state, status, time.Now().Format("2006-01-02 15:04:05"))

	if err := sendAlertEmail(mail, subject, body); err != nil {
		log.Printf("⚠️ 容器 %s 告警邮件发送失败: %v", name, err)
		return
	}
	log.Printf("📧 容器 %s 告警邮件已发送至 %s", name, strings.Join(mail.To, ","))
}

// sendAlertEmail 通过 SMTP 发送告警邮件：465 走隐式 TLS，587/25 走 STARTTLS（服务器支持时）或明文
func sendAlertEmail(mail *alertEmailConfig, subject, htmlBody string) error {
	if mail.Host == "" || len(mail.To) == 0 {
		return fmt.Errorf("SMTP 配置不完整")
	}
	addr := net.JoinHostPort(mail.Host, strconv.Itoa(mail.Port))
	timeout := 15 * time.Second

	var conn net.Conn
	var err error
	if mail.Port == 465 {
		// 隐式 TLS（绝大多数邮箱服务商的标准安全端口）
		d := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: mail.Host})
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return fmt.Errorf("连接 %s 失败: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, mail.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer client.Close()

	// 587 等端口：若服务器宣告 STARTTLS 则升级加密
	if ok, _ := client.Extension("STARTTLS"); ok && mail.Port != 465 {
		if err := client.StartTLS(&tls.Config{ServerName: mail.Host}); err != nil {
			return fmt.Errorf("STARTTLS 升级失败: %w", err)
		}
	}

	// 服务器要求认证时使用 PLAIN 认证（QQ/163/企业邮箱均支持）
	if ok, mechs := client.Extension("AUTH"); ok {
		if strings.Contains(mechs, "PLAIN") {
			auth := smtp.PlainAuth("", mail.Username, mail.Password, mail.Host)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP 认证失败: %w", err)
			}
		}
	}

	if err := client.Mail(mail.From); err != nil {
		return fmt.Errorf("设置发件人失败: %w", err)
	}
	for _, to := range mail.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("设置收件人 %s 失败: %w", to, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("打开数据通道失败: %w", err)
	}
	// 邮件头：主题按 RFC 2047 Q 编码支持中文；HTML 正文 UTF-8
	msg := strings.Join([]string{
		"From: " + mail.From,
		"To: " + strings.Join(mail.To, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"X-Mailer: server-status docker-guard",
		"",
		htmlBody,
	}, "\r\n")
	if _, err := writer.Write([]byte(msg)); err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("发送邮件失败: %w", err)
	}
	return client.Quit()
}
