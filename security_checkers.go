package main

// ==================== 安全检查器实现 ====================
//
// 全部为只读检测：发现问题 → 产出 Finding（含修复上下文）→ 由安全中心合并。
// 检查器绝不直接修改系统状态；修复必须走 Remediation 白名单动作。

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultSecurityCheckers 内置检查器清单（注册顺序即扫描顺序）
func defaultSecurityCheckers() []SecurityChecker {
	return []SecurityChecker{
		&loginSecurityChecker{},
		&openPortsChecker{},
		&firewallChecker{},
		&tlsCertChecker{},
		&filePermChecker{},
		&serviceHealthChecker{},
		&dockerSecurityChecker{},
	}
}

func mkFinding(checkID, dedupeKey, severity, title, desc, evidence, recommendation string, ctx map[string]any) SecurityFinding {
	return SecurityFinding{
		CheckID: checkID, DedupeKey: dedupeKey, Severity: severity,
		Title: title, Description: desc, Evidence: evidence, Recommendation: recommendation,
		Context: ctx,
	}
}

// ==================== 1. 登录安全 ====================

type loginSecurityChecker struct{}

func (c *loginSecurityChecker) ID() string          { return "login_security" }
func (c *loginSecurityChecker) Name() string        { return "登录安全" }
func (c *loginSecurityChecker) Category() string    { return "账户安全" }
func (c *loginSecurityChecker) Description() string { return "暴力破解尝试、失败登录统计、管理员数量与长期未使用账户检查" }

func (c *loginSecurityChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}}

	// --- 失败登录统计（读取现有审计日志，不重复造数据源）---
	failed := parseRecentFailedLogins(24 * time.Hour)
	totalFailed := 0
	perIP := map[string]int{}
	for ip, n := range failed.byIP {
		totalFailed += n
		perIP[ip] = n
	}
	detail := map[string]any{"failed_logins_24h": totalFailed}
	if totalFailed >= 100 {
		result.Status = "fail"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "bruteforce:burst", "high",
			"存在疑似暴力破解行为",
			fmt.Sprintf("过去 24 小时内共记录 %d 次登录失败，频次显著异常，服务器可能正在遭受暴力破解。", totalFailed),
			failedEvidence(failed.recent, 8),
			"为来源 IP 配置自动封禁规则（自动修复 → block_ip），并确认 SSH 已禁用密码登录。", nil))
	} else if totalFailed >= 20 {
		result.Status = "warn"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "bruteforce:burst", "medium",
			"登录失败次数偏多",
			fmt.Sprintf("过去 24 小时内共记录 %d 次登录失败，建议关注来源分布。", totalFailed),
			failedEvidence(failed.recent, 8),
			"若来源集中，可为该 IP 配置自动封禁策略；同时确认所有账户使用强密码。", nil))
	}
	// 单一 IP 高频失败 → 产出可自动封禁的风险（Context 带 IP，供 block_ip 规则使用）
	type ipCount struct {
		ip string
		n  int
	}
	var top []ipCount
	for ip, n := range perIP {
		top = append(top, ipCount{ip, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	for _, t := range top {
		if t.n >= 50 {
			result.Status = "fail"
			result.Findings = append(result.Findings, mkFinding(c.ID(), "bruteforce:"+t.ip, "high",
				fmt.Sprintf("IP %s 疑似暴力破解（%d 次失败）", t.ip, t.n),
				fmt.Sprintf("该 IP 过去 24 小时内产生 %d 次登录失败，远超正常用户行为。", t.n),
				failedEvidence(failed.recent, 5),
				"使用自动修复「封禁 IP」动作封禁该地址（默认 24h 自动到期）。", map[string]any{"ip": t.ip}))
			break // 只报最严重的一个
		}
	}
	detail["top_failed_ip"] = perIP

	// --- 管理员账户数量 ---
	adminCount, activeCount, unusedUsers, emptyPwUsers := auditUserAccounts()
	detail["admin_accounts"] = adminCount
	detail["active_accounts"] = activeCount
	if adminCount > 2 {
		if result.Status == "pass" {
			result.Status = "warn"
		}
		result.Findings = append(result.Findings, mkFinding(c.ID(), "admin:count", "low",
			fmt.Sprintf("管理员账户数量偏多（%d 个）", adminCount),
			"拥有超级管理员角色的账户超过 2 个，权限过度集中会放大单账户泄露的影响面。",
			fmt.Sprintf("管理员账户 %d 个 / 活跃账户 %d 个", adminCount, activeCount),
			"按最小权限原则收敛管理员数量，日常运维使用 operator 角色。", nil))
	}

	// --- 长期未使用账户 ---
	if len(unusedUsers) > 0 {
		if result.Status == "pass" {
			result.Status = "warn"
		}
		result.Findings = append(result.Findings, mkFinding(c.ID(), "account:unused", "low",
			fmt.Sprintf("存在 %d 个长期未使用的账户", len(unusedUsers)),
			"超过 90 天未登录的账户若已无人使用，属于闲置攻击面。",
			"账户: "+strings.Join(unusedUsers, ", "),
			"确认后停用或删除这些账户（用户管理页）。", nil))
	}

	// --- 弱密码风险：空密码账户 ---
	if len(emptyPwUsers) > 0 {
		result.Status = "fail"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "account:emptypw", "high",
			fmt.Sprintf("存在 %d 个无密码/异常密码状态账户", len(emptyPwUsers)),
			"这些账户缺少有效的密码散列，任何知道用户名的人都可能直接登录。",
			"账户: "+strings.Join(emptyPwUsers, ", "),
			"立即为这些账户设置强密码或禁用账户。", nil))
	}

	result.Detail = detail
	result.Summary = fmt.Sprintf("24h 失败登录 %d 次，管理员 %d 个，活跃账户 %d 个", totalFailed, adminCount, activeCount)
	return result
}

type failedLoginStats struct {
	byIP   map[string]int
	recent []string
}

// parseRecentFailedLogins 从审计日志（JSONL）统计近期的登录失败（action=auth.login.failed）
func parseRecentFailedLogins(window time.Duration) failedLoginStats {
	out := failedLoginStats{byIP: map[string]int{}}
	data, err := os.ReadFile(auditLogFile)
	if err != nil {
		return out
	}
	cutoff := time.Now().Add(-window)
	// 审计文件按时间追加，只扫描尾部 2000 行即可覆盖窗口
	lines := strings.Split(string(data), "\n")
	if len(lines) > 2000 {
		lines = lines[len(lines)-2000:]
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "auth.login.failed") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if ts, ok := m["time"].(string); ok {
			if t := parseDBTime(ts); !t.IsZero() && t.Before(cutoff) {
				continue
			}
		}
		detail, _ := m["detail"].(string)
		ip := ""
		if idx := strings.Index(detail, "ip="); idx >= 0 {
			ip = detail[idx+3:]
			if sp := strings.IndexAny(ip, " \t"); sp >= 0 {
				ip = ip[:sp]
			}
		}
		if ip == "" {
			continue
		}
		out.byIP[ip]++
		if len(out.recent) < 20 {
			out.recent = append(out.recent, fmt.Sprintf("%s %s %s", m["time"], ip, detail))
		}
	}
	return out
}

func failedEvidence(recent []string, n int) string {
	if len(recent) > n {
		recent = recent[:n]
	}
	return strings.Join(recent, "\n")
}

// auditUserAccounts 统计管理员/活跃账户、长期未使用账户与异常密码状态账户
func auditUserAccounts() (adminCount, activeCount int, unusedUsers, emptyPwUsers []string) {
	userManager.RLock()
	defer userManager.RUnlock()
	cutoff := time.Now().Add(-90 * 24 * time.Hour)
	for name, u := range userManager.UserInfos {
		if u == nil {
			continue
		}
		if u.RoleID == "admin" {
			adminCount++
		}
		if u.IsActive {
			activeCount++
		}
		if u.Password == "" {
			emptyPwUsers = append(emptyPwUsers, name)
			continue
		}
		if u.IsActive && (u.LastLogin.IsZero() || u.LastLogin.Before(cutoff)) {
			unusedUsers = append(unusedUsers, name)
		}
	}
	sort.Strings(unusedUsers)
	sort.Strings(emptyPwUsers)
	return
}

// ==================== 2. 开放端口 ====================

type openPortsChecker struct{}

func (c *openPortsChecker) ID() string          { return "open_ports" }
func (c *openPortsChecker) Name() string        { return "开放端口" }
func (c *openPortsChecker) Category() string    { return "网络暴露" }
func (c *openPortsChecker) Description() string { return "扫描本机 LISTEN 状态，按监听地址与端口类型评估公网暴露风险" }

// 高危数据库 / 远程管理端口（公网暴露即 critical）
var criticalPortMap = map[uint32]string{
	3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	1433: "SQL Server", 11211: "Memcached", 9200: "Elasticsearch",
	23: "Telnet", 445: "SMB", 135: "RPC", 139: "NetBIOS",
}

// 远程接入 / 文件传输端口（公网暴露即 high）
var highRiskPortMap = map[uint32]string{
	22: "SSH", 21: "FTP", 3389: "RDP", 5900: "VNC",
	2375: "Docker API", 2376: "Docker API", 2377: "Docker Swarm", 873: "Rsync", 2049: "NFS",
}

// webConsolePorts 本系统对外提供服务的常规 Web 端口（低风险）
var webConsolePorts = map[uint32]bool{80: true, 443: true, 9000: true, 8080: true}

func (c *openPortsChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}}
	ports, err := scanListeningPorts()
	if err != nil {
		return SecurityCheckResult{Status: "error", Summary: "端口扫描失败: " + err.Error(), Findings: []SecurityFinding{}}
	}
	var publicCount, privateCount, localCount int
	var dbPorts, riskPorts int
	for _, p := range ports {
		switch p.Exposure {
		case "public":
			publicCount++
		case "private":
			privateCount++
		case "local":
			localCount++
		}
		if p.Exposure != "public" {
			continue // 仅公网可达的监听构成风险；内网/本机监听不扣分
		}
		name, isCritical := criticalPortMap[p.Port]
		proto := strings.ToUpper(p.Protocol)
		if isCritical {
			dbPorts++
			result.Status = "fail"
			result.Findings = append(result.Findings, mkFinding(c.ID(),
				fmt.Sprintf("port:%d:%s", p.Port, p.Protocol), "critical",
				fmt.Sprintf("数据库/敏感服务 %s 端口 %d 直接暴露公网", name, p.Port),
				fmt.Sprintf("%s 监听在 %s:%d/%s（进程 %s，PID %d），公网可直连。数据库类服务暴露公网是最高风险项之一，极易被扫描爆破。", name, p.Address, p.Port, proto, p.Process, p.PID),
				fmt.Sprintf("%s:%d/%s %s", p.Address, p.Port, proto, p.Process),
				"立即通过防火墙限制来源 IP，或让服务仅监听 127.0.0.1/内网地址（端口管理页可关闭公网访问）。", nil))
			continue
		}
		if name, isHigh := highRiskPortMap[p.Port]; isHigh {
			riskPorts++
			if result.Status == "pass" {
				result.Status = "warn"
			}
			sev := "high"
			reco := "确认该服务必须公网可达；建议启用密钥登录/强认证，并配合防火墙限制来源。"
			if p.Port == 22 {
				reco = "建议启用密钥登录并禁用密码登录（PasswordAuthentication no），或在防火墙中限制来源 IP。"
			}
			if webConsolePorts[p.Port] {
				sev = "medium"
			}
			result.Findings = append(result.Findings, mkFinding(c.ID(),
				fmt.Sprintf("port:%d:%s", p.Port, p.Protocol), sev,
				fmt.Sprintf("远程服务 %s 暴露公网（端口 %d）", name, p.Port),
				fmt.Sprintf("%s 监听在 %s:%d/%s（进程 %s，PID %d），可被公网访问与扫描。", name, p.Address, p.Port, proto, p.Process, p.PID),
				fmt.Sprintf("%s:%d/%s %s", p.Address, p.Port, proto, p.Process),
				reco, nil))
			continue
		}
		if !webConsolePorts[p.Port] {
			// 未识别的公网监听：按中等风险提示，不能因为端口号少见就认为安全
			if result.Status == "pass" {
				result.Status = "warn"
			}
			result.Findings = append(result.Findings, mkFinding(c.ID(),
				fmt.Sprintf("port:%d:%s", p.Port, p.Protocol), "medium",
				fmt.Sprintf("公网监听端口 %d（%s）请确认业务归属", p.Port, p.Process),
				fmt.Sprintf("端口 %d/%s 监听在 %s（进程 %s，PID %d），不在常规 Web 端口清单中，公网可达。", p.Port, proto, p.Address, p.Process, p.PID),
				fmt.Sprintf("%s:%d/%s %s", p.Address, p.Port, proto, p.Process),
				"确认为必要业务后可忽略本条；否则请通过防火墙关闭公网访问。", nil))
		}
	}
	result.Detail = map[string]any{
		"public": publicCount, "private": privateCount, "local": localCount,
		"critical_ports": dbPorts, "high_risk_ports": riskPorts,
	}
	result.Summary = fmt.Sprintf("监听 %d 项：公网 %d / 内网 %d / 本机 %d", len(ports), publicCount, privateCount, localCount)
	return result
}

// ==================== 3. 防火墙 ====================

type firewallChecker struct{}

func (c *firewallChecker) ID() string          { return "firewall" }
func (c *firewallChecker) Name() string        { return "防火墙" }
func (c *firewallChecker) Category() string    { return "网络防护" }
func (c *firewallChecker) Description() string { return "探测 firewalld / nftables / iptables / ufw 可用性与规则数量（只检测，不修改）" }

func (c *firewallChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}, Detail: map[string]any{}}
	provider := detectFirewallProvider()
	name := provider.Name()
	ruleCount := countFirewallRules(name)
	active := name != "none"
	// ufw 兜底探测
	if !active {
		if ufwActive, n := probeUfw(); ufwActive {
			active = true
			name = "ufw"
			ruleCount = n
		}
	}
	changes := getPortChanges()
	result.Detail["provider"] = name
	result.Detail["rule_count"] = ruleCount
	result.Detail["recent_port_changes"] = len(changes)

	if !active {
		result.Status = "warn"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "firewall:missing", "medium",
			"未检测到可用的防火墙",
			"系统未运行 firewalld / nftables / iptables / ufw 中的任何一个，所有监听端口直接取决于应用自身行为。",
			"provider=none",
			"建议启用系统防火墙并仅放行必要端口（云服务器可使用安全组替代）。", nil))
		result.Summary = "未检测到可用防火墙"
		return result
	}
	if ruleCount == 0 {
		result.Status = "warn"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "firewall:empty", "low",
			fmt.Sprintf("防火墙（%s）没有任何规则", name),
			"防火墙处于运行状态但规则集为空，等于全部端口依赖应用自身监听行为。",
			"规则数 0",
			"添加默认拒绝策略并按需放行端口。", nil))
	}
	result.Summary = fmt.Sprintf("防火墙 %s 运行中，规则 %d 条，近期端口变化 %d 次", name, ruleCount, len(changes))
	return result
}

// countFirewallRules 统计防火墙规则数量（只读）
func countFirewallRules(provider string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var out string
	var err error
	switch provider {
	case "firewalld":
		out, err = runCommandOutput(ctx, "firewall-cmd", "--list-all")
		if err == nil {
			// services + ports 粗略计数
			n := strings.Count(out, "\n")
			return n
		}
	case "nftables":
		out, err = runCommandOutput(ctx, "nft", "list", "ruleset")
		if err == nil {
			return strings.Count(out, "\n")
		}
	case "iptables":
		out, err = runCommandOutput(ctx, "iptables", "-S")
		if err == nil {
			return strings.Count(out, "\n")
		}
	}
	return 0
}

// probeUfw 兜底探测 ufw（ports.go 的 FirewallProvider 不含 ufw）
func probeUfw() (bool, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := runCommandOutput(ctx, "ufw", "status")
	if err != nil {
		return false, 0
	}
	if !strings.Contains(out, "Status: active") {
		return false, 0
	}
	return true, strings.Count(out, "\n")
}

// ==================== 4. SSL / TLS 证书 ====================

type tlsCertChecker struct{}

func (c *tlsCertChecker) ID() string          { return "tls_cert" }
func (c *tlsCertChecker) Name() string        { return "SSL 证书" }
func (c *tlsCertChecker) Category() string    { return "证书安全" }
func (c *tlsCertChecker) Description() string { return "检查 server-status 自身 TLS 证书有效期、域名匹配与签发机构" }

func (c *tlsCertChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}, Detail: map[string]any{}}
	certPEM, err := os.ReadFile(tlsCertFile)
	if err != nil {
		result.Summary = "未找到本地 TLS 证书（可能由反向代理终止 TLS）"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "cert:missing", "info",
			"未检测到本地 TLS 证书",
			"若 TLS 由 Nginx 等反向代理终止则属正常；若服务直接对外请确保证书已配置。",
			tlsCertFile,
			"确认部署形态；直连部署请配置 SERVER_STATUS_TLS_CERT/_KEY。", nil))
		return result
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return SecurityCheckResult{Status: "error", Summary: "证书文件解析失败", Findings: []SecurityFinding{}}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return SecurityCheckResult{Status: "error", Summary: "证书内容解析失败: " + err.Error(), Findings: []SecurityFinding{}}
	}
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	issuer := cert.Issuer.CommonName
	dnsNames := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	result.Detail["not_after"] = cert.NotAfter.Format("2006-01-02 15:04")
	result.Detail["issuer"] = issuer
	result.Detail["dns_names"] = dnsNames
	result.Detail["days_left"] = days

	sev := ""
	switch {
	case days < 0:
		sev = "critical"
		result.Status = "fail"
	case days <= 14:
		sev = "high"
		result.Status = "fail"
	case days <= 30:
		sev = "medium"
		result.Status = "warn"
	}
	if sev != "" {
		stateText := fmt.Sprintf("将于 %d 天后过期", days)
		if days < 0 {
			stateText = "已过期 " + strconv.Itoa(-days) + " 天"
		}
		result.Findings = append(result.Findings, mkFinding(c.ID(), "cert:expiry", sev,
			fmt.Sprintf("TLS 证书%s", stateText),
			fmt.Sprintf("证书「%s」将于 %s 过期，过期后浏览器将拒绝访问。", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
			fmt.Sprintf("到期时间 %s，剩余 %d 天，签发机构 %s", cert.NotAfter.Format("2006-01-02"), days, issuer),
			"尽快续期证书（certbot renew 或重新签发）。", nil))
	}
	// 域名匹配
	if tlsDomain != "localhost" && tlsDomain != "" {
		matched := false
		for _, n := range dnsNames {
			if strings.EqualFold(strings.TrimSpace(n), tlsDomain) || strings.EqualFold(n, "*."+tlsDomain) {
				matched = true
				break
			}
		}
		for _, ip := range cert.IPAddresses {
			if ip.String() == tlsDomain {
				matched = true
				break
			}
		}
		result.Detail["domain_match"] = matched
		if !matched {
			result.Status = "warn"
			result.Findings = append(result.Findings, mkFinding(c.ID(), "cert:domain", "medium",
				"证书与配置域名不匹配",
				fmt.Sprintf("配置域名 %s 不在证书覆盖范围内，浏览器将提示证书错误。", tlsDomain),
				fmt.Sprintf("证书覆盖: %s", strings.Join(dnsNames, ", ")),
				"重新签发覆盖该域名的证书，或修正 SERVER_STATUS_DOMAIN 配置。", nil))
		}
	}
	if result.Summary == "" {
		result.Summary = fmt.Sprintf("证书有效，剩余 %d 天（%s 签发）", days, issuer)
	}
	return result
}

// ==================== 5. 系统文件权限 ====================

type filePermChecker struct{}

func (c *filePermChecker) ID() string          { return "file_permissions" }
func (c *filePermChecker) Name() string        { return "文件权限" }
func (c *filePermChecker) Category() string    { return "系统加固" }
func (c *filePermChecker) Description() string { return "检查数据目录、用户库、RBAC、TLS 私钥等敏感文件的访问权限" }

// sensitiveFiles 需要检查的敏感文件（相对 dataRoot）
var sensitiveFiles = []string{
	"users.json", "rbac.json", "audit.log", "ip_security.json", "ops_center.db",
	"private_notes.db", "config.json", ".env", "managed_services.json", "firewall_state.json",
	"tls/cert.pem", "tls/key.pem",
}

func (c *filePermChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}, Detail: map[string]any{}}
	if runtime.GOOS != "linux" {
		result.Findings = append(result.Findings, mkFinding(c.ID(), "platform:nonlinux", "info",
			"非 Linux 环境，文件权限检查跳过",
			fmt.Sprintf("当前运行于 %s，Unix 权限位不适用。", runtime.GOOS),
			runtime.GOOS,
			"生产部署（Linux）时会自动启用该检查。", nil))
		result.Summary = "非 Linux 环境，已跳过"
		return result
	}
	root := dataRoot()
	// 数据目录本身：不允许组/其他人可写
	if st, err := os.Stat(root); err == nil && st.IsDir() {
		mode := st.Mode().Perm()
		if mode&0022 != 0 {
			result.Status = "fail"
			result.Findings = append(result.Findings, mkFinding(c.ID(), "dir:"+root, "critical",
				"数据目录权限过宽",
				fmt.Sprintf("数据根目录 %s 允许组/其他用户写入，攻击者可篡改配置与数据。", root),
				fmt.Sprintf("%s 权限 %04o", root, mode),
				"执行 chmod 755 收紧目录权限。", nil))
		}
	}
	for _, rel := range sensitiveFiles {
		path := filepath.Join(root, rel)
		st, err := os.Stat(path)
		if err != nil {
			continue // 文件不存在视为未启用该能力
		}
		if st.IsDir() {
			continue
		}
		mode := st.Mode().Perm()
		isSecret := strings.HasSuffix(rel, "users.json") || strings.HasSuffix(rel, "rbac.json") ||
			strings.HasSuffix(rel, "key.pem") || strings.HasSuffix(rel, ".env") ||
			strings.HasSuffix(rel, ".db") || rel == "config.json"
		var sev, title, reco string
		switch {
		case mode&0002 != 0:
			sev, title = "critical", "敏感文件可被任意用户写入"
			reco = "立即执行 chmod 600 收紧权限（可通过自动修复一键处理）。"
		case mode&0020 != 0:
			sev, title = "medium", "敏感文件允许组写入"
			reco = "建议 chmod 640 或 600 收紧（可通过自动修复一键处理）。"
		case isSecret && mode&0004 != 0:
			sev, title = "high", "敏感文件可被其他用户读取"
			reco = fmt.Sprintf("建议权限 600，当前 %04o，可自动修复（仅收紧）。", mode)
		default:
			continue
		}
		if result.Status == "pass" || (result.Status == "warn" && sev == "critical") {
			if sev == "critical" {
				result.Status = "fail"
			} else if result.Status == "pass" {
				result.Status = "warn"
			}
		}
		// Context 提供修复上下文：chmod_sensitive_file 规则以 "$finding" 取 path/mode
		targetMode := "0600"
		if !isSecret && sev != "critical" {
			targetMode = "0640"
		}
		result.Findings = append(result.Findings, mkFinding(c.ID(), "file:"+path, sev, title+": "+rel,
			fmt.Sprintf("文件 %s 当前权限 %04o（%s）", path, mode, modeString(mode)),
			fmt.Sprintf("%s → %04o", path, mode), reco,
			map[string]any{"path": path, "mode": targetMode}))
	}
	if len(result.Findings) == 0 {
		result.Summary = fmt.Sprintf("%d 个敏感文件权限均正常", len(sensitiveFiles))
	} else {
		result.Summary = fmt.Sprintf("发现 %d 个权限异常的敏感文件", len(result.Findings)-1)
	}
	return result
}

func modeString(m os.FileMode) string {
	return fmt.Sprintf("%c%c%c%c%c%c%c%c%c",
		map[bool]byte{true: 'd', false: '-'}[false],
		boolRune(m&0400 != 0, 'r', '-'), boolRune(m&0200 != 0, 'w', '-'),
		boolRune(m&0100 != 0, 'x', '-'), boolRune(m&0040 != 0, 'r', '-'),
		boolRune(m&0020 != 0, 'w', '-'), boolRune(m&0010 != 0, 'x', '-'),
		boolRune(m&0004 != 0, 'r', '-'), boolRune(m&0002 != 0, 'w', '-'))
}

func boolRune(b bool, t, f byte) byte {
	if b {
		return t
	}
	return f
}

// ==================== 6. 服务健康 ====================

type serviceHealthChecker struct{}

func (c *serviceHealthChecker) ID() string          { return "service_health" }
func (c *serviceHealthChecker) Name() string        { return "服务健康" }
func (c *serviceHealthChecker) Category() string    { return "服务可用性" }
func (c *serviceHealthChecker) Description() string { return "检查监控清单与托管服务的 systemd 运行状态，异常停止即产生可自动修复的风险" }

// defaultWatchedServices 默认监控清单（用户可通过扫描设置修改，不硬编码业务）
var defaultWatchedServices = []string{"nginx", "docker", "sshd", "firewalld", "trojan-go"}

func (c *serviceHealthChecker) watched() []string {
	if opsStore != nil {
		var list []string
		if err := json.Unmarshal([]byte(opsStore.GetSetting("security.watched_services", "")), &list); err == nil && len(list) > 0 {
			return list
		}
	}
	return defaultWatchedServices
}

func (c *serviceHealthChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}, Detail: map[string]any{}}
	if runtime.GOOS != "linux" {
		result.Findings = append(result.Findings, mkFinding(c.ID(), "platform:nonlinux", "info",
			"非 Linux 环境，服务健康检查跳过",
			fmt.Sprintf("当前运行于 %s，systemd 不可用。", runtime.GOOS), runtime.GOOS,
			"生产部署（Linux）时会自动启用该检查。", nil))
		result.Summary = "非 systemd 环境，已跳过"
		return result
	}
	svcs, ok := getCachedServicesStale()
	if !ok || len(svcs) == 0 {
		return SecurityCheckResult{Status: "error", Summary: "无法获取 systemd 服务列表", Findings: []SecurityFinding{}}
	}
	byName := map[string]*ServiceListItem{}
	for _, s := range svcs {
		if s == nil {
			continue
		}
		byName[strings.TrimSuffix(s.Name, ".service")] = s
	}
	watched := c.watched()
	// 托管服务自动纳入监控
	for name := range managedSvcStore.services {
		if !containsString(watched, name) {
			watched = append(watched, name)
		}
	}
	found, stopped := 0, 0
	for _, name := range watched {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".service")
		if name == "" {
			continue
		}
		svc, ok := byName[name]
		if !ok {
			continue // 未安装的服务跳过，不算风险
		}
		found++
		if svc.Status != "RUNNING" && svc.Status != "STARTING" {
			stopped++
			result.Status = "fail"
			result.Findings = append(result.Findings, mkFinding(c.ID(), "service:"+name, "high",
				fmt.Sprintf("服务 %s 未在运行（%s）", name, svc.Status),
				fmt.Sprintf("被监控的服务 %s 当前状态为 %s，依赖它的功能可能已不可用。", name, svc.Status),
				fmt.Sprintf("%s: %s", name, svc.Status),
				"使用「启动服务」修复动作恢复运行；若服务已废弃请从监控清单移除。",
				map[string]any{"service": name}))
		}
	}
	result.Detail["watched"] = watched
	result.Detail["found"] = found
	result.Detail["stopped"] = stopped
	if found == 0 {
		result.Findings = append(result.Findings, mkFinding(c.ID(), "watchlist:empty", "info",
			"监控清单中的服务均未安装",
			"请在本页「扫描设置」中配置实际存在的服务名（如 nginx、sshd），以便及时发现服务异常。",
			strings.Join(defaultWatchedServices, ", "),
			"配置监控清单后重新扫描。", nil))
		result.Summary = "监控清单未命中任何已安装服务"
		return result
	}
	result.Summary = fmt.Sprintf("监控 %d 个服务，%d 个未运行", found, stopped)
	return result
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ==================== 7. Docker 安全 ====================

type dockerSecurityChecker struct{}

func (c *dockerSecurityChecker) ID() string          { return "docker_security" }
func (c *dockerSecurityChecker) Name() string        { return "Docker 安全" }
func (c *dockerSecurityChecker) Category() string    { return "容器安全" }
func (c *dockerSecurityChecker) Description() string { return "检测特权容器、host 网络/PID、挂载 Docker Socket、异常退出容器（只检测，不修改）" }

// hostConfigInspect 摘取 docker inspect 中与安全相关的字段
type hostConfigInspect struct {
	Privileged  bool              `json:"Privileged"`
	NetworkMode string            `json:"NetworkMode"`
	PidMode     string            `json:"PidMode"`
	Binds       []string          `json:"Binds"`
	PortBindings map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	} `json:"PortBindings"`
}

func (c *dockerSecurityChecker) Check(ctx context.Context) SecurityCheckResult {
	result := SecurityCheckResult{Status: "pass", Findings: []SecurityFinding{}, Detail: map[string]any{}}
	out, err := dockerCommandOutput(ctx, "ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Status}}")
	if err != nil {
		result.Summary = "Docker 未安装或不可用"
		result.Findings = append(result.Findings, mkFinding(c.ID(), "docker:unavailable", "info",
			"Docker 未安装或不可用",
			"本机未检测到可用的 Docker 运行时，容器安全检查跳过。", errText(err),
			"如需容器安全检查请安装 Docker。", nil))
		return result
	}
	containers := 0
	privileged, hostNet, hostPID, sockMount, abnormal := 0, 0, 0, 0, 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		name, state, status := parts[0], parts[1], parts[2]
		containers++
		hc := hostConfigInspect{}
		if raw, err := dockerCommandOutput(ctx, "inspect", "--format", "{{json .HostConfig}}", name); err == nil {
			_ = json.Unmarshal([]byte(raw), &hc)
		}
		if hc.Privileged {
			privileged++
			result.Status = "fail"
			result.Findings = append(result.Findings, mkFinding(c.ID(), "privileged:"+name, "high",
				fmt.Sprintf("容器 %s 以特权模式运行", name),
				"特权容器拥有几乎全部主机内核能力，一旦被攻破等同于主机被攻破。",
				fmt.Sprintf("%s: Privileged=true", name),
				"评估是否必须特权运行，改用 --cap-add 按需授权。", map[string]any{"container": name}))
		}
		if hc.NetworkMode == "host" {
			hostNet++
			if result.Status == "pass" {
				result.Status = "warn"
			}
			result.Findings = append(result.Findings, mkFinding(c.ID(), "hostnet:"+name, "medium",
				fmt.Sprintf("容器 %s 使用 host 网络", name),
				"host 网络模式下容器直接共享主机网络栈，端口隔离与流量管控失效。",
				fmt.Sprintf("%s: NetworkMode=host", name),
				"如无性能必要，改为 bridge 网络并显式映射端口。", map[string]any{"container": name}))
		}
		if hc.PidMode == "host" {
			hostPID++
			if result.Status == "pass" {
				result.Status = "warn"
			}
				result.Findings = append(result.Findings, mkFinding(c.ID(), "hostpid:"+name, "medium",
					fmt.Sprintf("容器 %s 使用 host PID 空间", name),
					"容器内进程可以看到主机全部进程，增大信息泄露与信号注入风险。",
					fmt.Sprintf("%s: PidMode=host", name),
					"如无必要请移除 --pid=host 配置。", map[string]any{"container": name}))
		}
		for _, b := range hc.Binds {
			if strings.HasPrefix(b, "/var/run/docker.sock") || strings.HasPrefix(b, "/run/docker.sock") {
				sockMount++
				result.Status = "fail"
					result.Findings = append(result.Findings, mkFinding(c.ID(), "sock:"+name, "critical",
						fmt.Sprintf("容器 %s 挂载了 Docker Socket", name),
						"挂载 docker.sock 等同于把主机 root 权限交给容器，属于最高危配置。",
						fmt.Sprintf("%s: bind=%s", name, b),
						"改用 docker API 代理（受限权限）或其他免 socket 方案。", map[string]any{"container": name}))
				break
			}
		}
		if state == "exited" && isAbnormalContainer(state, strings.ToLower(status)) {
			abnormal++
			if result.Status == "pass" {
				result.Status = "warn"
			}
			result.Findings = append(result.Findings, mkFinding(c.ID(), "exit:"+name, "medium",
				fmt.Sprintf("容器 %s 异常退出", name),
				fmt.Sprintf("容器状态: %s，非正常退出（退出码非 0）或处于重启循环。", status),
				fmt.Sprintf("%s: %s", name, status),
				"查看容器日志定位原因；确认后可用「重启容器」修复动作拉起。", map[string]any{"container": name}))
		}
	}
	result.Detail["containers"] = containers
	result.Detail["privileged"] = privileged
	result.Detail["host_network"] = hostNet
	result.Detail["host_pid"] = hostPID
	result.Detail["docker_socket_mount"] = sockMount
	result.Detail["abnormal_exited"] = abnormal
	result.Summary = fmt.Sprintf("容器 %d 个：特权 %d / host 网络 %d / socket 挂载 %d / 异常退出 %d",
		containers, privileged, hostNet, sockMount, abnormal)
	return result
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return truncateString(err.Error(), 200)
}

// runCommandOutput 执行只读系统命令并返回 stdout（带超时，仅供检查器探测）
func runCommandOutput(ctx context.Context, name string, args ...string) (string, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s 未安装", name)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}
