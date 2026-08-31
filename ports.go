package main

// ==================== 服务与端口中心 - 端口中心 ====================

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
	psprocess "github.com/shirou/gopsutil/v3/process"
)

// PortInfo 监听端口信息
type PortInfo struct {
	Port        uint32 `json:"port"`
	Protocol    string `json:"protocol"` // tcp/udp
	Address     string `json:"address"`
	Process     string `json:"process"`
	PID         int32  `json:"pid"`
	Executable  string `json:"executable"`
	Command     string `json:"command"`
	Service     string `json:"service"`  // 关联的 systemd 服务
	Exposure    string `json:"exposure"` // public/private/local
	Status      string `json:"status"`   // OPEN/BLOCKED
	Connections int    `json:"connections"`
}

// PortChange 端口变化记录
type PortChange struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // added/removed
	Port     uint32    `json:"port"`
	Protocol string    `json:"protocol"`
	Process  string    `json:"process"`
	Address  string    `json:"address"`
	Exposure string    `json:"exposure"`
}

var (
	portScanMu    sync.Mutex
	portScanCache []PortInfo
	portScanTime  time.Time

	portScanRefreshing bool // 端口扫描后台刷新进行中（singleflight，防止并发重复扫描）

	portChangeMu     sync.Mutex
	portChanges      []PortChange
	lastPortSnapshot map[string]bool
	lastPortMeta     map[string]PortChange

	fwProviderMu    sync.Mutex
	fwProviderCache FirewallProvider
	fwProviderTime  time.Time
)

type procDetail struct {
	name    string
	exe     string
	cmdline string
}

// scanListeningPorts 扫描当前监听端口（2 秒缓存）
func scanListeningPorts() ([]PortInfo, error) {
	portScanMu.Lock()
	defer portScanMu.Unlock()
	if portScanCache != nil && time.Since(portScanTime) < 2*time.Second {
		return portScanCache, nil
	}

	conns, err := psnet.Connections("inet")
	if err != nil {
		return nil, err
	}
	svcMap := pidServiceMap()
	procCache := map[int32]*procDetail{}
	connCount := map[string]int{}
	seen := map[string]bool{}
	list := make([]PortInfo, 0, len(conns))

	for _, c := range conns {
		if c.Laddr.Port == 0 {
			continue
		}
		proto := "tcp"
		if c.Type == syscall.SOCK_DGRAM {
			proto = "udp"
		}
		if strings.EqualFold(c.Status, "ESTABLISHED") {
			connCount[fmt.Sprintf("%s|%d", proto, c.Laddr.Port)]++
			continue
		}
		if proto == "tcp" && !strings.EqualFold(c.Status, "LISTEN") {
			continue
		}
		key := fmt.Sprintf("%s|%s|%d", proto, c.Laddr.IP, c.Laddr.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		info := PortInfo{
			Port:     uint32(c.Laddr.Port),
			Protocol: proto,
			Address:  c.Laddr.IP,
			PID:      c.Pid,
			Exposure: classifyListenAddr(c.Laddr.IP),
			Status:   "OPEN",
		}
		if c.Pid > 0 {
			pd := procCache[c.Pid]
			if pd == nil {
				pd = queryProcDetail(c.Pid)
				procCache[c.Pid] = pd
			}
			info.Process = pd.name
			info.Executable = pd.exe
			info.Command = pd.cmdline
			if unit, ok := svcMap[c.Pid]; ok {
				info.Service = unit
			}
		}
		list = append(list, info)
	}

	for i := range list {
		list[i].Connections = connCount[fmt.Sprintf("%s|%d", list[i].Protocol, list[i].Port)]
		if isPortBlocked(list[i].Port, list[i].Protocol) {
			list[i].Status = "BLOCKED"
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Port == list[j].Port {
			return list[i].Protocol < list[j].Protocol
		}
		return list[i].Port < list[j].Port
	})
	portScanCache = list
	portScanTime = time.Now()
	return list, nil
}

// pidServiceMap 建立 PID -> systemd 服务名 映射
func pidServiceMap() map[int32]string {
	list, err := collectServicesStatus()
	if err != nil {
		return map[int32]string{}
	}
	m := map[int32]string{}
	for _, s := range list {
		if s.PID > 0 {
			m[int32(s.PID)] = s.Name
		}
	}
	return m
}

// queryProcDetail 查询进程名称/可执行路径/命令行
func queryProcDetail(pid int32) *procDetail {
	d := &procDetail{}
	p, err := psprocess.NewProcess(pid)
	if err != nil {
		return d
	}
	if n, err := p.Name(); err == nil {
		d.name = n
	}
	if e, err := p.Exe(); err == nil {
		d.exe = e
	}
	if c, err := p.Cmdline(); err == nil {
		d.cmdline = c
		if len(d.cmdline) > 300 {
			d.cmdline = d.cmdline[:300] + "..."
		}
	}
	return d
}

// classifyListenAddr 公网/内网/本机监听分类
func classifyListenAddr(ip string) string {
	parsed := net.ParseIP(strings.Trim(ip, "[]"))
	if parsed == nil {
		return "public"
	}
	if parsed.IsUnspecified() { // 0.0.0.0 / ::
		return "public"
	}
	if parsed.IsLoopback() {
		return "local"
	}
	if parsed.IsPrivate() {
		return "private"
	}
	return "public"
}

// ==================== 端口变化检测 ====================

// trackPortChanges 对比快照，生成新增/关闭记录（保留最近 50 条）
func trackPortChanges(list []PortInfo) {
	portChangeMu.Lock()
	defer portChangeMu.Unlock()

	now := map[string]bool{}
	meta := map[string]PortChange{}
	for _, p := range list {
		key := fmt.Sprintf("%s|%d", p.Protocol, p.Port)
		now[key] = true
		meta[key] = PortChange{
			Port:     p.Port,
			Protocol: p.Protocol,
			Process:  p.Process,
			Address:  p.Address,
			Exposure: p.Exposure,
		}
	}

	if lastPortSnapshot != nil {
		for k := range now {
			if !lastPortSnapshot[k] {
				c := meta[k]
				c.Type = "added"
				c.Time = time.Now()
				portChanges = append(portChanges, c)
			}
		}
		for k := range lastPortSnapshot {
			if !now[k] {
				c := lastPortMeta[k]
				c.Type = "removed"
				c.Time = time.Now()
				portChanges = append(portChanges, c)
			}
		}
		sort.Slice(portChanges, func(i, j int) bool {
			return portChanges[i].Time.After(portChanges[j].Time)
		})
		if len(portChanges) > 50 {
			portChanges = portChanges[:50]
		}
	}
	lastPortSnapshot = now
	lastPortMeta = meta
}

func getPortChanges() []PortChange {
	portChangeMu.Lock()
	defer portChangeMu.Unlock()
	out := make([]PortChange, len(portChanges))
	copy(out, portChanges)
	return out
}

// trackPortChangesLoop 后台定时扫描端口并记录变化
func trackPortChangesLoop() {
	for {
		time.Sleep(15 * time.Second)
		list, err := scanListeningPorts()
		if err == nil {
			trackPortChanges(list)
		}
	}
}

// ==================== 防火墙统一抽象 ====================

// PortRule 端口访问规则
type PortRule struct {
	ID          string    `json:"id"`
	Port        uint32    `json:"port"`
	Protocol    string    `json:"protocol"` // tcp/udp
	Source      string    `json:"source"`   // public/private/local/ip/network
	SourceValue string    `json:"source_value"`
	Action      string    `json:"action"` // accept/block
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// FirewallState 持久化的防火墙管理状态
type FirewallState struct {
	Provider string     `json:"provider"`
	Blocked  []string   `json:"blocked"` // "9000/tcp"
	Rules    []PortRule `json:"rules"`
}

// firewallStateFile 防火墙状态文件（默认 <数据根目录>/firewall_state.json）
var firewallStateFile = filepath.Join(dataRoot(), "firewall_state.json")

var fwState struct {
	sync.RWMutex
	data FirewallState
}

func loadFirewallState() {
	data, err := os.ReadFile(firewallStateFile)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("读取防火墙状态文件失败: %v", err)
		return
	}
	var st FirewallState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("解析防火墙状态文件失败: %v", err)
		return
	}
	fwState.Lock()
	fwState.data = st
	fwState.Unlock()
}

func saveFirewallState() {
	fwState.RLock()
	st := fwState.data
	fwState.RUnlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(dirOf(firewallStateFile), 0755); err != nil {
		log.Printf("创建防火墙状态目录失败: %v", err)
		return
	}
	if err := os.WriteFile(firewallStateFile, data, 0600); err != nil {
		log.Printf("保存防火墙状态文件失败: %v", err)
	}
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}

// FirewallProvider 防火墙提供者抽象
type FirewallProvider interface {
	Name() string
	BlockPort(port uint32, proto string) error
	UnblockPort(port uint32, proto string) error
	ApplyRule(rule PortRule, cidrs []string, remove bool) error
}

type noopProvider struct{}

func (p *noopProvider) Name() string { return "none" }
func (p *noopProvider) BlockPort(port uint32, proto string) error {
	return fmt.Errorf("未检测到受支持的防火墙（firewalld / nftables / iptables）")
}
func (p *noopProvider) UnblockPort(port uint32, proto string) error {
	return fmt.Errorf("未检测到受支持的防火墙（firewalld / nftables / iptables）")
}
func (p *noopProvider) ApplyRule(rule PortRule, cidrs []string, remove bool) error {
	return fmt.Errorf("未检测到受支持的防火墙（firewalld / nftables / iptables）")
}

// detectFirewallProvider 探测防火墙类型（结果缓存 60 秒）。
// 不缓存时每次探测都会执行 `firewall-cmd --state`（最长 3 秒），
// 这是 /api/ports 接口响应慢的主要元凶之一。
func detectFirewallProvider() FirewallProvider {
	fwProviderMu.Lock()
	if fwProviderCache != nil && time.Since(fwProviderTime) < 60*time.Second {
		p := fwProviderCache
		fwProviderMu.Unlock()
		return p
	}
	fwProviderMu.Unlock()

	p := detectFirewallProviderUncached()

	fwProviderMu.Lock()
	fwProviderCache = p
	fwProviderTime = time.Now()
	fwProviderMu.Unlock()
	return p
}

// detectFirewallProviderUncached 实际执行防火墙类型探测（无缓存）
func detectFirewallProviderUncached() FirewallProvider {
	if bin, err := exec.LookPath("firewall-cmd"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "--state")
		if err := cmd.Run(); err == nil {
			return &firewalldProvider{bin: bin}
		}
	}
	if bin, err := exec.LookPath("nft"); err == nil {
		return &nftablesProvider{bin: bin}
	}
	if bin, err := exec.LookPath("iptables"); err == nil {
		return &iptablesProvider{bin: bin}
	}
	return &noopProvider{}
}

// ---------------- firewalld ----------------

type firewalldProvider struct{ bin string }

func (p *firewalldProvider) Name() string { return "firewalld" }

func (p *firewalldProvider) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		// firewalld 对“未放行端口”执行 remove 或对“已放行端口”执行 add 会报错，
		// 但目标状态已经满足，视为成功（幂等）
		msg := strings.ToUpper(strings.TrimSpace(string(out)))
		if strings.Contains(msg, "NOT_ENABLED") || strings.Contains(msg, "ALREADY_ENABLED") || strings.Contains(msg, "NOT ADDED") {
			return nil
		}
		return fmt.Errorf("firewall-cmd %s 失败: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *firewalldProvider) reload() error { return p.run("--reload") }

// BlockPort 添加 drop rich rule 阻断公网访问（public 区域默认 ACCEPT，仅移除端口不生效）
func (p *firewalldProvider) BlockPort(port uint32, proto string) error {
	rich := fmt.Sprintf("rule family=ipv4 port port=%d protocol=%s drop", port, proto)
	if err := p.run("--permanent", "--zone=public", "--add-rich-rule", rich); err != nil {
		return err
	}
	return p.reload()
}

// UnblockPort 移除 drop rich rule，恢复公网访问
func (p *firewalldProvider) UnblockPort(port uint32, proto string) error {
	rich := fmt.Sprintf("rule family=ipv4 port port=%d protocol=%s drop", port, proto)
	if err := p.run("--permanent", "--zone=public", "--remove-rich-rule", rich); err != nil {
		return err
	}
	return p.reload()
}

func (p *firewalldProvider) ApplyRule(rule PortRule, cidrs []string, remove bool) error {
	action := "accept"
	if rule.Action == "block" {
		action = "drop"
	}
	for _, cidr := range cidrs {
		host := cidr
		if i := strings.Index(cidr, "/"); i > 0 {
			host = cidr[:i]
		}
		family := "ipv4"
		if strings.Contains(host, ":") {
			family = "ipv6"
		}
		rich := fmt.Sprintf("rule family=%s source address=%s port port=%d protocol=%s %s", family, host, rule.Port, rule.Protocol, action)
		args := []string{"--permanent", "--zone=public"}
		if remove {
			args = append(args, "--remove-rich-rule")
		} else {
			args = append(args, "--add-rich-rule")
		}
		args = append(args, rich)
		if err := p.run(args...); err != nil {
			return err
		}
	}
	return p.reload()
}

// ---------------- nftables ----------------

type nftablesProvider struct{ bin string }

func (p *nftablesProvider) Name() string { return "nftables" }

func (p *nftablesProvider) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft %s 失败: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// ensure 创建独立于系统链的 server-status 表与 input 链
func (p *nftablesProvider) ensure() error {
	if err := p.run("add", "table", "inet", "server-status"); err != nil {
		// 表已存在时忽略
	}
	chain := "{ type filter hook input priority 0 ; policy accept ; }"
	if err := p.run("add", "chain", "inet", "server-status", "input", chain); err != nil {
		// 链已存在时忽略
	}
	return nil
}

func (p *nftablesProvider) BlockPort(port uint32, proto string) error {
	if err := p.ensure(); err != nil {
		return err
	}
	p.removeRule(ruleExpr(port, proto, "", "drop"))
	return p.run("add", "rule", "inet", "server-status", "input", ruleExpr(port, proto, "", "drop"))
}

func (p *nftablesProvider) UnblockPort(port uint32, proto string) error {
	if err := p.ensure(); err != nil {
		return err
	}
	return p.removeRule(ruleExpr(port, proto, "", "drop"))
}

func ruleExpr(port uint32, proto, cidr, action string) string {
	base := proto + " dport " + strconv.Itoa(int(port)) + " " + action
	if cidr != "" {
		base = "ip saddr " + cidr + " " + base
	}
	return base
}

// removeRule 通过 handle 删除匹配的 nft 规则
func (p *nftablesProvider) removeRule(expr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, "-a", "list", "chain", "inet", "server-status", "input")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil // 链不存在视为无规则
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, expr) {
			continue
		}
		idx := strings.LastIndex(line, "# handle ")
		if idx < 0 {
			continue
		}
		handle := strings.TrimSpace(line[idx+len("# handle "):])
		if handle != "" {
			p.run("delete", "rule", "inet", "server-status", "input", "handle", handle)
		}
	}
	return nil
}

func (p *nftablesProvider) ApplyRule(rule PortRule, cidrs []string, remove bool) error {
	if err := p.ensure(); err != nil {
		return err
	}
	action := "accept"
	if rule.Action == "block" {
		action = "drop"
	}
	for _, cidr := range cidrs {
		expr := ruleExpr(rule.Port, rule.Protocol, cidr, action)
		if remove {
			if err := p.removeRule(expr); err != nil {
				return err
			}
			continue
		}
		if err := p.run("add", "rule", "inet", "server-status", "input", expr); err != nil {
			return err
		}
	}
	return nil
}

// ---------------- iptables ----------------

type iptablesProvider struct{ bin string }

func (p *iptablesProvider) Name() string { return "iptables" }

func (p *iptablesProvider) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %s 失败: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *iptablesProvider) dropRule(port uint32, proto string) []string {
	return []string{"INPUT", "-p", proto, "--dport", strconv.Itoa(int(port)), "-j", "DROP"}
}

func (p *iptablesProvider) BlockPort(port uint32, proto string) error {
	rule := p.dropRule(port, proto)
	if err := p.run(append([]string{"-C"}, rule...)...); err == nil {
		return nil // 已存在
	}
	return p.run(append([]string{"-A"}, rule...)...)
}

func (p *iptablesProvider) UnblockPort(port uint32, proto string) error {
	rule := p.dropRule(port, proto)
	if err := p.run(append([]string{"-C"}, rule...)...); err != nil {
		return nil // 不存在
	}
	return p.run(append([]string{"-D"}, rule...)...)
}

func (p *iptablesProvider) ApplyRule(rule PortRule, cidrs []string, remove bool) error {
	action := "ACCEPT"
	if rule.Action == "block" {
		action = "DROP"
	}
	for _, cidr := range cidrs {
		args := []string{"INPUT", "-s", cidr, "-p", rule.Protocol, "--dport", strconv.Itoa(int(rule.Port)), "-j", action}
		if remove {
			if err := p.run(append([]string{"-D"}, args...)...); err != nil {
				return err
			}
			continue
		}
		if err := p.run(append([]string{"-C"}, args...)...); err == nil {
			continue
		}
		if err := p.run(append([]string{"-A"}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

// ==================== 防火墙状态与规则管理 ====================

func blockedKey(port uint32, proto string) string {
	return fmt.Sprintf("%d/%s", port, proto)
}

func isPortBlocked(port uint32, proto string) bool {
	key := blockedKey(port, proto)
	fwState.RLock()
	defer fwState.RUnlock()
	for _, k := range fwState.data.Blocked {
		if k == key {
			return true
		}
	}
	return false
}

func blockPort(port uint32, proto string) error {
	p := detectFirewallProvider()
	if err := p.BlockPort(port, proto); err != nil {
		return err
	}
	key := blockedKey(port, proto)
	fwState.Lock()
	fwState.data.Provider = p.Name()
	found := false
	for _, k := range fwState.data.Blocked {
		if k == key {
			found = true
			break
		}
	}
	if !found {
		fwState.data.Blocked = append(fwState.data.Blocked, key)
	}
	fwState.Unlock()
	saveFirewallState()
	portScanMu.Lock()
	portScanCache = nil
	portScanMu.Unlock()
	return nil
}

func unblockPort(port uint32, proto string) error {
	p := detectFirewallProvider()
	if err := p.UnblockPort(port, proto); err != nil {
		return err
	}
	key := blockedKey(port, proto)
	fwState.Lock()
	fwState.data.Provider = p.Name()
	out := fwState.data.Blocked[:0]
	for _, k := range fwState.data.Blocked {
		if k != key {
			out = append(out, k)
		}
	}
	fwState.data.Blocked = out
	fwState.Unlock()
	saveFirewallState()
	portScanMu.Lock()
	portScanCache = nil
	portScanMu.Unlock()
	return nil
}

func getFirewallInfo() map[string]interface{} {
	p := detectFirewallProvider()
	fwState.RLock()
	blocked := append([]string{}, fwState.data.Blocked...)
	rules := make([]PortRule, len(fwState.data.Rules))
	copy(rules, fwState.data.Rules)
	provider := fwState.data.Provider
	fwState.RUnlock()
	if provider == "" {
		provider = p.Name()
	}
	return map[string]interface{}{
		"provider":  provider,
		"available": p.Name() != "none",
		"blocked":   blocked,
		"rules":     rules,
	}
}

// ruleSourceCIDRs 展开规则访问来源为 CIDR 列表
func ruleSourceCIDRs(rule PortRule) ([]string, error) {
	switch rule.Source {
	case "public":
		return []string{"0.0.0.0/0"}, nil
	case "private":
		return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, nil
	case "local":
		return []string{"127.0.0.0/8"}, nil
	case "ip":
		ip := net.ParseIP(strings.TrimSpace(rule.SourceValue))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("指定 IP 无效（暂支持 IPv4）")
		}
		return []string{ip.String() + "/32"}, nil
	case "network":
		_, _, err := net.ParseCIDR(strings.TrimSpace(rule.SourceValue))
		if err != nil {
			return nil, fmt.Errorf("指定网段无效: %v", err)
		}
		return []string{strings.TrimSpace(rule.SourceValue)}, nil
	default:
		return nil, fmt.Errorf("访问来源类型不合法")
	}
}

func validatePortRule(rule *PortRule) error {
	if rule.Port < 1 || rule.Port > 65535 {
		return fmt.Errorf("端口号必须在 1~65535 之间")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return fmt.Errorf("协议必须是 tcp 或 udp")
	}
	if rule.Source != "public" && rule.Source != "private" && rule.Source != "local" &&
		rule.Source != "ip" && rule.Source != "network" {
		return fmt.Errorf("访问来源不合法")
	}
	if rule.Action != "accept" && rule.Action != "block" {
		return fmt.Errorf("动作必须是 accept 或 block")
	}
	_, err := ruleSourceCIDRs(*rule)
	return err
}

func applyPortRule(rule PortRule, remove bool) error {
	p := detectFirewallProvider()
	cidrs, err := ruleSourceCIDRs(rule)
	if err != nil {
		return err
	}
	if !rule.Enabled && !remove {
		return nil // 禁用中的规则不生效
	}
	return p.ApplyRule(rule, cidrs, remove)
}

func findRuleByID(id string) *PortRule {
	fwState.RLock()
	defer fwState.RUnlock()
	for i := range fwState.data.Rules {
		if fwState.data.Rules[i].ID == id {
			r := fwState.data.Rules[i]
			return &r
		}
	}
	return nil
}

// ==================== 端口 API 处理函数 ====================

// refreshPortScanCache 后台刷新端口扫描缓存（由 stale-first 读取触发，singleflight 防重入）
func refreshPortScanCache() {
	list, err := scanListeningPorts()
	portScanMu.Lock()
	if err == nil {
		portScanCache = list
		portScanTime = time.Now()
	}
	portScanRefreshing = false
	portScanMu.Unlock()
	if err == nil {
		trackPortChanges(list)
	}
}

// getCachedPortsStale 以 stale-first 策略读取端口缓存：
// 只要缓存存在就立即返回（即使已过期，保证调用方秒开）；
// 缓存缺失或超过 2 秒新鲜期时触发后台刷新，绝不阻塞调用方。
// 返回 (端口列表, 缓存是否存在)。
func getCachedPortsStale() ([]PortInfo, bool) {
	portScanMu.Lock()
	cached := portScanCache
	needRefresh := (cached == nil || time.Since(portScanTime) >= 2*time.Second) && !portScanRefreshing
	if needRefresh {
		portScanRefreshing = true
	}
	portScanMu.Unlock()
	if needRefresh {
		go refreshPortScanCache()
	}
	if cached == nil {
		return nil, false
	}
	return cached, true
}

// buildPortsPayload 组装端口中心页面数据（ports + firewall + changes），与 /api/ports 响应结构一致
func buildPortsPayload(ports []PortInfo) map[string]interface{} {
	return map[string]interface{}{
		"ports":    ports,
		"firewall": getFirewallInfo(),
		"changes":  getPortChanges(),
	}
}

// portsWSHandler GET /ws/ports —— 服务与端口中心页面级 WebSocket 推送：
// 连接建立后立即推送当前缓存数据（陈旧数据先行，页面秒开），随后每 5 秒推送一次；
// 数据永远读自缓存（端口 + 服务），过期仅触发后台刷新，推送协程不会被慢采集
// （systemd 枚举/防火墙探测）阻塞。按连接用户的 RBAC 权限过滤推送字段：
// port:view → ports/firewall/changes；service:view → services/systemd_available。
// 认证链由路由中间件保障：会话 Cookie + RBAC + Origin 校验。
func portsWSHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "ports")

	// 字段级权限过滤：路由为 Any(port:view, service:view)，此处再细分推送内容
	session, sessOK := getSessionFromRequest(r)
	canPorts := sessOK && hasPermission(session.Username, "port:view")
	canSvc := sessOK && hasPermission(session.Username, "service:view")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("服务端口 WebSocket Upgrade Error:", err)
		return
	}
	defer conn.Close()

	// 读协程：仅用于感知客户端断开（页面关闭/刷新即退出推送循环）
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// push 推送一帧数据；失败（连接断开/写超时）返回 false
	push := func() bool {
		data := map[string]interface{}{}
		if canPorts {
			ports, ok := getCachedPortsStale()
			if !ok {
				ports = []PortInfo{} // 冷启动首帧允许为空，后续帧会带上数据
			}
			mergePortsPayload(data, ports)
		}
		if canSvc {
			svcs, ok := getCachedServicesStale()
			if !ok {
				svcs = []*ServiceListItem{}
			}
			data["services"] = svcs
			data["systemd_available"] = ok
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(map[string]interface{}{
			"code":    200,
			"message": "success",
			"data":    data,
		}) == nil
	}

	if !push() { // 首帧立即推送（秒开关键）
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

// mergePortsPayload 将端口中心数据（ports + firewall + changes）合并进 data
func mergePortsPayload(data map[string]interface{}, ports []PortInfo) {
	data["ports"] = ports
	data["firewall"] = getFirewallInfo()
	data["changes"] = getPortChanges()
}

// listPortsHandler GET /api/ports
func listPortsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "ports")
	list, err := scanListeningPorts()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "扫描监听端口失败: "+err.Error())
		return
	}
	trackPortChanges(list)
	writeJSON(w, http.StatusOK, "获取端口列表成功", buildPortsPayload(list))
}

// listPortChangesHandler GET /api/ports/changes
func listPortChangesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	writeJSON(w, http.StatusOK, "获取端口变化成功", getPortChanges())
}

// getPortDetailHandler GET /api/ports/{port}?protocol=tcp|udp
func getPortDetailHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "端口号必须在 1~65535 之间")
		return
	}
	proto := strings.ToLower(r.URL.Query().Get("protocol"))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		writeJSONError(w, http.StatusBadRequest, "协议必须是 tcp 或 udp")
		return
	}
	list, err := scanListeningPorts()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "扫描监听端口失败: "+err.Error())
		return
	}
	for _, p := range list {
		if p.Port == uint32(port) && p.Protocol == proto {
			writeJSON(w, http.StatusOK, "获取端口详情成功", p)
			return
		}
	}
	writeJSONError(w, http.StatusNotFound, "端口未在监听")
}

// closePortHandler POST /api/ports/{port}/close
func closePortHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "端口号必须在 1~65535 之间")
		return
	}
	proto := portRequestProtocol(r)
	if err := blockPort(uint32(port), proto); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(r, "port.close", fmt.Sprintf("防火墙阻断 %d/%s", port, proto))
	writeJSON(w, http.StatusOK, "已通过防火墙阻断公网访问", map[string]interface{}{"port": port, "protocol": proto})
}

// openPortHandler POST /api/ports/{port}/open
func openPortHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "端口号必须在 1~65535 之间")
		return
	}
	proto := portRequestProtocol(r)
	if err := unblockPort(uint32(port), proto); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditAction(r, "port.open", fmt.Sprintf("防火墙放行 %d/%s", port, proto))
	writeJSON(w, http.StatusOK, "已开放公网访问", map[string]interface{}{"port": port, "protocol": proto})
}

func portRequestProtocol(r *http.Request) string {
	proto := ""
	if r.Body != nil {
		var body struct {
			Protocol string `json:"protocol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			proto = strings.ToLower(strings.TrimSpace(body.Protocol))
		}
	}
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	return proto
}

// listFirewallHandler GET /api/firewall
func listFirewallHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	writeJSON(w, http.StatusOK, "获取防火墙信息成功", getFirewallInfo())
}

// createPortRuleHandler POST /api/ports/rules
func createPortRuleHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	var rule PortRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if err := validatePortRule(&rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.ID = fmt.Sprintf("r%d", time.Now().UnixNano())
	rule.CreatedAt = time.Now()
	if err := applyPortRule(rule, false); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "应用防火墙规则失败: "+err.Error())
		return
	}
	fwState.Lock()
	fwState.data.Provider = detectFirewallProvider().Name()
	fwState.data.Rules = append(fwState.data.Rules, rule)
	fwState.Unlock()
	saveFirewallState()
	auditAction(r, "port.rule.create", fmt.Sprintf("新增端口规则 %d/%s %s %s", rule.Port, rule.Protocol, rule.Source, rule.Action))
	writeJSON(w, http.StatusOK, "规则创建成功", rule)
}

// deletePortRuleHandler DELETE /api/ports/rules/{id}
func deletePortRuleHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	id := r.PathValue("id")
	rule := findRuleByID(id)
	if rule == nil {
		writeJSONError(w, http.StatusNotFound, "规则不存在")
		return
	}
	if err := applyPortRule(*rule, true); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "移除防火墙规则失败: "+err.Error())
		return
	}
	fwState.Lock()
	out := fwState.data.Rules[:0]
	for _, rl := range fwState.data.Rules {
		if rl.ID != id {
			out = append(out, rl)
		}
	}
	fwState.data.Rules = out
	fwState.Unlock()
	saveFirewallState()
	auditAction(r, "port.rule.delete", "删除端口规则 "+id)
	writeJSON(w, http.StatusOK, "规则已删除", nil)
}
