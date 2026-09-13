package main

// ==================== 白名单修复动作实现 ====================
//
// 所有动作只允许操作受控资源：
//   - systemd：只允许操作「托管服务 + 监控清单 + 显式白名单」内的单元
//   - Docker：只允许 restart 已存在容器，参数经严格正则校验
//   - IP：复用现有 ipsecurity 封禁体系（含白名单保护）
//   - 文件：cleanup/chmod/rotate 全部限定路径白名单，禁止路径穿越
// 禁止 exec.Command("sh", "-c", userInput) 一类用法。

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func init() {
	registerRemediationAction(&startServiceAction{})
	registerRemediationAction(&stopServiceAction{})
	registerRemediationAction(&restartServiceAction{})
	registerRemediationAction(&disableServiceAction{})
	registerRemediationAction(&dockerRestartAction{})
	registerRemediationAction(&blockIPAction{})
	registerRemediationAction(&unblockIPAction{})
	registerRemediationAction(&cleanupTempAction{})
	registerRemediationAction(&rotateLogAction{})
	registerRemediationAction(&chmodSensitiveFileAction{})
	registerRemediationAction(&securityScanAction{})
}

// ---------------- systemd 服务动作 ----------------

// remediationAllowedServices 可操作服务白名单：托管服务 ∪ 监控清单 ∪ 显式配置
func remediationAllowedServices() map[string]bool {
	allowed := map[string]bool{}
	for name := range managedServicesRegistry() {
		allowed[strings.TrimSuffix(name, ".service")] = true
	}
	// 安全中心监控清单（security.watched_services）
	var watched []string
	if opsStore != nil {
		if err := json.Unmarshal([]byte(opsStore.GetSetting("security.watched_services", "")), &watched); err == nil {
			for _, s := range watched {
				allowed[strings.TrimSuffix(strings.TrimSpace(s), ".service")] = true
			}
		}
		// 修复动作显式白名单
		var extra []string
		if err := json.Unmarshal([]byte(opsStore.GetSetting("remediation.allowed_services", "")), &extra); err == nil {
			for _, s := range extra {
				allowed[strings.TrimSuffix(strings.TrimSpace(s), ".service")] = true
			}
		}
	}
	return allowed
}

// managedServicesRegistry 返回托管服务注册表名称集合（兼容测试环境未初始化）
func managedServicesRegistry() map[string]bool {
	managedSvcStore.mu.RLock()
	defer managedSvcStore.mu.RUnlock()
	out := map[string]bool{}
	for k := range managedSvcStore.services {
		out[k] = true
	}
	return out
}

// dockerCommandOutput 执行 docker CLI 子命令并返回 stdout（与 docker.go 相同的调用方式）
func dockerCommandOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// validateServiceParam 校验服务名并归一化为 unit 名
func validateServiceParam(params map[string]any) (string, error) {
	name, err := paramServiceName(params, "service")
	if err != nil {
		return "", err
	}
	base := strings.TrimSuffix(name, ".service")
	if !remediationAllowedServices()[base] {
		return "", fmt.Errorf("服务 %s 不在允许操作清单内（托管服务 / 安全监控清单 / remediation.allowed_services）", base)
	}
	if strings.HasSuffix(name, ".service") {
		return name, nil
	}
	return base + ".service", nil
}

type startServiceAction struct{}

func (a *startServiceAction) ID() string          { return "start_service" }
func (a *startServiceAction) Name() string        { return "启动服务" }
func (a *startServiceAction) Description() string { return "通过 systemctl start 启动指定的 systemd 服务并验证 active 状态" }
func (a *startServiceAction) RiskLevel() string   { return "low" }
func (a *startServiceAction) AllowAuto() bool     { return true }
func (a *startServiceAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "service", Label: "服务名", Type: "string", Required: true, Help: "仅允许托管服务与监控清单中的服务"}}
}

func (a *startServiceAction) Validate(params map[string]any) error {
	_, err := validateServiceParam(params)
	return err
}

func (a *startServiceAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("启动服务 %s", strings.TrimSuffix(unit, ".service")),
		Steps:       []string{"执行 systemctl start（内部受控 Action，不可编辑）", "执行 systemctl is-active 验证状态"},
		Impact:      "服务将立即启动并对外提供服务",
		Risk:        "低：仅启动受控清单内的服务",
		CommandHint: "systemctl start " + unit,
	}, nil
}

func (a *startServiceAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	if _, err := runSystemctl(ctx, "start", unit); err != nil {
		return &ActionResult{Success: false, Message: err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已执行 systemctl start %s", unit)}, nil
}

func (a *startServiceAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	out, err := runSystemctl(ctx, "is-active", unit)
	if err != nil || strings.TrimSpace(out) != "active" {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("服务状态为 %s，预期 active", strings.TrimSpace(out))}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("%s 已处于 active 状态", unit)}, nil
}

type stopServiceAction struct{}

func (a *stopServiceAction) ID() string          { return "stop_service" }
func (a *stopServiceAction) Name() string        { return "停止服务" }
func (a *stopServiceAction) Description() string { return "通过 systemctl stop 停止指定的 systemd 服务（高风险，仅人工确认执行）" }
func (a *stopServiceAction) RiskLevel() string   { return "high" }
func (a *stopServiceAction) AllowAuto() bool     { return false }
func (a *stopServiceAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "service", Label: "服务名", Type: "string", Required: true}}
}

func (a *stopServiceAction) Validate(params map[string]any) error {
	_, err := validateServiceParam(params)
	return err
}

func (a *stopServiceAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("停止服务 %s", strings.TrimSuffix(unit, ".service")),
		Steps:       []string{"执行 systemctl stop（内部受控 Action）", "执行 systemctl is-active 验证已停止"},
		Impact:      "服务将立即停止，依赖它的功能将不可用",
		Risk:        "高：停止服务可能造成业务中断",
		CommandHint: "systemctl stop " + unit,
	}, nil
}

func (a *stopServiceAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	if _, err := runSystemctl(ctx, "stop", unit); err != nil {
		return &ActionResult{Success: false, Message: err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已执行 systemctl stop %s", unit)}, nil
}

func (a *stopServiceAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	out, _ := runSystemctl(ctx, "is-active", unit)
	if strings.TrimSpace(out) == "active" {
		return &VerifyResult{OK: false, Message: "服务仍处于 active 状态"}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("%s 已停止", unit)}, nil
}

type restartServiceAction struct{}

func (a *restartServiceAction) ID() string          { return "restart_service" }
func (a *restartServiceAction) Name() string        { return "重启服务" }
func (a *restartServiceAction) Description() string { return "通过 systemctl restart 重启指定的 systemd 服务并验证 active 状态" }
func (a *restartServiceAction) RiskLevel() string   { return "medium" }
func (a *restartServiceAction) AllowAuto() bool     { return false }
func (a *restartServiceAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "service", Label: "服务名", Type: "string", Required: true}}
}

func (a *restartServiceAction) Validate(params map[string]any) error {
	_, err := validateServiceParam(params)
	return err
}

func (a *restartServiceAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("重启服务 %s", strings.TrimSuffix(unit, ".service")),
		Steps:       []string{"执行 systemctl restart（内部受控 Action）", "执行 systemctl is-active 验证状态"},
		Impact:      "服务会短暂中断后重新启动",
		Risk:        "中：重启期间存在短暂服务中断",
		CommandHint: "systemctl restart " + unit,
	}, nil
}

func (a *restartServiceAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	if _, err := runSystemctl(ctx, "restart", unit); err != nil {
		return &ActionResult{Success: false, Message: err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已执行 systemctl restart %s", unit)}, nil
}

func (a *restartServiceAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	out, err := runSystemctl(ctx, "is-active", unit)
	if err != nil || strings.TrimSpace(out) != "active" {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("服务状态为 %s，预期 active", strings.TrimSpace(out))}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("%s 已重启并处于 active 状态", unit)}, nil
}

type disableServiceAction struct{}

func (a *disableServiceAction) ID() string          { return "disable_service" }
func (a *disableServiceAction) Name() string        { return "禁用开机自启" }
func (a *disableServiceAction) Description() string { return "systemctl disable 取消服务开机自启（高风险，仅人工确认执行）" }
func (a *disableServiceAction) RiskLevel() string   { return "high" }
func (a *disableServiceAction) AllowAuto() bool     { return false }
func (a *disableServiceAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "service", Label: "服务名", Type: "string", Required: true}}
}

func (a *disableServiceAction) Validate(params map[string]any) error {
	_, err := validateServiceParam(params)
	return err
}

func (a *disableServiceAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("禁用 %s 开机自启", strings.TrimSuffix(unit, ".service")),
		Steps:       []string{"执行 systemctl disable（内部受控 Action）", "执行 systemctl is-enabled 验证"},
		Impact:      "服务重启后将不再自动拉起（当前运行状态不受影响）",
		Risk:        "高：影响开机自启行为",
		CommandHint: "systemctl disable " + unit,
	}, nil
}

func (a *disableServiceAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	if _, err := runSystemctl(ctx, "disable", unit); err != nil {
		return &ActionResult{Success: false, Message: err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已执行 systemctl disable %s", unit)}, nil
}

func (a *disableServiceAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	unit, err := validateServiceParam(params)
	if err != nil {
		return nil, err
	}
	out, _ := runSystemctl(ctx, "is-enabled", unit)
	if strings.TrimSpace(out) == "enabled" {
		return &VerifyResult{OK: false, Message: "服务仍处于 enabled 状态"}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("%s 已取消开机自启", unit)}, nil
}

// ---------------- Docker 动作 ----------------

type dockerRestartAction struct{}

func (a *dockerRestartAction) ID() string          { return "docker_restart" }
func (a *dockerRestartAction) Name() string        { return "重启容器" }
func (a *dockerRestartAction) Description() string { return "docker restart 重启指定容器（停止状态的容器会被拉起）并验证 running" }
func (a *dockerRestartAction) RiskLevel() string   { return "medium" }
func (a *dockerRestartAction) AllowAuto() bool     { return false }
func (a *dockerRestartAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "container", Label: "容器名", Type: "string", Required: true}}
}

// dockerContainerExists 校验容器名真实存在（防止借参数注入额外 CLI 参数）
func dockerContainerExists(ctx context.Context, name string) (bool, error) {
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := dockerCommandOutput(ctx2, "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == name {
			return true, nil
		}
	}
	return false, nil
}

func (a *dockerRestartAction) Validate(params map[string]any) error {
	name, ok := params["container"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("缺少参数 container")
	}
	if len(name) > 100 || strings.ContainsAny(name, " \t\n/;|&$`") {
		return fmt.Errorf("容器名含非法字符")
	}
	return nil
}

func (a *dockerRestartAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	name, ok := params["container"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少参数 container")
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("重启容器 %s", name),
		Steps:       []string{"执行 docker restart（内部受控 Action）", "重新读取容器状态验证 running"},
		Impact:      "容器将重启，期间其服务短暂不可用",
		Risk:        "中：容器重启期间服务短暂中断",
		CommandHint: "docker restart " + name,
	}, nil
}

func (a *dockerRestartAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	name, _ := params["container"].(string)
	exists, err := dockerContainerExists(ctx, name)
	if err != nil {
		return &ActionResult{Success: false, Message: "无法连接 Docker：" + err.Error()}, nil
	}
	if !exists {
		return &ActionResult{Success: false, Message: fmt.Sprintf("容器 %s 不存在", name)}, nil
	}
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if out, err := dockerCommandOutput(ctx2, "restart", name); err != nil {
		return &ActionResult{Success: false, Message: err.Error(), Output: out}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已执行 docker restart %s", name)}, nil
}

func (a *dockerRestartAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	name, _ := params["container"].(string)
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := dockerCommandOutput(ctx2, "inspect", "-f", "{{.State.Running}}", name)
	if err != nil || strings.TrimSpace(out) != "true" {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("容器 %s 未处于 running 状态", name)}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("容器 %s 已处于 running 状态", name)}, nil
}

// ---------------- IP 封禁动作（复用现有 ipsecurity 体系） ----------------

type blockIPAction struct{}

func (a *blockIPAction) ID() string   { return "block_ip" }
func (a *blockIPAction) Name() string { return "封禁 IP" }
func (a *blockIPAction) Description() string {
	return "将恶意 IP 加入现有封禁体系（与 IP 安全中心共用白名单与到期机制）"
}
func (a *blockIPAction) RiskLevel() string { return "medium" }
func (a *blockIPAction) AllowAuto() bool   { return true }
func (a *blockIPAction) ParamSpec() []ActionParam {
	return []ActionParam{
		{Name: "ip", Label: "IP 地址", Type: "string", Required: true},
		{Name: "duration", Label: "封禁时长", Type: "enum", Required: false, Options: []string{"10m", "1h", "6h", "24h", "7d", "30d", "permanent"}, Default: "24h"},
		{Name: "reason", Label: "封禁原因", Type: "string", Required: false},
	}
}

func (a *blockIPAction) Validate(params map[string]any) error {
	ip, _ := params["ip"].(string)
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return fmt.Errorf("参数 ip 不是合法 IP 地址")
	}
	if isWhitelisted(strings.TrimSpace(ip)) {
		return fmt.Errorf("IP %s 在白名单中，禁止封禁", ip)
	}
	dur, _ := params["duration"].(string)
	if dur == "" {
		dur = "24h"
	}
	if dur != "permanent" {
		if _, ok := parseBlockDuration(dur); !ok {
			return fmt.Errorf("不支持的封禁时长 %s", dur)
		}
	}
	return nil
}

func (a *blockIPAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	ip, _ := params["ip"].(string)
	dur, _ := params["duration"].(string)
	if dur == "" {
		dur = "24h"
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("封禁 IP %s（%s）", ip, dur),
		Steps:       []string{"写入现有 IP 封禁体系（与 IP 安全中心共用）", "查询封禁列表确认生效"},
		Impact:      "该 IP 将无法访问本服务，直到到期解封",
		Risk:        "中：误封白名单外的正常用户 IP 会造成访问中断",
		CommandHint: "内部受控 Action（复用 /api/ip/block 数据通道）",
	}, nil
}

func (a *blockIPAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	ip := strings.TrimSpace(params["ip"].(string))
	dur, _ := params["duration"].(string)
	if dur == "" {
		dur = "24h"
	}
	reason, _ := params["reason"].(string)
	if reason == "" {
		reason = "安全中心修复动作"
	}
	now := time.Now()
	var until time.Time
	if dur == "permanent" {
		until = now.AddDate(100, 0, 0)
	} else {
		d, _ := parseBlockDuration(dur)
		until = now.Add(d)
	}
	b := &BlockedIP{
		IP: ip, BlockedAt: now, BlockedUntil: until,
		Reason: reason, Trigger: "security_center", Source: "manual", Duration: dur, Score: 100,
	}
	// addAutoBlock 负责持久化、事件推送与审计（与 IP 安全中心一致）
	addAutoBlock(b, nil)
	return &ActionResult{Success: true, Message: fmt.Sprintf("已封禁 IP %s（%s）", ip, dur)}, nil
}

func (a *blockIPAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	ip := strings.TrimSpace(params["ip"].(string))
	if !isIPBlocked(ip) {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("IP %s 未出现在封禁列表中", ip)}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("已确认 IP %s 处于封禁状态", ip)}, nil
}

type unblockIPAction struct{}

func (a *unblockIPAction) ID() string          { return "unblock_ip" }
func (a *unblockIPAction) Name() string        { return "解封 IP" }
func (a *unblockIPAction) Description() string { return "从现有封禁体系中解封指定 IP" }
func (a *unblockIPAction) RiskLevel() string   { return "medium" }
func (a *unblockIPAction) AllowAuto() bool     { return false }
func (a *unblockIPAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "ip", Label: "IP 地址", Type: "string", Required: true}}
}

func (a *unblockIPAction) Validate(params map[string]any) error {
	ip, _ := params["ip"].(string)
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return fmt.Errorf("参数 ip 不是合法 IP 地址")
	}
	return nil
}

func (a *unblockIPAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	ip, _ := params["ip"].(string)
	return &ActionPreview{
		Title:       fmt.Sprintf("解封 IP %s", ip),
		Steps:       []string{"从现有 IP 封禁体系移除", "查询封禁列表确认已解封"},
		Impact:      "该 IP 将恢复访问能力",
		Risk:        "中：恶意 IP 解封后可能再次发起攻击",
		CommandHint: "内部受控 Action（复用 /api/ip/unblock 数据通道）",
	}, nil
}

func (a *unblockIPAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	ip := strings.TrimSpace(params["ip"].(string))
	removeBlockedIP(ip, nil)
	return &ActionResult{Success: true, Message: fmt.Sprintf("已解封 IP %s", ip)}, nil
}

func (a *unblockIPAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	ip := strings.TrimSpace(params["ip"].(string))
	if isIPBlocked(ip) {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("IP %s 仍在封禁列表中", ip)}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("已确认 IP %s 不在封禁列表", ip)}, nil
}

// ---------------- 临时文件清理 ----------------

type cleanupTempAction struct{}

func (a *cleanupTempAction) ID() string          { return "cleanup_temp" }
func (a *cleanupTempAction) Name() string        { return "清理临时文件" }
func (a *cleanupTempAction) Description() string { return "删除白名单目录内超过指定年龄的临时文件（涉及删除文件，仅人工确认执行）" }
func (a *cleanupTempAction) RiskLevel() string   { return "medium" }
func (a *cleanupTempAction) AllowAuto() bool     { return false }

func (a *cleanupTempAction) ParamSpec() []ActionParam {
	return []ActionParam{
		{Name: "path", Label: "目标目录", Type: "string", Required: false, Help: "留空默认清理数据目录 tmp/；仅允许系统临时目录与数据目录 tmp/cache"},
		{Name: "max_age_hours", Label: "文件最短保留小时数", Type: "int", Required: false, Default: 168},
	}
}

func cleanupTempAllowedRoots() []string {
	roots := []string{os.TempDir(), filepath.Join(dataRoot(), "tmp"), filepath.Join(dataRoot(), "cache")}
	return roots
}

func isPathWithin(child, parent string) bool {
	abs1, err1 := filepath.Abs(child)
	abs2, err2 := filepath.Abs(parent)
	if err1 != nil || err2 != nil {
		return false
	}
	abs1 = filepath.Clean(abs1)
	abs2 = filepath.Clean(abs2)
	if abs1 == abs2 {
		return true
	}
	return strings.HasPrefix(abs1, abs2+string(filepath.Separator))
}

func (a *cleanupTempAction) Validate(params map[string]any) error {
	target, _ := params["path"].(string)
	if target == "" {
		target = filepath.Join(dataRoot(), "tmp")
	}
	if !isPathWithin(target, target) {
		return fmt.Errorf("路径解析失败")
	}
	ok := false
	for _, root := range cleanupTempAllowedRoots() {
		if isPathWithin(target, root) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("目录 %s 不在允许清理的白名单内（系统临时目录 / 数据目录 tmp、cache）", target)
	}
	return nil
}

func (a *cleanupTempAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	if err := a.Validate(params); err != nil {
		return nil, err
	}
	target, _ := params["path"].(string)
	if target == "" {
		target = filepath.Join(dataRoot(), "tmp")
	}
	age := 168
	if v, ok := params["max_age_hours"].(float64); ok && v > 0 {
		age = int(v)
	}
	return &ActionPreview{
		Title:       fmt.Sprintf("清理临时目录 %s 中 %d 小时前的文件", target, age),
		Steps:       []string{"遍历目录统计匹配文件", "逐个删除超龄文件（保留目录结构）", "汇总释放空间"},
		Impact:      fmt.Sprintf("将删除 %s 下超过 %d 小时未修改的文件", target, age),
		Risk:        "中：涉及删除文件，请确认目录内无长期需要保留的临时产物",
		CommandHint: "内部受控 Action（Go 遍历删除，白名单目录）",
	}, nil
}

func (a *cleanupTempAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	target, _ := params["path"].(string)
	if target == "" {
		target = filepath.Join(dataRoot(), "tmp")
	}
	ageHours := 168.0
	if v, ok := params["max_age_hours"].(float64); ok && v > 0 {
		ageHours = v
	}
	cutoff := time.Now().Add(-time.Duration(ageHours) * time.Hour)
	var freed int64
	var removed int
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == target {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if info.IsDir() {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			size := info.Size()
			if os.Remove(path) == nil {
				freed += size
				removed++
			}
		}
		return nil
	})
	if err != nil {
		return &ActionResult{Success: false, Message: "清理失败：" + err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已删除 %d 个文件，释放 %s", removed, fmtBytesHuman(freed))}, nil
}

func (a *cleanupTempAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	target, _ := params["path"].(string)
	if target == "" {
		target = filepath.Join(dataRoot(), "tmp")
	}
	ageHours := 168.0
	if v, ok := params["max_age_hours"].(float64); ok && v > 0 {
		ageHours = v
	}
	cutoff := time.Now().Add(-time.Duration(ageHours) * time.Hour)
	remaining := 0
	filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			remaining++
		}
		return nil
	})
	if remaining > 0 {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("仍有 %d 个超龄文件未删除", remaining)}, nil
	}
	return &VerifyResult{OK: true, Message: "目标目录内已无超龄文件"}, nil
}

func fmtBytesHuman(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ---------------- 日志轮转（copytruncate，白名单限定 logDir） ----------------

type rotateLogAction struct{}

func (a *rotateLogAction) ID() string          { return "rotate_log" }
func (a *rotateLogAction) Name() string        { return "轮转日志" }
func (a *rotateLogAction) Description() string { return "对运行日志执行 copytruncate 轮转并 gzip 归档（仅限数据目录 log/，审计日志除外）" }
func (a *rotateLogAction) RiskLevel() string   { return "low" }
func (a *rotateLogAction) AllowAuto() bool     { return true }

func (a *rotateLogAction) ParamSpec() []ActionParam {
	return []ActionParam{
		{Name: "path", Label: "日志文件", Type: "string", Required: true, Help: "仅允许数据目录 log/ 下的文件，审计日志 audit.log 除外"},
		{Name: "size_mb", Label: "触发轮转的最小体积(MB)", Type: "int", Required: false, Default: 20},
	}
}

func (a *rotateLogAction) Validate(params map[string]any) error {
	path, _ := params["path"].(string)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("缺少参数 path")
	}
	if !isPathWithin(path, logDir) {
		return fmt.Errorf("仅允许轮转数据目录 log/ 下的日志文件")
	}
	if strings.Contains(filepath.Base(path), "audit") {
		return fmt.Errorf("审计日志不允许通过修复动作轮转")
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("日志文件不存在: %s", path)
	}
	if st.IsDir() {
		return fmt.Errorf("目标不是普通文件")
	}
	return nil
}

func (a *rotateLogAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	if err := a.Validate(params); err != nil {
		return nil, err
	}
	path, _ := params["path"].(string)
	sizeMB := 20
	if v, ok := params["size_mb"].(float64); ok && v > 0 {
		sizeMB = int(v)
	}
	st, _ := os.Stat(path)
	return &ActionPreview{
		Title:       fmt.Sprintf("轮转日志 %s", filepath.Base(path)),
		Steps:       []string{"gzip 归档当前日志（保留最近 3 份）", "truncate 原文件（服务无需重启）"},
		Impact:      fmt.Sprintf("当前体积 %s，超过 %d MB 才执行轮转", fmtBytesHuman(st.Size()), sizeMB),
		Risk:        "低：copytruncate 不影响正在写入的日志句柄",
		CommandHint: "内部受控 Action（Go copytruncate + gzip）",
	}, nil
}

func (a *rotateLogAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	path, _ := params["path"].(string)
	sizeMB := 20.0
	if v, ok := params["size_mb"].(float64); ok && v > 0 {
		sizeMB = v
	}
	st, err := os.Stat(path)
	if err != nil {
		return &ActionResult{Success: false, Message: "读取日志失败：" + err.Error()}, nil
	}
	if float64(st.Size()) < sizeMB*(1<<20) {
		return &ActionResult{Success: true, Message: fmt.Sprintf("日志体积 %s 未达 %g MB，跳过轮转", fmtBytesHuman(st.Size()), sizeMB)}, nil
	}
	// 历史归档顺移 .2.gz → .3.gz
	for i := 2; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d.gz", path, i)
		dst := fmt.Sprintf("%s.%d.gz", path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	// copytruncate：复制到临时文件后 gzip，再清空原文件
	tmp := path + ".rotating.tmp"
	if err := copyFileContents(path, tmp); err != nil {
		return &ActionResult{Success: false, Message: "复制日志失败：" + err.Error()}, nil
	}
	arc := path + ".1.gz"
	if err := gzipFile(tmp, arc); err != nil {
		_ = os.Remove(tmp)
		return &ActionResult{Success: false, Message: "gzip 压缩失败：" + err.Error()}, nil
	}
	_ = os.Remove(tmp)
	if err := os.Truncate(path, 0); err != nil {
		return &ActionResult{Success: false, Message: "截断日志失败：" + err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已轮转 %s → %s", filepath.Base(path), filepath.Base(arc))}, nil
}

func (a *rotateLogAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	path, _ := params["path"].(string)
	arc := path + ".1.gz"
	if _, err := os.Stat(arc); err != nil {
		return &VerifyResult{OK: false, Message: "归档文件不存在，轮转可能未执行"}, nil
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 50*(1<<20) {
		return &VerifyResult{OK: false, Message: "原日志体积未缩小"}, nil
	}
	return &VerifyResult{OK: true, Message: "归档已生成，原日志已截断"}, nil
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ---------------- 敏感文件权限收紧 ----------------

type chmodSensitiveFileAction struct{}

func (a *chmodSensitiveFileAction) ID() string   { return "chmod_sensitive_file" }
func (a *chmodSensitiveFileAction) Name() string { return "收紧文件权限" }
func (a *chmodSensitiveFileAction) Description() string {
	return "把数据目录内的敏感文件权限收紧到指定值（仅限 0600/0640/0400 等收紧模式，仅人工确认执行）"
}
func (a *chmodSensitiveFileAction) RiskLevel() string { return "medium" }
func (a *chmodSensitiveFileAction) AllowAuto() bool   { return false }

func (a *chmodSensitiveFileAction) ParamSpec() []ActionParam {
	return []ActionParam{
		{Name: "path", Label: "文件路径", Type: "string", Required: true, Help: "仅允许数据根目录内的文件"},
		{Name: "mode", Label: "目标权限", Type: "enum", Required: true, Options: []string{"0600", "0640", "0400"}, Default: "0600"},
	}
}

var allowedTightenModes = map[string]os.FileMode{"0600": 0600, "0640": 0640, "0400": 0400}

func (a *chmodSensitiveFileAction) Validate(params map[string]any) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("文件权限检查与修复仅支持 Linux 环境")
	}
	path, _ := params["path"].(string)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("缺少参数 path")
	}
	if !isPathWithin(path, dataRoot()) {
		return fmt.Errorf("仅允许修改数据根目录内的文件权限")
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("文件不存在: %s", path)
	}
	if st.IsDir() {
		return fmt.Errorf("仅支持修改普通文件权限")
	}
	modeStr, _ := params["mode"].(string)
	mode, ok := allowedTightenModes[modeStr]
	if !ok {
		return fmt.Errorf("仅支持收紧模式 0600 / 0640 / 0400")
	}
	if cur := st.Mode().Perm(); cur&^mode != 0 && cur < mode {
		return fmt.Errorf("目标权限 %04o 比当前 %04o 更宽松，拒绝执行（只允许收紧）", mode, cur)
	}
	return nil
}

func (a *chmodSensitiveFileAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	if err := a.Validate(params); err != nil {
		return nil, err
	}
	path, _ := params["path"].(string)
	mode, _ := params["mode"].(string)
	st, _ := os.Stat(path)
	return &ActionPreview{
		Title:       fmt.Sprintf("收紧 %s 权限为 %s", filepath.Base(path), mode),
		Steps:       []string{"执行 chmod（内部受控 Action）", "重新 stat 验证权限"},
		Impact:      fmt.Sprintf("权限从 %04o 变更为 %s，其他用户将无法读取该敏感文件", st.Mode().Perm(), mode),
		Risk:        "低：只收紧不放宽；请确认服务运行账户仍可读取",
		CommandHint: "chmod " + mode + " " + path,
	}, nil
}

func (a *chmodSensitiveFileAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	path, _ := params["path"].(string)
	modeStr, _ := params["mode"].(string)
	mode := allowedTightenModes[modeStr]
	if err := os.Chmod(path, mode); err != nil {
		return &ActionResult{Success: false, Message: "chmod 失败：" + err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: fmt.Sprintf("已将 %s 权限调整为 %s", filepath.Base(path), modeStr)}, nil
}

func (a *chmodSensitiveFileAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	path, _ := params["path"].(string)
	modeStr, _ := params["mode"].(string)
	st, err := os.Stat(path)
	if err != nil {
		return &VerifyResult{OK: false, Message: "读取文件失败"}, nil
	}
	if st.Mode().Perm() != allowedTightenModes[modeStr] {
		return &VerifyResult{OK: false, Message: fmt.Sprintf("当前权限 %04o 与目标 %s 不一致", st.Mode().Perm(), modeStr)}, nil
	}
	return &VerifyResult{OK: true, Message: fmt.Sprintf("权限已确认 %s", modeStr)}, nil
}

// ---------------- 触发安全扫描 ----------------

type securityScanAction struct{}

func (a *securityScanAction) ID() string          { return "security_scan" }
func (a *securityScanAction) Name() string        { return "触发安全扫描" }
func (a *securityScanAction) Description() string { return "异步触发一次全量安全扫描（供「每日安全扫描」定时任务与事件触发使用）" }
func (a *securityScanAction) RiskLevel() string   { return "low" }
func (a *securityScanAction) AllowAuto() bool     { return true }
func (a *securityScanAction) ParamSpec() []ActionParam {
	return []ActionParam{}
}

func (a *securityScanAction) Validate(params map[string]any) error { return nil }

func (a *securityScanAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	return &ActionPreview{
		Title:       "触发全量安全扫描",
		Steps:       []string{"后台启动安全检查器流水线", "扫描进度实时推送"},
		Impact:      "扫描在后台异步执行，不影响正常服务",
		Risk:        "低：只读检测，不修改任何系统状态",
		CommandHint: "内部受控 Action（SecurityCenter.StartScan）",
	}, nil
}

func (a *securityScanAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	if opsCenter == nil {
		return &ActionResult{Success: false, Message: "安全中心未初始化"}, nil
	}
	if err := opsCenter.StartScan(); err != nil {
		return &ActionResult{Success: false, Message: err.Error()}, nil
	}
	return &ActionResult{Success: true, Message: "已触发全量安全扫描"}, nil
}

func (a *securityScanAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	if opsCenter == nil {
		return &VerifyResult{OK: false, Message: "安全中心未初始化"}, nil
	}
	st := opsCenter.ScanStatusSnapshot()
	switch st.Status {
	case "running":
		return &VerifyResult{OK: true, Message: "扫描进行中"}, nil
	default:
		if time.Since(st.StartedAt) < 5*time.Minute && st.Status == "success" {
			return &VerifyResult{OK: true, Message: "扫描已完成"}, nil
		}
		return &VerifyResult{OK: false, Message: "扫描未在运行"}, nil
	}
}
