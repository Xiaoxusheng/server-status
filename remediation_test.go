package main

// 自动修复引擎回归测试：白名单注册、Preview、Execute/Verify、冷却、最大次数、
// 自动模式安全闸门（critical 拦截 / AllowAuto / 全局开关）、参数上下文解析、审计落盘。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAction 可配置行为的测试动作
type fakeAction struct {
	id         string
	allowAuto  bool
	risk       string
	execErr    error
	execFail   bool
	verifyOK   bool
	verifyErr  error
	execCalls  int
	onExecute  func()
}

func (a *fakeAction) ID() string            { return a.id }
func (a *fakeAction) Name() string          { return "测试动作" + a.id }
func (a *fakeAction) Description() string   { return "测试用" }
func (a *fakeAction) RiskLevel() string     { return a.risk }
func (a *fakeAction) AllowAuto() bool       { return a.allowAuto }
func (a *fakeAction) ParamSpec() []ActionParam {
	return []ActionParam{{Name: "service", Label: "服务名", Type: "string", Required: true}}
}
func (a *fakeAction) Validate(params map[string]any) error {
	if _, ok := params["service"]; !ok {
		return errors.New("缺少 service")
	}
	return nil
}
func (a *fakeAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	return &ActionPreview{Title: "预览", Steps: []string{"s1"}, Impact: "无", Risk: "低"}, nil
}
func (a *fakeAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	a.execCalls++
	if a.onExecute != nil {
		a.onExecute()
	}
	if a.execErr != nil {
		return nil, a.execErr
	}
	if a.execFail {
		return &ActionResult{Success: false, Message: "模拟执行失败"}, nil
	}
	return &ActionResult{Success: true, Message: "已执行"}, nil
}
func (a *fakeAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	if a.verifyErr != nil {
		return nil, a.verifyErr
	}
	return &VerifyResult{OK: a.verifyOK, Message: map[bool]string{true: "验证通过", false: "状态仍异常"}[a.verifyOK]}, nil
}

// setupRemediationTest 准备隔离的引擎环境（存储 / 审计文件 / 注册表）
func setupRemediationTest(t *testing.T) (*OpsStore, string) {
	t.Helper()
	store := newTestOpsStore(t)
	oldStore := remEngine.store
	remEngine.store = store
	t.Cleanup(func() { remEngine.store = oldStore })

	tmpAudit := filepath.Join(t.TempDir(), "audit.log")
	oldAudit := auditLogFile
	auditLogFile = tmpAudit
	t.Cleanup(func() { auditLogFile = oldAudit })

	remEngine.mu.Lock()
	remEngine.inFlight = map[string]bool{}
	remEngine.mu.Unlock()
	return store, tmpAudit
}

func registerFakeAction(t *testing.T, a *fakeAction) {
	t.Helper()
	registerRemediationAction(a)
	t.Cleanup(func() { unregisterRemediationAction(a.id) })
}

func insertFinding(t *testing.T, store *OpsStore, checkID, key, severity string, ctx map[string]any) *SecurityFinding {
	t.Helper()
	f := &SecurityFinding{CheckID: checkID, DedupeKey: key, Severity: severity, Title: "风险" + key, Context: ctx}
	if _, _, err := store.UpsertFinding(f); err != nil {
		t.Fatalf("插入发现失败: %v", err)
	}
	return f
}

func TestRemediationManualSuccess(t *testing.T) {
	store, auditPath := setupRemediationTest(t)
	fa := &fakeAction{id: "fake_start", allowAuto: true, verifyOK: true}
	registerFakeAction(t, fa)
	rule := &RemediationRule{ID: "r1", Name: "拉起服务", CheckID: "service_health", Mode: "manual",
		Enabled: true, ActionID: "fake_start", Parameters: map[string]any{"service": "$finding"},
		MaxAttempts: 3, CooldownSeconds: 60}
	store.SaveRule(rule)
	f := insertFinding(t, store, "service_health", "service:nginx", "high", map[string]any{"service": "nginx"})

	exec, err := remEngine.RunManual(f.ID, "", "admin", nil)
	if err != nil {
		t.Fatalf("手动修复失败: %v", err)
	}
	if exec.Status != "success" || exec.Steps["verify"] == "" {
		t.Fatalf("执行结果错误: %+v", exec)
	}
	got, _ := store.GetFinding(f.ID)
	if got.Status != "resolved" {
		t.Fatalf("修复成功后 finding 应 resolved, got %s", got.Status)
	}
	// 审计已落盘且不含敏感 shell
	data, err := os.ReadFile(auditPath)
	if err != nil || !strings.Contains(string(data), "remediation.execute") || !strings.Contains(string(data), "admin") {
		t.Fatalf("审计未写入: %v %s", err, string(data))
	}
	if strings.Contains(string(data), "sh -c") {
		t.Fatal("审计不应包含 shell 命令")
	}
}

func TestRemediationVerifyFailureMarksFailed(t *testing.T) {
	store, _ := setupRemediationTest(t)
	fa := &fakeAction{id: "fake_start", allowAuto: true, verifyOK: false}
	registerFakeAction(t, fa)
	store.SaveRule(&RemediationRule{ID: "r1", Name: "r", CheckID: "service_health", Mode: "manual",
		Enabled: true, ActionID: "fake_start", Parameters: map[string]any{"service": "$finding"}})
	f := insertFinding(t, store, "service_health", "service:nginx", "high", map[string]any{"service": "nginx"})

	exec, err := remEngine.RunManual(f.ID, "", "admin", nil)
	if err == nil || exec.Status != "failed" {
		t.Fatalf("验证失败应返回 failed: %+v err=%v", exec, err)
	}
	got, _ := store.GetFinding(f.ID)
	if got.Status != "failed" || got.LastExecError == "" {
		t.Fatalf("finding 应标记 failed 并记录原因: %+v", got)
	}
}

func TestRemediationAutoGuards(t *testing.T) {
	store, _ := setupRemediationTest(t)

	// 1) rule.Mode != auto → 不执行
	fa := &fakeAction{id: "fake_a", allowAuto: true, verifyOK: true}
	registerFakeAction(t, fa)
	store.SaveRule(&RemediationRule{ID: "r_manual", Name: "r", CheckID: "check_x", Mode: "manual",
		Enabled: true, ActionID: "fake_a", Parameters: map[string]any{"service": "nginx"}})
	f := insertFinding(t, store, "check_x", "k1", "medium", nil)
	if exec, _ := remEngine.RunAuto(f); exec != nil {
		t.Fatal("manual 模式不应自动执行")
	}

	// 2) 动作 AllowAuto=false → 不执行
	fa2 := &fakeAction{id: "fake_b", allowAuto: false, verifyOK: true}
	registerFakeAction(t, fa2)
	store.SaveRule(&RemediationRule{ID: "r_noauto", Name: "r", CheckID: "check_x", Mode: "auto",
		Enabled: true, ActionID: "fake_b", Parameters: map[string]any{"service": "nginx"}})
	if exec, _ := remEngine.RunAuto(f); exec != nil {
		t.Fatal("AllowAuto=false 的动作不应自动执行")
	}

	// 3) critical 风险 → 不执行（即使动作允许自动）
	store.SaveRule(&RemediationRule{ID: "r_auto", Name: "r", CheckID: "check_x", Mode: "auto",
		Enabled: true, ActionID: "fake_a", Parameters: map[string]any{"service": "nginx"}})
	fc := insertFinding(t, store, "check_x", "kc", "critical", nil)
	if exec, _ := remEngine.RunAuto(fc); exec != nil {
		t.Fatal("critical 风险禁止自动执行")
	}

	// 4) 全局开关关闭 → 不执行
	store.SetSetting("remediation.auto_enabled", "0")
	fm := insertFinding(t, store, "check_x", "km", "medium", nil)
	if exec, _ := remEngine.RunAuto(fm); exec != nil {
		t.Fatal("全局自动修复关闭时不应执行")
	}
	store.SetSetting("remediation.auto_enabled", "1")

	// 5) 正常自动执行 + 冷却期内不重复执行
	fok := insertFinding(t, store, "check_x", "kok", "medium", nil)
	exec, err := remEngine.RunAuto(fok)
	if err != nil || exec == nil || exec.Status != "success" {
		t.Fatalf("自动修复应成功: %+v err=%v", exec, err)
	}
	if exec2, _ := remEngine.RunAuto(fok); exec2 != nil {
		t.Fatal("冷却期内不应再次自动执行")
	}
}

func TestRemediationMaxAttemptsNeedsManual(t *testing.T) {
	store, _ := setupRemediationTest(t)
	fa := &fakeAction{id: "fake_fail", allowAuto: true, execFail: true}
	registerFakeAction(t, fa)
	store.SaveRule(&RemediationRule{ID: "r_max", Name: "r", CheckID: "check_y", Mode: "auto",
		Enabled: true, ActionID: "fake_fail", Parameters: map[string]any{"service": "nginx"},
		MaxAttempts: 1, CooldownSeconds: 1})
	f := insertFinding(t, store, "check_y", "k", "medium", nil)
	// 第一次：执行（本轮周期第 1 次，达到上限）
	if exec, _ := remEngine.RunAuto(f); exec == nil {
		t.Fatal("第一次应执行")
	}
	// 冷却 1 秒后：次数达到上限 → 跳过 + 发出 needs_manual 事件
	time.Sleep(1100 * time.Millisecond)
	if exec, _ := remEngine.RunAuto(f); exec != nil {
		t.Fatal("达到最大次数后不应再执行")
	}
	// 再来一次不应重复发事件
	if exec, _ := remEngine.RunAuto(f); exec != nil {
		t.Fatal("超限后不应执行")
	}
	events, total, _ := store.ListEvents("error", "remediation.needs_manual", 10, 0)
	if total != 1 || len(events) != 1 {
		t.Fatalf("needs_manual 事件应恰好一次, got %d", total)
	}
}

func TestResolveParamsFromFindingContext(t *testing.T) {
	rule := &RemediationRule{Parameters: map[string]any{"service": "$finding", "fixed": "v"}}
	f := &SecurityFinding{Context: map[string]any{"service": "nginx"}}
	params, err := resolveParams(rule, f)
	if err != nil || params["service"] != "nginx" || params["fixed"] != "v" {
		t.Fatalf("参数解析错误: %+v err=%v", params, err)
	}
	// 上下文缺失 → 明确报错
	f2 := &SecurityFinding{}
	if _, err := resolveParams(rule, f2); err == nil {
		t.Fatal("缺少上下文应报错")
	}
}

func TestServiceNameValidation(t *testing.T) {
	if _, err := paramServiceName(map[string]any{"service": "nginx"}, "service"); err != nil {
		t.Fatalf("合法服务名被拒绝: %v", err)
	}
	for _, bad := range []string{"nginx; rm -rf /", "a b", "", "$(x)", "a\nb"} {
		if _, err := paramServiceName(map[string]any{"service": bad}, "service"); err == nil {
			t.Fatalf("非法服务名未被拦截: %q", bad)
		}
	}
}

func TestActionRegistryWhitelist(t *testing.T) {
	// 内置白名单动作必须全部已注册
	for _, id := range []string{"start_service", "stop_service", "restart_service", "disable_service",
		"docker_restart", "block_ip", "unblock_ip", "cleanup_temp", "rotate_log",
		"chmod_sensitive_file", "security_scan"} {
		if _, ok := getRemediationAction(id); !ok {
			t.Fatalf("白名单动作 %s 未注册", id)
		}
	}
	actions := listRemediationActions()
	if len(actions) < 11 {
		t.Fatalf("动作清单数量异常: %d", len(actions))
	}
}
