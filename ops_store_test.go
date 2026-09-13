package main

// 运维中心 SQLite 存储层回归测试（临时目录建库，互不干扰）

import (
	"testing"
	"time"
)

func newTestOpsStore(t *testing.T) *OpsStore {
	t.Helper()
	store, err := NewOpsStore(t.TempDir() + "/ops_center.db")
	if err != nil {
		t.Fatalf("创建测试存储失败: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestOpsStoreFindingUpsertMerge(t *testing.T) {
	s := newTestOpsStore(t)
	f := &SecurityFinding{
		CheckID: "open_ports", DedupeKey: "port:22:tcp", Severity: "high",
		Title: "SSH 暴露", Description: "d1", Evidence: "e1", Recommendation: "r1",
		Context: map[string]any{"port": 22},
	}
	created, reopened, err := s.UpsertFinding(f)
	if err != nil || !created || reopened {
		t.Fatalf("首次写入应 created=true: created=%v reopened=%v err=%v", created, reopened, err)
	}
	if f.ID == "" || f.Status != "open" || f.Occurrences != 1 {
		t.Fatalf("新发现状态错误: %+v", f)
	}
	// 再次发现同一风险 → 合并，次数+1
	f2 := *f
	f2.Evidence = "e2"
	created, reopened, err = s.UpsertFinding(&f2)
	if err != nil || created || reopened {
		t.Fatalf("第二次写入应合并: created=%v reopened=%v err=%v", created, reopened, err)
	}
	if f2.Occurrences != 2 {
		t.Fatalf("合并后 occurrences 应为 2, got %d", f2.Occurrences)
	}
	got, err := s.GetFinding(f.ID)
	if err != nil || got.Evidence != "e2" || got.Context["port"] != float64(22) && got.Context["port"] != 22 {
		t.Fatalf("合并后内容错误: %+v err=%v", got, err)
	}
}

func TestOpsStoreFindingReopenAndResolve(t *testing.T) {
	s := newTestOpsStore(t)
	f := &SecurityFinding{CheckID: "c", DedupeKey: "k1", Severity: "medium", Title: "t"}
	s.UpsertFinding(f)
	// 标记解决后再扫描到 → 重新打开
	s.UpdateFindingStatus(f.ID, "resolved", "")
	got, _ := s.GetFinding(f.ID)
	if got.Status != "resolved" || got.ResolvedAt == nil {
		t.Fatalf("应已 resolved: %+v", got)
	}
	created, reopened, _ := s.UpsertFinding(f)
	if created || !reopened {
		t.Fatalf("复现已解决风险应 reopened=true, got created=%v reopened=%v", created, reopened)
	}
	// ignored 状态不复活
	s.UpdateFindingStatus(f.ID, "ignored", "")
	created, reopened, _ = s.UpsertFinding(f)
	if created || reopened {
		t.Fatalf("ignored 风险不应复活: created=%v reopened=%v", created, reopened)
	}
	got, _ = s.GetFinding(f.ID)
	if got.Status != "ignored" {
		t.Fatalf("ignored 应保持, got %s", got.Status)
	}
}

func TestOpsStoreResolveFindingsNotIn(t *testing.T) {
	s := newTestOpsStore(t)
	f1 := &SecurityFinding{CheckID: "open_ports", DedupeKey: "port:80:tcp", Severity: "low", Title: "A"}
	f2 := &SecurityFinding{CheckID: "open_ports", DedupeKey: "port:443:tcp", Severity: "low", Title: "B"}
	f3 := &SecurityFinding{CheckID: "firewall", DedupeKey: "fw", Severity: "low", Title: "C"}
	s.UpsertFinding(f1)
	s.UpsertFinding(f2)
	s.UpsertFinding(f3)
	// open_ports 扫描只再见到 port:80 → port:443 自动恢复，firewall 不受影响
	resolved, err := s.ResolveFindingsNotIn("open_ports", map[string]bool{"port:80:tcp": true})
	if err != nil {
		t.Fatalf("ResolveFindingsNotIn 失败: %v", err)
	}
	if len(resolved) != 1 || resolved[0].DedupeKey != "port:443:tcp" {
		t.Fatalf("应只恢复 port:443, got %+v", resolved)
	}
	got, _ := s.GetFinding(f3.ID)
	if got.Status != "open" {
		t.Fatalf("其他检查器的发现不应被恢复, got %s", got.Status)
	}
}

func TestOpsStoreRulesAndExecutions(t *testing.T) {
	s := newTestOpsStore(t)
	r := &RemediationRule{
		ID: "rule_x", Name: "测试策略", CheckID: "service_health", Mode: "auto",
		Enabled: true, RequireConfirm: true, ActionID: "start_service",
		Parameters: map[string]any{"service": "nginx"}, MinSeverity: "high",
		MaxAttempts: 3, CooldownSeconds: 60,
	}
	if err := s.SaveRule(r); err != nil {
		t.Fatalf("SaveRule: %v", err)
	}
	got, err := s.GetRule("rule_x")
	if err != nil || got.Parameters["service"] != "nginx" || got.Mode != "auto" || !got.Enabled {
		t.Fatalf("规则读取不一致: %+v err=%v", got, err)
	}
	// 更新
	r.Mode = "manual"
	s.SaveRule(r)
	rules, _ := s.ListRules()
	if len(rules) != 1 || rules[0].Mode != "manual" {
		t.Fatalf("规则更新失败: %+v", rules)
	}
	// 执行记录
	e := &RemediationExecution{ID: "rem_1", RuleID: "rule_x", FindingID: "fnd_1", ActionID: "start_service",
		Trigger: "auto", Operator: "system", Status: "running", StartedAt: time.Now()}
	if err := s.AddRemediationExecution(e); err != nil {
		t.Fatalf("AddRemediationExecution: %v", err)
	}
	if n, _ := s.CountRemediationExecutionsSince("rule_x", "fnd_1", time.Now().Add(-time.Hour)); n != 1 {
		t.Fatalf("执行计数应为 1, got %d", n)
	}
	e.Status = "success"
	now := time.Now()
	e.FinishedAt = &now
	e.DurationMS = 123
	s.UpdateRemediationExecution(e)
	gotExec, _ := s.GetRemediationExecution("rem_1")
	if gotExec.Status != "success" || gotExec.DurationMS != 123 {
		t.Fatalf("执行记录更新失败: %+v", gotExec)
	}
	total, success, failed, _ := s.CountRemediationToday()
	if total != 1 || success != 1 || failed != 0 {
		t.Fatalf("今日统计错误: %d %d %d", total, success, failed)
	}
	if err := s.DeleteRule("rule_x"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if n, _ := s.CountRules(); n != 0 {
		t.Fatalf("删除后规则数应为 0")
	}
}

func TestOpsStoreTasksRoundtrip(t *testing.T) {
	s := newTestOpsStore(t)
	runAt := time.Now().Add(time.Hour)
	tk := &Task{
		ID: "task_1", Name: "每日扫描", Type: "cron", Schedule: "30 5 * * *",
		ActionID: "security_scan", Parameters: map[string]any{}, Enabled: true,
		TimeoutSec: 600, MaxAttempts: 2, RetryBackoffSec: 60, CreatedBy: "admin",
		Trigger: nil,
	}
	if err := s.SaveTask(tk); err != nil {
		t.Fatalf("SaveTask: %v", err)
	}
	got, err := s.GetTask("task_1")
	if err != nil || got.Name != "每日扫描" || got.Schedule != "30 5 * * *" || got.TimeoutSec != 600 {
		t.Fatalf("任务读取不一致: %+v err=%v", got, err)
	}
	// 一次性任务含 RunAt / Trigger
	tk2 := &Task{ID: "task_2", Name: "once", Type: "once", RunAt: &runAt, ActionID: "security_scan",
		Trigger: &TaskTrigger{Type: "cpu_high", Threshold: 90}}
	s.SaveTask(tk2)
	got2, _ := s.GetTask("task_2")
	if got2.RunAt == nil || got2.Trigger == nil || got2.Trigger.Threshold != 90 {
		t.Fatalf("once 任务 RunAt/Trigger 读取失败: %+v", got2)
	}
	// 运行时回写
	next := time.Now().Add(2 * time.Hour)
	last := time.Now()
	s.UpdateTaskRuntime("task_1", &next, &last, "success")
	got, _ = s.GetTask("task_1")
	if got.NextRunAt == nil || got.LastStatus != "success" {
		t.Fatalf("UpdateTaskRuntime 失败: %+v", got)
	}
	// UpdateTaskLastRun 不动 next_run_at
	s.UpdateTaskLastRun("task_1", time.Now(), "failed")
	got, _ = s.GetTask("task_1")
	if got.LastStatus != "failed" || got.NextRunAt == nil {
		t.Fatalf("UpdateTaskLastRun 不应影响 next_run_at: %+v", got)
	}
}

func TestOpsStoreTaskExecutionsAndStats(t *testing.T) {
	s := newTestOpsStore(t)
	now := time.Now()
	e1 := &TaskExecution{ID: "tex_1", TaskID: "task_1", TaskName: "A", Status: "running",
		TriggerType: "schedule", Attempt: 1, MaxAttempts: 1, CreatedAt: now, Steps: map[string]string{"execute": "ok"}}
	e2 := &TaskExecution{ID: "tex_2", TaskID: "task_2", TaskName: "B", Status: "success",
		TriggerType: "manual", CreatedAt: now}
	e3 := &TaskExecution{ID: "tex_3", TaskID: "task_2", TaskName: "B", Status: "failed",
		TriggerType: "schedule", CreatedAt: now.Add(-48 * time.Hour), ErrorMessage: "boom"}
	for _, e := range []*TaskExecution{e1, e2, e3} {
		if err := s.AddTaskExecution(e); err != nil {
			t.Fatalf("AddTaskExecution: %v", err)
		}
	}
	if n, _ := s.CountRunningTaskExecutions(""); n != 1 {
		t.Fatalf("运行中执行数应为 1, got %d", n)
	}
	if n, _ := s.CountRunningTaskExecutions("task_2"); n != 0 {
		t.Fatalf("task_2 无运行中执行")
	}
	// 过滤
	list, total, _ := s.ListTaskExecutions(TaskExecutionFilter{TaskID: "task_2", Limit: 10})
	if total != 2 || len(list) != 2 {
		t.Fatalf("task_2 历史应为 2 条, got %d", total)
	}
	since := now.Add(-24 * time.Hour)
	list, total, _ = s.ListTaskExecutions(TaskExecutionFilter{Since: &since, Limit: 10})
	if total != 2 {
		t.Fatalf("24h 内应为 2 条, got %d", total)
	}
	list, _, _ = s.ListTaskExecutions(TaskExecutionFilter{Status: "failed", Limit: 10})
	if len(list) != 1 || list[0].ErrorMessage != "boom" {
		t.Fatalf("failed 过滤失败: %+v", list)
	}
	running, scheduled, failed24h, doneToday, _ := s.TaskStats()
	if running != 1 || scheduled != 0 || failed24h != 0 || doneToday != 1 {
		t.Fatalf("TaskStats 错误: running=%d scheduled=%d failed24h=%d doneToday=%d", running, scheduled, failed24h, doneToday)
	}
	// 事件
	s.AddEvent(&SecurityEvent{Level: "warning", Type: "finding.open", Title: "t1", Source: "x"})
	s.AddEvent(&SecurityEvent{Level: "info", Type: "scan.completed", Title: "t2", Source: "x"})
	evs, total, _ := s.ListEvents("warning", "", 10, 0)
	if total != 1 || len(evs) != 1 || evs[0].Title != "t1" {
		t.Fatalf("事件过滤失败: %+v", evs)
	}
	s.CleanupOldRecords(1, 1)
}
