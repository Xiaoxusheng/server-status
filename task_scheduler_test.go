package main

// 运维任务调度器回归测试：到期触发、下次执行推进、执行锁跳过、一次性任务自动停用、扫描计划。

import (
	"context"
	"testing"
	"time"
)

func setupSchedulerTest(t *testing.T) (*OpsStore, *TaskScheduler) {
	t.Helper()
	store := newTestOpsStore(t)
	oldStore, oldOpsStore := taskScheduler.store, opsStore
	oldLast := taskScheduler.lastEvent
	taskScheduler.store = store
	opsStore = store
	taskScheduler.lastEvent = map[string]time.Time{}
	t.Cleanup(func() {
		taskScheduler.store = oldStore
		opsStore = oldOpsStore
		taskScheduler.lastEvent = oldLast
	})
	taskExecutor.mu.Lock()
	taskExecutor.running = map[string]string{}
	taskExecutor.cancels = map[string]context.CancelFunc{}
	taskExecutor.mu.Unlock()
	return store, taskScheduler
}

func registerQuickAction(t *testing.T) {
	t.Helper()
	registerRemediationAction(&quickAction{})
	t.Cleanup(func() { unregisterRemediationAction("quick_ok") })
}

// quickAction 立即成功的测试动作
type quickAction struct{}

func (a *quickAction) ID() string               { return "quick_ok" }
func (a *quickAction) Name() string             { return "快速动作" }
func (a *quickAction) Description() string      { return "测试用" }
func (a *quickAction) RiskLevel() string        { return "low" }
func (a *quickAction) AllowAuto() bool          { return true }
func (a *quickAction) ParamSpec() []ActionParam { return nil }
func (a *quickAction) Validate(params map[string]any) error { return nil }
func (a *quickAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	return &ActionPreview{Title: "预览"}, nil
}
func (a *quickAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	return &ActionResult{Success: true, Message: "ok"}, nil
}
func (a *quickAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	return &VerifyResult{OK: true, Message: "ok"}, nil
}

func TestSchedulerFiresDueTask(t *testing.T) {
	store, sched := setupSchedulerTest(t)
	registerQuickAction(t)

	task := &Task{ID: "t_due", Name: "到期任务", Type: "cron", Schedule: "0 3 * * *",
		ActionID: "quick_ok", Enabled: true, TimeoutSec: 30, MaxAttempts: 1}
	store.SaveTask(task)
	past := time.Now().Add(-time.Minute)
	store.UpdateTaskRuntime(task.ID, &past, nil, "")

	sched.tickSchedule() // 同步调用，触发到期任务

	// 执行结果落地
	deadline := time.Now().Add(3 * time.Second)
	var execs []TaskExecution
	for time.Now().Before(deadline) {
		execs, _, _ = store.ListTaskExecutions(TaskExecutionFilter{TaskID: task.ID, Limit: 10})
		if len(execs) > 0 && execs[0].Status == "success" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(execs) == 0 || execs[0].Status != "success" {
		t.Fatalf("到期任务应执行成功: %+v", execs)
	}
	// 下次执行时间被推进到未来
	got, _ := store.GetTask(task.ID)
	if got.NextRunAt == nil || !got.NextRunAt.After(time.Now()) {
		t.Fatalf("下次执行时间应推进: %+v", got.NextRunAt)
	}
	if got.LastStatus != "success" {
		t.Fatalf("任务最近状态应为 success, got %s", got.LastStatus)
	}
	// 立刻再次 tick：next_run 在未来，不应重复触发
	sched.tickSchedule()
	execs2, total, _ := store.ListTaskExecutions(TaskExecutionFilter{TaskID: task.ID, Limit: 10})
	if total != 1 {
		t.Fatalf("不应重复触发, got %d 条执行记录: %+v", total, execs2)
	}
}

func TestSchedulerSkipsWhenPreviousRunning(t *testing.T) {
	store, sched := setupSchedulerTest(t)
	release := make(chan struct{})
	defer close(release)
	ba := &blockingAction{id: "block_sched", release: release}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_busy", Name: "占用中", Type: "cron", Schedule: "*/5 * * * *",
		ActionID: "block_sched", Enabled: true, TimeoutSec: 60}
	store.SaveTask(task)
	past := time.Now().Add(-time.Minute)
	store.UpdateTaskRuntime(task.ID, &past, nil, "")

	// 先手动占住执行锁
	if _, err := taskExecutor.Submit(task, "manual", "admin", nil); err != nil {
		t.Fatalf("占位提交失败: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	sched.tickSchedule()

	// 应产生一条 skipped 记录（执行锁生效），且 next_run 已推进
	execs, _, _ := store.ListTaskExecutions(TaskExecutionFilter{TaskID: task.ID, Limit: 10})
	foundSkipped := false
	for _, e := range execs {
		if e.Status == "skipped" {
			foundSkipped = true
		}
	}
	if !foundSkipped {
		t.Fatalf("应记录 skipped 执行: %+v", execs)
	}
	got, _ := store.GetTask(task.ID)
	if got.NextRunAt == nil || !got.NextRunAt.After(time.Now()) {
		t.Fatal("跳过后下次执行时间仍应推进")
	}
}

func TestSchedulerOnceTaskFiresAndDisables(t *testing.T) {
	store, sched := setupSchedulerTest(t)
	registerQuickAction(t)

	task := &Task{ID: "t_once", Name: "一次性", Type: "once", ActionID: "quick_ok",
		Enabled: true, TimeoutSec: 30, MaxAttempts: 1}
	runAt := time.Now().Add(-time.Second)
	task.RunAt = &runAt
	store.SaveTask(task)
	store.UpdateTaskRuntime(task.ID, &runAt, nil, "")

	sched.tickSchedule()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := store.GetTask(task.ID)
		if err == nil && !got.Enabled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := store.GetTask(task.ID)
	if got.Enabled {
		t.Fatal("一次性任务触发后应自动停用")
	}
	if got.NextRunAt != nil {
		t.Fatal("一次性任务触发后 next_run 应清空")
	}
	execs, total, _ := store.ListTaskExecutions(TaskExecutionFilter{TaskID: task.ID, Limit: 10})
	if total != 1 || execs[0].Status != "success" {
		t.Fatalf("一次性任务应执行一次成功: %+v", execs)
	}
}

func TestTaskValidationRejectsInvalidCron(t *testing.T) {
	registerQuickAction(t)
	tk := &Task{Name: "x", Type: "cron", Schedule: "0 3 * *", ActionID: "quick_ok"}
	if err := validateTaskInput(tk); err == nil {
		t.Fatal("非法 cron 应被拒绝")
	}
	tk2 := &Task{Name: "x", Type: "cron", Schedule: "0 3 * * *", ActionID: "quick_ok"}
	if err := validateTaskInput(tk2); err != nil {
		t.Fatalf("合法任务不应被拒绝: %v", err)
	}
}

func TestScanScheduleNextRun(t *testing.T) {
	// 每天模式：以昨天为基准 → 下一个 05:30（今天未到则今天，已过则明天）
	sched := ScanSchedule{Enabled: true, Type: "daily", Hour: 5, Minute: 30}
	last := time.Now().AddDate(0, 0, -1)
	next := nextScheduleRun(sched, last)
	want := time.Date(last.Year(), last.Month(), last.Day(), 5, 30, 0, 0, time.Local).AddDate(0, 0, 1)
	for next.Before(time.Now()) || want.Before(time.Now()) {
		want = want.AddDate(0, 0, 1)
	}
	if !next.Equal(want) {
		t.Fatalf("daily 下次扫描应为 %v, got %v", want, next)
	}
	// 从未扫描过 → 启动后 2 分钟内首扫
	next2 := nextScheduleRun(sched, time.Time{})
	if next2.IsZero() || next2.Before(time.Now()) {
		t.Fatal("首次扫描应安排在未来")
	}
	// 关闭计划 → zero
	sched.Enabled = false
	if !nextScheduleRun(sched, last).IsZero() {
		t.Fatal("关闭计划应返回零值")
	}
}
