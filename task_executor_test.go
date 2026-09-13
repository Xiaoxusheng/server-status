package main

// 运维任务执行器回归测试：执行锁（防重复）、超时、取消、失败重试、并发上限。

import (
	"context"
	"sync"
	"testing"
	"time"
)

// blockingAction 阻塞型测试动作：等待 release 通道或 ctx 取消
type blockingAction struct {
	id         string
	release    chan struct{}
	started    chan string // 每次 Execute 开始时发送任务标识（nil 则不发送）
	failNTimes int         // 前 N 次返回失败（用于重试测试）
	mu         sync.Mutex
}

func (a *blockingAction) ID() string               { return a.id }
func (a *blockingAction) Name() string             { return "阻塞测试动作" }
func (a *blockingAction) Description() string      { return "测试用" }
func (a *blockingAction) RiskLevel() string        { return "low" }
func (a *blockingAction) AllowAuto() bool          { return true }
func (a *blockingAction) ParamSpec() []ActionParam { return nil }
func (a *blockingAction) Validate(params map[string]any) error { return nil }
func (a *blockingAction) Preview(ctx context.Context, params map[string]any) (*ActionPreview, error) {
	return &ActionPreview{Title: "预览"}, nil
}
func (a *blockingAction) Execute(ctx context.Context, params map[string]any) (*ActionResult, error) {
	if a.started != nil {
		a.started <- a.id
	}
	a.mu.Lock()
	if a.failNTimes > 0 {
		a.failNTimes--
		a.mu.Unlock()
		return &ActionResult{Success: false, Message: "模拟失败"}, nil
	}
	a.mu.Unlock()
	select {
	case <-a.release:
		return &ActionResult{Success: true, Message: "ok"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (a *blockingAction) Verify(ctx context.Context, params map[string]any) (*VerifyResult, error) {
	return &VerifyResult{OK: true, Message: "ok"}, nil
}

func setupExecutorTest(t *testing.T) *OpsStore {
	t.Helper()
	store := newTestOpsStore(t)
	oldStore, oldRemStore := opsStore, remEngine.store
	opsStore = store
	remEngine.store = store
	t.Cleanup(func() {
		opsStore, remEngine.store = oldStore, oldRemStore
	})

	// 清空执行器状态，避免测试间串扰
	taskExecutor.mu.Lock()
	taskExecutor.running = map[string]string{}
	taskExecutor.cancels = map[string]context.CancelFunc{}
	taskExecutor.mu.Unlock()
	return store
}

func registerBlockingAction(t *testing.T, a *blockingAction) {
	t.Helper()
	registerRemediationAction(a)
	t.Cleanup(func() { unregisterRemediationAction(a.id) })
}

func waitExecutionStatus(t *testing.T, store *OpsStore, execID string, statuses ...string) *TaskExecution {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e, err := store.GetTaskExecution(execID)
		if err == nil {
			for _, s := range statuses {
				if e.Status == s {
					// 稍候片刻，让执行器 goroutine 完成收尾写库（last_run / 审计），避免与测试清理竞争
					time.Sleep(200 * time.Millisecond)
					e, _ = store.GetTaskExecution(execID)
					return e
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	e, _ := store.GetTaskExecution(execID)
	t.Fatalf("执行 %s 未达到期望状态, 当前: %+v", execID, e)
	return nil
}

func TestTaskExecutorDuplicateLock(t *testing.T) {
	store := setupExecutorTest(t)
	release := make(chan struct{})
	ba := &blockingAction{id: "block_lock", release: release}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_lock", Name: "锁测试", Type: "cron", ActionID: "block_lock", TimeoutSec: 5}
	execID1, err := taskExecutor.Submit(task, "manual", "admin", nil)
	if err != nil {
		t.Fatalf("首次提交失败: %v", err)
	}
	// 同一任务并发第二次提交 → 执行锁拒绝
	if _, err := taskExecutor.Submit(task, "manual", "admin", nil); err == nil {
		t.Fatal("执行锁应拒绝并发提交")
	}
	// 不同任务可并发提交
	task2 := &Task{ID: "t_lock2", Name: "锁测试2", Type: "cron", ActionID: "block_lock", TimeoutSec: 5}
	if _, err := taskExecutor.Submit(task2, "manual", "admin", nil); err != nil {
		t.Fatalf("不同任务提交不应被锁拒绝: %v", err)
	}
	close(release)
	waitExecutionStatus(t, store, execID1, "success")
}

func TestTaskExecutorCancel(t *testing.T) {
	store := setupExecutorTest(t)
	release := make(chan struct{})
	ba := &blockingAction{id: "block_cancel", release: release}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_cancel", Name: "取消测试", Type: "cron", ActionID: "block_cancel", TimeoutSec: 30}
	execID, err := taskExecutor.Submit(task, "manual", "admin", nil)
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // 等待进入执行
	if err := taskExecutor.Cancel(execID); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	e := waitExecutionStatus(t, store, execID, "cancelled")
	if e.ErrorMessage == "" {
		t.Fatal("取消应记录原因")
	}
	// 已结束的执行无法再取消
	if err := taskExecutor.Cancel(execID); err == nil {
		t.Fatal("已结束的执行不应可取消")
	}
	close(release)
}

func TestTaskExecutorTimeout(t *testing.T) {
	store := setupExecutorTest(t)
	release := make(chan struct{})
	defer close(release)
	ba := &blockingAction{id: "block_timeout", release: release}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_timeout", Name: "超时测试", Type: "cron", ActionID: "block_timeout", TimeoutSec: 1}
	execID, err := taskExecutor.Submit(task, "manual", "admin", nil)
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	e := waitExecutionStatus(t, store, execID, "timeout")
	if e.DurationMS < 300 {
		t.Fatalf("超时耗时异常: %dms", e.DurationMS)
	}
}

func TestTaskExecutorRetryThenSuccess(t *testing.T) {
	store := setupExecutorTest(t)
	// release 预先关闭：动作只在 failNTimes 未耗尽时失败，耗尽后立即成功
	release := make(chan struct{})
	close(release)
	ba := &blockingAction{id: "block_retry", release: release, failNTimes: 2}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_retry", Name: "重试测试", Type: "cron", ActionID: "block_retry",
		TimeoutSec: 30, MaxAttempts: 3, RetryBackoffSec: 0}
	execID, err := taskExecutor.Submit(task, "manual", "admin", nil)
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	e := waitExecutionStatus(t, store, execID, "success")
	if e.Attempt != 3 {
		t.Fatalf("第 3 次尝试才成功, got attempt=%d", e.Attempt)
	}
}

func TestTaskExecutorRetryExhaustedGeneratesEvent(t *testing.T) {
	store := setupExecutorTest(t)
	ba := &blockingAction{id: "block_exhaust", release: make(chan struct{}), failNTimes: 99}
	registerBlockingAction(t, ba)

	task := &Task{ID: "t_exhaust", Name: "重试耗尽测试", Type: "cron", ActionID: "block_exhaust",
		TimeoutSec: 30, MaxAttempts: 2, RetryBackoffSec: 0}
	execID, err := taskExecutor.Submit(task, "manual", "admin", nil)
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	e := waitExecutionStatus(t, store, execID, "failed")
	if e.Attempt != 2 {
		t.Fatalf("应在第 2 次尝试后停止, got %d", e.Attempt)
	}
	events, total, _ := store.ListEvents("error", "task.failed", 10, 0)
	if total == 0 || len(events) == 0 {
		t.Fatal("达到 max_attempts 后应生成告警事件")
	}
}

func TestTaskExecutorConcurrencyLimit(t *testing.T) {
	store := setupExecutorTest(t)
	release := make(chan struct{})
	var once sync.Once
	closeRelease := func() { once.Do(func() { close(release) }) }
	defer closeRelease()
	started := make(chan string, 8)

	var execIDs []string
	for i := 0; i < 4; i++ {
		ba := &blockingAction{id: string(rune('a' + i)), release: release, started: started}
		registerBlockingAction(t, ba)
		task := &Task{ID: "t_cc" + string(rune('a'+i)), Name: "并发" + string(rune('a'+i)),
			Type: "cron", ActionID: ba.ID(), TimeoutSec: 60}
		execID, err := taskExecutor.Submit(task, "manual", "admin", nil)
		if err != nil {
			t.Fatalf("提交任务 %d 失败: %v", i, err)
		}
		execIDs = append(execIDs, execID)
	}
	// 全局并发上限 3：应恰好收到 3 个开始信号，第 4 个卡在信号量等待
	got := 0
	deadline := time.After(2 * time.Second)
collect:
	for got < 3 {
		select {
		case <-started:
			got++
		case <-deadline:
			break collect
		}
	}
	if got != 3 {
		t.Fatalf("并发上限应允许 3 个同时执行, 实际开始 %d", got)
	}
	select {
	case <-started:
		t.Fatal("第 4 个任务不应越过并发限制开始执行")
	case <-time.After(300 * time.Millisecond):
	}
	// 放行后全部结束
	closeRelease()
	for _, id := range execIDs {
		waitExecutionStatus(t, store, id, "success")
	}
	if taskExecutor.RunningCount() != 0 {
		t.Fatal("放行后仍有执行残留")
	}
}
