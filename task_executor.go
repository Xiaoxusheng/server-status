package main

// ==================== 运维任务执行器 ====================
//
// 并发限制 + 超时 + 取消 + 失败重试 + 执行锁 + 状态追踪。
// 任务只能执行 Action Registry 中的白名单动作，并强制 Verify。

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// TaskExecutor 任务执行器
type TaskExecutor struct {
	mu      sync.Mutex
	running map[string]string          // taskID → executionID（执行锁：同一任务不能并发两轮）
	cancels map[string]context.CancelFunc // executionID → cancel
	sem     chan struct{}              // 并发限制
}

var taskExecutor = &TaskExecutor{
	running: map[string]string{},
	cancels: map[string]context.CancelFunc{},
	sem:     make(chan struct{}, 3), // 最多 3 个任务并发执行
}

// Submit 提交一次执行（异步）。返回 executionID。
// 同一任务已有一轮在跑时返回错误（执行锁）。
func (x *TaskExecutor) Submit(t *Task, triggerType, operator string, r *http.Request) (string, error) {
	store := opsStore // 提交时捕获，执行期不依赖可变全局
	if store == nil {
		return "", fmt.Errorf("运维中心存储未就绪")
	}
	action, ok := getRemediationAction(t.ActionID)
	if !ok {
		return "", fmt.Errorf("动作 %s 不在白名单中，任务无法执行", t.ActionID)
	}
	if err := action.Validate(t.Parameters); err != nil {
		return "", fmt.Errorf("任务参数校验失败: %w", err)
	}

	x.mu.Lock()
	if _, busy := x.running[t.ID]; busy {
		x.mu.Unlock()
		return "", fmt.Errorf("任务「%s」正在执行中，请勿重复触发", t.Name)
	}
	exec := &TaskExecution{
		ID: genOpsID("tex"), TaskID: t.ID, TaskName: t.Name, Status: "running",
		TriggerType: triggerType, Attempt: 1,
		MaxAttempts: maxInt(t.MaxAttempts, 1),
		Operator:    operator,
		CreatedAt:   time.Now(),
	}
	if err := store.AddTaskExecution(exec); err != nil {
		x.mu.Unlock()
		return "", fmt.Errorf("写入执行记录失败: %w", err)
	}
	x.running[t.ID] = exec.ID
	x.mu.Unlock()

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("任务执行 panic: task=%s err=%v", t.Name, rec)
				x.finish(store, exec, t, "failed", fmt.Sprintf("内部错误: %v", rec), r)
			}
		}()
		x.run(store, t, exec, action, r)
	}()
	opsHub.broadcast(map[string]any{
		"type": "task.started", "task_id": t.ID, "task_name": t.Name,
		"execution_id": exec.ID, "trigger": triggerType,
	})
	return exec.ID, nil
}

// run 执行主体：并发闸门 → 超时控制 → 重试 → Verify → 回写
func (x *TaskExecutor) run(store *OpsStore, t *Task, exec *TaskExecution, action RemediationAction, r *http.Request) {
	// 并发限制：等待空位（防止任务堆积耗尽资源）
	select {
	case x.sem <- struct{}{}:
		defer func() { <-x.sem }()
	case <-time.After(5 * time.Minute):
		x.finish(store, exec, t, "skipped", "等待执行槽位超时，已跳过本次触发", r)
		return
	}

	timeoutSec := t.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 600
	}
	timeout := time.Duration(timeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	x.mu.Lock()
	x.cancels[exec.ID] = cancel
	x.mu.Unlock()
	defer cancel()
	defer func() {
		x.mu.Lock()
		delete(x.cancels, exec.ID)
		x.mu.Unlock()
	}()

	now := time.Now()
	exec.StartedAt = &now
	exec.Steps = map[string]string{}
	store.UpdateTaskExecution(exec)

	// 若动作需要参数而任务参数含 "$finding" 占位则拒绝（任务参数必须具体）
	params := t.Parameters
	for k, v := range params {
		if s, ok := v.(string); ok && s == "$finding" {
			x.finish(store, exec, t, "failed", fmt.Sprintf("任务参数 %s 不能使用风险上下文占位符（仅修复策略支持）", k), r)
			return
		}
	}

	maxAttempts := maxInt(t.MaxAttempts, 1)
	backoff := time.Duration(maxInt(t.RetryBackoffSec, 0)) * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		exec.Attempt = attempt
		if attempt > 1 {
			exec.Steps[fmt.Sprintf("retry_%d", attempt)] = "开始重试"
			store.UpdateTaskExecution(exec)
		}

		result, execErr := action.Execute(ctx, params)
		if result != nil {
			exec.Steps["execute"] = result.Message
		}
		// 取消 / 超时检查
		if ctx.Err() == context.Canceled {
			x.finish(store, exec, t, "cancelled", "已被人工取消", r)
			return
		}
		if ctx.Err() == context.DeadlineExceeded {
			exec.Steps["timeout"] = fmt.Sprintf("超过 %s 限时", timeout)
			x.finish(store, exec, t, "timeout", fmt.Sprintf("执行超过 %s 限时被终止", timeout), r)
			return
		}
		if execErr != nil || result == nil || !result.Success {
			msg := "执行失败"
			if execErr != nil {
				msg = execErr.Error()
			} else if result != nil && result.Message != "" {
				msg = result.Message
			}
			exec.ErrorMessage = truncateString(msg, 400)
			if attempt < maxAttempts {
				exec.Steps[fmt.Sprintf("attempt_%d", attempt)] = "失败：" + truncateString(msg, 200)
				store.UpdateTaskExecution(exec)
				if backoff > 0 {
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						if ctx.Err() == context.Canceled {
							x.finish(store, exec, t, "cancelled", "重试等待期间被取消", r)
						} else {
							x.finish(store, exec, t, "timeout", "重试等待期间超时", r)
						}
						return
					}
				}
				continue // 重试
			}
			// 达到最大尝试次数：停止重试，生成告警事件，转入人工处理
			x.finish(store, exec, t, "failed", msg, r)
			opsStore.AddEvent(&SecurityEvent{
				Level: "error", Type: "task.failed",
				Title:  fmt.Sprintf("任务失败：%s", t.Name),
				Source: "任务中心", RefID: t.ID,
				Detail: fmt.Sprintf("重试 %d 次后仍失败：%s", maxAttempts, truncateString(msg, 200)),
			})
			return
		}

		// Verify：不能只看执行成功，必须验证最终状态
		vr, verifyErr := action.Verify(ctx, params)
		if ctx.Err() == context.Canceled {
			x.finish(store, exec, t, "cancelled", "已被人工取消", r)
			return
		}
		if ctx.Err() == context.DeadlineExceeded {
			x.finish(store, exec, t, "timeout", fmt.Sprintf("执行超过 %s 限时被终止", timeout), r)
			return
		}
		if verifyErr != nil {
			vr = &VerifyResult{OK: false, Message: verifyErr.Error()}
		}
		if vr != nil {
			exec.Steps["verify"] = vr.Message
		}
		if verifyErr != nil || vr == nil || !vr.OK {
			msg := "验证未通过"
			if verifyErr != nil {
				msg = "验证出错: " + verifyErr.Error()
			} else if vr != nil && vr.Message != "" {
				msg = vr.Message
			}
			exec.ErrorMessage = truncateString(msg, 400)
			if attempt < maxAttempts {
				exec.Steps[fmt.Sprintf("attempt_%d", attempt)] = "验证未通过：" + truncateString(msg, 200)
				store.UpdateTaskExecution(exec)
				if backoff > 0 {
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						x.finish(store, exec, t, "cancelled", "重试等待期间被取消", r)
						return
					}
				}
				continue
			}
			x.finish(store, exec, t, "failed", msg, r)
			opsStore.AddEvent(&SecurityEvent{
				Level: "error", Type: "task.failed",
				Title:  fmt.Sprintf("任务失败：%s", t.Name),
				Source: "任务中心", RefID: t.ID,
				Detail: fmt.Sprintf("执行成功但验证未通过（重试 %d 次）：%s", maxAttempts, truncateString(msg, 200)),
			})
			return
		}
		// 成功
		x.finish(store, exec, t, "success", "", r)
		return
	}
}

// finish 收尾：释放执行锁、写执行记录、回写任务状态、审计、广播
func (x *TaskExecutor) finish(store *OpsStore, exec *TaskExecution, t *Task, status, message string, r *http.Request) {
	x.mu.Lock()
	if x.running[t.ID] == exec.ID {
		delete(x.running, t.ID)
	}
	x.mu.Unlock()

	now := time.Now()
	exec.Status = status
	if message != "" {
		exec.ErrorMessage = truncateString(message, 400)
	}
	exec.FinishedAt = &now
	if !exec.StartedAt.IsZero() {
		exec.DurationMS = now.Sub(*exec.StartedAt).Milliseconds()
	}
	if exec.Steps == nil {
		exec.Steps = map[string]string{}
	}
	if err := store.UpdateTaskExecution(exec); err != nil {
		log.Printf("更新任务执行记录失败: %v", err)
	}
	store.UpdateTaskLastRun(t.ID, now, status)

	// 审计（不记录敏感参数）
	detail := fmt.Sprintf("task=%q action=%s trigger=%s attempt=%d/%d result=%s 耗时=%dms %s",
		t.Name, t.ActionID, exec.TriggerType, exec.Attempt, exec.MaxAttempts, status, exec.DurationMS, message)
	if exec.TriggerType == "manual" {
		clientIP := ""
		if r != nil {
			clientIP = getClientIP(r)
		}
		writeAuditEntry(exec.Operator, clientIP, "task.execute", detail)
	} else {
		writeAuditEntry("system", "", "task.execute", detail)
	}

	opsHub.broadcast(map[string]any{
		"type": "task." + status, "task_id": t.ID, "task_name": t.Name,
		"execution_id": exec.ID, "status": status, "message": message,
	})
	log.Printf("⚙️ 任务「%s」执行结束: %s（%dms）%s", t.Name, status, exec.DurationMS, message)
}

// Cancel 取消执行中的任务
func (x *TaskExecutor) Cancel(execID string) error {
	x.mu.Lock()
	cancel, ok := x.cancels[execID]
	x.mu.Unlock()
	if !ok {
		return fmt.Errorf("该执行不在运行中，无法取消")
	}
	cancel()
	return nil
}

// RunningExecutionID 查询任务当前执行的 executionID
func (x *TaskExecutor) RunningExecutionID(taskID string) (string, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	id, ok := x.running[taskID]
	return id, ok
}

// RunningCount 当前并发执行中的任务数
func (x *TaskExecutor) RunningCount() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.running)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
