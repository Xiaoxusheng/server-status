package main

// ==================== 运维任务调度器 ====================
//
// 独立于 HTTP Handler 的守护协程：
//   - scheduleLoop：每 20s 检查到期任务（cron / interval / once），带执行锁防重复
//   - eventLoop：每 60s 评估事件触发条件（CPU/磁盘/服务停止/容器退出/IP 异常）
//   - OnSecurityFindings：扫描闭环回调，安全风险触发对应任务
// 绝不使用 for{time.Sleep} 阻塞式轮询单任务，也不在 HTTP 请求内同步执行任务。

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pscpu "github.com/shirou/gopsutil/v3/cpu"
	psdisk "github.com/shirou/gopsutil/v3/disk"
)

// ---------------- Cron 表达式（5 段，自实现，无第三方依赖） ----------------

// CronExpr 解析后的 cron 表达式
type CronExpr struct {
	minute, hour, dom, month, dow map[int]bool
	domRestricted, dowRestricted  bool
	raw                           string
}

var cronAliases = map[string]string{
	"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
	"@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *",
}

// ParseCron 解析 5 段 cron：分 时 日 月 周；支持 * , - / 与 @daily 等别名
func ParseCron(expr string) (*CronExpr, error) {
	expr = strings.TrimSpace(expr)
	if alias, ok := cronAliases[strings.ToLower(expr)]; ok {
		expr = alias
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron 表达式必须是 5 段（分 时 日 月 周），当前 %d 段", len(fields))
	}
	c := &CronExpr{
		minute: map[int]bool{}, hour: map[int]bool{}, dom: map[int]bool{},
		month: map[int]bool{}, dow: map[int]bool{}, raw: expr,
	}
	var err error
	if c.minute, err = parseCronField(fields[0], 0, 59); err != nil {
		return nil, fmt.Errorf("分钟段无效: %w", err)
	}
	if c.hour, err = parseCronField(fields[1], 0, 23); err != nil {
		return nil, fmt.Errorf("小时段无效: %w", err)
	}
	if c.dom, err = parseCronField(fields[2], 1, 31); err != nil {
		return nil, fmt.Errorf("日段无效: %w", err)
	}
	if c.month, err = parseCronField(fields[3], 1, 12); err != nil {
		return nil, fmt.Errorf("月段无效: %w", err)
	}
	if c.dow, err = parseCronField(fields[4], 0, 7); err != nil {
		return nil, fmt.Errorf("周段无效: %w", err)
	}
	if c.dow[7] { // 7 视作周日（0）
		c.dow[0] = true
		delete(c.dow, 7)
	}
	c.domRestricted = fields[2] != "*"
	c.dowRestricted = fields[4] != "*"
	if len(c.minute) == 0 || len(c.hour) == 0 || len(c.month) == 0 {
		return nil, fmt.Errorf("cron 表达式存在空值段")
	}
	return c, nil
}

func parseCronField(field string, min, max int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("存在空子段")
		}
		step := 1
		if idx := strings.Index(part, "/"); idx >= 0 {
			s, err := strconv.Atoi(part[idx+1:])
			if err != nil || s <= 0 || s > max-min+1 {
				return nil, fmt.Errorf("步长 %q 无效", part[idx+1:])
			}
			step = s
			part = part[:idx]
		}
		lo, hi := min, max
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(bounds[0])
			b, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || a < min || b > max || a > b {
				return nil, fmt.Errorf("范围 %q 无效", part)
			}
			lo, hi = a, b
		default:
			v, err := strconv.Atoi(part)
			if err != nil || v < min || v > max {
				return nil, fmt.Errorf("数值 %q 超出范围 [%d,%d]", part, min, max)
			}
			lo, hi = v, v
		}
		for v := lo; v <= hi; v += step {
			out[v] = true
		}
	}
	return out, nil
}

// Next 计算.after 之后的下一个触发时间（精确到分钟）
func (c *CronExpr) Next(after time.Time) time.Time {
	t := after.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if !c.month[int(t.Month())] {
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()).AddDate(0, 1, 0)
			continue
		}
		if !c.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if !c.hour[t.Hour()] {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if !c.minute[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// NextAfter 返回 after 之后且不早于 minTime 的下一个触发时间
func (c *CronExpr) NextAfter(after, minTime time.Time) time.Time {
	n := c.Next(after)
	if !n.IsZero() && n.Before(minTime) {
		return c.Next(minTime)
	}
	return n
}

func (c *CronExpr) dayMatches(t time.Time) bool {
	domOK := c.dom[t.Day()]
	dowOK := c.dow[int(t.Weekday())]
	switch {
	case c.domRestricted && c.dowRestricted:
		return domOK || dowOK // 标准 cron 语义：两者都受限时取并集
	case c.domRestricted:
		return domOK
	case c.dowRestricted:
		return dowOK
	default:
		return true
	}
}

// String 返回原始表达式
func (c *CronExpr) String() string { return c.raw }

// DescribeCron 生成人类可读描述（常用模式）
func DescribeCron(expr string) string {
	e := strings.TrimSpace(expr)
	switch strings.ToLower(e) {
	case "@hourly", "0 * * * *":
		return "每小时整点"
	case "@daily", "0 0 * * *":
		return "每天 00:00"
	case "@weekly", "0 0 * * 0":
		return "每周日 00:00"
	case "@monthly", "0 0 1 * *":
		return "每月 1 日 00:00"
	}
	fields := strings.Fields(e)
	if len(fields) != 5 {
		return e
	}
	step := func(s string) (int, bool) {
		if strings.HasPrefix(s, "*/") {
			if n, err := strconv.Atoi(s[2:]); err == nil {
				return n, true
			}
		}
		return 0, false
	}
	if n, ok := step(fields[0]); ok && fields[1] == "*" {
		return fmt.Sprintf("每 %d 分钟", n)
	}
	if n, ok := step(fields[1]); ok && fields[0] == "0" {
		return fmt.Sprintf("每 %d 小时", n)
	}
	if m, err := strconv.Atoi(fields[0]); err == nil {
		if h, err := strconv.Atoi(fields[1]); err == nil && fields[2] == "*" && fields[3] == "*" && fields[4] == "*" {
			return fmt.Sprintf("每天 %02d:%02d", h, m)
		}
		if h, err := strconv.Atoi(fields[1]); err == nil && fields[2] == "*" && fields[3] == "*" {
			if w, err := strconv.Atoi(fields[4]); err == nil {
				days := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}
				return fmt.Sprintf("每周%s %02d:%02d", days[w%7], h, m)
			}
		}
	}
	return e
}

// ValidateCronExpr 校验 cron 是否合法（创建/更新任务时调用）
func ValidateCronExpr(expr string) error {
	_, err := ParseCron(expr)
	return err
}

// ---------------- 调度器 ----------------

type TaskScheduler struct {
	mu          sync.Mutex
	store       *OpsStore
	lastEvent   map[string]time.Time // 事件任务最近一次触发（内存加速，落库看 last_run_at）
	securityFired map[string]time.Time
}

var taskScheduler = &TaskScheduler{lastEvent: map[string]time.Time{}, securityFired: map[string]time.Time{}}

// Start 启动调度守护协程
func (s *TaskScheduler) Start(store *OpsStore) {
	s.store = store
	go s.scheduleLoop()
	go s.eventLoop()
}

// computeNextRun 计算任务下次执行时间
func (s *TaskScheduler) computeNextRun(t *Task, after time.Time) *time.Time {
	var next time.Time
	switch t.Type {
	case "cron":
		expr, err := ParseCron(t.Schedule)
		if err != nil {
			return nil
		}
		next = expr.Next(after)
	case "interval":
		if t.IntervalSec <= 0 {
			return nil
		}
		next = after.Add(time.Duration(t.IntervalSec) * time.Second)
	case "once":
		if t.RunAt == nil {
			return nil
		}
		next = *t.RunAt
	default:
		return nil
	}
	if next.IsZero() {
		return nil
	}
	return &next
}

// scheduleLoop 到期任务检查（含一次性任务与执行锁）
func (s *TaskScheduler) scheduleLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.tickSchedule()
	}
}

func (s *TaskScheduler) tickSchedule() {
	if s.store == nil {
		return
	}
	tasks, err := s.store.ListTasks()
	if err != nil {
		log.Printf("读取任务列表失败: %v", err)
		return
	}
	now := time.Now()
	for i := range tasks {
		t := tasks[i]
		if !t.Enabled {
			continue
		}
		switch t.Type {
		case "cron", "interval":
			next := t.NextRunAt
			if next == nil || next.Before(now.Add(-24*time.Hour)) {
				// 未初始化或严重漂移：重新计算
				next = s.computeNextRun(&t, now)
				if next == nil {
					continue
				}
				s.store.UpdateTaskRuntime(t.ID, next, t.LastRunAt, t.LastStatus)
				t.NextRunAt = next
			}
			if now.Before(*t.NextRunAt) {
				continue
			}
			// 执行锁：上一轮未结束则本轮跳过（记录 skipped 便于排查任务堆积）
			if n, _ := s.store.CountRunningTaskExecutions(t.ID); n > 0 {
				s.store.AddTaskExecution(&TaskExecution{
					ID: genOpsID("tex"), TaskID: t.ID, TaskName: t.Name, Status: "skipped",
					TriggerType: "schedule", Operator: "system",
					ErrorMessage: "上一轮执行尚未结束，本次触发已跳过（执行锁生效）",
					Steps:        map[string]string{"lock": "running lock held"},
				})
				adv := s.computeNextRun(&t, now)
				if adv != nil {
					s.store.UpdateTaskRuntime(t.ID, adv, t.LastRunAt, t.LastStatus)
				}
				continue
			}
			// 触发并推进下次执行时间
			adv := s.computeNextRun(&t, now)
			if adv != nil {
				s.store.UpdateTaskRuntime(t.ID, adv, t.LastRunAt, t.LastStatus)
			}
			if _, err := taskExecutor.Submit(&t, "schedule", "system", nil); err != nil {
				log.Printf("调度任务 %s 失败: %v", t.Name, err)
			}
		case "once":
			if t.RunAt == nil || now.Before(*t.RunAt) {
				continue
			}
			// 触发后自动停用，防止重复执行
			disabled := false
			s.store.UpdateTaskRuntime(t.ID, nil, t.LastRunAt, t.LastStatus)
			t.Enabled = false
			if err := s.store.SaveTask(&t); err != nil {
				log.Printf("停用一次性任务失败: %v", err)
			}
			disabled = true
			_ = disabled
			if n, _ := s.store.CountRunningTaskExecutions(t.ID); n > 0 {
				continue
			}
			if _, err := taskExecutor.Submit(&t, "schedule", "system", nil); err != nil {
				log.Printf("执行一次性任务 %s 失败: %v", t.Name, err)
			}
		}
	}
}

// RunNow 立即执行任务（HTTP 入口；audit 在 executor 内完成）
func (s *TaskScheduler) RunNow(taskID, operator string, r *http.Request) (string, error) {
	if s.store == nil {
		return "", fmt.Errorf("运维中心存储未就绪")
	}
	t, err := s.store.GetTask(taskID)
	if err != nil {
		return "", fmt.Errorf("任务不存在")
	}
	if !t.Enabled {
		return "", fmt.Errorf("任务已停用，请先启用")
	}
	return taskExecutor.Submit(t, "manual", operator, r)
}

// CancelExecution 取消执行中的任务
func (s *TaskScheduler) CancelExecution(execID string) error {
	return taskExecutor.Cancel(execID)
}

// ---------------- 事件触发 ----------------

// eventLoop 事件触发评估（60s 周期，阈值型触发天然允许近似精度）
func (s *TaskScheduler) eventLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.evaluateEventTriggers()
	}
}

func (s *TaskScheduler) evaluateEventTriggers() {
	if s.store == nil {
		return
	}
	tasks, err := s.store.ListTasks()
	if err != nil {
		return
	}
	now := time.Now()
	for i := range tasks {
		t := tasks[i]
		if !t.Enabled || t.Type != "event" || t.Trigger == nil {
			continue
		}
		tr := t.Trigger
		cooldown := time.Duration(tr.CooldownSec) * time.Second
		if cooldown <= 0 {
			cooldown = 10 * time.Minute
		}
		// 冷却：内存记录 + 落库 last_run_at 双保险（重启后仍生效）
		s.mu.Lock()
		last := s.lastEvent[t.ID]
		s.mu.Unlock()
		if last.IsZero() && t.LastRunAt != nil {
			last = *t.LastRunAt
		}
		if !last.IsZero() && now.Sub(last) < cooldown {
			continue
		}
		fired, detail := s.evaluateTrigger(tr)
		if !fired {
			continue
		}
		s.mu.Lock()
		s.lastEvent[t.ID] = now
		s.mu.Unlock()
		s.store.AddEvent(&SecurityEvent{
			Level: "warning", Type: "task.event_fired",
			Title:  fmt.Sprintf("事件触发任务：%s", t.Name),
			Source: "任务中心", RefID: t.ID, Detail: detail,
		})
		if _, err := taskExecutor.Submit(&t, "event", "system", nil); err != nil {
			log.Printf("事件触发任务 %s 失败: %v", t.Name, err)
		}
	}
}

// evaluateTrigger 评估单个事件触发条件，返回 (是否触发, 描述)
func (s *TaskScheduler) evaluateTrigger(tr *TaskTrigger) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch tr.Type {
	case "cpu_high":
		threshold := tr.Threshold
		if threshold <= 0 {
			threshold = 90
		}
		percents, err := pscpu.Percent(0, false)
		if err != nil || len(percents) == 0 {
			return false, ""
		}
		cpu := percents[0]
		if cpu >= float64(threshold) {
			return true, fmt.Sprintf("CPU 使用率 %.0f%% 超过阈值 %d%%", cpu, threshold)
		}
	case "disk_high":
		threshold := tr.Threshold
		if threshold <= 0 {
			threshold = 90
		}
		mount := "/"
		if runtime.GOOS == "windows" {
			mount = filepathDrive(dataRoot())
		}
		if du, err := psdisk.Usage(mount); err == nil && du.UsedPercent >= float64(threshold) {
			return true, fmt.Sprintf("磁盘 %s 使用率 %.0f%% 超过阈值 %d%%", mount, du.UsedPercent, threshold)
		}
	case "service_stopped":
		svcs, ok := getCachedServicesStale()
		if !ok {
			return false, ""
		}
		for _, svc := range svcs {
			if svc == nil {
				continue
			}
			name := strings.TrimSuffix(svc.Name, ".service")
			if tr.Match != "" && name != tr.Match {
				continue
			}
			if svc.Status != "RUNNING" && svc.Status != "STARTING" {
				return true, fmt.Sprintf("服务 %s 当前状态 %s", name, svc.Status)
			}
		}
	case "docker_container_exit":
		out, err := dockerCommandOutput(ctx, "ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Status}}")
		if err != nil {
			return false, ""
		}
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
			if len(parts) < 3 {
				continue
			}
			if tr.Match != "" && parts[0] != tr.Match {
				continue
			}
			if parts[1] == "exited" && isAbnormalContainer(parts[1], strings.ToLower(parts[2])) {
				return true, fmt.Sprintf("容器 %s 异常退出（%s）", parts[0], parts[2])
			}
		}
	case "ip_abnormal":
		threshold := tr.Threshold
		if threshold <= 0 {
			threshold = 5
		}
		antiCrawler.RLock()
		active := 0
		for _, b := range antiCrawler.blockedIPs {
			if b != nil && time.Now().Before(b.BlockedUntil) {
				active++
			}
		}
		antiCrawler.RUnlock()
		if active >= threshold {
			return true, fmt.Sprintf("当前封禁 IP 数量 %d 超过阈值 %d", active, threshold)
		}
	}
	return false, ""
}

// OnSecurityFindings 扫描闭环：新风险触发 security_finding 类型任务
func (s *TaskScheduler) OnSecurityFindings(findings []SecurityFinding) {
	if s.store == nil || len(findings) == 0 {
		return
	}
	tasks, err := s.store.ListTasks()
	if err != nil {
		return
	}
	now := time.Now()
	for i := range tasks {
		t := tasks[i]
		if !t.Enabled || t.Type != "event" || t.Trigger == nil || t.Trigger.Type != "security_finding" {
			continue
		}
		minSev := t.Trigger.Match
		if minSev == "" {
			minSev = "high"
		}
		cooldown := time.Duration(t.Trigger.CooldownSec) * time.Second
		if cooldown <= 0 {
			cooldown = time.Hour
		}
		s.mu.Lock()
		last := s.securityFired[t.ID]
		s.mu.Unlock()
		if last.IsZero() && t.LastRunAt != nil {
			last = *t.LastRunAt
		}
		if !last.IsZero() && now.Sub(last) < cooldown {
			continue
		}
		for _, f := range findings {
			if severityRank(f.Severity) >= severityRank(minSev) {
				s.mu.Lock()
				s.securityFired[t.ID] = now
				s.mu.Unlock()
				s.store.AddEvent(&SecurityEvent{
					Level: "warning", Type: "task.event_fired",
					Title:  fmt.Sprintf("安全风险触发任务：%s", t.Name),
					Source: "安全中心", RefID: t.ID,
					Detail: fmt.Sprintf("风险「%s」（%s）满足触发条件（%s 及以上）", f.Title, f.Severity, minSev),
				})
				if _, err := taskExecutor.Submit(&t, "event", "system", nil); err != nil {
					log.Printf("安全事件触发任务 %s 失败: %v", t.Name, err)
				}
				break
			}
		}
	}
}

// upcomingUpcoming 取未来将执行的任务（任务中心「即将执行」时间线）
func (s *TaskScheduler) upcoming(limit int) []Task {
	if s.store == nil {
		return nil
	}
	tasks, err := s.store.ListTasks()
	if err != nil {
		return nil
	}
	out := make([]Task, 0, limit)
	for _, t := range tasks {
		if t.Enabled && t.NextRunAt != nil && (t.Type == "cron" || t.Type == "interval") {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextRunAt.Before(*out[j].NextRunAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func filepathDrive(path string) string {
	vol := filepath.VolumeName(path)
	if vol == "" {
		return "C:"
	}
	return vol + `\`
}
