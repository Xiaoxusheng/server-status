package main

import (
	"testing"
	"time"
)

func TestAlertRuleCRUD(t *testing.T) {
	s := newTestOpsStore(t)

	r := &AlertRule{
		Name: "磁盘告警", Metric: alertMetricDisk, Op: "gt", Threshold: 85,
		DurationSec: 300, Severity: "warning", Channels: []string{"email", "webhook"},
		Enabled: true, CooldownSec: 600, MuteStart: "23:30", MuteEnd: "07:00",
	}
	saved, err := s.SaveAlertRule(r)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if saved.ID == "" {
		t.Fatal("ID 未生成")
	}

	list, err := s.ListAlertRules()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	got := list[0]
	if got.Name != "磁盘告警" || got.Threshold != 85 || len(got.Channels) != 2 || !got.Enabled {
		t.Fatalf("字段回读不符: %+v", got)
	}

	// 更新
	saved.Threshold = 90
	saved.Enabled = false
	if _, err := s.SaveAlertRule(saved); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := s.GetAlertRule(saved.ID)
	if again == nil || again.Threshold != 90 || again.Enabled {
		t.Fatalf("更新未生效: %+v", again)
	}
	if n, _ := s.ListAlertRules(); len(n) != 1 {
		t.Fatalf("更新后条数 = %d", len(n))
	}

	if err := s.DeleteAlertRule(saved.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if list, _ := s.ListAlertRules(); len(list) != 0 {
		t.Fatalf("删除后仍有 %d 条", len(list))
	}
}

func TestAlertEventsAndFiringCount(t *testing.T) {
	s := newTestOpsStore(t)

	base := time.Now().Add(-time.Minute)
	for i, st := range []string{"firing", "resolved"} {
		if err := s.AddAlertEvent(&AlertEvent{
			RuleID: "ar_1", RuleName: "磁盘告警", Metric: alertMetricDisk, Severity: "warning",
			Status: st, Value: 90, Threshold: 85, Message: "m", Notified: st == "firing",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("add event: %v", err)
		}
	}

	all, err := s.ListAlertEvents(50, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("events = %d, %v", len(all), err)
	}
	// 倒序：最新在前
	if all[0].Status != "resolved" {
		t.Errorf("事件未按时间倒序: %s", all[0].Status)
	}
	onlyFiring, _ := s.ListAlertEvents(50, "firing")
	if len(onlyFiring) != 1 {
		t.Errorf("firing 过滤 = %d", len(onlyFiring))
	}
	// 最新一条是 resolved，因此"当前触发中"应为 0
	if n := s.CountFiringAlerts(); n != 0 {
		t.Errorf("CountFiringAlerts = %d, want 0", n)
	}
	if n := s.CountAlertEventsSince(time.Now().Add(-time.Hour)); n != 2 {
		t.Errorf("CountAlertEventsSince = %d, want 2", n)
	}
}

func TestAlertsConfigRoundTrip(t *testing.T) {
	s := newTestOpsStore(t)

	def := s.GetAlertsConfig()
	if def.IntervalSec != 30 || def.Enabled {
		t.Errorf("默认配置不符: %+v", def)
	}

	cfg := alertsConfig{
		Enabled: true, IntervalSec: 15, MuteStart: "22:00", MuteEnd: "08:00",
		WebhookURL: "https://example.com/hook",
		Email:      &alertEmailConfig{Host: "smtp.qq.com", Port: 465, Username: "u@qq.com", Password: "p", To: []string{"a@b.com"}},
	}
	if err := s.SaveAlertsConfig(cfg); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	got := s.GetAlertsConfig()
	if !got.Enabled || got.IntervalSec != 15 || got.WebhookURL != cfg.WebhookURL {
		t.Fatalf("配置回读不符: %+v", got)
	}
	if got.Email == nil || got.Email.Host != "smtp.qq.com" || len(got.Email.To) != 1 {
		t.Fatalf("邮件配置回读不符: %+v", got.Email)
	}

	// 间隔过小应被夹到 10 秒，避免把机器打爆
	if err := s.SaveAlertsConfig(alertsConfig{IntervalSec: 1}); err != nil {
		t.Fatal(err)
	}
	if v := s.GetAlertsConfig().IntervalSec; v != 10 {
		t.Errorf("interval 未夹紧: %d", v)
	}
}

func TestEnsureDefaultAlertRules(t *testing.T) {
	s := newTestOpsStore(t)

	if err := s.ensureDefaultAlertRules(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rules, _ := s.ListAlertRules()
	if len(rules) != 4 {
		t.Fatalf("默认规则数 = %d, want 4", len(rules))
	}
	metrics := map[string]bool{}
	for _, r := range rules {
		metrics[r.Metric] = true
		if r.ID == "" || r.Name == "" {
			t.Errorf("默认规则字段不完整: %+v", r)
		}
	}
	for _, m := range []string{alertMetricDisk, alertMetricMem, alertMetricCert, alertMetricService} {
		if !metrics[m] {
			t.Errorf("缺少默认规则指标 %s", m)
		}
	}

	// 幂等：再次调用不应重复插入
	if err := s.ensureDefaultAlertRules(); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.ListAlertRules(); len(again) != 4 {
		t.Errorf("重复 seed 后条数 = %d", len(again))
	}
}

func TestInAlertMuteWindow(t *testing.T) {
	at := func(h, m int) time.Time {
		return time.Date(2026, 11, 11, h, m, 0, 0, time.Local)
	}
	cfg := alertsConfig{MuteStart: "23:00", MuteEnd: "08:00"}

	cases := []struct {
		name string
		now  time.Time
		rule *AlertRule
		want bool
	}{
		{"跨零点-深夜", at(2, 30), &AlertRule{}, true},
		{"跨零点-午夜前", at(23, 30), &AlertRule{}, true},
		{"跨零点-午间", at(12, 0), &AlertRule{}, false},
		{"跨零点-边界起", at(23, 0), &AlertRule{}, true},
		{"跨零点-边界终", at(8, 0), &AlertRule{}, false},
		{"规则级覆盖-命中", at(14, 0), &AlertRule{MuteStart: "13:00", MuteEnd: "15:00"}, true},
		{"规则级覆盖-未命中", at(22, 0), &AlertRule{MuteStart: "13:00", MuteEnd: "15:00"}, false},
		{"非跨零点", at(9, 30), &AlertRule{MuteStart: "09:00", MuteEnd: "18:00"}, true},
		// 规则里填了非法时间：宁可发通知也不要静默吞掉，因此判定为不静默
		{"非法格式不静默", at(2, 30), &AlertRule{MuteStart: "bad", MuteEnd: "also"}, false},
	}
	for _, c := range cases {
		if got := inAlertMuteWindow(c.now, c.rule, cfg); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}

	// 起止相同视为不静默
	if inAlertMuteWindow(at(23, 30), &AlertRule{MuteStart: "09:00", MuteEnd: "09:00"}, cfg) {
		t.Error("起止相同不应静默")
	}
}

// 真跑一次 evaluateOnce：验证"触发一次 → 不重复触发 → 条件消失后补恢复"
func TestAlertEngineEvaluateLifecycle(t *testing.T) {
	s := newTestOpsStore(t)
	prev := opsStore
	opsStore = s
	defer func() { opsStore = prev }()

	rule := &AlertRule{
		Name: "永远满足", Metric: alertMetricCPU, Op: "gt", Threshold: -1,
		DurationSec: 0, Severity: "warning", Channels: []string{"webhook"},
		Enabled: true, CooldownSec: 0,
	}
	saved, err := s.SaveAlertRule(rule)
	if err != nil {
		t.Fatal(err)
	}

	cfg := alertsConfig{Enabled: true}
	eng := &alertEngine{state: make(map[string]*alertRuleState)}

	// 第一轮：满足条件且 duration=0 → 立刻 firing
	eng.evaluateOnce(cfg)
	events, _ := s.ListAlertEvents(20, "")
	if len(events) != 1 || events[0].Status != "firing" {
		t.Fatalf("首轮应有 1 条 firing，实际 %d 条: %+v", len(events), events)
	}
	if events[0].Notified {
		t.Error("Webhook 未配置，不应标记为已通知")
	}

	// 第二轮：已经在 firing，不应重复产生事件
	eng.evaluateOnce(cfg)
	events, _ = s.ListAlertEvents(20, "")
	if len(events) != 1 {
		t.Fatalf("firing 期间不应重复落事件，实际 %d 条", len(events))
	}

	// 把阈值调到不可能满足，模拟指标回落 → 应补一条 resolved
	saved.Threshold = 1e9
	if _, err := s.SaveAlertRule(saved); err != nil {
		t.Fatal(err)
	}
	eng.evaluateOnce(cfg)
	events, _ = s.ListAlertEvents(20, "")
	if len(events) != 2 {
		t.Fatalf("恢复后应有 2 条事件，实际 %d 条", len(events))
	}
	if events[0].Status != "resolved" {
		t.Errorf("最新事件应为 resolved，实际 %s", events[0].Status)
	}
}
