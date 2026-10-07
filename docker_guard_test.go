// docker_guard_test.go -- 容器守护逻辑单元测试
package main

import (
	"testing"
	"time"
)

// TestIsNormalExitStatus 验证退出码判定：0/143 为正常停止（手动 stop），其余为异常
func TestIsNormalExitStatus(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"Exited (0) 5 minutes ago", true},
		{"Exited (143) 2 seconds ago", true},
		{"Exited (137) 3 minutes ago", false}, // OOM Kill / 强杀
		{"Exited (1) just now", false},        // 崩溃
		{"Exited (255) 1 hour ago", false},
		{"Up 6 hours (healthy)", false},       // 非退出状态文本无退出码
		{"Dead", false},
	}
	for _, c := range cases {
		if got := isNormalExitStatus(c.status); got != c.want {
			t.Errorf("isNormalExitStatus(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}

// TestPruneRestarts 验证滑动窗口清理：窗口内保留、窗口外丢弃
func TestPruneRestarts(t *testing.T) {
	now := time.Now()
	ts := []time.Time{
		now.Add(-10 * time.Minute),
		now.Add(-30 * time.Minute),
		now.Add(-61 * time.Minute), // 60 分钟窗口外
		now.Add(-2 * time.Hour),    // 窗口外
	}
	kept := pruneRestarts(ts, now, time.Hour)
	if len(kept) != 2 {
		t.Fatalf("pruneRestarts 保留 %d 条, want 2", len(kept))
	}
	// 底层数组复用：前两条应为窗口内的时间戳
	if !kept[0].Equal(ts[0]) || !kept[1].Equal(ts[1]) {
		t.Error("pruneRestarts 保留了错误的时间戳")
	}
}

// TestExcludeContainer 验证排除规则：精确匹配与 glob 模式
func TestExcludeContainer(t *testing.T) {
	cfg := dockerGuardConfig{
		Exclude:     map[string]bool{"openlist": true},
		ExcludePats: []string{"temp-*", "test.?"},
	}
	for name, want := range map[string]bool{
		"openlist":   true,
		"temp-cache": true,
		"test.1":     true,
		"openlist2":  false,
		"myapp":      false,
	} {
		if got := cfg.isExcludedContainer(name); got != want {
			t.Errorf("isExcludedContainer(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestLoadDockerGuardConfigDefaults 无配置文件时应返回安全的默认值且不启用
func TestLoadDockerGuardConfigDefaults(t *testing.T) {
	t.Setenv("SERVER_STATUS_HOME", t.TempDir()) // 空目录，无 config.json
	cfg := loadDockerGuardConfig()
	if cfg.Enabled {
		t.Error("默认 Enabled 应为 false")
	}
	if cfg.CheckInterval != 30*time.Second {
		t.Errorf("默认 CheckInterval = %v, want 30s", cfg.CheckInterval)
	}
	if cfg.MaxRestarts != 3 {
		t.Errorf("默认 MaxRestarts = %d, want 3", cfg.MaxRestarts)
	}
	if cfg.AlertEmail != nil {
		t.Error("无配置时 AlertEmail 应为 nil")
	}
}

// TestHandleAbnormalRestartLimit 验证超限分支：不重启、更新告警时间、清零计数重新开始
func TestHandleAbnormalRestartLimit(t *testing.T) {
	g := &dockerGuard{
		cfg: dockerGuardConfig{
			MaxRestarts: 3,
			Window:      time.Hour,
			Cooldown:    30 * time.Minute,
		},
		states:   map[string]*containerGuardState{},
		baseline: map[string]bool{},
	}
	now := time.Now()
	st := &containerGuardState{
		restarts:  []time.Time{now.Add(-time.Minute), now.Add(-2 * time.Minute), now.Add(-3 * time.Minute)},
		lastAlert: time.Time{},
	}
	g.states["crashy"] = st

	// 已达上限且未告警：应发送告警（无 SMTP 配置仅打日志）并清零计数，冷却期内不再动作
	g.handleAbnormalLocked("crashy", "exited", "Exited (1) 5 seconds ago", now)
	if !st.lastAlert.Equal(now) {
		t.Errorf("lastAlert 未更新: %v", st.lastAlert)
	}
	if len(st.restarts) != 0 {
		t.Errorf("超限告警后 restarts 应清零, got %d", len(st.restarts))
	}

	// 冷却期内：不应重复告警
	g.handleAbnormalLocked("crashy", "exited", "Exited (1) 5 seconds ago", now.Add(time.Minute))
	if !st.lastAlert.Equal(now) {
		t.Error("冷却期内不应重复告警")
	}
}

// TestSendAlertEmailValidation 验证 SMTP 配置不完整时的快速失败
func TestSendAlertEmailValidation(t *testing.T) {
	err := sendAlertEmail(&alertEmailConfig{Host: "smtp.qq.com"}, "subj", "<p>body</p>")
	if err == nil {
		t.Error("无收件人时应返回错误")
	}
}
