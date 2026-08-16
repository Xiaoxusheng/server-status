package main

import (
	"strings"
	"testing"
)

func TestValidateManagedService(t *testing.T) {
	valid := &ManagedService{
		Name:        "douyin-upload",
		ExecStart:   "/opt/server-status/douyin-upload",
		WorkingDir:  "/opt/server-status/douyin",
		Args:        []string{"--config", "/opt/server-status/config.yaml"},
		User:        "root",
		Restart:     "on-failure",
		RestartSec:  5,
		Environment: []EnvVar{{Key: "PORT", Value: "9001"}},
	}
	if err := validateManagedService(valid); err != nil {
		t.Fatalf("valid service rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*ManagedService)
		bad  string
	}{
		{"名称含斜杠", func(s *ManagedService) { s.Name = "a/b" }, "服务名称"},
		{"名称路径穿越", func(s *ManagedService) { s.Name = ".." }, "服务名称"},
		{"相对程序路径", func(s *ManagedService) { s.ExecStart = "app" }, "绝对路径"},
		{"程序路径换行注入", func(s *ManagedService) { s.ExecStart = "/bin/app\nExecStart=/bin/evil" }, "不允许的字符"},
		{"非法Restart", func(s *ManagedService) { s.Restart = "always;rm" }, "Restart"},
		{"非法环境变量键", func(s *ManagedService) { s.Environment = []EnvVar{{Key: "A B", Value: "1"}} }, "环境变量键名"},
		{"非法用户", func(s *ManagedService) { s.User = "root;" }, "运行用户"},
	}
	for _, c := range cases {
		s := *valid
		c.mut(&s)
		err := validateManagedService(&s)
		if err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.bad) {
			t.Errorf("%s: error %q does not contain %q", c.name, err.Error(), c.bad)
		}
	}
}

func TestBuildUnitFile(t *testing.T) {
	s := &ManagedService{
		Name:        "demo",
		DisplayName: "Demo",
		ExecStart:   "/usr/bin/demo",
		WorkingDir:  "/srv/demo",
		Args:        []string{"--port", "9001", "--name", "hello world"},
		User:        "demo",
		Restart:     "always",
		RestartSec:  3,
		Environment: []EnvVar{{Key: "PORT", Value: "9001"}, {Key: "MODE", Value: "prod"}},
		AutoStart:   true,
	}
	content, err := buildUnitFile(s)
	if err != nil {
		t.Fatalf("buildUnitFile failed: %v", err)
	}
	for _, want := range []string{
		"[Unit]",
		"Description=Demo",
		"[Service]",
		"WorkingDirectory=/srv/demo",
		`ExecStart=/usr/bin/demo --port 9001 --name "hello world"`,
		"User=demo",
		"Restart=always",
		"RestartSec=3",
		`Environment="PORT=9001"`,
		`Environment="MODE=prod"`,
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("unit file missing %q\n%s", want, content)
		}
	}
}

func TestSystemdEscape(t *testing.T) {
	if v, err := systemdEscape("plain"); err != nil || v != "plain" {
		t.Errorf("plain: got %q err %v", v, err)
	}
	if v, err := systemdEscape("has space"); err != nil || v != `"has space"` {
		t.Errorf("space: got %q err %v", v, err)
	}
	if v, err := systemdEscape("100%"); err != nil || v != "100%%" {
		t.Errorf("percent: got %q err %v", v, err)
	}
	if _, err := systemdEscape("bad\nline"); err == nil {
		t.Error("newline should be rejected")
	}
	if _, err := systemdEscape(`bad"quote`); err == nil {
		t.Error("quote should be rejected")
	}
}

func TestClassifyListenAddr(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":      "public",
		"::":           "public",
		"127.0.0.1":    "local",
		"::1":          "local",
		"192.168.1.10": "private",
		"10.1.2.3":     "private",
		"172.20.0.1":   "private",
		"8.8.8.8":      "public",
		"not-an-ip":    "public",
	}
	for ip, want := range cases {
		if got := classifyListenAddr(ip); got != want {
			t.Errorf("classifyListenAddr(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestRuleSourceCIDRs(t *testing.T) {
	rule := PortRule{Source: "private"}
	cidrs, err := ruleSourceCIDRs(rule)
	if err != nil {
		t.Fatalf("private: %v", err)
	}
	if len(cidrs) != 3 {
		t.Errorf("private should expand to 3 CIDRs, got %d", len(cidrs))
	}
	rule = PortRule{Source: "ip", SourceValue: "1.2.3.4"}
	cidrs, err = ruleSourceCIDRs(rule)
	if err != nil {
		t.Fatalf("ip: %v", err)
	}
	if cidrs[0] != "1.2.3.4/32" {
		t.Errorf("ip: got %v", cidrs)
	}
	rule = PortRule{Source: "ip", SourceValue: "300.1.1.1"}
	if _, err := ruleSourceCIDRs(rule); err == nil {
		t.Error("invalid ip should error")
	}
	rule = PortRule{Source: "network", SourceValue: "192.168.1.0/24"}
	if _, err := ruleSourceCIDRs(rule); err != nil {
		t.Errorf("valid network rejected: %v", err)
	}
	rule = PortRule{Source: "network", SourceValue: "nonsense"}
	if _, err := ruleSourceCIDRs(rule); err == nil {
		t.Error("invalid network should error")
	}
}
