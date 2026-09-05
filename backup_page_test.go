package main

import (
	"strings"
	"testing"
)

// 日志样例：按真实日志的时间正序追加，覆盖 中断 / 成功 / 失败 / 成功(含清理) 四轮运行
const backupLogSample = `2026-09-02 03:30:01 本地打包完成 private-notes-20260902-033001.tar.gz.enc (596M,已加密)
2026-09-02 03:31:00 本地打包完成 private-notes-20260902-033002.tar.gz.enc (596M,已加密)
2026-09-02 03:31:58 上传成功 → /home/备份/私人手记/private-notes-20260902-033002.tar.gz.enc
2026-09-02 03:31:58 备份完成 ✔
2026-09-03 03:30:01 本地打包完成 private-notes-20260903-033001.tar.gz.enc (598M,已加密)
2026-09-03 03:30:19 备份失败: 上传失败 HTTP 401
2026-09-04 03:30:02 本地打包完成 private-notes-20260904-033001.tar.gz.enc (601M,已加密)
2026-09-04 03:32:44 上传成功 → /home/备份/私人手记/private-notes-20260904-033001.tar.gz.enc
2026-09-04 03:32:44 备份完成 ✔
2026-09-05 03:30:01 本地打包完成 private-notes-20260905-033001.tar.gz.enc (606M,已加密)
2026-09-05 03:33:22 上传成功 → /home/备份/私人手记/private-notes-20260905-033001.tar.gz.enc
2026-09-05 03:33:22 清理云端旧备份 private-notes-20260806-033001.tar.gz.enc
2026-09-05 03:33:22 备份完成 ✔
`

func TestParseBackupRuns(t *testing.T) {
	recs := parseBackupRuns(strings.Split(backupLogSample, "\n"))
	if len(recs) != 5 {
		t.Fatalf("期望解析出 5 轮运行，实际 %d: %+v", len(recs), recs)
	}
	// 正序：最新一轮在最后
	last := recs[4]
	if last.Time != "2026-09-05 03:30:01" || last.Status != "success" {
		t.Errorf("最后一轮应为 09-05 成功，得到 %s %s", last.Time, last.Status)
	}
	if last.File != "private-notes-20260905-033001.tar.gz.enc" || last.Size != "606M" {
		t.Errorf("文件/大小解析错误: %s %s", last.File, last.Size)
	}
	if last.Duration != "3m21s" {
		t.Errorf("耗时解析错误: %s", last.Duration)
	}
	if !strings.Contains(last.Detail, "已加密") || !strings.Contains(last.Detail, "清理旧份 ×1") {
		t.Errorf("说明应含加密与清理标记: %s", last.Detail)
	}
	// 失败轮：状态 fail，原因进说明，耗时 18s
	fail := recs[2]
	if fail.Status != "fail" || !strings.Contains(fail.Detail, "上传失败 HTTP 401") || fail.Duration != "18s" {
		t.Errorf("失败轮解析错误: %+v", fail)
	}
	// 中断轮：未上传也未失败，标记日志中断
	interrupted := recs[0]
	if interrupted.Status != "fail" || !strings.Contains(interrupted.Detail, "日志中断") {
		t.Errorf("中断轮应标记失败: %+v", interrupted)
	}
	if interrupted.File != "private-notes-20260902-033001.tar.gz.enc" {
		t.Errorf("中断轮应保留首个文件名: %s", interrupted.File)
	}
}

func TestParseBackupCronFrom(t *testing.T) {
	content := "# 注释行\n30 3 * * * root /home/os/pv-backup.sh >/dev/null 2>&1\n"
	cron, script := parseBackupCronFrom(content)
	if cron != "30 3 * * *" {
		t.Errorf("cron 表达式错误: %q", cron)
	}
	if script != "/home/os/pv-backup.sh" {
		t.Errorf("脚本路径不应取到重定向字段: %q", script)
	}
	if c, s := parseBackupCronFrom("# 全是注释\n"); c != "" || s != "" {
		t.Errorf("无有效行应返回空: %q %q", c, s)
	}
}

func TestParseBackupScriptFrom(t *testing.T) {
	content := `#!/bin/bash
# 注释
OPENLIST_DAV="http://127.0.0.1:5244/dav"   # OpenList WebDAV 地址
REMOTE_DIR="/home/备份/私人手记"
KEEP_COUNT=30                               # 云端保留份数
PASSPHRASE="b215fcb4e3c2a4c8a0bfb32f48ecae23"  # 加密口令
`
	cfg := parseBackupScriptFrom(content)
	if cfg["OPENLIST_DAV"] != "http://127.0.0.1:5244/dav" {
		t.Errorf("带注释的引号值解析错误: %q", cfg["OPENLIST_DAV"])
	}
	if cfg["KEEP_COUNT"] != "30" {
		t.Errorf("不带引号的值解析错误: %q", cfg["KEEP_COUNT"])
	}
	if cfg["PASSPHRASE"] != "b215fcb4e3c2a4c8a0bfb32f48ecae23" {
		t.Errorf("口令值解析错误: %q", cfg["PASSPHRASE"])
	}
	if _, ok := cfg["DAV_USER"]; ok {
		t.Errorf("非白名单键不应被收录")
	}
}

func TestCronDesc(t *testing.T) {
	cases := map[string]string{
		"30 3 * * *":  "每天 03:30",
		"0 4 * * 1-5": "工作日 04:00",
		"*/5 * * * *": "*/5 * * * *", // 复杂表达式原样返回
		"bad":         "",            // 字段数不对按未识别处理
	}
	for expr, want := range cases {
		if got := cronDesc(expr); got != want {
			t.Errorf("cronDesc(%q) = %q, 期望 %q", expr, got, want)
		}
	}
}

func TestValidateCronExpr(t *testing.T) {
	valid := []string{
		"30 3 * * *",
		"*/5 * * * *",
		"0 4 * * 1-5",
		"15 2,4 */2 1-6 1-5",
		"0 */6 * * *",
	}
	for _, expr := range valid {
		if err := validateCronExpr(expr); err != nil {
			t.Errorf("validateCronExpr(%q) 应通过, 实际: %v", expr, err)
		}
	}
	invalid := []string{
		"* * * *",              // 只有 4 段
		"30 3 * * * *",         // 6 段
		"60 * * * *",           // 分钟越界
		"30 24 * * *",          // 小时越界
		"-1 * * * *",           // 负数
		"abc * * * *",          // 非数字
		"30 3 * * *; rm -rf /", // 注入尝试：段数超限
		"30 3 * * *\nrm -rf /", // 注入尝试：换行多行
		"*/0 * * * *",          // 步进 0
		"5-1 * * * *",          // 区间倒置
	}
	for _, expr := range invalid {
		if err := validateCronExpr(expr); err == nil {
			t.Errorf("validateCronExpr(%q) 应拒绝", expr)
		}
	}
}

func TestRebuildCronLine(t *testing.T) {
	line := "30 3 * * * root /home/os/pv-backup.sh >/dev/null 2>&1"
	got, err := rebuildCronLine(line, "0 4 * * 1-5")
	if err != nil {
		t.Fatalf("rebuildCronLine 报错: %v", err)
	}
	want := "0 4 * * 1-5 root /home/os/pv-backup.sh >/dev/null 2>&1"
	if got != want {
		t.Errorf("重建行 = %q, 期望 %q", got, want)
	}
	if _, err := rebuildCronLine("pv-backup.sh", "0 4 * * *"); err == nil {
		t.Errorf("字段不足的行应报错")
	}
}
