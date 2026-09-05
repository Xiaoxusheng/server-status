package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ==================== 云备份展示（只读） ====================
// 数据来源：/etc/cron.d/pv-backup（执行计划与脚本路径）、pv-backup.sh 头部配置段
// （远端目录/保留份数/加密方式/日志路径）、备份日志（每次运行的上传记录）。
// 页面与接口均只读，不提供触发备份 / 恢复 / 删除能力。

const (
	backupDefaultScriptPath = "/home/os/pv-backup.sh"
	backupDefaultLogFile    = "/var/log/pv-backup.log"
	backupCronFile          = "/etc/cron.d/pv-backup"
	// 日志读取上限：日志按天滚动增长有限，超出只取末尾（与系统日志接口同思路）
	backupLogMaxRead = 4 << 20
)

// BackupRecord 一次备份运行 = 日志里「本地打包完成」到「备份完成 ✔ / 备份失败」之间的记录
type BackupRecord struct {
	Time     string `json:"time"`     // 本轮首个事件时间
	File     string `json:"file"`     // 备份包文件名
	Size     string `json:"size"`     // 打包完成行标注的大小（如 606M）
	Duration string `json:"duration"` // 首末事件时间差，如 19s / 3m21s
	Status   string `json:"status"`   // success | fail
	Detail   string `json:"detail"`   // 已加密 / 清理旧份 ×N / 失败原因
}

type backupSummary struct {
	LastTime     string `json:"last_time"`
	LastStatus   string `json:"last_status"`
	Success30d   int    `json:"success_30d"`
	Fail30d      int    `json:"fail_30d"`
	ScheduleCron string `json:"schedule_cron"`
	ScheduleDesc string `json:"schedule_desc"`
	ScriptPath   string `json:"script_path"`
	RemoteDir    string `json:"remote_dir"`
	KeepCount    string `json:"keep_count"`
	Enc          string `json:"enc"`
	LogFile      string `json:"log_file"`
	UpdatedAt    string `json:"updated_at"`
}

var (
	backupLogLineRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)$`)
	backupPackRe    = regexp.MustCompile(`本地打包完成\s+(\S+)\s+\(([^,)]+)`)
)

// readBackupLines 读取日志文件全部行；文件过大时只读末尾 maxRead 字节并丢弃半行
func readBackupLines(path string, maxRead int64) []string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var offset int64
	if info.Size() > maxRead {
		offset = info.Size() - maxRead
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return nil
	}
	buf := make([]byte, info.Size()-offset)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	text := string(buf[:n])
	if offset > 0 {
		// 丢弃截断处的半行
		if i := strings.Index(text, "\n"); i >= 0 {
			text = text[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	return lines
}

// parseBackupScript 从脚本头部的 KEY="VALUE" # 注释 格式提取配置段
func parseBackupScript(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	return parseBackupScriptFrom(string(data))
}

func parseBackupScriptFrom(content string) map[string]string {
	cfg := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if eq <= 0 || strings.HasPrefix(line, "#") {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		switch key {
		case "LOG_FILE", "REMOTE_DIR", "KEEP_COUNT", "OPENLIST_DAV", "PASSPHRASE", "SRC_DB", "SRC_CONF", "SRC_DATA":
		default:
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		if strings.HasPrefix(val, "\"") {
			// 带引号：取到下一对引号为止，行尾注释自然被排除
			if end := strings.Index(val[1:], "\""); end >= 0 {
				val = val[1 : 1+end]
			} else {
				val = strings.Trim(val, "\"")
			}
		} else {
			// 不带引号：截掉行尾 # 注释
			if i := strings.Index(val, "#"); i >= 0 {
				val = strings.TrimSpace(val[:i])
			}
			val = strings.Trim(val, "\"")
		}
		cfg[key] = val
	}
	return cfg
}

// parseBackupCron 从 /etc/cron.d/pv-backup 提取执行计划与脚本路径
func parseBackupCron() (cronExpr, scriptPath string) {
	data, err := os.ReadFile(backupCronFile)
	if err != nil {
		return "", ""
	}
	return parseBackupCronFrom(string(data))
}

func parseBackupCronFrom(content string) (cronExpr, scriptPath string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "pv-backup.sh") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// cron.d 行格式：分 时 日 月 周 用户 命令…；命令里可能带 >/dev/null 2>&1 重定向，
		// 按后缀/前缀找真正的脚本路径，不能直接取最后一个字段
		cmd := fields[5:]
		for _, f := range cmd {
			if strings.HasSuffix(f, ".sh") {
				return strings.Join(fields[:5], " "), f
			}
		}
		for _, f := range cmd {
			if strings.HasPrefix(f, "/") {
				return strings.Join(fields[:5], " "), f
			}
		}
	}
	return "", ""
}

// cronDesc 把常见的「分 时 日 月 周」翻译成中文；复杂表达式原样返回
func cronDesc(expr string) string {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return ""
	}
	min, hour, dom, mon, dow := fields[0], fields[1], fields[2], fields[3], fields[4]
	isNum := func(s string) bool {
		_, err := strconv.Atoi(s)
		return err == nil
	}
	hm := ""
	if isNum(min) && isNum(hour) {
		hm = fmtHourMinute(hour, min)
	}
	if dom == "*" && mon == "*" && dow == "*" && hm != "" {
		return "每天 " + hm
	}
	if dom == "*" && mon == "*" && dow == "1-5" && hm != "" {
		return "工作日 " + hm
	}
	return expr
}

func fmtHourMinute(hour, min string) string {
	h, _ := strconv.Atoi(hour)
	m, _ := strconv.Atoi(min)
	return fmt2(h) + ":" + fmt2(m)
}

func fmt2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// backupRunAccum 解析过程中的单轮累积器
type backupRunAccum struct {
	start, last time.Time
	file, size  string
	encrypted   bool
	cleaned     int
	uploaded    bool
	failed      bool
	failReason  string
}

func (a *backupRunAccum) record() BackupRecord {
	status := "success"
	detail := []string{}
	if a.failed {
		status = "fail"
		if a.failReason != "" {
			detail = append(detail, a.failReason)
		}
	} else if !a.uploaded {
		// 运行被打断：既无上传成功也无失败标记（如下一轮直接开始）
		status = "fail"
		detail = append(detail, "日志中断，未见上传结果")
	}
	if a.encrypted {
		detail = append(detail, "已加密")
	}
	if a.cleaned > 0 {
		detail = append(detail, "清理旧份 ×"+strconv.Itoa(a.cleaned))
	}
	dur := a.last.Sub(a.start)
	durStr := "—"
	if dur > time.Second {
		if dur < time.Minute {
			durStr = strconv.Itoa(int(dur.Seconds())) + "s"
		} else {
			durStr = strconv.Itoa(int(dur.Minutes())) + "m" + strconv.Itoa(int(dur.Seconds())%60) + "s"
		}
	}
	return BackupRecord{
		Time:     a.start.Format("2006-01-02 15:04:05"),
		File:     a.file,
		Size:     a.size,
		Duration: durStr,
		Status:   status,
		Detail:   strings.Join(detail, "，"),
	}
}

// parseBackupRuns 把日志行聚合成一次次的备份运行（时间正序）
func parseBackupRuns(lines []string) []BackupRecord {
	records := []BackupRecord{}
	var cur *backupRunAccum
	closeRun := func() {
		if cur != nil && !cur.start.IsZero() {
			records = append(records, cur.record())
		}
		cur = nil
	}
	for _, line := range lines {
		m := backupLogLineRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
		if err != nil {
			continue
		}
		rest := m[2]
		switch {
		case strings.HasPrefix(rest, "本地打包完成"):
			closeRun()
			cur = &backupRunAccum{start: ts, last: ts}
			if pm := backupPackRe.FindStringSubmatch(rest); pm != nil {
				cur.file = pm[1]
				cur.size = pm[2]
				cur.encrypted = strings.Contains(rest, "已加密")
			}
		case strings.HasPrefix(rest, "备份失败"):
			if cur == nil {
				cur = &backupRunAccum{start: ts}
			}
			cur.failed = true
			cur.failReason = strings.TrimSpace(strings.TrimPrefix(rest, "备份失败:"))
			cur.last = ts
			closeRun()
		default:
			if cur == nil {
				continue
			}
			switch {
			case strings.HasPrefix(rest, "上传成功"):
				cur.uploaded = true
			case strings.HasPrefix(rest, "清理云端旧备份"):
				cur.cleaned++
			}
			cur.last = ts
			if strings.HasPrefix(rest, "备份完成") {
				closeRun()
			}
		}
	}
	closeRun()
	return records
}

// backupLogAndScript 汇总读取脚本配置与日志记录（summary/records 两个接口共用）
func backupLogAndScript() (map[string]string, string, []BackupRecord) {
	_, scriptPath := parseBackupCron()
	if scriptPath == "" {
		scriptPath = backupDefaultScriptPath
	}
	cfg := parseBackupScript(scriptPath)
	logFile := cfg["LOG_FILE"]
	if logFile == "" {
		logFile = backupDefaultLogFile
	}
	return cfg, logFile, parseBackupRuns(readBackupLines(logFile, backupLogMaxRead))
}

// backupSummaryHandler GET /api/backup/summary
func backupSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "只允许GET请求")
		return
	}
	cfg, logFile, records := backupLogAndScript()

	sum := backupSummary{
		LogFile:   logFile,
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	if n := len(records); n > 0 {
		// 日志理论上按时间正序追加，但这里按时间取最大值，兼容乱序/手工整理过的日志
		last := records[0]
		for _, rec := range records[1:] {
			if rec.Time > last.Time {
				last = rec
			}
		}
		sum.LastTime = last.Time
		sum.LastStatus = last.Status
	}
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, rec := range records {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", rec.Time, time.Local)
		if err != nil || t.Before(cutoff) {
			continue
		}
		if rec.Status == "success" {
			sum.Success30d++
		} else {
			sum.Fail30d++
		}
	}
	cronExpr, scriptPath := parseBackupCron()
	if scriptPath == "" {
		scriptPath = backupDefaultScriptPath
	}
	sum.ScheduleCron = cronExpr
	sum.ScheduleDesc = cronDesc(cronExpr)
	sum.ScriptPath = scriptPath
	sum.RemoteDir = cfg["REMOTE_DIR"]
	sum.KeepCount = cfg["KEEP_COUNT"]
	if pass := cfg["PASSPHRASE"]; pass != "" && pass != "CHANGE_ME" {
		sum.Enc = "AES-256-CBC"
	} else {
		sum.Enc = "未加密"
	}
	writeJSON(w, http.StatusOK, "ok", sum)
}

// backupRecordsHandler GET /api/backup/records?limit=50
func backupRecordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "只允许GET请求")
		return
	}
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 200 {
		limit = n
	}
	_, _, records := backupLogAndScript()
	// 日志按时间正序解析，页面上倒序展示（最新在前）
	sort.Slice(records, func(i, j int) bool { return records[i].Time > records[j].Time })
	if len(records) > limit {
		records = records[:limit]
	}
	writeJSON(w, http.StatusOK, "ok", records)
}

// backupRawLogHandler GET /api/backup/log?lines=50
func backupRawLogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "只允许GET请求")
		return
	}
	lines := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil && n > 0 && n <= 200 {
		lines = n
	}
	_, logFile, _ := backupLogAndScript()
	all := readBackupLines(logFile, backupLogMaxRead)
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	for i := range all {
		all[i] = strings.TrimRight(all[i], "\r")
	}
	writeJSON(w, http.StatusOK, "ok", map[string]interface{}{"lines": all})
}

// ==================== 备份计划修改（role:manage） ====================

// validateCronField 校验单个 cron 字段：* 、*/n 、数字 、区间 、列表 ，各部分可带步进
func validateCronField(field string, min, max int) error {
	for _, part := range strings.Split(field, ",") {
		base, step := part, ""
		if i := strings.Index(part, "/"); i >= 0 {
			base, step = part[:i], part[i+1:]
			if n, err := strconv.Atoi(step); err != nil || n <= 0 {
				return fmt.Errorf("步进 %q 无效", step)
			}
		}
		if base == "*" {
			continue
		}
		lo, hi := 0, 0
		if i := strings.Index(base, "-"); i >= 0 {
			a, err1 := strconv.Atoi(base[:i])
			b, err2 := strconv.Atoi(base[i+1:])
			if err1 != nil || err2 != nil {
				return fmt.Errorf("区间 %q 无效", base)
			}
			lo, hi = a, b
		} else {
			a, err := strconv.Atoi(base)
			if err != nil {
				return fmt.Errorf("值 %q 无效", base)
			}
			lo, hi = a, a
		}
		if lo < min || hi > max || lo > hi {
			return fmt.Errorf("值 %d-%d 超出范围 %d-%d", lo, hi, min, max)
		}
	}
	return nil
}

// validateCronExpr 校验 5 段 cron 表达式（分 时 日 月 周）；表达式内容只允许数字与
// * / - , 空白，保证写回 /etc/cron.d 时不可能注入命令
func validateCronExpr(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("cron 表达式必须为 5 段（分 时 日 月 周）")
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	names := [5]string{"分钟", "小时", "日", "月", "星期"}
	for i, f := range fields {
		if err := validateCronField(f, bounds[i][0], bounds[i][1]); err != nil {
			return fmt.Errorf("%s字段非法: %v", names[i], err)
		}
	}
	return nil
}

// rebuildCronLine 只替换 cron.d 计划行的前 5 段，保留用户与命令部分（含重定向）
func rebuildCronLine(line, expr string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return "", fmt.Errorf("计划行格式不完整")
	}
	return expr + " " + strings.Join(fields[5:], " "), nil
}

// backupScheduleUpdateHandler POST /api/backup/schedule {"cron":"30 3 * * *"}
// 原地改写 /etc/cron.d/pv-backup 的计划行：仅替换时间字段，脚本与用户字段不动
func backupScheduleUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "只允许POST请求")
		return
	}
	var req struct {
		Cron string `json:"cron"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	// 收敛空白（换行/Tab 归一为单空格）后再校验，杜绝写入多行或异常字符
	expr := strings.Join(strings.Fields(strings.TrimSpace(req.Cron)), " ")
	if err := validateCronExpr(expr); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := os.ReadFile(backupCronFile)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取 "+backupCronFile+" 失败")
		return
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || !strings.Contains(t, "pv-backup.sh") {
			continue
		}
		newLine, err := rebuildCronLine(t, expr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		lines[i] = newLine
		found = true
		break
	}
	if !found {
		writeJSONError(w, http.StatusBadRequest, "未在 "+backupCronFile+" 中找到备份计划行，拒绝新建")
		return
	}
	// 临时文件 + rename 原子替换，避免 cron 读到半截文件
	tmp := backupCronFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入计划文件失败")
		return
	}
	if err := os.Rename(tmp, backupCronFile); err != nil {
		os.Remove(tmp)
		writeJSONError(w, http.StatusInternalServerError, "替换计划文件失败")
		return
	}
	auditAction(r, "backup.schedule.update", "cron="+expr)
	writeJSON(w, http.StatusOK, "ok", map[string]string{"schedule_cron": expr, "schedule_desc": cronDesc(expr)})
}
