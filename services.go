package main

// ==================== 服务与端口中心 - systemd 服务管理 ====================

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	unitDir       = "/etc/systemd/system"
	managedMarker = "# Managed by Server Status"
)

// managedServicesFile 受管服务登记文件（默认 <数据根目录>/managed_services.json）
var managedServicesFile = filepath.Join(dataRoot(), "managed_services.json")

// serviceNameRe systemd 单元名称允许的字符集（防止路径穿越与任意文件写入）
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+$`)

// envKeyRe 环境变量键名
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// posixUserRe 运行用户/组
var posixUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

var validRestartModes = map[string]bool{
	"always":      true,
	"on-failure":  true,
	"on-abnormal": true,
	"on-abort":    true,
	"on-success":  true,
	"no":          true,
}

// EnvVar 环境变量键值对
type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ManagedService 本系统创建（托管）的服务定义
type ManagedService struct {
	Name            string    `json:"name"`
	DisplayName     string    `json:"display_name"`
	Description     string    `json:"description"`
	ExecStart       string    `json:"exec_start"`
	WorkingDir      string    `json:"working_dir"`
	Args            []string  `json:"args"`
	User            string    `json:"user"`
	Group           string    `json:"group"`
	Environment     []EnvVar  `json:"environment"`
	Restart         string    `json:"restart"`
	RestartSec      int       `json:"restart_sec"`
	AutoStart       bool      `json:"auto_start"`
	TimeoutStartSec int       `json:"timeout_start_sec"`
	TimeoutStopSec  int       `json:"timeout_stop_sec"`
	LimitNOFILE     int       `json:"limit_nofile"`
	Nice            int       `json:"nice"`
	ExecStartPre    []string  `json:"exec_start_pre"`
	ExecStop        []string  `json:"exec_stop"`
	StartNow        bool      `json:"start_now"`
	CreatedAt       time.Time `json:"created_at"`
}

// ServiceListItem 服务列表项
type ServiceListItem struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description"`
	Status      string  `json:"status"` // RUNNING/STARTING/STOPPED/FAILED/UNKNOWN
	Enabled     bool    `json:"enabled"`
	PID         int     `json:"pid"`
	CPU         float64 `json:"cpu"`
	MemoryMB    float64 `json:"memory_mb"`
	Uptime      string  `json:"uptime"`
	ExitCode    int     `json:"exit_code"`
	Source      string  `json:"source"` // created/custom/system
	Managed     bool    `json:"managed"`
}

// ServiceDetail 服务详情（列表项 + 托管配置 + 关联端口）
type ServiceDetail struct {
	Service ServiceListItem `json:"service"`
	Config  *ManagedService `json:"config"`
	Ports   []PortInfo      `json:"ports"`
}

// managedServiceStore 托管服务注册表（内存 + JSON 持久化）
type managedServiceStore struct {
	mu       sync.RWMutex
	services map[string]*ManagedService
}

var managedSvcStore = &managedServiceStore{services: map[string]*ManagedService{}}

// loadManagedServices 启动时加载托管服务定义
func loadManagedServices() {
	data, err := os.ReadFile(managedServicesFile)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("读取托管服务文件失败: %v", err)
		return
	}
	var list []*ManagedService
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("解析托管服务文件失败: %v", err)
		return
	}
	managedSvcStore.mu.Lock()
	for _, s := range list {
		if s != nil && serviceNameRe.MatchString(s.Name) {
			managedSvcStore.services[s.Name] = s
		}
	}
	managedSvcStore.mu.Unlock()
	log.Printf("已加载 %d 个托管服务定义", len(list))
}

// saveManagedServices 持久化托管服务定义
func saveManagedServices() {
	managedSvcStore.mu.RLock()
	list := make([]*ManagedService, 0, len(managedSvcStore.services))
	for _, s := range managedSvcStore.services {
		list = append(list, s)
	}
	managedSvcStore.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		log.Printf("序列化托管服务失败: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(managedServicesFile), 0755); err != nil {
		log.Printf("创建托管服务目录失败: %v", err)
		return
	}
	if err := os.WriteFile(managedServicesFile, data, 0600); err != nil {
		log.Printf("保存托管服务文件失败: %v", err)
	}
}

func getManagedService(name string) *ManagedService {
	managedSvcStore.mu.RLock()
	defer managedSvcStore.mu.RUnlock()
	s, _ := managedSvcStore.services[name]
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

func setManagedService(s *ManagedService) {
	managedSvcStore.mu.Lock()
	managedSvcStore.services[s.Name] = s
	managedSvcStore.mu.Unlock()
	saveManagedServices()
}

func deleteManagedService(name string) {
	managedSvcStore.mu.Lock()
	delete(managedSvcStore.services, name)
	managedSvcStore.mu.Unlock()
	saveManagedServices()
}

// unitFilePath systemd 单元文件路径
func unitFilePath(name string) string {
	return filepath.Join(unitDir, name+".service")
}

// isManagedUnit 判断单元是否由本系统创建（注册表或文件标记）
func isManagedUnit(name string) bool {
	if getManagedService(name) != nil {
		return true
	}
	path := unitFilePath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), managedMarker)
}

// runSystemctl 以参数方式执行 systemctl，禁止 shell 拼接
func runSystemctl(ctx context.Context, args ...string) (string, error) {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return "", fmt.Errorf("当前系统不支持 systemd（未找到 systemctl）")
	}
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=false")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return text, fmt.Errorf("systemctl %s 执行失败: %s", strings.Join(args, " "), text)
	}
	return text, nil
}

// 服务状态缓存（2 秒 TTL）
var (
	servicesStatusMu   sync.Mutex
	servicesStatusList []*ServiceListItem
	servicesStatusTime time.Time
)

// collectServicesStatus 汇总系统全部 systemd 服务状态
func collectServicesStatus() ([]*ServiceListItem, error) {
	servicesStatusMu.Lock()
	defer servicesStatusMu.Unlock()
	if servicesStatusList != nil && time.Since(servicesStatusTime) < 2*time.Second {
		return servicesStatusList, nil
	}

	// systemd 219 等旧版本不支持 show --type=service --all 与 -p 组合使用，
	// 这里改用 list-units + list-unit-files + 单单元 show 的兼容写法
	unitsOut, err := runSystemctl(context.Background(),
		"list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, err
	}

	type unitInfo struct {
		active       string
		sub          string
		desc         string
		mainPID      int
		exitCode     int
		fragmentPath string
	}
	units := map[string]*unitInfo{}
	for _, line := range strings.Split(unitsOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		units[fields[0]] = &unitInfo{
			active: fields[2],
			sub:    fields[3],
			desc:   strings.Join(fields[4:], " "),
		}
	}

	// 开机自启状态（list-unit-files 为权威来源）
	enabledMap := map[string]bool{}
	if filesOut, err := runSystemctl(context.Background(), "list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"); err == nil {
		for _, line := range strings.Split(filesOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasSuffix(fields[0], ".service") {
				enabledMap[fields[0]] = fields[1] == "enabled"
			}
		}
	}

	// 对非 inactive 单元查询 MainPID / 退出码 / 单元文件路径（单单元 show 兼容旧版 systemd）
	for name, info := range units {
		if info.active == "inactive" {
			continue
		}
		showOut, err := runSystemctl(context.Background(), "show", name,
			"-p", "MainPID", "-p", "ExecMainStatus", "-p", "FragmentPath")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(showOut, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "MainPID":
				info.mainPID, _ = strconv.Atoi(v)
			case "ExecMainStatus":
				info.exitCode, _ = strconv.Atoi(v)
			case "FragmentPath":
				info.fragmentPath = v
			}
		}
	}

	// 资源统计缓存：同一 PID 只查一次 ps
	statsCache := map[int]*procStats{}

	list := make([]*ServiceListItem, 0, len(units))
	for name, info := range units {
		unitName := strings.TrimSuffix(name, ".service")
		item := &ServiceListItem{
			Name:        unitName,
			Description: info.desc,
			Status:      "UNKNOWN",
			PID:         info.mainPID,
			ExitCode:    info.exitCode,
			Source:      "system",
		}
		switch info.active {
		case "active":
			if info.sub == "running" {
				item.Status = "RUNNING"
			} else if info.sub == "exited" {
				item.Status = "STOPPED"
			} else {
				item.Status = "STARTING"
			}
		case "activating", "reloading":
			item.Status = "STARTING"
		case "deactivating":
			item.Status = "STOPPED"
		case "failed":
			item.Status = "FAILED"
		case "inactive":
			item.Status = "STOPPED"
		}
		if item.Status == "UNKNOWN" && strings.EqualFold(info.sub, "failed") {
			item.Status = "FAILED"
		}
		if v, ok := enabledMap[name]; ok {
			item.Enabled = v
		}
		if strings.Contains(info.fragmentPath, "/etc/systemd/system") || strings.Contains(info.fragmentPath, "/run/systemd/system") {
			item.Source = "custom"
		}
		if cfg := getManagedService(unitName); cfg != nil {
			item.Managed = true
			item.Source = "created"
			item.DisplayName = cfg.DisplayName
			if item.Description == "" {
				item.Description = cfg.Description
			}
		} else if isManagedUnit(unitName) {
			item.Managed = true
			item.Source = "created"
		}
		if item.DisplayName == "" {
			item.DisplayName = item.Description
		}
		if item.DisplayName == "" {
			item.DisplayName = unitName
		}
		if item.PID > 0 {
			st := statsCache[item.PID]
			if st == nil {
				st = queryProcessStats(item.PID)
				statsCache[item.PID] = st
			}
			item.CPU = st.cpu
			item.MemoryMB = st.rssMB
			item.Uptime = st.etime
		}
		list = append(list, item)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	servicesStatusList = list
	servicesStatusTime = time.Now()
	return list, nil
}

type procStats struct {
	cpu   float64
	rssMB float64
	etime string
}

// queryProcessStats 通过 ps 查询单进程 CPU/内存/运行时长
func queryProcessStats(pid int) *procStats {
	st := &procStats{}
	bin, err := exec.LookPath("ps")
	if err != nil {
		return st
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-p", strconv.Itoa(pid), "-o", "pcpu=,pmem=,rss=,etime=", "--no-headers")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return st
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 4 {
		st.cpu, _ = strconv.ParseFloat(fields[0], 64)
		rssKB, _ := strconv.ParseFloat(fields[2], 64)
		st.rssMB = rssKB / 1024
		st.etime = fields[3]
	}
	return st
}

// ==================== 单元文件生成与校验 ====================

// systemdEscape 转义单个 Exec* 参数，禁止换行/引号/反斜杠/百分号注入
func systemdEscape(s string) (string, error) {
	if s == "" {
		return `""`, nil
	}
	if strings.ContainsAny(s, "\r\n\t\"\\") {
		return "", fmt.Errorf("包含不允许的字符（换行/引号/反斜杠）")
	}
	s = strings.ReplaceAll(s, "%", "%%")
	if strings.ContainsAny(s, " ") {
		return `"` + s + `"`, nil
	}
	return s, nil
}

func validateAbsPath(p, field string) error {
	if p == "" {
		return nil
	}
	if !isAbsPath(p) {
		return fmt.Errorf("%s 必须是绝对路径", field)
	}
	if strings.ContainsAny(p, "\r\n\t\"\\%") {
		return fmt.Errorf("%s 包含不允许的字符", field)
	}
	return nil
}

// isAbsPath 判断绝对路径（兼容在 Windows 上开发调试 Linux 部署路径的情况）
func isAbsPath(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/")
}

// validateManagedService 校验服务定义
func validateManagedService(s *ManagedService) error {
	if !serviceNameRe.MatchString(s.Name) || strings.Contains(s.Name, "..") {
		return fmt.Errorf("服务名称只能包含字母、数字、下划线、点、@ 和连字符")
	}
	if err := validateAbsPath(s.ExecStart, "程序路径"); err != nil {
		return err
	}
	if err := validateAbsPath(s.WorkingDir, "工作目录"); err != nil {
		return err
	}
	if s.User != "" && !posixUserRe.MatchString(s.User) {
		return fmt.Errorf("运行用户格式不合法")
	}
	if s.Group != "" && !posixUserRe.MatchString(s.Group) {
		return fmt.Errorf("运行组格式不合法")
	}
	if s.Restart == "" {
		s.Restart = "no"
	}
	if !validRestartModes[s.Restart] {
		return fmt.Errorf("Restart 必须是 always / on-failure / no 等合法值")
	}
	if s.RestartSec < 0 || s.TimeoutStartSec < 0 || s.TimeoutStopSec < 0 || s.LimitNOFILE < 0 {
		return fmt.Errorf("超时和资源限制不能为负数")
	}
	if s.Nice < -20 || s.Nice > 19 {
		return fmt.Errorf("Nice 取值范围为 -20 ~ 19")
	}
	for _, e := range s.Environment {
		if e.Key != "" && !envKeyRe.MatchString(e.Key) {
			return fmt.Errorf("环境变量键名 %q 不合法", e.Key)
		}
		if strings.ContainsAny(e.Value, "\r\n\"") {
			return fmt.Errorf("环境变量 %s 的值包含不允许的字符", e.Key)
		}
	}
	for _, line := range append(append([]string{}, s.ExecStartPre...), s.ExecStop...) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		if !isAbsPath(tokens[0]) {
			return fmt.Errorf("ExecStartPre/ExecStop 必须以绝对路径开头")
		}
		for _, tok := range tokens {
			if _, err := systemdEscape(tok); err != nil {
				return err
			}
		}
	}
	return nil
}

// buildExecLine 将程序路径与参数拼接为安全的 ExecStart 行
func buildExecLine(bin string, args []string) (string, error) {
	parts := make([]string, 0, len(args)+1)
	esc, err := systemdEscape(bin)
	if err != nil {
		return "", fmt.Errorf("程序路径%s", err)
	}
	parts = append(parts, esc)
	for _, a := range args {
		esc, err := systemdEscape(a)
		if err != nil {
			return "", fmt.Errorf("启动参数%s", err)
		}
		parts = append(parts, esc)
	}
	return strings.Join(parts, " "), nil
}

// buildUnitFile 生成 systemd 单元文件内容（结构化字段，不做任意字符串注入）
func buildUnitFile(s *ManagedService) (string, error) {
	if err := validateManagedService(s); err != nil {
		return "", err
	}
	execLine, err := buildExecLine(s.ExecStart, s.Args)
	if err != nil {
		return "", err
	}
	desc := s.Description
	if desc == "" {
		desc = s.DisplayName
	}
	desc = strings.ReplaceAll(strings.ReplaceAll(desc, "\r", " "), "\n", " ")
	desc = strings.ReplaceAll(desc, "%", "%%")

	var b strings.Builder
	b.WriteString(managedMarker + " - 请勿手动编辑\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=" + desc + "\n")
	b.WriteString("After=network.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	if s.WorkingDir != "" {
		b.WriteString("WorkingDirectory=" + s.WorkingDir + "\n")
	}
	b.WriteString("ExecStart=" + execLine + "\n")
	if s.User != "" {
		b.WriteString("User=" + s.User + "\n")
	}
	if s.Group != "" {
		b.WriteString("Group=" + s.Group + "\n")
	}
	if s.Restart != "" && s.Restart != "no" {
		b.WriteString("Restart=" + s.Restart + "\n")
	}
	if s.RestartSec > 0 {
		b.WriteString("RestartSec=" + strconv.Itoa(s.RestartSec) + "\n")
	}
	for _, e := range s.Environment {
		if e.Key == "" {
			continue
		}
		val := strings.ReplaceAll(e.Value, "%", "%%")
		b.WriteString("Environment=\"" + e.Key + "=" + val + "\"\n")
	}
	if s.TimeoutStartSec > 0 {
		b.WriteString("TimeoutStartSec=" + strconv.Itoa(s.TimeoutStartSec) + "\n")
	}
	if s.TimeoutStopSec > 0 {
		b.WriteString("TimeoutStopSec=" + strconv.Itoa(s.TimeoutStopSec) + "\n")
	}
	if s.LimitNOFILE > 0 {
		b.WriteString("LimitNOFILE=" + strconv.Itoa(s.LimitNOFILE) + "\n")
	}
	if s.Nice != 0 {
		b.WriteString("Nice=" + strconv.Itoa(s.Nice) + "\n")
	}
	for _, line := range s.ExecStartPre {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tokens := strings.Fields(line)
		l, err := buildExecLine(tokens[0], tokens[1:])
		if err != nil {
			return "", err
		}
		b.WriteString("ExecStartPre=" + l + "\n")
	}
	for _, line := range s.ExecStop {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tokens := strings.Fields(line)
		l, err := buildExecLine(tokens[0], tokens[1:])
		if err != nil {
			return "", err
		}
		b.WriteString("ExecStop=" + l + "\n")
	}
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String(), nil
}

// writeUnitFile 写入单元文件
func writeUnitFile(s *ManagedService) error {
	content, err := buildUnitFile(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return fmt.Errorf("创建 systemd 目录失败: %v", err)
	}
	path := unitFilePath(s.Name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入单元文件失败: %v", err)
	}
	_, err = runSystemctl(context.Background(), "daemon-reload")
	return err
}

// ==================== 服务 API 处理函数 ====================

func serviceUnitName(name string) (string, error) {
	if !serviceNameRe.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("服务名称不合法")
	}
	return name + ".service", nil
}

// listServicesHandler GET /api/services
func listServicesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "services")
	list, err := collectServicesStatus()
	if err != nil {
		writeJSON(w, http.StatusOK, "当前系统无法读取 systemd 服务列表", map[string]interface{}{
			"systemd_available": false,
			"services":          []*ServiceListItem{},
			"error":             err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, "获取服务列表成功", map[string]interface{}{
		"systemd_available": true,
		"services":          list,
	})
}

// getServiceHandler GET /api/services/{name}
func getServiceHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.PathValue("name")
	if _, err := serviceUnitName(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := collectServicesStatus()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "无法读取服务状态: "+err.Error())
		return
	}
	var found *ServiceListItem
	for _, s := range list {
		if s.Name == name {
			found = s
			break
		}
	}
	if found == nil {
		writeJSONError(w, http.StatusNotFound, "服务不存在")
		return
	}
	detail := ServiceDetail{Service: *found, Config: getManagedService(name)}
	if detail.Config == nil && found.Managed {
		detail.Config = getManagedService(name)
	}
	detail.Ports = portsForPID(int32(found.PID))
	writeJSON(w, http.StatusOK, "获取服务详情成功", detail)
}

// createServiceHandler POST /api/services
func createServiceHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	var req ManagedService
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.ExecStart = strings.TrimSpace(req.ExecStart)
	if _, err := serviceUnitName(req.Name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if getManagedService(req.Name) != nil {
		writeJSONError(w, http.StatusConflict, "服务已存在，请使用编辑功能")
		return
	}
	if _, err := os.Stat(unitFilePath(req.Name)); err == nil {
		writeJSONError(w, http.StatusConflict, "同名 systemd 服务已存在，不允许覆盖")
		return
	}
	req.CreatedAt = time.Now()
	if err := validateManagedService(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := writeUnitFile(&req); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.AutoStart {
		if _, err := runSystemctl(context.Background(), "enable", req.Name+".service"); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入单元文件成功，但设置开机自启失败: "+err.Error())
			return
		}
	}
	setManagedService(&req)
	if req.StartNow {
		if _, err := runSystemctl(context.Background(), "start", req.Name+".service"); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "服务已创建，但启动失败: "+err.Error())
			return
		}
	}
	auditAction(r, "service.create", "创建服务 "+req.Name)
	writeJSON(w, http.StatusOK, "服务创建成功", req)
}

// updateServiceHandler PUT /api/services/{name}
func updateServiceHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.PathValue("name")
	if _, err := serviceUnitName(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	old := getManagedService(name)
	if old == nil {
		writeJSONError(w, http.StatusForbidden, "仅允许编辑本系统创建的服务")
		return
	}
	var req ManagedService
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	req.Name = name // 名称不可修改
	req.CreatedAt = old.CreatedAt
	req.ExecStart = strings.TrimSpace(req.ExecStart)
	if err := validateManagedService(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := writeUnitFile(&req); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.AutoStart != old.AutoStart {
		op := "disable"
		if req.AutoStart {
			op = "enable"
		}
		if _, err := runSystemctl(context.Background(), op, name+".service"); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "更新配置成功，但切换开机自启失败: "+err.Error())
			return
		}
	}
	setManagedService(&req)
	auditAction(r, "service.update", "更新服务 "+name)
	writeJSON(w, http.StatusOK, "服务更新成功", req)
}

// deleteServiceHandler DELETE /api/services/{name}
func deleteServiceHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.PathValue("name")
	if _, err := serviceUnitName(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !isManagedUnit(name) {
		writeJSONError(w, http.StatusForbidden, "系统服务不允许删除，仅允许删除本系统创建的服务")
		return
	}
	unit := name + ".service"
	// 停止当前服务
	runSystemctl(context.Background(), "stop", unit)
	// 禁用开机自启
	runSystemctl(context.Background(), "disable", unit)
	// 删除单元文件
	path := unitFilePath(name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		writeJSONError(w, http.StatusInternalServerError, "删除单元文件失败: "+err.Error())
		return
	}
	runSystemctl(context.Background(), "daemon-reload")
	deleteManagedService(name)
	auditAction(r, "service.delete", "删除服务 "+name)
	writeJSON(w, http.StatusOK, "服务已删除", nil)
}

// serviceActionHandler 启停/重启/自启操作
func serviceActionHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recordAccess(r)
		name := r.PathValue("name")
		unit, err := serviceUnitName(name)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := runSystemctl(context.Background(), action, unit); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		auditAction(r, "service."+action, "对服务 "+name+" 执行 "+action)
		// 让状态缓存立即失效
		servicesStatusMu.Lock()
		servicesStatusList = nil
		servicesStatusMu.Unlock()
		writeJSON(w, http.StatusOK, "操作成功", nil)
	}
}

// getServiceLogsHandler GET /api/services/{name}/logs?tail=N
func getServiceLogsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.PathValue("name")
	unit, err := serviceUnitName(name)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	tail := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && n > 0 && n <= 2000 {
		tail = n
	}
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "当前系统不支持 journalctl")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-u", unit, "-n", strconv.Itoa(tail), "--no-pager", "-o", "short-iso")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取日志失败: "+err.Error())
		return
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, "获取日志成功", lines)
}

// serviceLogsWSHandler WebSocket 实时推送服务日志（journalctl -f）
func serviceLogsWSHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.URL.Query().Get("service")
	unit, err := serviceUnitName(name)
	if err != nil {
		http.Error(w, "service 参数不合法", http.StatusBadRequest)
		return
	}
	tail := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("tail")); err == nil && n > 0 && n <= 2000 {
		tail = n
	}
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		http.Error(w, "当前系统不支持 journalctl", http.StatusInternalServerError)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("服务日志 WebSocket Upgrade Error:", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-u", unit, "-n", strconv.Itoa(tail), "--no-pager", "-o", "short-iso", "-f")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=false")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println("服务日志管道创建失败:", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Println("journalctl 启动失败:", err)
		return
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// 客户端断开检测
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

// portsForPID 返回指定进程监听的端口
func portsForPID(pid int32) []PortInfo {
	ports, err := scanListeningPorts()
	if err != nil || pid <= 0 {
		return []PortInfo{}
	}
	out := []PortInfo{}
	for _, p := range ports {
		if p.PID == pid {
			out = append(out, p)
		}
	}
	return out
}

// getServicePortsHandler GET /api/services/{name}/ports
func getServicePortsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	name := r.PathValue("name")
	if _, err := serviceUnitName(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := collectServicesStatus()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "无法读取服务状态: "+err.Error())
		return
	}
	pid := int32(0)
	for _, s := range list {
		if s.Name == name {
			pid = int32(s.PID)
			break
		}
	}
	writeJSON(w, http.StatusOK, "获取服务端口成功", portsForPID(pid))
}
