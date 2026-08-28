// docker.go -- Docker 容器监控与管理
// 通过 Docker CLI 获取容器列表/资源占用，并支持启停/重启/日志查看。
// 所有写操作必须经过 authMiddleware(requirePermission("docker:manage", ...))，由 CSRF + RBAC 双重保护。
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dockerContainer 单个容器的展示数据结构
type dockerContainer struct {
	ID        string `json:"id"`         // 容器短 ID（12 位）
	Name      string `json:"name"`       // 容器名称
	Image     string `json:"image"`      // 镜像
	State     string `json:"state"`      // running / exited / created ...
	Status    string `json:"status"`     // docker 原始状态文本（Up 6 hours / Exited (137) ...）
	Ports     string `json:"ports"`      // 端口映射
	CreatedAt string `json:"created_at"` // 创建时间（docker 文本）
	CPU       string `json:"cpu"`        // CPU 占用百分比文本
	MemUsage  string `json:"mem_usage"`  // 内存占用（已用 / 上限）
	NetIO     string `json:"net_io"`     // 网络 I/O（如 1.27MB / 905kB 收/发）
	BlockIO   string `json:"block_io"`   // 块 I/O（如 115MB / 1.96MB）
	Abnormal  bool   `json:"abnormal"`   // 是否异常（restarting/unhealthy/OOMKilled 等）
}

// dockerListCache 存储 Docker 容器列表的短时缓存，采用 stale-while-revalidate 策略：
// docker stats 采集耗时约 2~4 秒，若同步等待会让接口慢响应（浏览器/代理可能判定为网络错误）。
// 因此过期后仍立即返回旧数据，同时触发后台刷新，保证接口始终快速响应。
var dockerListCache struct {
	sync.Mutex
	containers []dockerContainer
	ts         time.Time
	refreshing bool // 后台刷新进行中（singleflight，防止并发重复采集）
}

const (
	dockerListCacheTTL   = 3 * time.Second  // 新鲜期：此窗口内直接返回缓存
	dockerListCacheStale = 30 * time.Second // 陈旧容忍期：先返回旧数据，同时后台刷新
)

// dockerListHandler 获取容器列表（含 stats 资源占用），只读，需 docker:view
func dockerListHandler(w http.ResponseWriter, r *http.Request) {
	dockerListCache.Lock()
	if dockerListCache.containers != nil && time.Since(dockerListCache.ts) < dockerListCacheStale {
		// 缓存可用（新鲜或陈旧容忍期内）：立即返回，过期则顺带触发后台刷新
		cached := dockerListCache.containers
		needRefresh := time.Since(dockerListCache.ts) >= dockerListCacheTTL && !dockerListCache.refreshing
		if needRefresh {
			dockerListCache.refreshing = true
		}
		dockerListCache.Unlock()
		if needRefresh {
			go refreshDockerListCache()
		}
		writeJSON(w, http.StatusOK, "success", map[string]interface{}{"containers": cached})
		return
	}
	dockerListCache.Unlock()

	// 无可用缓存（冷启动预热未完成 / 写操作后主动失效）：同步采集
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	containers, err := collectDockerContainers(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "获取容器列表失败: "+err.Error(), nil)
		return
	}

	// 写入缓存
	dockerListCache.Lock()
	dockerListCache.containers = containers
	dockerListCache.ts = time.Now()
	dockerListCache.Unlock()

	writeJSON(w, http.StatusOK, "success", map[string]interface{}{"containers": containers})
}

// refreshDockerListCache 后台刷新容器列表缓存（由 stale-while-revalidate 与启动预热调用）
func refreshDockerListCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	containers, err := collectDockerContainers(ctx)

	dockerListCache.Lock()
	if err == nil {
		dockerListCache.containers = containers
		dockerListCache.ts = time.Now()
	}
	dockerListCache.refreshing = false
	dockerListCache.Unlock()
}

// collectDockerContainers 执行 docker ps + stats 并组装容器列表
func collectDockerContainers(ctx context.Context) ([]dockerContainer, error) {
	psOut, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--no-trunc",
		"--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Ports}}|{{.CreatedAt}}").Output()
	if err != nil {
		return nil, err
	}

	// stats 单独执行并解析为 map（name -> cpu|mem|net|block）
	statsMap := fetchDockerStatsMap(ctx)

	lines := strings.Split(strings.TrimSpace(string(psOut)), "\n")
	containers := make([]dockerContainer, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 7)
		if len(parts) < 6 {
			continue
		}
		// 名称可能为空（默认取镜像名），docker 输出中 Name 列一般非空
		c := dockerContainer{
			ID:        strings.TrimPrefix(parts[0], "sha256:")[:min(len(parts[0]), 12)],
			Name:      parts[1],
			Image:     parts[2],
			State:     parts[3],
			Status:    parts[4],
			Ports:     parts[5],
			CreatedAt: parts[6],
		}
		if stats, ok := statsMap[c.Name]; ok {
			c.CPU = stats["cpu"]
			c.MemUsage = stats["mem"]
			c.NetIO = stats["net"]
			c.BlockIO = stats["block"]
		}
		// 异常判定：非正常运行状态（重启中/暂停/僵尸/健康检查失败/OOM）
		lowStatus := strings.ToLower(c.Status)
		c.Abnormal = isAbnormalContainer(c.State, lowStatus)
		containers = append(containers, c)
	}

	// 按运行中优先、异常次之、名称排序，便于浏览
	sort.SliceStable(containers, func(i, j int) bool {
		if containers[i].State != containers[j].State {
			return containers[i].State == "running"
		}
		if containers[i].Abnormal != containers[j].Abnormal {
			return containers[i].Abnormal
		}
		return containers[i].Name < containers[j].Name
	})

	return containers, nil
}

// isAbnormalContainer 判断容器是否处于异常状态（用于异常统计与列表标识）
func isAbnormalContainer(state, lowStatus string) bool {
	switch state {
	case "restarting", "paused", "dead":
		return true
	case "exited":
		// 正常退出（Exit 0）不算异常，非 0 退出码视为异常
		return strings.Contains(lowStatus, "exited (1") || strings.Contains(lowStatus, "exited (2") ||
			strings.Contains(lowStatus, "exited (13") || strings.Contains(lowStatus, "exited (13")
	}
	if strings.Contains(lowStatus, "unhealthy") {
		return true
	}
	return false
}

// fetchDockerStatsMap 执行 docker stats --no-stream 并返回 name -> {cpu, mem, net, block} 映射
func fetchDockerStatsMap(ctx context.Context) map[string]map[string]string {
	result := map[string]map[string]string{}
	statsOut, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream",
		"--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}").Output()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(strings.TrimSpace(string(statsOut)), "\n") {
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}
		result[parts[0]] = map[string]string{"cpu": parts[1], "mem": parts[2], "net": parts[3], "block": parts[4]}
	}
	return result
}

// min 返回两个整数中较小者，用于截断容器 ID 显示
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dockerActionHandler 容器启停/重启，POST 写操作，需 docker:manage
// 请求体: {"container": "容器名称或ID", "action": "start|stop|restart"}
func dockerActionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Container string `json:"container"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, "请求格式错误", nil)
		return
	}
	req.Container = strings.TrimSpace(req.Container)
	req.Action = strings.TrimSpace(req.Action)
	if req.Container == "" {
		writeJSON(w, http.StatusBadRequest, "缺少容器名称", nil)
		return
	}
	// 白名单校验 action，防止命令注入
	switch req.Action {
	case "start", "stop", "restart":
	default:
		writeJSON(w, http.StatusBadRequest, "不支持的操作: "+req.Action, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", req.Action, req.Container).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "操作失败: "+strings.TrimSpace(string(out)), nil)
		return
	}
	recordAccess(r)
	auditAction(r, "docker", req.Action+" "+req.Container)
	invalidateDockerCaches() // 状态已变更，使缓存失效以便前端立刻看到最新状态
	writeJSON(w, http.StatusOK, "操作成功: "+strings.TrimSpace(string(out)), nil)
}

// dockerLogsHandler 获取容器日志（最近 N 行），只读，需 docker:view
// 查询参数: ?container=xxx&lines=100&since=10m
func dockerLogsHandler(w http.ResponseWriter, r *http.Request) {
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	if container == "" {
		writeJSON(w, http.StatusBadRequest, "缺少容器名称", nil)
		return
	}
	// 限制行数防止读取过大日志导致资源耗尽
	lines := 100
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			lines = n
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	args := []string{"logs", "--tail", strconv.Itoa(lines)}
	if since := strings.TrimSpace(r.URL.Query().Get("since")); since != "" {
		args = append(args, "--since", since)
	}
	args = append(args, container)

	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		if len(out) == 0 {
			writeJSON(w, http.StatusInternalServerError, "获取日志失败", nil)
			return
		}
		// 容器已停止时 docker logs 可能返回非零，但日志仍有效，此时返回部分内容
	}
	writeJSON(w, http.StatusOK, "success", map[string]interface{}{
		"logs": string(out),
	})
}

// dockerPageHandler 提供 Docker 管理页面（需登录且具备 docker:view 权限）
func dockerPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData, err := os.ReadFile(filepath.Join(indexPath, "docker.html"))
	if err != nil {
		http.Error(w, "无法读取 Docker 页面: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(htmlData)
}

// dockerOverview 资源概览与 daemon 健康汇总（供页面 Header 与统计卡使用）
type dockerOverview struct {
	OK              bool    `json:"ok"`               // daemon 是否可用
	Version         string  `json:"version"`          // Docker 版本
	TotalContainers int     `json:"total_containers"` // 容器总数
	Running         int     `json:"running"`          // 运行中
	Stopped         int     `json:"stopped"`          // 已停止
	Abnormal        int     `json:"abnormal"`         // 异常容器数（restarting/unhealthy/退出码非0）
	CPUTotal        string  `json:"cpu_total"`        // 全部运行容器 CPU 汇总文本（如 1.06%）
	MemUsed         string  `json:"mem_used"`         // 内存已用（如 159 MiB）
	MemTotal        string  `json:"mem_total"`        // 内存上限（如 21.49 GiB）
	MemPct          float64 `json:"mem_pct"`          // 内存占用百分比
	DiskUsed        string  `json:"disk_used"`        // 磁盘已用
	DiskTotal       string  `json:"disk_total"`       // 磁盘总容量（TYPE=Containers 的 SIZE）
}

// dockerOverviewCache 存储 overview 短时缓存（与列表缓存相同的 stale-while-revalidate 策略）
var dockerOverviewCache struct {
	sync.Mutex
	data       dockerOverview
	ok         bool
	ts         time.Time
	refreshing bool // 后台刷新进行中（singleflight）
}

// dockerOverviewHandler 汇总 Docker daemon 健康状态与资源占用，需 docker:view
func dockerOverviewHandler(w http.ResponseWriter, r *http.Request) {
	dockerOverviewCache.Lock()
	if dockerOverviewCache.ok && time.Since(dockerOverviewCache.ts) < dockerListCacheStale {
		// 缓存可用：立即返回，过期则顺带触发后台刷新
		data := dockerOverviewCache.data
		needRefresh := time.Since(dockerOverviewCache.ts) >= dockerListCacheTTL && !dockerOverviewCache.refreshing
		if needRefresh {
			dockerOverviewCache.refreshing = true
		}
		dockerOverviewCache.Unlock()
		if needRefresh {
			go refreshDockerOverviewCache()
		}
		writeJSON(w, http.StatusOK, "success", data)
		return
	}
	dockerOverviewCache.Unlock()

	// 无可用缓存：同步采集
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ov := collectDockerOverview(ctx)

	dockerOverviewCache.Lock()
	dockerOverviewCache.data = ov
	dockerOverviewCache.ok = true
	dockerOverviewCache.ts = time.Now()
	dockerOverviewCache.Unlock()

	writeJSON(w, http.StatusOK, "success", ov)
}

// refreshDockerOverviewCache 后台刷新 overview 缓存（由 stale-while-revalidate 与启动预热调用）
func refreshDockerOverviewCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ov := collectDockerOverview(ctx)

	dockerOverviewCache.Lock()
	dockerOverviewCache.data = ov
	dockerOverviewCache.ok = true
	dockerOverviewCache.ts = time.Now()
	dockerOverviewCache.refreshing = false
	dockerOverviewCache.Unlock()
}

// warmDockerCaches 服务启动时预热 Docker 缓存（在 main 中以 goroutine 调用）
// docker stats 首次采集约 2~4 秒，预热后用户首次打开页面即可命中缓存，避免冷启动慢响应。
func warmDockerCaches() {
	dockerListCache.Lock()
	dockerListCache.refreshing = true
	dockerListCache.Unlock()
	refreshDockerListCache()

	dockerOverviewCache.Lock()
	dockerOverviewCache.refreshing = true
	dockerOverviewCache.Unlock()
	refreshDockerOverviewCache()

	dockerListCache.Lock()
	n := len(dockerListCache.containers)
	warmed := !dockerListCache.ts.IsZero()
	dockerListCache.Unlock()
	if warmed {
		log.Printf("✅ Docker 缓存预热完成（%d 个容器）", n)
	} else {
		log.Println("⚠️ Docker 缓存预热失败（本机可能未安装 Docker 或 daemon 未运行）")
	}
}

// invalidateDockerCaches 写操作（启停/重启/删除）后使缓存立即失效，确保下一次请求拿到最新状态
func invalidateDockerCaches() {
	dockerListCache.Lock()
	dockerListCache.ts = time.Time{}
	dockerListCache.Unlock()
	dockerOverviewCache.Lock()
	dockerOverviewCache.ts = time.Time{}
	dockerOverviewCache.Unlock()
}

// collectDockerOverview 执行 Docker 查询并组装概览数据
func collectDockerOverview(ctx context.Context) dockerOverview {
	ov := dockerOverview{}

	// 1. daemon 健康 + 版本
	verOut, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		ov.OK = false
		return ov
	}
	ov.OK = true
	ov.Version = strings.TrimSpace(string(verOut))

	// 2. 容器列表统计（含状态与异常计数）
	abnormal := 0
	psOut, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--no-trunc",
		"--format", "{{.Names}}|{{.State}}|{{.Status}}").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}
			ov.TotalContainers++
			if parts[1] == "running" {
				ov.Running++
			} else {
				ov.Stopped++
			}
			if isAbnormalContainer(parts[1], strings.ToLower(parts[2])) {
				abnormal++
			}
		}
	}
	ov.Abnormal = abnormal

	// 3. 汇总运行中容器的 CPU/内存（复用 stats 输出）
	statsOut, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream",
		"--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}").Output()
	if err == nil {
		var cpuSum float64
		var memUsedKB, memTotalKB float64
		for _, line := range strings.Split(strings.TrimSpace(string(statsOut)), "\n") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}
			// CPU: 去 % 尾并累加
			cpuStr := strings.TrimSuffix(parts[0], "%")
			if v, err := strconv.ParseFloat(strings.TrimSpace(cpuStr), 64); err == nil {
				cpuSum += v
			}
			// MemUsage: "32.5MiB / 3.595GiB"
			used, total := parseMemPair(parts[1])
			memUsedKB += used
			memTotalKB += total
		}
		ov.CPUTotal = formatMB(cpuSum) + "%"
		ov.MemUsed = formatSize(memUsedKB * 1024)
		ov.MemTotal = formatSize(memTotalKB * 1024)
		if memTotalKB > 0 {
			ov.MemPct = memUsedKB / memTotalKB * 100
		}
	}

	// 4. 磁盘（docker system df 的 TYPE=Containers 行 SIZE）
	dfOut, err := exec.CommandContext(ctx, "docker", "system", "df").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(dfOut)), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == "Containers" {
				ov.DiskUsed = fields[2]
				ov.DiskTotal = fields[3]
			}
		}
	}

	return ov
}

// parseMemPair 解析 "32.5MiB / 3.595GiB" 为 (usedKiB, totalKiB)
func parseMemPair(s string) (float64, float64) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) < 2 {
		return 0, 0
	}
	return toKiB(parts[0]), toKiB(parts[1])
}

// toKiB 将 "32.5MiB" / "3.595GiB" / "1024B" 换算为 KiB
func toKiB(s string) float64 {
	s = strings.TrimSpace(s)
	mult := 1.0
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "tib"), strings.Contains(lower, "tb"):
		mult = 1024 * 1024 * 1024
	case strings.Contains(lower, "gib"), strings.Contains(lower, "gb"):
		mult = 1024 * 1024
	case strings.Contains(lower, "mib"), strings.Contains(lower, "mb"):
		mult = 1024
	case strings.Contains(lower, "kib"), strings.Contains(lower, "kb"):
		mult = 1
	default:
		mult = 1.0 / 1024 // 纯 B → KiB
	}
	v, err := strconv.ParseFloat(trimNum(s), 64)
	if err != nil {
		return 0
	}
	return v * mult
}

// trimNum 提取字符串开头的数字部分（如 "3.595GiB" → "3.595"）
func trimNum(s string) string {
	s = strings.TrimSpace(s)
	for i, ch := range s {
		if (ch < '0' || ch > '9') && ch != '.' {
			return s[:i]
		}
	}
	return s
}

// formatSize 将字节数格式化为人类可读大小
func formatSize(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	idx := 0
	for b >= 1024 && idx < len(units)-1 {
		b /= 1024
		idx++
	}
	return strconv.FormatFloat(b, 'f', 1, 64) + " " + units[idx]
}

// formatMB 将数字格式化为两位小数文本（用于 CPU 百分比汇总）
func formatMB(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// dockerContainerDetail 容器详情（网络/挂载/环境变量等）
type dockerContainerDetail struct {
	Name        string            `json:"name"`
	ID          string            `json:"id"`
	Image       string            `json:"image"`
	State       string            `json:"state"`
	ExitCode    int               `json:"exit_code"`
	Created     string            `json:"created"`
	NetworkMode string            `json:"network_mode"`
	IP          string            `json:"ip"`
	Ports       string            `json:"ports"`
	Mounts      []string          `json:"mounts"`
	Env         map[string]string `json:"env"` // 已脱敏（含敏感 key 的值仅显示占位符）
	EnvHidden   []string          `json:"env_hidden"`
}

// dockerInspectHandler 获取单个容器详情（网络/挂载/环境变量），Env 脱敏，需 docker:view
// 查询参数: ?container=xxx
func dockerInspectHandler(w http.ResponseWriter, r *http.Request) {
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	if container == "" {
		writeJSON(w, http.StatusBadRequest, "缺少容器名称", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 直接读取 inspect 原生 JSON，用 json 解码（比 Go 模板分段更可靠）
	out, err := exec.CommandContext(ctx, "docker", "inspect", container).Output()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "获取容器详情失败: "+err.Error(), nil)
		return
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(out, &arr); err != nil || len(arr) == 0 {
		writeJSON(w, http.StatusInternalServerError, "解析容器详情失败", nil)
		return
	}
	item := arr[0]

	detail := dockerContainerDetail{
		Name:      strVal(item["Name"]),
		ID:        shortID(strVal(item["Id"])),
		Image:     strVal(item["Image"]),
		Env:       map[string]string{},
		EnvHidden: []string{},
	}
	// 去掉名称前导斜杠
	detail.Name = strings.TrimPrefix(detail.Name, "/")

	// 基础字段（顶层缺省时从嵌套对象取）
	if st, ok := item["State"].(map[string]interface{}); ok {
		detail.State = strVal(st["Status"])
		if ec, ok := st["ExitCode"].(float64); ok {
			detail.ExitCode = int(ec)
		}
	}
	if cfg, ok := item["Config"].(map[string]interface{}); ok {
		if detail.Image == "" {
			detail.Image = strVal(cfg["Image"])
		}
		if envArr, ok := cfg["Env"].([]interface{}); ok {
			for _, e := range envArr {
				kv := strVal(e)
				eq := strings.Index(kv, "=")
				if eq <= 0 {
					continue
				}
				key, val := kv[:eq], kv[eq+1:]
				if isSensitiveEnvKey(strings.ToLower(key)) {
					detail.EnvHidden = append(detail.EnvHidden, key)
					detail.Env[key] = "******"
				} else {
					detail.Env[key] = val
				}
			}
		}
	}
	if created, ok := item["Created"].(string); ok {
		detail.Created = created
	}
	if hc, ok := item["HostConfig"].(map[string]interface{}); ok {
		detail.NetworkMode = strVal(hc["NetworkMode"])
	}
	if ns, ok := item["NetworkSettings"].(map[string]interface{}); ok {
		if nets, ok := ns["Networks"].(map[string]interface{}); ok {
			for _, n := range nets {
				if nm, ok := n.(map[string]interface{}); ok {
					if ip := strVal(nm["IPAddress"]); ip != "" {
						detail.IP = ip
						break
					}
				}
			}
		}
		detail.Ports = strVal(ns["Ports"])
	}
	if mounts, ok := item["Mounts"].([]interface{}); ok {
		for _, m := range mounts {
			if mm, ok := m.(map[string]interface{}); ok {
				src := strVal(mm["Source"])
				dst := strVal(mm["Destination"])
				if dst != "" {
					detail.Mounts = append(detail.Mounts, src+" => "+dst)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, "success", detail)
}

// shortID 截取容器长 ID 的前 12 位
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// strVal 从 interface{} 安全取字符串
func strVal(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// isSensitiveEnvKey 判断环境变量 key 是否敏感（值需要打码）
func isSensitiveEnvKey(k string) bool {
	for _, kw := range []string{"pass", "secret", "token", "key", "auth", "cookie", "session", "credential"} {
		if strings.Contains(k, kw) {
			return true
		}
	}
	return false
}

// dockerRemoveHandler 删除容器（危险操作），POST + CSRF，需 docker:manage
// 请求体: {"container": "容器名称或ID"}
func dockerRemoveHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Container string `json:"container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, "请求格式错误", nil)
		return
	}
	req.Container = strings.TrimSpace(req.Container)
	if req.Container == "" {
		writeJSON(w, http.StatusBadRequest, "缺少容器名称", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// 强制删除（含运行中容器）
	out, err := exec.CommandContext(ctx, "docker", "rm", "-f", req.Container).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "删除失败: "+strings.TrimSpace(string(out)), nil)
		return
	}
	recordAccess(r)
	auditAction(r, "docker", "remove "+req.Container)
	invalidateDockerCaches() // 状态已变更，使缓存失效以便前端立刻看到最新状态
	writeJSON(w, http.StatusOK, "已删除: "+strings.TrimSpace(string(out)), nil)
}
