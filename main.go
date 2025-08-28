package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

type ServerStatus struct {
	CPUUsage      float64          `json:"cpu_usage"`
	MemoryUsage   float64          `json:"memory_usage"`
	MemoryTotal   uint64           `json:"memory_total"`
	DiskUsage     float64          `json:"disk_usage"`
	DiskTotal     uint64           `json:"disk_total"`
	UploadSpeed   float64          `json:"upload_speed"`
	DownloadSpeed float64          `json:"download_speed"`
	TotalUpload   string           `json:"total_upload"`
	TotalDownload string           `json:"total_download"`
	ReadSpeed     float64          `json:"read_speed"`
	WriteSpeed    float64          `json:"write_speed"`
	Load1         float64          `json:"load1"`
	Load5         float64          `json:"load5"`
	Load15        float64          `json:"load15"`
	Uptime        string           `json:"uptime"`
	OnlineCount   int              `json:"online_count"`
	UniqueIPs     []string         `json:"unique_ips"`
	OnlineUsers   []OnlineUserInfo `json:"online_users"`
	// 新增主机信息字段
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Platform      string `json:"platform"`
	KernelVersion string `json:"kernel_version"`
	Architecture  string `json:"architecture"`
}

// 新增：用于WebSocket传输的在线用户信息结构
type OnlineUserInfo struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Since     string `json:"since"` // 格式化时间字符串
	Page      string `json:"page"`
}

// 访问统计结构体
type AccessStats struct {
	sync.RWMutex
	DailyVisits    map[string]int
	WeeklyVisits   map[string]int
	UniqueVisitors map[string]map[string]bool
}

type AccessStatsSnapshot struct {
	DailyVisits  map[string]int `json:"daily_visits"`
	WeeklyVisits map[string]int `json:"weekly_visits"`
}

// 在线用户结构体
type OnlineUser struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Since     time.Time `json:"since"`
	Page      string    `json:"page"`
}

type OnlineUsers struct {
	sync.RWMutex
	Users map[string]*OnlineUser // key is IP+UserAgent to identify unique sessions
}

// 持久化结构体
type PersistData struct {
	TotalUploadAccum   uint64              `json:"total_upload_accum"`
	TotalDownloadAccum uint64              `json:"total_download_accum"`
	AccessStats        AccessStatsSnapshot `json:"access_stats"`
}

var (
	authToken          = "123456"
	upgrader           = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	startTime          = time.Now()
	lastNetStats       = map[string]NetStat{}
	lastDiskStats      = map[string]DiskStat{}
	totalUploadAccum   uint64
	totalDownloadAccum uint64
	accessStats        = &AccessStats{
		DailyVisits:    make(map[string]int),
		WeeklyVisits:   make(map[string]int),
		UniqueVisitors: make(map[string]map[string]bool),
	}
	onlineUsers = &OnlineUsers{
		Users: make(map[string]*OnlineUser),
	}
	url = "https://wustwu.cn:8081/static/"
	// 新增：主机信息缓存
	hostInfo      *host.InfoStat
	hostInfoErr   error
	hostInfoMutex sync.Mutex
)

const dataFile = "server_data.json"

type NetStat struct {
	BytesSent uint64
	BytesRecv uint64
	Time      time.Time
}

type DiskStat struct {
	ReadBytes  uint64
	WriteBytes uint64
	Time       time.Time
}

// EpubInfo 保存每本书的信息
type EpubInfo struct {
	FileName     string `json:"file_name"`
	Title        string `json:"title"`
	Author       string `json:"author"`
	ChapterCount int    `json:"chapter_count"`
	Url          string `json:"url"`
}

// 新增：获取主机信息函数
func getHostInfo() (*host.InfoStat, error) {
	hostInfoMutex.Lock()
	defer hostInfoMutex.Unlock()

	// 如果已经获取过且没有错误，直接返回缓存的信息
	if hostInfo != nil && hostInfoErr == nil {
		return hostInfo, nil
	}

	// 重新获取主机信息
	hostInfo, hostInfoErr = host.Info()
	if hostInfoErr != nil {
		log.Printf("获取主机信息失败: %v", hostInfoErr)
		return nil, hostInfoErr
	}

	return hostInfo, nil
}

func enableCORSh(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// 加载持久化数据
func loadData() {
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		saveData()
		return
	}

	file, err := os.Open(dataFile)
	if err != nil {
		log.Println("读取数据文件失败:", err)
		return
	}
	defer file.Close()

	var data PersistData
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		log.Println("解析数据文件失败:", err)
		return
	}

	totalUploadAccum = data.TotalUploadAccum
	totalDownloadAccum = data.TotalDownloadAccum
	accessStats.DailyVisits = data.AccessStats.DailyVisits
	accessStats.WeeklyVisits = data.AccessStats.WeeklyVisits

	log.Println("✅ 数据加载完成")
}

// 保存持久化数据
func saveData() {
	accessStats.RLock()
	data := PersistData{
		TotalUploadAccum:   totalUploadAccum,
		TotalDownloadAccum: totalDownloadAccum,
		AccessStats: AccessStatsSnapshot{
			DailyVisits:  accessStats.DailyVisits,
			WeeklyVisits: accessStats.WeeklyVisits,
		},
	}
	accessStats.RUnlock()

	file, err := os.OpenFile(dataFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Println("保存数据文件失败:", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Println("写入数据文件失败:", err)
	}
}

var mediaDir = "/root/file/static"
var num = 0
var key = 0
var files = []string{}

func main() {
	loadData()

	// 启动时获取主机信息
	go func() {
		_, err := getHostInfo()
		if err != nil {
			log.Printf("初始化主机信息失败: %v", err)
		} else {
			log.Println("✅ 主机信息获取完成")
		}
	}()

	// 定时保存数据
	go func() {
		for {
			time.Sleep(30 * time.Second)
			saveData()
		}
	}()

	// 定时清理长时间无活动的在线用户
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			onlineUsers.Lock()
			now := time.Now()
			for key, user := range onlineUsers.Users {
				// 如果用户超过30分钟无活动，移除
				if now.Sub(user.Since) > 30*time.Minute {
					delete(onlineUsers.Users, key)
				}
			}
			onlineUsers.Unlock()
		}
	}()

	// 监听退出信号
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		saveData()
		log.Println("程序退出，数据已保存")
		os.Exit(0)
	}()

	// 每日统计重置
	go resetDailyStats()

	//http.HandleFunc("/", indexHandler)
	http.Handle("/", http.FileServer(http.Dir("/root/os/templates")))
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/video", homeHandler)
	http.HandleFunc("/status-ifaces", enableCORSh(http.HandlerFunc(ifacesHandler)))
	http.HandleFunc("/random-media", enableCORSh(http.HandlerFunc(randomMediaHandler)))
	http.HandleFunc("/access-stats", accessStatsHandler)
	http.HandleFunc("/exec", execHandler)
	http.HandleFunc("/epubs", enableCORSh(http.HandlerFunc(listEpubs)))

	fmt.Println("Server running at https://localhost:9000")
	log.Fatal(http.ListenAndServeTLS(":9000", "/root/ssl/wustwu.cn.pem", "/root/ssl/wustwu.cn.key", nil))
}

func listEpubs(w http.ResponseWriter, r *http.Request) {
	dir := "/root/file/static" // EPUB 文件所在目录
	var urls []string

	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理 .epub 文件
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".epub") {
			urls = append(urls, url+info.Name())
		}
		return nil
	})

	if err != nil {
		http.Error(w, "读取 EPUB 目录失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(urls)
}

// ---------------- 在线用户处理 ----------------
func updateOnlineUser(r *http.Request, page string) {
	ip := getClientIP(r)
	userAgent := r.UserAgent()
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// 创建唯一标识符：IP + UserAgent
	userKey := fmt.Sprintf("%s|%s", ip, userAgent)

	onlineUsers.Lock()
	defer onlineUsers.Unlock()

	// 更新或添加用户
	onlineUsers.Users[userKey] = &OnlineUser{
		IP:        ip,
		UserAgent: userAgent,
		Since:     time.Now(),
		Page:      page,
	}
}

func getClientIP(r *http.Request) string {
	// 首先检查 X-Forwarded-For 头
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// 取第一个 IP（可能有多个，用逗号分隔）
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// 如果是 IPv6 地址且被方括号包围（如 [::1]），去除方括号
			if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
				return ip[1 : len(ip)-1]
			}
			return ip
		}
	}

	// 如果没有代理，直接从 RemoteAddr 获取
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 如果分割失败，尝试直接使用（可能是没有端口的情况）
		return r.RemoteAddr
	}

	// 处理 IPv6 地址（可能带有方括号）
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}

	return host
}

// 获取在线用户统计信息和详细列表
func getOnlineUsersStats() (int, []string, []OnlineUserInfo) {
	onlineUsers.RLock()
	defer onlineUsers.RUnlock()

	onlineCount := len(onlineUsers.Users)
	ipSet := make(map[string]bool)
	userList := make([]OnlineUserInfo, 0, onlineCount)

	for _, user := range onlineUsers.Users {
		ipSet[user.IP] = true
		// 添加用户详细信息到列表
		userList = append(userList, OnlineUserInfo{
			IP:        user.IP,
			UserAgent: user.UserAgent,
			Since:     user.Since.Format("2006-01-02 15:04:05"),
			Page:      user.Page,
		})
	}

	// 获取唯一IP列表
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}

	return onlineCount, ipList, userList
}

// ---------------- 访问统计 ----------------
func accessStatsHandler(w http.ResponseWriter, r *http.Request) {
	accessStats.RLock()
	defer accessStats.RUnlock()

	recentDays := make(map[string]int)
	now := time.Now()
	for i := 0; i < 7; i++ {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		recentDays[date] = accessStats.DailyVisits[date]
	}

	recentWeeks := make(map[string]int)
	for i := 0; i < 4; i++ {
		week := now.AddDate(0, 0, -7*i).Format("2006-01")
		recentWeeks[week] = accessStats.WeeklyVisits[week]
	}

	totalVisits := 0
	for _, count := range accessStats.DailyVisits {
		totalVisits += count
	}

	stats := map[string]interface{}{
		"daily_visits":  recentDays,
		"weekly_visits": recentWeeks,
		"total_visits":  totalVisits,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func resetDailyStats() {
	for {
		now := time.Now()
		next := now.Add(24 * time.Hour)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
		duration := next.Sub(now)
		time.Sleep(duration)

		accessStats.Lock()
		week := now.Format("2006-01")
		accessStats.WeeklyVisits[week] += accessStats.DailyVisits[now.Format("2006-01-02")]
		today := time.Now().Format("2006-01-02")
		accessStats.DailyVisits[today] = 0
		accessStats.UniqueVisitors[today] = make(map[string]bool)
		accessStats.Unlock()
	}
}

func recordAccess(r *http.Request) {
	ip := getClientIP(r)

	today := time.Now().Format("2006-01-02")

	accessStats.Lock()
	defer accessStats.Unlock()

	if _, exists := accessStats.UniqueVisitors[today]; !exists {
		accessStats.UniqueVisitors[today] = make(map[string]bool)
	}

	if !accessStats.UniqueVisitors[today][ip] {
		accessStats.UniqueVisitors[today][ip] = true
		accessStats.DailyVisits[today]++
	}
}

// ---------------- 媒体文件 ----------------
func randomMediaHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "random-media")

	type fileUrl struct {
		Src  string `json:"src"`
		Code int32  `json:"code"`
	}
	s := new(fileUrl)
	rand.NewSource(time.Now().UnixNano())

	if num != 0 && len(files) == 0 {
		s.Code = 1
		json.NewEncoder(w).Encode(s)
		return
	}

	if num > 0 && key <= 10 {
		key++
		randIdx := rand.Intn(len(files))
		s.Code = 200
		s.Src = "https://wustwu.cn:8081/static/" + files[randIdx]
		json.NewEncoder(w).Encode(s)
	} else {
		key = 0
		num = 0
		files = nil
		files = make([]string, 0, 40)
		err := filepath.WalkDir(mediaDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext == ".jpg" || ext == ".png" || ext == ".jpeg" || ext == ".mp4" || ext == ".webm" {
				files = append(files, d.Name())
				num++
			}
			return nil
		})
		if err != nil {
			log.Println(err)
			http.Error(w, "Error reading media folder", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if len(files) == 0 {
			s.Code = 1
			json.NewEncoder(w).Encode(s)
			return
		}

		randIdx := rand.Intn(len(files))
		s.Code = 200
		s.Src = "https://wustwu.cn:8081/static/" + files[randIdx]
		json.NewEncoder(w).Encode(s)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "video")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData, err := os.ReadFile("/root/os/templates/video.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取 HTML 文件: %v", err), http.StatusInternalServerError)
		log.Printf("读取 video.html 失败: %v", err)
		return
	}
	_, err = w.Write(htmlData)
	if err != nil {
		http.Error(w, fmt.Sprintf("err: %v", err), http.StatusInternalServerError)
		log.Printf("写入响应失败: %v", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "index")
	tmpl := template.Must(template.ParseFiles("/root/os/templates/index.html"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func ifacesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "status-ifaces")
	ifaces, err := psnet.Interfaces()
	if err != nil {
		http.Error(w, "Error fetching interfaces", http.StatusInternalServerError)
		return
	}
	names := []string{}
	for _, i := range ifaces {
		if len(i.HardwareAddr) > 0 {
			names = append(names, i.Name)
		}
	}
	json.NewEncoder(w).Encode(names)
}

// ---------------- WebSocket ----------------
func wsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "websocket")
	token := r.URL.Query().Get("token")
	if token != authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	iface := r.URL.Query().Get("iface")
	if iface == "" {
		http.Error(w, "iface required", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket Upgrade Error:", err)
		return
	}

	// 获取用户标识
	ip := getClientIP(r)
	userAgent := r.UserAgent()
	userKey := fmt.Sprintf("%s|%s", ip, userAgent)

	// 设置连接参数
	conn.SetReadLimit(512)                                 // 限制消息大小
	conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // 设置读超时
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// 创建退出通道
	done := make(chan struct{})

	// 启动goroutine读取客户端消息（主要用于检测连接状态）
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				// 检查是否是正常关闭
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket读取错误: %v", err)
				}
				break
			}
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	pingTicker := time.NewTicker(30 * time.Second) // 每30秒发送一次ping
	defer func() {
		ticker.Stop()
		pingTicker.Stop()
		// 连接关闭时移除用户
		onlineUsers.Lock()
		delete(onlineUsers.Users, userKey)
		onlineUsers.Unlock()
		conn.Close()
	}()

	for {
		select {
		case <-done:
			// 客户端断开连接
			return
		case <-ticker.C:
			// 更新在线用户时间
			updateOnlineUser(r, "websocket")

			status, err := getServerStatus(iface)
			if err != nil {
				log.Println("Error getting status:", err)
				return
			}

			// 设置写超时
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			data, err := json.Marshal(status)
			if err != nil {
				log.Println("JSON Marshal Error:", err)
				return
			}

			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println("WebSocket Write Error:", err)
				return
			}
		case <-pingTicker.C:
			// 发送ping消息检测连接状态
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("WebSocket Ping Error:", err)
				return
			}
		}
	}
}

// ---------------- Server Status ----------------
func getServerStatus(iface string) (*ServerStatus, error) {
	now := time.Now()

	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	loadAvg, err := load.Avg()
	if err != nil {
		return nil, err
	}

	netIOs, err := psnet.IOCounters(true)
	if err != nil {
		return nil, err
	}
	var uploadSpeed, downloadSpeed float64
	for _, io := range netIOs {
		if io.Name != iface {
			continue
		}
		last := lastNetStats[iface]
		if !last.Time.IsZero() {
			secs := now.Sub(last.Time).Seconds()
			if secs > 0 {
				uploadSpeed = float64(io.BytesSent-last.BytesSent) / 1024 / secs
				downloadSpeed = float64(io.BytesRecv-last.BytesRecv) / 1024 / secs
				totalUploadAccum += uint64(io.BytesSent-last.BytesSent) / 1024
				totalDownloadAccum += uint64(io.BytesRecv-last.BytesRecv) / 1024
			}
		}
		lastNetStats[iface] = NetStat{
			BytesSent: io.BytesSent,
			BytesRecv: io.BytesRecv,
			Time:      now,
		}
		break
	}

	diskIOs, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}
	var readSpeed, writeSpeed float64
	for name, io := range diskIOs {
		last := lastDiskStats[name]
		if !last.Time.IsZero() {
			secs := now.Sub(last.Time).Seconds()
			if secs > 0 {
				readSpeed += float64(io.ReadBytes-last.ReadBytes) / 1024 / secs
				writeSpeed += float64(io.WriteBytes-last.WriteBytes) / 1024 / secs
			}
		}
		lastDiskStats[name] = DiskStat{
			ReadBytes:  io.ReadBytes,
			WriteBytes: io.WriteBytes,
			Time:       now,
		}
	}

	uptime := time.Since(startTime)
	hours := int(uptime.Hours())
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60
	uptimeStr := fmt.Sprintf("%d小时%d分%d秒", hours, minutes, seconds)

	// 获取在线用户统计信息和详细列表
	onlineCount, uniqueIPs, onlineUsersList := getOnlineUsersStats()

	// 获取主机信息
	hostInfo, err := getHostInfo()
	var hostname, osName, platform, kernelVersion string

	if err == nil && hostInfo != nil {
		hostname = hostInfo.Hostname
		osName = hostInfo.OS
		platform = hostInfo.Platform
		kernelVersion = hostInfo.KernelVersion
	} else {
		// 如果获取失败，使用备用方法
		hostname, _ = os.Hostname()
		osName = runtime.GOOS
		platform = runtime.GOOS
		kernelVersion = "unknown"
	}

	return &ServerStatus{
		CPUUsage:      cpuPercent[0],
		MemoryUsage:   memInfo.UsedPercent,
		MemoryTotal:   memInfo.Total / 1024 / 1024,
		DiskUsage:     diskInfo.UsedPercent,
		DiskTotal:     diskInfo.Total / 1024 / 1024 / 1024,
		UploadSpeed:   uploadSpeed,
		DownloadSpeed: downloadSpeed,
		TotalUpload:   formatBytes(totalUploadAccum),
		TotalDownload: formatBytes(totalDownloadAccum),
		ReadSpeed:     readSpeed,
		WriteSpeed:    writeSpeed,
		Load1:         loadAvg.Load1,
		Load5:         loadAvg.Load5,
		Load15:        loadAvg.Load15,
		Uptime:        uptimeStr,
		OnlineCount:   onlineCount,
		UniqueIPs:     uniqueIPs,
		OnlineUsers:   onlineUsersList,
		Hostname:      hostname,
		OS:            osName,
		Platform:      platform,
		KernelVersion: kernelVersion,
		Architecture:  runtime.GOARCH,
	}, nil
}

func formatBytes(kb uint64) string {
	const (
		KB = 1
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case kb >= GB:
		return fmt.Sprintf("%.2f GB", float64(kb)/float64(GB))
	case kb >= MB:
		return fmt.Sprintf("%.2f MB", float64(kb)/float64(MB))
	default:
		return fmt.Sprintf("%d KB", kb)
	}
}

// ---------------- 安全命令执行接口 ----------------
var allowedCommands = map[string][]string{
	"uptime": {},
	"df":     {"-h"},
	"free":   {"-m"},
	"who":    {},
	"uname":  {"-a"},
	"ls":     {"-lh", "/"},
}

func execHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "exec")

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token != authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cmdName := r.URL.Query().Get("command")
	if cmdName == "" {
		http.Error(w, "Missing command parameter", http.StatusBadRequest)
		return
	}

	args, ok := allowedCommands[cmdName]
	if !ok {
		http.Error(w, "Command not allowed", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdName, args...)
	output, err := cmd.CombinedOutput()

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
			"output":  string(output),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"output": string(output),
	})
}
