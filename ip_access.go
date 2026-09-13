package main

// ==================== 按 IP 访问追踪：/api/ipinfo 单路由 ====================
// 本地实现原 8081 独立服务的 /ipinfo 接口：主服务自行记录每个来源 IP 的
// 访问统计（总请求 / 首次 / 最后 / 状态码分布）与最近请求明细，响应字段与
// 旧服务保持一致，IP 流量面板（ip-panel.html）无需任何改动。

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 容量上限：明细环形队列长度与统计条目数，防止长期运行时内存与落盘文件无限增长
const (
	ipAccessRecordsCap  = 1000
	ipAccessStatsCap    = 10000
	ipAccessDetailPerIP = 200 // 单 IP 详情返回的明细条数上限
)

// ipAccessFile 持久化文件（默认 <数据根目录>/ip_access.json）
var ipAccessFile = filepath.Join(dataRoot(), "ip_access.json")

// ipAccessStat 单个 IP 的累计访问统计（JSON 字段与旧 8081 服务对齐）
type ipAccessStat struct {
	IP           string           `json:"ip"`
	TotalAccess  int64            `json:"total_access"`
	FirstAccess  time.Time        `json:"first_access"`
	LastAccess   time.Time        `json:"last_access"`
	StatusCounts map[string]int64 `json:"status_counts"`
}

// ipAccessRecord 单条请求明细（IP 流量面板「最近访问记录」）；
// URL 仅记路径不记查询串，避免下载令牌等敏感参数进入统计
type ipAccessRecord struct {
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	Status    int       `json:"status"`
}

type ipAccessTracker struct {
	mu      sync.RWMutex
	stats   map[string]*ipAccessStat
	records []ipAccessRecord // 追加制，超上限从头丢弃
}

var ipAccess = &ipAccessTracker{stats: make(map[string]*ipAccessStat)}

// recordIPAccess 请求结束后按真实状态码记账
func (t *ipAccessTracker) record(r *http.Request, status int) {
	ip := getClientIP(r)
	if ip == "" {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.stats[ip]
	if st == nil {
		if len(t.stats) >= ipAccessStatsCap {
			t.evictOldestLocked()
		}
		st = &ipAccessStat{IP: ip, FirstAccess: now, StatusCounts: make(map[string]int64)}
		t.stats[ip] = st
	}
	st.TotalAccess++
	st.LastAccess = now
	st.StatusCounts[strconv.Itoa(status)]++

	t.records = append(t.records, ipAccessRecord{
		IP:        ip,
		Timestamp: now,
		URL:       r.URL.Path,
		Method:    r.Method,
		Status:    status,
	})
	if len(t.records) > ipAccessRecordsCap {
		t.records = t.records[len(t.records)-ipAccessRecordsCap:]
	}
}

// evictOldestLocked 统计条目超限时淘汰最久未访问的 IP
func (t *ipAccessTracker) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	first := true
	for ip, st := range t.stats {
		if first || st.LastAccess.Before(oldest) {
			oldestIP, oldest, first = ip, st.LastAccess, false
		}
	}
	if oldestIP != "" {
		delete(t.stats, oldestIP)
	}
}

// snapshotList 全量统计（按最后访问倒序），供 GET /api/ipinfo 列表模式
func (t *ipAccessTracker) snapshotList() []ipAccessStat {
	t.mu.RLock()
	defer t.mu.RUnlock()
	list := make([]ipAccessStat, 0, len(t.stats))
	for _, st := range t.stats {
		list = append(list, *st)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastAccess.After(list[j].LastAccess) })
	return list
}

// lookup 单 IP 统计 + 最近明细（明细按时间倒序）
func (t *ipAccessTracker) lookup(ip string) (ipAccessStat, []ipAccessRecord, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st, ok := t.stats[ip]
	if !ok {
		return ipAccessStat{}, nil, false
	}
	recs := make([]ipAccessRecord, 0, ipAccessDetailPerIP)
	for i := len(t.records) - 1; i >= 0 && len(recs) < ipAccessDetailPerIP; i-- {
		if t.records[i].IP == ip {
			recs = append(recs, t.records[i])
		}
	}
	return *st, recs, true
}

// loadIPAccess 启动时恢复历史统计
func loadIPAccess() {
	data, err := os.ReadFile(ipAccessFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("读取 ip_access.json 失败: %v", err)
		}
		return
	}
	var snap struct {
		Stats   []ipAccessStat   `json:"stats"`
		Records []ipAccessRecord `json:"records"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		log.Printf("解析 ip_access.json 失败: %v", err)
		return
	}
	ipAccess.mu.Lock()
	defer ipAccess.mu.Unlock()
	for i := range snap.Stats {
		st := snap.Stats[i]
		if st.IP == "" || net.ParseIP(st.IP) == nil {
			continue
		}
		if st.StatusCounts == nil {
			st.StatusCounts = make(map[string]int64)
		}
		ipAccess.stats[st.IP] = &st
	}
	if len(snap.Records) > ipAccessRecordsCap {
		snap.Records = snap.Records[len(snap.Records)-ipAccessRecordsCap:]
	}
	ipAccess.records = snap.Records
}

// saveIPAccess 周期性与退出时落盘（原子写入）
func saveIPAccess() {
	ipAccess.mu.RLock()
	list := make([]ipAccessStat, 0, len(ipAccess.stats))
	for _, st := range ipAccess.stats {
		list = append(list, *st)
	}
	records := make([]ipAccessRecord, len(ipAccess.records))
	copy(records, ipAccess.records)
	ipAccess.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool { return list[i].LastAccess.After(list[j].LastAccess) })
	if len(list) > ipAccessStatsCap {
		list = list[:ipAccessStatsCap]
	}
	snap := struct {
		Stats   []ipAccessStat   `json:"stats"`
		Records []ipAccessRecord `json:"records"`
	}{Stats: list, Records: records}
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	if err := writeFileAtomic(ipAccessFile, data, 0600); err != nil {
		log.Printf("写入 ip_access.json 失败: %v", err)
	}
}

// statusRecorder 包装 ResponseWriter 记录真实状态码；
// 实现 Hijack / Flush 以兼容 WebSocket 升级与流式响应
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("底层 ResponseWriter 未实现 http.Hijacker")
	}
	s.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

// ipAccessMiddleware 全链路按 IP 记账；/api/ipinfo 自身不记账，
// 避免 IP 面板轮询把自己的请求混进统计
func ipAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path != "/api/ipinfo" {
			ipAccess.record(r, rec.status)
		}
	})
}

// ipinfoHandler GET /api/ipinfo（原 8081 /ipinfo 的本地单路由实现）
// 无参：返回全部 IP 统计数组；?ip=x：返回该 IP 的 {stats, records}。
// 未记录过的 IP 返回纯文本 "IP not found"（与旧服务一致，前端据此提示无记录）。
func ipinfoHandler(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ipAccess.snapshotList())
		return
	}
	if net.ParseIP(ip) == nil {
		http.Error(w, "无效的IP地址", http.StatusBadRequest)
		return
	}
	st, recs, ok := ipAccess.lookup(ip)
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("IP not found"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"stats": st, "records": recs})
}
