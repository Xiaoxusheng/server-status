package main

// ==================== IP 安全中心：封禁 / 白名单 / 历史 / 事件 ====================

import (
	"encoding/json"
	"fmt"
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

	"github.com/gorilla/websocket"
)

// ipSecurityFile IP 安全数据文件（默认 <数据根目录>/ip_security.json）
var ipSecurityFile = filepath.Join(dataRoot(), "ip_security.json")

// BlockedIP 封禁记录（手动 + 系统自动统一结构）
type BlockedIP struct {
	IP           string     `json:"ip"`
	BlockedAt    time.Time  `json:"blocked_at"`
	BlockedUntil time.Time  `json:"blocked_until"`
	UnblockedAt  *time.Time `json:"unblocked_at,omitempty"`
	UnblockedBy  string     `json:"unblocked_by,omitempty"` // manual / auto
	Reason       string     `json:"reason"`
	Trigger      string     `json:"trigger"`
	Score        int        `json:"score"`
	RequestCount int        `json:"request_count"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	Source       string     `json:"source"` // manual / auto / unknown
	Duration     string     `json:"duration,omitempty"`
	Note         string     `json:"note,omitempty"`
}

// IPWhitelistEntry 白名单条目
type IPWhitelistEntry struct {
	ID        string    `json:"id"`
	IPOrCIDR  string    `json:"ip_or_cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// ipSecurityFileData 持久化结构（原子写入）
type ipSecurityFileData struct {
	Blocked   map[string]*BlockedIP `json:"blocked"`
	History   []*BlockedIP          `json:"history"`
	Whitelist []IPWhitelistEntry    `json:"whitelist"`
}

// ipSecStore 白名单与自动封禁历史
type ipSecStore struct {
	mu        sync.RWMutex
	whitelist []IPWhitelistEntry
	history   []*BlockedIP
}

var ipSec = &ipSecStore{}

// ---------------- 持久化 ----------------

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadIPSecurity 加载 ip_security.json，并迁移旧版 blocked_ips.json 数据
func loadIPSecurity() {
	data, err := os.ReadFile(ipSecurityFile)
	if err == nil {
		var st ipSecurityFileData
		if err := json.Unmarshal(data, &st); err == nil {
			antiCrawler.Lock()
			for k, v := range st.Blocked {
				if v != nil && v.IP == "" {
					v.IP = k
				}
				antiCrawler.blockedIPs[k] = v
			}
			antiCrawler.Unlock()
			ipSec.mu.Lock()
			ipSec.history = st.History
			ipSec.whitelist = st.Whitelist
			ipSec.mu.Unlock()
		} else {
			log.Printf("解析 ip_security.json 失败: %v", err)
		}
	} else if !os.IsNotExist(err) {
		log.Printf("读取 ip_security.json 失败: %v", err)
	}

	// 迁移旧版 blocked_ips.json（[]string，手动封禁 365 天）
	if oldData, err := os.ReadFile(blockedIPsFile); err == nil {
		var ips []string
		if json.Unmarshal(oldData, &ips) == nil && len(ips) > 0 {
			now := time.Now()
			until := now.Add(365 * 24 * time.Hour)
			antiCrawler.Lock()
			for _, ip := range ips {
				if _, exists := antiCrawler.blockedIPs[ip]; !exists {
					antiCrawler.blockedIPs[ip] = &BlockedIP{
						IP:           ip,
						BlockedAt:    now,
						BlockedUntil: until,
						Reason:       "管理员手动封禁（旧数据迁移）",
						Source:       "manual",
						Duration:     "365d",
					}
				}
			}
			antiCrawler.Unlock()
			log.Printf("已迁移 %d 条旧版手动封禁记录", len(ips))
		}
	}
	saveIPSecurity()
}

// saveIPSecurity 原子持久化当前封禁 / 历史 / 白名单
func saveIPSecurity() {
	antiCrawler.RLock()
	blocked := make(map[string]*BlockedIP, len(antiCrawler.blockedIPs))
	for k, v := range antiCrawler.blockedIPs {
		blocked[k] = v
	}
	antiCrawler.RUnlock()

	ipSec.mu.RLock()
	history := append([]*BlockedIP(nil), ipSec.history...)
	whitelist := append([]IPWhitelistEntry(nil), ipSec.whitelist...)
	ipSec.mu.RUnlock()

	st := ipSecurityFileData{Blocked: blocked, History: history, Whitelist: whitelist}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(dirOf(ipSecurityFile), 0755); err != nil {
		log.Printf("创建 IP 安全目录失败: %v", err)
		return
	}
	if err := writeFileAtomic(ipSecurityFile, data, 0600); err != nil {
		log.Printf("保存 ip_security.json 失败: %v", err)
	}
}

// ---------------- 历史记录 ----------------

// appendAutoHistory 追加自动封禁历史（按 IP+封禁时间去重）
func appendAutoHistory(b *BlockedIP) {
	ipSec.mu.Lock()
	defer ipSec.mu.Unlock()
	for _, h := range ipSec.history {
		if h.IP == b.IP && h.BlockedAt.Equal(b.BlockedAt) {
			return
		}
	}
	ipSec.history = append(ipSec.history, b)
}

// ---------------- 封禁操作 ----------------

func parseBlockDuration(s string) (time.Duration, bool) {
	switch s {
	case "10m":
		return 10 * time.Minute, true
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	}
	if strings.HasSuffix(s, "m") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "m")); err == nil && n > 0 {
			return time.Duration(n) * time.Minute, true
		}
	}
	return 0, false
}

// addAutoBlock 记录系统自动封禁并推送事件、审计、持久化
func addAutoBlock(b *BlockedIP, r *http.Request) {
	antiCrawler.Lock()
	antiCrawler.blockedIPs[b.IP] = b
	antiCrawler.Unlock()
	saveIPSecurity()

	ipEventsHub.broadcast(map[string]interface{}{
		"type":          "ip.blocked",
		"source":        "auto",
		"ip":            b.IP,
		"reason":        b.Reason,
		"trigger":       b.Trigger,
		"blocked_until": b.BlockedUntil.Format(time.RFC3339),
	})
	// 系统自动封禁，无操作者会话，操作人记为 system
	writeAuditEntry("system", "",
		"ip.block.auto",
		fmt.Sprintf("系统自动封禁 IP=%s 原因=%s 触发=%s 请求数=%d 评分=%d", b.IP, b.Reason, b.Trigger, b.RequestCount, b.Score))
	log.Printf("🚫 系统自动封禁 IP %s（%s / %s）", b.IP, b.Reason, b.Trigger)
}

// expireBlockedIP 过期清理：自动封禁写入历史并解封
func expireBlockedIP(ip string) {
	antiCrawler.Lock()
	b := antiCrawler.blockedIPs[ip]
	if b != nil {
		if b.Source == "auto" {
			now := time.Now()
			b.UnblockedAt = &now
			b.UnblockedBy = "auto"
			appendAutoHistory(b)
		}
		delete(antiCrawler.blockedIPs, ip)
	}
	antiCrawler.Unlock()
	saveIPSecurity()
	if b != nil && b.Source == "auto" {
		// 系统自动解封，无请求上下文，操作人记为 system
		writeAuditEntry("system", "", "ip.unblock.auto", "自动封禁到期解封 IP="+ip)
		log.Printf("⏳ 自动封禁到期，IP %s 已恢复访问", ip)
	}
}

// removeBlockedIP 手动解封（自动封禁同时归档历史）
func removeBlockedIP(ip string, r *http.Request) {
	antiCrawler.Lock()
	b := antiCrawler.blockedIPs[ip]
	if b != nil && b.Source == "auto" {
		now := time.Now()
		b.UnblockedAt = &now
		b.UnblockedBy = "manual"
		appendAutoHistory(b)
	}
	delete(antiCrawler.blockedIPs, ip)
	antiCrawler.Unlock()
	saveIPSecurity()
	if b != nil && b.Source == "auto" {
		auditAction(r, "ip.unblock.auto", "手动解封系统自动封禁 IP="+ip)
	} else {
		auditAction(r, "ip.unblock.manual", "手动解封 IP="+ip)
	}
}

// pruneExpiredBlocks 定期清理所有过期封禁
func pruneExpiredBlocks(now time.Time) {
	changed := false
	antiCrawler.Lock()
	for ip, b := range antiCrawler.blockedIPs {
		if b == nil {
			delete(antiCrawler.blockedIPs, ip)
			changed = true
			continue
		}
		if now.After(b.BlockedUntil) {
			if b.Source == "auto" {
				b.UnblockedAt = &now
				b.UnblockedBy = "auto"
				appendAutoHistory(b)
			}
			delete(antiCrawler.blockedIPs, ip)
			changed = true
		}
	}
	antiCrawler.Unlock()
	if changed {
		saveIPSecurity()
	}
}

func ipSecurityPruneLoop() {
	t := time.NewTicker(30 * time.Second)
	for range t.C {
		pruneExpiredBlocks(time.Now())
	}
}

// ---------------- 白名单 ----------------

// isWhitelisted 判断 IP 是否命中白名单（精确或 CIDR）
func isWhitelisted(ip string) bool {
	parsed := net.ParseIP(ip)
	ipSec.mu.RLock()
	defer ipSec.mu.RUnlock()
	for _, e := range ipSec.whitelist {
		if e.IPOrCIDR == ip {
			return true
		}
		if strings.Contains(e.IPOrCIDR, "/") {
			_, netw, err := net.ParseCIDR(e.IPOrCIDR)
			if err == nil && parsed != nil && netw.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// ---------------- 事件推送（WebSocket） ----------------

type ipEventHub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

var ipEventsHub = &ipEventHub{clients: map[*websocket.Conn]bool{}}

func (h *ipEventHub) broadcast(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
			delete(h.clients, c)
			c.Close()
		}
	}
}

// ipEventsWSHandler WebSocket：推送 ip.blocked 等安全事件
func ipEventsWSHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("IP 事件 WebSocket 升级失败:", err)
		return
	}
	ipEventsHub.mu.Lock()
	ipEventsHub.clients[conn] = true
	ipEventsHub.mu.Unlock()
	defer func() {
		ipEventsHub.mu.Lock()
		delete(ipEventsHub.clients, conn)
		ipEventsHub.mu.Unlock()
		conn.Close()
	}()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// ---------------- 汇总统计 ----------------

// ipSecuritySummary 汇总当前自动封禁、24h 历史、今日异常、趋势、规则
func ipSecuritySummary() map[string]interface{} {
	pruneExpiredBlocks(time.Now())
	now := time.Now()
	today := now.Format("2006-01-02")

	antiCrawler.RLock()
	autoBlocked := 0
	for _, b := range antiCrawler.blockedIPs {
		if b != nil && b.Source == "auto" && now.Before(b.BlockedUntil) {
			autoBlocked++
		}
	}
	highFreq := map[string]bool{}
	for ip, pats := range antiCrawler.requestPatterns {
		if len(pats) > 100 {
			highFreq[ip] = true
		}
	}
	badUA := map[string]bool{}
	behavior := map[string]bool{}
	for _, p := range antiCrawler.clientFingerprints {
		if p == nil || p.IP == "" {
			continue
		}
		if p.Score > 0 {
			behavior[p.IP] = true
		}
		if !checkUserAgentString(p.UserAgent) {
			badUA[p.IP] = true
		}
	}
	antiCrawler.RUnlock()

	// 今日自动封禁事件（当前 + 历史）
	auto24h := 0
	trend := make([]int, 24)
	allAuto := map[string]bool{}
	ipSec.mu.RLock()
	for _, h := range ipSec.history {
		if h != nil && h.Source == "auto" && now.Sub(h.BlockedAt) <= 24*time.Hour {
			auto24h++
		}
		if h != nil && h.Source == "auto" && h.BlockedAt.Format("2006-01-02") == today {
			trend[h.BlockedAt.Hour()]++
			allAuto[h.IP] = true
		}
	}
	ipSec.mu.RUnlock()
	antiCrawler.RLock()
	for _, b := range antiCrawler.blockedIPs {
		if b != nil && b.Source == "auto" {
			if now.Sub(b.BlockedAt) <= 24*time.Hour {
				auto24h++
			}
			if b.BlockedAt.Format("2006-01-02") == today {
				trend[b.BlockedAt.Hour()]++
				allAuto[b.IP] = true
			}
		}
	}
	antiCrawler.RUnlock()

	// 今日异常 IP 分类
	anomalySet := map[string]bool{}
	for ip := range highFreq {
		anomalySet[ip] = true
	}
	for ip := range badUA {
		anomalySet[ip] = true
	}
	for ip := range behavior {
		anomalySet[ip] = true
	}
	other := []string{}
	for ip := range anomalySet {
		if !highFreq[ip] && !badUA[ip] && !behavior[ip] {
			other = append(other, ip)
		}
	}
	sort.Strings(other)

	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	rules := []map[string]interface{}{
		{"name": "高频请求", "desc": "5 分钟内请求超过 100 次", "duration": "封禁 1 小时"},
		{"name": "行为评分", "desc": "客户端行为评分超过 50", "duration": "封禁 1 小时"},
	}

	return map[string]interface{}{
		"auto_blocked":     autoBlocked,
		"auto_blocked_24h": auto24h,
		"auto_today_ips":   keys(allAuto),
		"today_anomaly": map[string]interface{}{
			"total":     len(anomalySet),
			"high_freq": len(highFreq),
			"bad_ua":    len(badUA),
			"behavior":  len(behavior),
			"http_4xx":  0,
			"http_5xx":  0,
			"other":     len(other),
		},
		"anomaly_ips": map[string]interface{}{
			"high_freq": keys(highFreq),
			"bad_ua":    keys(badUA),
			"behavior":  keys(behavior),
			"other":     other,
		},
		"trend": trend,
		"rules": rules,
	}
}

// ---------------- API 处理函数 ----------------

// listBlockedIPsHandler GET /api/ip/blocked（增强：来源/原因/倒计时）
func listBlockedIPsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	pruneExpiredBlocks(time.Now())
	now := time.Now()
	antiCrawler.RLock()
	list := make([]*BlockedIP, 0, len(antiCrawler.blockedIPs))
	for _, b := range antiCrawler.blockedIPs {
		if b == nil {
			continue
		}
		list = append(list, b)
	}
	antiCrawler.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })

	type item struct {
		*BlockedIP
		Expires          string `json:"expires"`
		Blocked          bool   `json:"blocked"`
		RemainingSeconds int64  `json:"remaining_seconds"`
		Status           string `json:"status"` // blocked / expired
	}
	out := make([]item, 0, len(list))
	for _, b := range list {
		remaining := int64(0)
		status := "blocked"
		if b.BlockedUntil.After(now) {
			remaining = int64(b.BlockedUntil.Sub(now).Seconds())
		} else {
			status = "expired"
		}
		out = append(out, item{
			BlockedIP:        b,
			Expires:          b.BlockedUntil.Format("2006-01-02 15:04:05"),
			Blocked:          status == "blocked",
			RemainingSeconds: remaining,
			Status:           status,
		})
	}
	writeJSON(w, http.StatusOK, "获取封禁列表成功", out)
}

// listBlockHistoryHandler GET /api/ip/blocked/history
func listBlockHistoryHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	ipSec.mu.RLock()
	list := append([]*BlockedIP(nil), ipSec.history...)
	ipSec.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].BlockedAt.After(list[j].BlockedAt) })
	writeJSON(w, http.StatusOK, "获取自动封禁历史成功", list)
}

// listWhitelistHandler GET /api/ip/whitelist
func listWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	ipSec.mu.RLock()
	list := append([]IPWhitelistEntry(nil), ipSec.whitelist...)
	ipSec.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	writeJSON(w, http.StatusOK, "获取白名单成功", list)
}

// addWhitelistHandler POST /api/ip/whitelist
func addWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	var req struct {
		IPOrCIDR string `json:"ip_or_cidr"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	entry := strings.TrimSpace(req.IPOrCIDR)
	if entry == "" {
		writeJSONError(w, http.StatusBadRequest, "请输入 IP 或网段")
		return
	}
	if strings.Contains(entry, "/") {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			writeJSONError(w, http.StatusBadRequest, "网段格式无效（需 CIDR，如 192.168.1.0/24）")
			return
		}
	} else if net.ParseIP(entry) == nil {
		writeJSONError(w, http.StatusBadRequest, "IP 地址无效")
		return
	}
	username := ""
	if s, ok := getSessionFromRequest(r); ok {
		username = s.Username
	}
	ipSec.mu.Lock()
	for _, e := range ipSec.whitelist {
		if e.IPOrCIDR == entry {
			ipSec.mu.Unlock()
			writeJSONError(w, http.StatusConflict, "该 IP/网段已在白名单中")
			return
		}
	}
	ipSec.whitelist = append(ipSec.whitelist, IPWhitelistEntry{
		ID:        fmt.Sprintf("w%d", time.Now().UnixNano()),
		IPOrCIDR:  entry,
		Note:      strings.TrimSpace(req.Note),
		CreatedAt: time.Now(),
		CreatedBy: username,
	})
	ipSec.mu.Unlock()
	saveIPSecurity()
	auditAction(r, "ip.whitelist.add", "白名单添加 "+entry)
	writeJSON(w, http.StatusOK, "白名单已添加", nil)
}

// removeWhitelistHandler POST /api/ip/whitelist/remove
func removeWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	ipSec.mu.Lock()
	out := ipSec.whitelist[:0]
	removed := ""
	for _, e := range ipSec.whitelist {
		if e.ID == req.ID {
			removed = e.IPOrCIDR
			continue
		}
		out = append(out, e)
	}
	ipSec.whitelist = out
	ipSec.mu.Unlock()
	if removed == "" {
		writeJSONError(w, http.StatusNotFound, "白名单条目不存在")
		return
	}
	saveIPSecurity()
	auditAction(r, "ip.whitelist.remove", "白名单移除 "+removed)
	writeJSON(w, http.StatusOK, "白名单已移除", nil)
}

// ipSecuritySummaryHandler GET /api/ip/security/summary
func ipSecuritySummaryHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	writeJSON(w, http.StatusOK, "获取 IP 安全汇总成功", ipSecuritySummary())
}
