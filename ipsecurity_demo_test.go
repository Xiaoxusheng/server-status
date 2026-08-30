package main

// IP 封禁功能演示测试：
// 直接调用生产代码，完整演示 高频触发 → 行为评分触发 → 白名单豁免 →
// 手动封禁 → 封禁列表/倒计时 → 解封 → 过期自动解封 的整个运行过程。
// 运行：go test -run TestIPBlockDemo -v
// 注意：会临时写入 数据目录下的 ip_security.json 与审计日志，结束后自动恢复原状。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// demoReq 构造一个带指定来源 IP 的请求（User-Agent 正常，避免行为评分干扰）
func demoReq(ip, ua string) *http.Request {
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = ip + ":12345"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "zh-CN")
	r.Header.Set("Accept-Encoding", "gzip")
	return r
}

func TestIPBlockDemo(t *testing.T) {
	const (
		ipRate     = "10.10.0.55" // 高频请求演示
		ipBehavior = "10.10.0.66" // 行为评分演示
		ipWl       = "10.10.0.77" // 白名单豁免演示
		ipManual   = "10.10.0.88" // 手动封禁演示
	)

	// ===== 快照现场，结束后恢复（不污染生产数据） =====
	origFile, _ := os.ReadFile(ipSecurityFile)
	antiCrawler.RLock()
	origBlocked := make(map[string]*BlockedIP, len(antiCrawler.blockedIPs))
	for k, v := range antiCrawler.blockedIPs {
		origBlocked[k] = v
	}
	origFP := make(map[string]*ClientProfile, len(antiCrawler.clientFingerprints))
	for k, v := range antiCrawler.clientFingerprints {
		origFP[k] = v
	}
	origReq := make(map[string][]time.Time, len(antiCrawler.requestPatterns))
	for k, v := range antiCrawler.requestPatterns {
		origReq[k] = v
	}
	antiCrawler.RUnlock()
	ipSec.mu.RLock()
	origWL := append([]IPWhitelistEntry(nil), ipSec.whitelist...)
	origHist := append([]*BlockedIP(nil), ipSec.history...)
	ipSec.mu.RUnlock()

	defer func() {
		antiCrawler.Lock()
		antiCrawler.blockedIPs = origBlocked
		antiCrawler.clientFingerprints = origFP
		antiCrawler.requestPatterns = origReq
		antiCrawler.Unlock()
		ipSec.mu.Lock()
		ipSec.whitelist = origWL
		ipSec.history = origHist
		ipSec.mu.Unlock()
		if origFile != nil {
			writeFileAtomic(ipSecurityFile, origFile, 0600)
		}
		fmt.Println("\n✅ 演示结束，已恢复演示前的封禁/白名单/历史数据")
	}()

	demoIPs := []string{ipRate, ipBehavior, ipManual}
	printBlocked := func(tag string) {
		antiCrawler.RLock()
		defer antiCrawler.RUnlock()
		fmt.Printf("\n[%s] 当前封禁状态：\n", tag)
		has := false
		for _, ip := range demoIPs {
			if b, ok := antiCrawler.blockedIPs[ip]; ok && b != nil {
				has = true
				fmt.Printf("  %-14s source=%-6s reason=%-8s trigger=%-15s score=%-3d req=%-3d 到期=%s\n",
					ip, b.Source, b.Reason, b.Trigger, b.Score, b.RequestCount, b.BlockedUntil.Format("15:04:05"))
			}
		}
		if !has {
			fmt.Println("  （无演示 IP 处于封禁状态）")
		}
	}

	// ===== ① 高频请求触发系统自动封禁 =====
	fmt.Println("===== ① 高频请求触发自动封禁（5 分钟 > 100 次） =====")
	fmt.Println("  模拟 IP", ipRate, "连续发起请求...")
	for i := 1; i <= 130; i++ {
		ok := analyzeBehavior(demoReq(ipRate, "Mozilla/5.0"), "demo-rate")
		if i%20 == 0 {
			fmt.Printf("    第 %d 次请求 → 放行=%v\n", i, ok)
		}
		if !ok {
			fmt.Printf("  ✅ 第 %d 次请求触发封禁（analyzeBehavior 返回 false）\n", i)
			break
		}
	}
	antiCrawler.RLock()
	bRate := antiCrawler.blockedIPs[ipRate]
	antiCrawler.RUnlock()
	if bRate == nil {
		t.Fatal("高频请求未能触发自动封禁")
	}
	fmt.Printf("  封禁记录：reason=%s trigger=%s request_count=%d\n", bRate.Reason, bRate.Trigger, bRate.RequestCount)
	fmt.Printf("  isIPBlocked(%s) = %v（拦截生效）\n", ipRate, isIPBlocked(ipRate))
	fmt.Printf("  WebSocket 事件 payload：{\"type\":\"ip.blocked\",\"source\":\"auto\",\"ip\":%q,\"reason\":%q,\"trigger\":%q,\"blocked_until\":%q}\n",
		ipRate, bRate.Reason, bRate.Trigger, bRate.BlockedUntil.Format(time.RFC3339))
	printBlocked("① 高频触发后")

	// ===== ② 行为评分触发系统自动封禁 =====
	fmt.Println("\n===== ② 行为评分触发自动封禁（评分 > 50） =====")
	antiCrawler.Lock()
	antiCrawler.clientFingerprints["demo-behavior"] = &ClientProfile{
		Fingerprint: "demo-behavior", IP: ipBehavior, UserAgent: "curl/8.0",
		FirstSeen: time.Now(), LastSeen: time.Now(), RequestCount: 382, Score: 60,
	}
	antiCrawler.Unlock()
	ok := analyzeBehavior(demoReq(ipBehavior, "curl/8.0"), "demo-behavior")
	fmt.Printf("  评分=60 的客户端发起 1 次请求 → 放行=%v（预期 false）\n", ok)
	antiCrawler.RLock()
	bBehavior := antiCrawler.blockedIPs[ipBehavior]
	antiCrawler.RUnlock()
	if bBehavior == nil {
		t.Fatal("行为评分未能触发自动封禁")
	}
	fmt.Printf("  封禁记录：reason=%s trigger=%s score=%d request_count=%d fingerprint=%s\n",
		bBehavior.Reason, bBehavior.Trigger, bBehavior.Score, bBehavior.RequestCount, bBehavior.Fingerprint)
	printBlocked("② 行为评分触发后")

	// ===== ③ 白名单豁免 =====
	fmt.Println("\n===== ③ 白名单豁免（CIDR 10.10.0.0/24） =====")
	ipSec.mu.Lock()
	ipSec.whitelist = append(ipSec.whitelist, IPWhitelistEntry{
		ID: "demo-wl", IPOrCIDR: "10.10.0.0/24", Note: "演示白名单", CreatedAt: time.Now(),
	})
	ipSec.mu.Unlock()
	fmt.Printf("  isWhitelisted(%s) = %v\n", ipWl, isWhitelisted(ipWl))
	blocked := false
	for i := 1; i <= 130; i++ {
		if !analyzeBehavior(demoReq(ipWl, "Mozilla/5.0"), "demo-wl") {
			blocked = true
			break
		}
	}
	fmt.Printf("  白名单 IP %s 连续 130 次请求后 → 被封禁=%v（预期 false，白名单不会被自动封禁）\n", ipWl, blocked)
	printBlocked("③ 白名单豁免后")

	// ===== ④ 手动封禁（时长 + 原因） =====
	fmt.Println("\n===== ④ 手动封禁（1 小时 / 暴力尝试 / 备注） =====")
	body := `{"ip":"` + ipManual + `","duration":"1h","reason":"暴力尝试","note":"演示测试手动封禁"}`
	req := httptest.NewRequest("POST", "/api/ip/block", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	blockIPHandler(rec, req)
	fmt.Printf("  POST /api/ip/block → HTTP %d，响应：%s\n", rec.Code, strings.TrimSpace(rec.Body.String()))
	printBlocked("④ 手动封禁后")

	// ===== ⑤ 封禁列表 API（来源 / 原因 / 倒计时） =====
	fmt.Println("\n===== ⑤ GET /api/ip/blocked 返回（来源/原因/剩余秒数） =====")
	req2 := httptest.NewRequest("GET", "/api/ip/blocked", nil)
	rec2 := httptest.NewRecorder()
	listBlockedIPsHandler(rec2, req2)
	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析列表响应失败: %v", err)
	}
	for _, it := range resp.Data {
		ip, _ := it["ip"].(string)
		if strings.HasPrefix(ip, "10.10.0.") {
			fmt.Printf("  ip=%-14s source=%-6v reason=%-10v trigger=%-15v score=%-3v req=%-3v remaining=%-5v status=%v\n",
				ip, it["source"], it["reason"], it["trigger"], it["score"], it["request_count"], it["remaining_seconds"], it["status"])
		}
	}

	// ===== ⑥ 手动解封（自动封禁归档历史） =====
	fmt.Println("\n===== ⑥ 手动解封自动封禁 IP =====")
	req3 := httptest.NewRequest("POST", "/api/ip/unblock", strings.NewReader(`{"ip":"`+ipRate+`"}`))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	unblockIPHandler(rec3, req3)
	fmt.Printf("  POST /api/ip/unblock(%s) → HTTP %d，响应：%s\n", ipRate, rec3.Code, strings.TrimSpace(rec3.Body.String()))
	printBlocked("⑥ 解封后")

	// ===== ⑦ 到期自动解封（自动封禁写入历史） =====
	fmt.Println("\n===== ⑦ 到期自动解封（把行为评分封禁的到期时间改为过去） =====")
	antiCrawler.Lock()
	if b, ok := antiCrawler.blockedIPs[ipBehavior]; ok {
		b.BlockedUntil = time.Now().Add(-time.Second)
	}
	antiCrawler.Unlock()
	pruneExpiredBlocks(time.Now())
	fmt.Printf("  isIPBlocked(%s) = %v（已恢复访问）\n", ipBehavior, isIPBlocked(ipBehavior))

	req4 := httptest.NewRequest("GET", "/api/ip/blocked/history", nil)
	rec4 := httptest.NewRecorder()
	listBlockHistoryHandler(rec4, req4)
	var resp4 struct {
		Data []map[string]interface{} `json:"data"`
	}
	_ = json.Unmarshal(rec4.Body.Bytes(), &resp4)
	fmt.Println("  GET /api/ip/blocked/history 中的演示记录：")
	for _, it := range resp4.Data {
		ip, _ := it["ip"].(string)
		if strings.HasPrefix(ip, "10.10.0.") {
			fmt.Printf("    ip=%-14s reason=%-10v unblocked_by=%-6v 解封时间=%v\n",
				ip, it["reason"], it["unblocked_by"], it["unblocked_at"])
		}
	}
	printBlocked("⑦ 到期自动解封后")
}
