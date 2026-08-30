// stress 是 server-status 的压力测试工具（纯标准库实现，无需额外依赖）。
//
// 用法示例：
//
//	# 公网场景（未认证），50 并发持续 30 秒
//	go run ./stress -target https://127.0.0.1:9000 -scenario public -c 50 -d 30s
//
//	# 认证场景（先登录拿会话，再压测已认证接口）
//	go run ./stress -target https://127.0.0.1:9000 -scenario auth -username admin -password 'xxx' -c 50 -d 60s
//
//	# 限制总速率 200 QPS，逐步爬坡 10 秒
//	go run ./stress -target https://example.com:9000 -rate 200 -ramp 10s -c 100 -d 2m
//
// 注意事项：
//   - 请在局域网内或低峰期执行，避免触发服务端 ipsecurity 自动封禁（ip.block.auto）。
//   - 工具对每个 worker 仅登录一次，不会触发 /login 的登录限流（15 分钟窗口）。
//   - 压测的是只读 GET 接口，不会产生写操作或审计噪音。
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 请求结果记录：单次请求的耗时与结束状态（成功/HTTP错误/网络错误）
type reqResult struct {
	latency  time.Duration
	status   int // 0 表示网络层错误（未收到响应）
	err      string
	endpoint string
}

// endpoint 描述一个被压测的接口：路径与权重（权重决定在混合场景中被选中的概率）
type endpoint struct {
	path   string
	weight int
}

// 场景定义：public 为未认证可访问路径；auth 为需要会话的路径
var (
	publicEndpoints = []endpoint{
		{path: "/", weight: 3},
		{path: "/check-auth", weight: 2},
		{path: "/download-info", weight: 1},
	}
	authEndpoints = []endpoint{
		{path: "/", weight: 3},
		{path: "/check-auth", weight: 2},
		{path: "/status-ifaces", weight: 1},
	}
)

func main() {
	var (
		target   = flag.String("target", "https://127.0.0.1:9000", "目标服务器基址 URL")
		scenario = flag.String("scenario", "public", "压测场景: public | auth")
		conc     = flag.Int("c", 50, "并发 worker 数")
		dur      = flag.Duration("d", 30*time.Second, "压测持续时间")
		ramp     = flag.Duration("ramp", 0, "爬坡时间（worker 在该时间内逐个启动）")
		rate     = flag.Float64("rate", 0, "总速率上限（QPS），0 表示不限速")
		timeout  = flag.Duration("timeout", 10*time.Second, "单次请求超时")
		username = flag.String("username", "", "认证场景的用户名")
		password = flag.String("password", "", "认证场景的密码（建议通过环境变量 STRESS_PASSWORD 传入）")
		insecure = flag.Bool("insecure", true, "跳过 TLS 证书校验（自签证书场景）")
	)
	flag.Parse()

	if pass := os.Getenv("STRESS_PASSWORD"); pass != "" {
		*password = pass
	}

	if *scenario == "auth" && (*username == "" || *password == "") {
		fmt.Fprintln(os.Stderr, "错误: auth 场景需要 -username 与 -password（或环境变量 STRESS_PASSWORD）")
		os.Exit(2)
	}

	fmt.Printf("========== server-status 压力测试 ==========\n")
	fmt.Printf("目标: %s\n场景: %s\n并发: %d | 时长: %s | 爬坡: %s | 速率上限: %s\n\n",
		*target, *scenario, *conc, *dur, *ramp, func() string {
			if *rate <= 0 {
				return "不限"
			}
			return fmt.Sprintf("%.0f QPS", *rate)
		}())

	// 共享 Transport：放大连接池以匹配并发数，避免 TIME_WAIT 堆积
	transport := &http.Transport{
		MaxIdleConns:        *conc * 2,
		MaxIdleConnsPerHost: *conc,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
		ForceAttemptHTTP2:   true,
	}

	// 全局统计
	var (
		mu       sync.Mutex
		results  []reqResult
		total    atomic.Int64
		netErrs  atomic.Int64
		statuses = map[int]*atomic.Int64{}
	)
	// getStatusCounter 返回指定状态码的原子计数器（懒初始化，需持有 mu）
	getStatusCounter := func(code int) *atomic.Int64 {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := statuses[code]; ok {
			return c
		}
		c := &atomic.Int64{}
		statuses[code] = c
		return c
	}

	// pickEndpoint 按权重随机选择一个待压测路径
	endpoints := publicEndpoints
	if *scenario == "auth" {
		endpoints = authEndpoints
	}
	totalWeight := 0
	for _, e := range endpoints {
		totalWeight += e.weight
	}
	pickEndpoint := func() string {
		x := fastrand() % uint32(totalWeight)
		for _, e := range endpoints {
			if x < uint32(e.weight) {
				return e.path
			}
			x -= uint32(e.weight)
		}
		return endpoints[0].path
	}

	// doLogin 为单个 worker 执行一次登录，返回 http.Client 与 session_id。
	// 注意：兼容带 Domain 属性的会话 Cookie 与 IP 直连场景，这里手动解析 Set-Cookie，
	// 由 worker 在每个请求中显式携带 session_id。
	doLogin := func() (*http.Client, string, error) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, "", err
		}
		client := &http.Client{Transport: transport, Jar: jar, Timeout: *timeout}
		body, _ := json.Marshal(map[string]string{"username": *username, "password": *password})
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*target, "/")+"/login", strings.NewReader(string(body)))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/json")
		// UA 必须与后续压测请求一致：服务端会话校验 UserAgent 一致性，防止 Cookie 盗用重放
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("登录请求失败: %w", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("登录失败: HTTP %d（检查用户名/密码，或是否触发限流）", resp.StatusCode)
		}
		for _, c := range resp.Cookies() {
			if c.Name == "session_id" && c.Value != "" {
				return client, c.Value, nil
			}
		}
		return nil, "", fmt.Errorf("登录响应中未找到 session_id Cookie")
	}

	// worker 是单个压测协程：循环发起请求直到收到停止信号
	worker := func(id int, stop <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()

		// 爬坡：按 worker 序号错开启动时间
		if *ramp > 0 && *conc > 1 {
			delay := time.Duration(int64(*ramp) * int64(id) / int64(*conc))
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}

		client := &http.Client{Transport: transport, Timeout: *timeout}
		var sessionID string
		if *scenario == "auth" {
			c, sid, err := doLogin()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[worker %d] %v，该 worker 退出\n", id, err)
				return
			}
			client = c
			sessionID = sid
		}

		// 限速：将该 worker 分摊到全局速率的 1/N，按均值间隔睡眠
		var interval time.Duration
		if *rate > 0 {
			interval = time.Duration(float64(time.Second) * float64(*conc) / *rate)
		}

		base := strings.TrimRight(*target, "/")
		for {
			select {
			case <-stop:
				return
			default:
			}
			if interval > 0 {
				time.Sleep(interval)
			}

			path := pickEndpoint()
			req, err := http.NewRequest(http.MethodGet, base+path, nil)
			if err != nil {
				continue
			}
			// 认证场景：显式携带 session_id（绕开 Cookie Domain 限制，见 doLogin 注释）
			if sessionID != "" {
				req.Header.Set("Cookie", "session_id="+sessionID)
			}
			// 伪装成浏览器请求：服务端 verifySecurityHeaders 会校验
			// UA、Accept、Accept-Language、Accept-Encoding，缺失则 403
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			start := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(start)

			total.Add(1)
			r := reqResult{latency: lat, endpoint: path}
			if err != nil {
				netErrs.Add(1)
				r.err = err.Error()
			} else {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				r.status = resp.StatusCode
				getStatusCounter(resp.StatusCode).Add(1)
				if resp.StatusCode >= 400 {
					r.err = fmt.Sprintf("HTTP %d", resp.StatusCode)
				}
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}
	}

	// 启动压测：持续时间到达后关闭 stop 通道通知所有 worker 退出
	stop := make(chan struct{})
	var wg sync.WaitGroup
	go func() {
		time.Sleep(*dur)
		close(stop)
	}()
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go worker(i, stop, &wg)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(*dur + *ramp + 30*time.Second):
		fmt.Fprintln(os.Stderr, "\n警告: 部分 worker 未按时退出，强制输出统计")
		close(stop)
	}
	elapsed := time.Since(start)

	printReport(elapsed, int(total.Load()), int(netErrs.Load()), statuses, results)
}

// printReport 汇总并输出压测报告：吞吐、延迟分位数、状态码分布
func printReport(elapsed time.Duration, total, netErrs int, statuses map[int]*atomic.Int64, results []reqResult) {
	fmt.Printf("\n========== 压测报告 ==========\n")
	fmt.Printf("实际耗时: %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("总请求: %d | RPS: %.1f\n", total, float64(total)/elapsed.Seconds())

	// 状态码分布
	fmt.Printf("\n状态码分布:\n")
	codes := make([]int, 0, len(statuses))
	for c := range statuses {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	okCount := 0
	for _, c := range codes {
		n := statuses[c].Load()
		fmt.Printf("  HTTP %d: %d (%.1f%%)\n", c, n, float64(n)/float64(max(total, 1))*100)
		if c >= 200 && c < 400 {
			okCount += int(n)
		}
	}
	if netErrs > 0 {
		fmt.Printf("  网络错误: %d (%.1f%%)\n", netErrs, float64(netErrs)/float64(max(total, 1))*100)
	}
	fmt.Printf("成功(2xx/3xx): %d | 失败: %d\n", okCount, total-okCount)

	// 延迟分位数（仅统计收到响应的请求）
	if len(results) == 0 {
		return
	}
	lats := make([]float64, 0, len(results))
	var sum time.Duration
	for _, r := range results {
		if r.status > 0 {
			lats = append(lats, float64(r.latency))
			sum += r.latency
		}
	}
	if len(lats) == 0 {
		return
	}
	sort.Float64s(lats)
	pct := func(p float64) time.Duration {
		idx := int(float64(len(lats)-1) * p)
		return time.Duration(lats[idx])
	}
	fmt.Printf("\n响应延迟（共 %d 个有效样本）:\n", len(lats))
	fmt.Printf("  avg: %s | p50: %s | p90: %s | p95: %s | p99: %s | max: %s\n",
		(sum / time.Duration(len(lats))).Round(time.Millisecond),
		pct(0.50).Round(time.Millisecond), pct(0.90).Round(time.Millisecond),
		pct(0.95).Round(time.Millisecond), pct(0.99).Round(time.Millisecond),
		time.Duration(lats[len(lats)-1]).Round(time.Millisecond))

	// 失败请求样例（最多 5 条），便于定位问题
	shown := 0
	fmt.Printf("\n失败样例:\n")
	for _, r := range results {
		if r.err != "" && shown < 5 {
			fmt.Printf("  [%s] %s\n", r.endpoint, r.err)
			shown++
		}
	}
	if shown == 0 {
		fmt.Printf("  无\n")
	}

	// 容量判断参考：p99 < 500ms 且错误率 < 1% 视为健康
	errRate := float64(total-okCount) / float64(max(total, 1))
	verdict := "健康: 当前并发下服务表现良好"
	if errRate >= 0.01 || pct(0.99) > 500*time.Millisecond {
		verdict = "承压: 建议降低并发或排查慢接口"
	}
	fmt.Printf("\n结论: %s（p99=%s, 错误率=%.1f%%）\n", verdict, pct(0.99).Round(time.Millisecond), errRate*100)
}

// fastrand 返回一个轻量伪随机数（xorshift64），避免引入 math/rand 的锁开销
var randState = uint64(time.Now().UnixNano())

func fastrand() uint32 {
	randState ^= randState << 13
	randState ^= randState >> 7
	randState ^= randState << 17
	return uint32(randState >> 32)
}
