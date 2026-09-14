package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ==================== Rate Limit 解析 ====================

func TestParseHeaderInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"5000", 5000, true},
		{" 42 ", 42, true},
		{"0", 0, true},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, ok := parseHeaderInt(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseHeaderInt(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestGitHubRecordRateLimit(t *testing.T) {
	// 重置全局限流快照，避免与其他用例互相污染
	githubRateLimitMu.Lock()
	githubLastLimit, githubHasLimit = githubRateLimitSnapshot{}, false
	githubRateLimitMu.Unlock()

	h := http.Header{}
	h.Set("X-RateLimit-Limit", "5000")
	h.Set("X-RateLimit-Remaining", "123")
	h.Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(30*time.Minute).Unix()))
	githubRecordRateLimit(h)

	snap, ok := githubLastRateLimit()
	if !ok {
		t.Fatal("应记录到限流快照")
	}
	if snap.Limit != 5000 || snap.Remaining != 123 {
		t.Errorf("Limit/Remaining = %d/%d, want 5000/123", snap.Limit, snap.Remaining)
	}
	if snap.ResetAt.IsZero() {
		t.Error("ResetAt 不应为零值")
	}
}

// GitHub 未提供限流头时，不应凭猜测编造数值。
func TestGitHubRecordRateLimitIgnoresMissingHeaders(t *testing.T) {
	githubRateLimitMu.Lock()
	githubLastLimit, githubHasLimit = githubRateLimitSnapshot{}, false
	githubRateLimitMu.Unlock()

	githubRecordRateLimit(http.Header{})
	if _, ok := githubLastRateLimit(); ok {
		t.Error("无 X-RateLimit 头时不应记录快照（禁止猜测）")
	}
}

// ==================== README 安全与截断 ====================

func TestGitHubReadmeBase64DecodeAndTruncate(t *testing.T) {
	long := strings.Repeat("中", githubReadmeMaxChars+200)
	payload := map[string]any{
		"name":     "README.md",
		"html_url": "https://github.com/Xiaoxusheng/server-status/blob/main/README.md",
		"encoding": "base64",
		"content":  base64.StdEncoding.EncodeToString([]byte(long)),
	}
	buf, _ := json.Marshal(payload)
	ts, _ := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	})
	_ = ts

	got, _, err := githubFetchReadme(context.Background(), "Xiaoxusheng", "server-status", "")
	if err != nil {
		t.Fatalf("获取 README 失败: %v", err)
	}
	rd, ok := got.(*GitHubReadme)
	if !ok || rd == nil {
		t.Fatal("返回类型异常")
	}
	if !rd.Truncated {
		t.Error("超长 README 应标记 Truncated")
	}
	// 必须按字符截断，不能切断多字节字符（出现 U+FFFD 即为截断错误）
	if strings.ContainsRune(rd.Content, '\uFFFD') {
		t.Error("截断破坏了多字节字符")
	}
	if len([]rune(rd.Content)) != githubReadmeMaxChars {
		t.Errorf("截断后字符数 = %d, want %d", len([]rune(rd.Content)), githubReadmeMaxChars)
	}
}

func TestGitHubReadmeShortNotTruncated(t *testing.T) {
	content := "# 标题\n\n正常内容 `code`"
	payload := map[string]any{
		"name": "README.md", "html_url": "https://github.com/x/y/blob/main/README.md",
		"encoding": "base64",
		"content":  base64.StdEncoding.EncodeToString([]byte(content)),
	}
	buf, _ := json.Marshal(payload)
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf)
	})

	got, _, err := githubFetchReadme(context.Background(), "Xiaoxusheng", "server-status", "")
	if err != nil {
		t.Fatalf("获取失败: %v", err)
	}
	rd := got.(*GitHubReadme)
	if rd.Truncated {
		t.Error("短 README 不应标记 Truncated")
	}
	if !strings.Contains(rd.Content, "正常内容") {
		t.Errorf("内容被破坏: %q", rd.Content)
	}
}

func TestGitHubTruncateRunes(t *testing.T) {
	s := "abcdef"
	if got := githubTruncateRunes(s, 3); got != "abc" {
		t.Errorf("= %q, want abc", got)
	}
	if got := githubTruncateRunes(s, 100); got != s {
		t.Errorf("未超限应原样返回，得到 %q", got)
	}
	multi := "中文测试"
	if got := githubTruncateRunes(multi, 2); got != "中文" {
		t.Errorf("= %q, want 中文", got)
	}
}

// ==================== SSRF / 输入校验 ====================

func TestGitHubValidateOwnerRepoRejectsTraversal(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", nil)

	bad := []struct{ owner, name string }{
		{"Xiaoxusheng", "../../etc/passwd"},
		{"Xiaoxusheng", "repo/../../x"},
		{"Xiaoxusheng", "repo name"},
		{"Xiaoxusheng", ""},
		{"attacker", "server-status"}, // owner 必须等于配置用户名
		{"Xiaoxusheng", strings.Repeat("a", 200)},
	}
	for _, c := range bad {
		if err := githubValidateOwnerRepo(c.owner, c.name); err == nil {
			t.Errorf("应拒绝 owner=%q repo=%q", c.owner, c.name)
		}
	}
	// 合法输入必须通过
	if err := githubValidateOwnerRepo("Xiaoxusheng", "server-status"); err != nil {
		t.Errorf("合法输入被误拒: %v", err)
	}
	if err := githubValidateOwnerRepo("Xiaoxusheng", "go-auto-uploader"); err != nil {
		t.Errorf("合法输入被误拒: %v", err)
	}
}

// ==================== 缓存行为 ====================

// 同一 key 在 TTL 内重复读取必须命中缓存，不产生第二次上游请求。
func TestGitHubCacheHitAvoidsSecondRequest(t *testing.T) {
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockProfileJSON()))
	})

	fetch := func(ctx context.Context, key string) (any, string, error) {
		var p GitHubProfile
		body, etag, err := githubGet(ctx, "/user", "application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, "", err
		}
		return p, etag, nil
	}

	ctx := context.Background()
	if _, _, _, err := githubGetOrFetch(ctx, "profile", time.Minute, fetch); err != nil {
		t.Fatalf("首次获取失败: %v", err)
	}
	first := hits.Load()
	if first == 0 {
		t.Fatal("首次应产生上游请求")
	}

	for i := 0; i < 5; i++ {
		if _, _, _, err := githubGetOrFetch(ctx, "profile", time.Minute, fetch); err != nil {
			t.Fatalf("第 %d 次缓存读取失败: %v", i, err)
		}
	}
	if got := hits.Load(); got != first {
		t.Errorf("TTL 内 5 次读取产生了额外请求：hits = %d, want %d", got, first)
	}
}

// 上游失败且无缓存时，必须返回错误（由 handler 转成友好提示），而不是伪造数据。
func TestGitHubCacheNoFallbackWhenEmpty(t *testing.T) {
	_, _ = setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	})

	ctx := context.Background()
	fetch := func(ctx context.Context, key string) (any, string, error) {
		body, _, err := githubGet(ctx, "/user", "application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		return string(body), "", nil
	}

	_, _, _, err := githubGetOrFetch(ctx, "no-cache-key", time.Minute, fetch)
	if err == nil {
		t.Error("无缓存且上游失败时应返回错误，不得伪造数据")
	}
}

// 上游失败但存在旧缓存时，应降级返回旧数据并标记 stale。
func TestGitHubCacheServesStaleOnFailure(t *testing.T) {
	var fail atomic.Bool
	_, _ = setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`"cached-payload"`))
	})

	fetch := func(ctx context.Context, key string) (any, string, error) {
		body, etag, err := githubGet(ctx, "/user", "application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		var s string
		if err := json.Unmarshal(body, &s); err != nil {
			return nil, "", err
		}
		return s, etag, nil
	}

	ctx := context.Background()
	// 用极短 TTL 让缓存立即过期
	if _, _, _, err := githubGetOrFetch(ctx, "stale-key", time.Nanosecond, fetch); err != nil {
		t.Fatalf("预热失败: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	fail.Store(true)

	// 首次失败会进入冷却；冷却期内再读应拿到旧缓存并标记 stale
	data, stale, _, err := githubGetOrFetch(ctx, "stale-key", time.Nanosecond, fetch)
	if err != nil {
		t.Fatalf("有旧缓存时不应返回错误，得到: %v", err)
	}
	if s, _ := data.(string); s != "cached-payload" {
		t.Errorf("应返回旧缓存内容，得到 %v", data)
	}
	if !stale {
		t.Error("降级返回旧缓存时应标记 stale=true")
	}
}

// ==================== Star 快照采集（配置项） ====================

func TestGitHubConfigStarSnapshotInterval(t *testing.T) {
	cfg := `{
	  "github": {
	    "enabled": true, "username": "Xiaoxusheng", "token": "",
	    "cache_ttl": 1800, "repo_limit": 250,
	    "show_forks": false, "show_archived": false,
	    "featured": [], "star_snapshot_interval": 86400
	  }
	}`
	setupGitHubTest(t, cfg, "", nil)
	got := githubConfig()
	if got.StarSnapshotInterval != 24*time.Hour {
		t.Errorf("StarSnapshotInterval = %v, want %v", got.StarSnapshotInterval, 24*time.Hour)
	}
}

// 配置非法（小于 1 小时）时必须回落到 24h，防止被打成高频采集。
func TestGitHubConfigStarSnapshotIntervalClamps(t *testing.T) {
	cfg := `{
	  "github": {
	    "enabled": true, "username": "Xiaoxusheng", "token": "",
	    "cache_ttl": 1800, "repo_limit": 250,
	    "show_forks": false, "show_archived": false,
	    "featured": [], "star_snapshot_interval": 10
	  }
	}`
	setupGitHubTest(t, cfg, "", nil)
	got := githubConfig()
	if got.StarSnapshotInterval != 24*time.Hour {
		t.Errorf("非法间隔应回落 %v，得到 %v", 24*time.Hour, got.StarSnapshotInterval)
	}
}

// ==================== Token 绝不外泄 ====================

// API 响应体与 DTO 中绝不能出现 token 明文。
func TestGitHubTokenNeverLeaksInResponse(t *testing.T) {
	const secret = "ghp_SUPER_SECRET_TOKEN_VALUE_1234567890"

	reposJSON := `[{"id":1,"name":"server-status","full_name":"Xiaoxusheng/server-status","html_url":"https://github.com/Xiaoxusheng/server-status","description":"d","language":"Go","stargazers_count":2,"forks_count":0,"open_issues_count":0,"watchers_count":2,"size":100,"default_branch":"main","created_at":"2025-08-27T00:00:00Z","updated_at":"2026-09-14T00:00:00Z","pushed_at":"2026-09-14T00:00:00Z","owner":{"login":"Xiaoxusheng"}}]`

	_, _ = setupGitHubTest(t, testGitHubConfig, secret, func(w http.ResponseWriter, r *http.Request) {
		// 服务端必须把 token 放在 Authorization 头里
		if !strings.Contains(r.Header.Get("Authorization"), "Bearer") {
			t.Errorf("请求未携带 Bearer 鉴权头")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reposJSON))
	})

	ctx := context.Background()
	data, _, _, err := githubGetOrFetch(ctx, "repos:test", time.Minute, githubFetchRepos)
	if err != nil {
		t.Fatalf("拉取仓库失败: %v", err)
	}
	raw, _ := json.Marshal(data)
	if strings.Contains(string(raw), secret) {
		t.Error("DTO 序列化结果中出现了 token 明文")
	}
	// 逐个字段确认 DTO 不含任何 token 字段
	repos := data.([]GitHubRepository)
	if len(repos) != 1 {
		t.Fatalf("仓库数 = %d, want 1", len(repos))
	}
	b, _ := json.Marshal(repos[0])
	if strings.Contains(strings.ToLower(string(b)), "token") {
		t.Errorf("GitHubRepository DTO 含 token 相关字段: %s", b)
	}
}

// ==================== 仓库 DTO 不透传原始 JSON ====================

func TestGitHubRepoDTODropsInternalFields(t *testing.T) {
	reposJSON := `[{"id":1,"name":"r","full_name":"Xiaoxusheng/r",
	  "html_url":"https://github.com/Xiaoxusheng/r","description":"d","language":"Go",
	  "stargazers_count":7,"forks_count":1,"open_issues_count":2,"watchers_count":7,
	  "size":10,"default_branch":"main","archived":false,"fork":false,"private":false,
	  "license":{"spdx_id":"MIT","name":"MIT License"},
	  "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z",
	  "pushed_at":"2026-09-10T00:00:00Z","owner":{"login":"Xiaoxusheng"},
	  "node_id":"R_abc","url":"https://api.github.com/repos/Xiaoxusheng/r",
	  "clone_url":"https://github.com/Xiaoxusheng/r.git","ssh_url":"git@github.com:x/r.git"}]`

	_, _ = setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reposJSON))
	})

	data, _, _, err := githubGetOrFetch(context.Background(), "repos:dto", time.Minute, githubFetchRepos)
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	repos := data.([]GitHubRepository)
	b, _ := json.Marshal(repos[0])
	s := string(b)

	// 内部/无用字段不应出现在对外 DTO 中
	forbidden := []string{"node_id", "clone_url", "ssh_url", "private"}
	for _, f := range forbidden {
		if strings.Contains(s, `"`+f+`"`) {
			t.Errorf("DTO 不应包含字段 %q: %s", f, s)
		}
	}
	// 关键字段必须存在且数值正确
	if repos[0].Stars != 7 || repos[0].Name != "r" {
		t.Errorf("关键字段缺失或错误: %+v", repos[0])
	}
	if repos[0].License == "" {
		t.Error("License 应被提取")
	}
}

// ==================== Actions 404 优雅降级 ====================

// 项目未启用 Actions 时 GitHub 返回 404，应降级为「无 Actions」而非报错。
func TestGitHubActions404Graceful(t *testing.T) {
	_, _ = setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})
	resp, err := githubFetchActions(context.Background(), "Xiaoxusheng", "server-status")
	if err != nil {
		t.Fatalf("404 应优雅降级而非报错: %v", err)
	}
	if resp == nil {
		t.Fatal("返回 nil")
	}
	if resp.Summary == nil || resp.Summary.Available {
		t.Errorf("应标记为无 Actions: %+v", resp.Summary)
	}
}

// ==================== 并发去重 ====================

// 同一 key 并发读取时，inflight 去重应让上游请求数远小于并发数。
func TestGitHubCacheInflightDedup(t *testing.T) {
	var slow atomic.Int64
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		slow.Add(1)
		time.Sleep(80 * time.Millisecond) // 拉长窗口以暴露并发穿透
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockProfileJSON()))
	})

	fetch := func(ctx context.Context, key string) (any, string, error) {
		body, etag, err := githubGet(ctx, "/user", "application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		var p GitHubProfile
		_ = json.Unmarshal(body, &p)
		return p, etag, nil
	}

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, _, errs[idx] = githubGetOrFetch(context.Background(), "dedup-key", time.Minute, fetch)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("协程 %d 失败: %v", i, err)
		}
	}
	if got := hits.Load(); got >= int64(n) {
		t.Errorf("并发去重失效：%d 个并发产生了 %d 次上游请求", n, got)
	}
	if got := hits.Load(); got == 0 {
		t.Error("应至少发生一次上游请求")
	}
}

// ==================== 缓存 TTL 常量自检 ====================

// 断言分层 TTL 落在需求约定的范围内，防止后续被误改。
func TestGitHubTTLConstants(t *testing.T) {
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"Profile", githubTTLProfile, 30 * time.Minute},
		{"Detail", githubTTLDetail, 10 * time.Minute},
		{"Commits", githubTTLCommits, 10 * time.Minute},
		{"Releases", githubTTLReleases, 10 * time.Minute},
		{"Actions", githubTTLActions, 5 * time.Minute},
		{"Readme", githubTTLReadme, 30 * time.Minute},
		{"Languages", githubTTLLanguages, 30 * time.Minute},
		{"Contributors", githubTTLContributors, 30 * time.Minute},
		{"Activity", githubTTLActivity, 5 * time.Minute},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s TTL = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// ==================== 便捷断言：httptest 未使用时避免编译告警 ====================

var _ = httptest.NewServer
