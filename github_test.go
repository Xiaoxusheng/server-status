package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setupGitHubTest 为单个测试准备：临时数据目录（config.json）、mock GitHub 服务、
// 重置进程内配置单例与缓存。返回 mock 服务与请求计数器。
func setupGitHubTest(t *testing.T, cfgJSON, token string, mock http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	dir := t.TempDir()
	if cfgJSON != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o644); err != nil {
			t.Fatalf("写入测试配置失败: %v", err)
		}
	}
	t.Setenv("SERVER_STATUS_HOME", dir)
	t.Setenv("SERVER_STATUS_GITHUB_TOKEN", token)

	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if mock != nil {
			mock(w, r)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	githubCfgOnce = sync.Once{}
	githubAPIBase = ts.URL
	githubClient = ts.Client()
	githubCache = newGitHubMemCache()
	return ts, &hits
}

const testGitHubConfig = `{
  "github": {
    "enabled": true,
    "username": "Xiaoxusheng",
    "token": "",
    "cache_ttl": 1800,
    "repo_limit": 250,
    "show_forks": false,
    "show_archived": false,
    "featured": ["Server-Status"]
  }
}`

func mockProfileJSON() string {
	return `{"login":"Xiaoxusheng","name":"Xiaoxusheng","avatar_url":"https://avatars.example.com/u.png","bio":"builder","html_url":"https://github.com/Xiaoxusheng","public_repos":8,"followers":10,"following":5}`
}

func TestGitHubProfileNormalResponse(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/Xiaoxusheng" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	rec := httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d，body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int                   `json:"code"`
		Data GitHubProfileResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Code != 200 || resp.Data.Profile == nil {
		t.Fatalf("响应结构异常: %+v", resp)
	}
	p := resp.Data.Profile
	if p.Login != "Xiaoxusheng" || p.PublicRepos != 8 || p.Followers != 10 || p.Following != 5 {
		t.Errorf("Profile DTO 字段不符: %+v", p)
	}
	if p.AvatarURL == "" || p.HTMLURL == "" {
		t.Errorf("头像/主页地址缺失: %+v", p)
	}
	if resp.Data.Stale || resp.Data.RateLimited {
		t.Errorf("正常响应不应携带 stale/rate_limited 标记")
	}
}

func TestGitHubTokenSentAndNotLeaked(t *testing.T) {
	const secret = "ghp_super_secret_token_123"
	var gotAuth string
	setupGitHubTest(t, testGitHubConfig, secret, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	rec := httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if gotAuth != "Bearer "+secret {
		t.Errorf("Token 应以 Bearer 头发送，实际: %q", gotAuth)
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("响应体泄露了 Token！body: %s", body)
	}
	if strings.Contains(body, "token") {
		t.Errorf("响应体不应包含 token 字段: %s", body)
	}
}

func TestGitHubProfileCacheHitAndExpiry(t *testing.T) {
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	do := func() GitHubProfileResponse {
		rec := httptest.NewRecorder()
		githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", rec.Code)
		}
		var resp struct {
			Data GitHubProfileResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		return resp.Data
	}

	do()
	do()
	if n := hits.Load(); n != 1 {
		t.Fatalf("第二次请求应命中缓存，mock 被调用 %d 次", n)
	}

	// 将缓存条目置为过期 → 应重新请求 GitHub
	key := "profile:xiaoxusheng"
	githubCache.mu.Lock()
	if entry, ok := githubCache.entries[key]; ok {
		entry.expiresAt = time.Now().Add(-time.Second)
		githubCache.entries[key] = entry
	} else {
		t.Fatal("缓存条目不存在")
	}
	githubCache.mu.Unlock()

	do()
	if n := hits.Load(); n != 2 {
		t.Fatalf("缓存过期后应重新请求 GitHub，mock 被调用 %d 次", n)
	}
}

func TestGitHubStaleFallbackOnFailure(t *testing.T) {
	fail := atomic.Bool{}
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	// 首次成功，填充缓存
	rec := httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("首次请求应成功: %d", rec.Code)
	}

	// 缓存过期 + GitHub 故障 → 应回旧缓存并标记 stale
	fail.Store(true)
	githubCache.mu.Lock()
	entry := githubCache.entries["profile:xiaoxusheng"]
	entry.expiresAt = time.Now().Add(-time.Second)
	githubCache.entries["profile:xiaoxusheng"] = entry
	githubCache.mu.Unlock()

	rec = httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GitHub 故障时应回退旧缓存而不是报错: %d", rec.Code)
	}
	var resp struct {
		Data GitHubProfileResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Data.Stale {
		t.Errorf("应携带 stale=true 标记")
	}
	if resp.Data.Profile == nil || resp.Data.Profile.Login != "Xiaoxusheng" {
		t.Errorf("stale 数据内容不符: %+v", resp.Data.Profile)
	}

	// 失败冷却期内不应再次穿透 GitHub
	before := hits.Load()
	githubProfileHandler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if hits.Load() != before {
		t.Errorf("冷却期内不应再次请求 GitHub")
	}
}

func TestGitHubAPIFailureFriendlyError(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", http.StatusInternalServerError)
	})

	rec := httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("期望 502，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "upstream exploded") || strings.Contains(body, "500") {
		t.Errorf("不应透出内部错误细节: %s", body)
	}
	if !strings.Contains(body, "暂时无法获取 GitHub 项目") {
		t.Errorf("应返回友好文案: %s", body)
	}
}

func TestGitHubRateLimitDetected(t *testing.T) {
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	})

	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
		return rec
	}

	rec := do()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("期望 429，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "GitHub API 请求次数已达到限制") {
		t.Errorf("限流文案不符: %s", rec.Body.String())
	}

	// 冷却期内不再穿透
	before := hits.Load()
	do()
	if hits.Load() != before {
		t.Errorf("限流冷却期内不应再次请求 GitHub")
	}
}

func TestGitHubDisabled(t *testing.T) {
	setupGitHubTest(t, `{"github":{"enabled":false,"username":"Xiaoxusheng"}}`, "", nil)
	rec := httptest.NewRecorder()
	githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "GitHub 功能未启用") {
		t.Errorf("文案不符: %s", rec.Body.String())
	}
}

func TestGitHubReposPaginationFilterAndDTO(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/users/Xiaoxusheng/repos") {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		page := 1
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		// 三页：每页 100 / 100 / 50，共 250
		count := 100
		if page == 3 {
			count = 50
		}
		repos := make([]map[string]any, 0, count)
		for i := 0; i < count; i++ {
			id := (page-1)*100 + i
			name := fmt.Sprintf("repo-%04d", id)
			m := map[string]any{
				"id": id, "name": name, "full_name": "Xiaoxusheng/" + name,
				"description": "desc", "html_url": "https://github.com/Xiaoxusheng/" + name,
				"stargazers_count": id, "watchers_count": id, "forks_count": 1,
				"open_issues_count": 2, "language": "Go", "default_branch": "main",
				"topics": []string{"monitor"}, "created_at": "2024-01-01T00:00:00Z",
				"updated_at": "2026-01-02T03:04:05Z", "pushed_at": "2026-02-03T04:05:06Z",
				"owner": map[string]any{"login": "Xiaoxusheng"},
			}
			switch id {
			case 0:
				m["name"] = "Server-Status" // 命中 featured（大小写不敏感）
			case 1:
				m["fork"] = true // show_forks=false 应被过滤
			case 2:
				m["archived"] = true // show_archived=false 应被过滤
			}
			repos = append(repos, m)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(repos)
	})

	rec := httptest.NewRecorder()
	githubReposHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/repos", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d，body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data GitHubReposResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	// 250 个中过滤掉 1 fork + 1 archived = 248
	if resp.Data.Total != 248 {
		t.Errorf("期望 248 个仓库（过滤 fork/archived），实际 %d", resp.Data.Total)
	}
	if len(resp.Data.Repos) != 248 {
		t.Errorf("Repos 长度不符: %d", len(resp.Data.Repos))
	}
	var featured, fork *GitHubRepository
	for i := range resp.Data.Repos {
		r := &resp.Data.Repos[i]
		if r.Featured {
			featured = r
		}
		if r.Fork {
			fork = r
		}
		if r.Name == "repo-0002" && r.Archived {
			t.Errorf("archived 仓库不应出现在结果中")
		}
	}
	if fork != nil {
		t.Errorf("show_forks=false 时不应返回 fork 仓库")
	}
	if featured == nil || featured.Name != "Server-Status" {
		t.Errorf("featured 标记缺失: %+v", featured)
	}
	if featured.PushedAt != "2026-02-03T04:05:06Z" {
		t.Errorf("PushedAt 格式不符: %s", featured.PushedAt)
	}
	if featured.Topics == nil || len(featured.Topics) != 1 || featured.Topics[0] != "monitor" {
		t.Errorf("Topics 转换不符: %+v", featured.Topics)
	}
	if featured.Issues != 2 || featured.Forks != 1 || featured.Stars != 0 {
		t.Errorf("统计字段转换不符: %+v", featured)
	}
}

func TestGitHubRepoDetailOwnerGuard(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})

	cases := []struct {
		owner, repo string
		wantCode    int
	}{
		{"OtherUser", "whatever", http.StatusNotFound},    // 非配置用户：拒绝代理
		{"../etc", "passwd", http.StatusNotFound},         // 非法路径
		{"Xiaoxusheng", "bad name!", http.StatusNotFound}, // 非法仓库名
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/github/repos/x/y", nil)
		req.SetPathValue("owner", c.owner)
		req.SetPathValue("repo", c.repo)
		githubRepoDetailHandler(rec, req)
		if rec.Code != c.wantCode {
			t.Errorf("owner=%q repo=%q: 期望 %d，实际 %d", c.owner, c.repo, c.wantCode, rec.Code)
		}
	}
}

func TestGitHubRepoDetailNormal(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/Xiaoxusheng/server-status" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, `{"id":1,"name":"server-status","full_name":"Xiaoxusheng/server-status","description":"d","html_url":"https://github.com/Xiaoxusheng/server-status","stargazers_count":15,"forks_count":3,"open_issues_count":1,"language":"Go","default_branch":"main","license":{"spdx_id":"MIT","key":"mit","name":"MIT License"},"topics":["go"],"created_at":"2024-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","pushed_at":"2026-02-03T00:00:00Z","owner":{"login":"Xiaoxusheng"}}`)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/github/repos/Xiaoxusheng/server-status", nil)
	req.SetPathValue("owner", "Xiaoxusheng")
	req.SetPathValue("repo", "server-status")
	githubRepoDetailHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d，body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data GitHubRepoResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Repo == nil || resp.Data.Repo.License != "MIT" || resp.Data.Repo.Stars != 15 {
		t.Errorf("详情 DTO 不符: %+v", resp.Data.Repo)
	}
}

func TestGitHubReadmeFetchAndTruncation(t *testing.T) {
	long := strings.Repeat("# 标题\n内容段落。\n", 800) // > 6000 字符
	short := "## 简短说明\n正文"
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/readme") {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		content := short
		if strings.Contains(r.URL.Path, "bigrepo") {
			content = long
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"name": "README.md", "path": "README.md",
			"html_url": "https://github.com/Xiaoxusheng/x/blob/main/README.md",
			"content":  base64.StdEncoding.EncodeToString([]byte(content)),
			"encoding": "base64",
		})
	})

	// 短 README：不截断
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/github/repos/Xiaoxusheng/smallrepo/readme", nil)
	req.SetPathValue("owner", "Xiaoxusheng")
	req.SetPathValue("repo", "smallrepo")
	githubReadmeHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
	var resp struct {
		Data GitHubReadmeResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Readme == nil || resp.Data.Readme.Truncated || resp.Data.Readme.Content != short {
		t.Errorf("短 README 不应截断: %+v", resp.Data.Readme)
	}
	if strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString([]byte(short))) {
		t.Errorf("README 内容不应以 base64 原样返回")
	}

	// 长 README：服务端截断到 6000 字符
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/github/repos/Xiaoxusheng/bigrepo/readme", nil)
	req.SetPathValue("owner", "Xiaoxusheng")
	req.SetPathValue("repo", "bigrepo")
	githubReadmeHandler(rec, req)
	resp.Data.Readme = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.Readme == nil || !resp.Data.Readme.Truncated {
		t.Fatalf("长 README 应标记 truncated: %+v", resp.Data.Readme)
	}
	if n := len([]rune(resp.Data.Readme.Content)); n != 6000 {
		t.Errorf("期望截断到 6000 字符，实际 %d", n)
	}
}

func TestGitHubConvertRepoDTO(t *testing.T) {
	featured := map[string]bool{"server-status": true}
	raw := &githubRawRepo{
		ID: 42, Name: "server-status", FullName: "Xiaoxusheng/server-status",
		Description: "monitor", HTMLURL: "https://github.com/Xiaoxusheng/server-status",
		Homepage: "https://example.com", Stargazers: 12, Watchers: 12, ForksCount: 3,
		OpenIssues: 2, Language: "Go", DefaultBranch: "main",
		License:   &githubRawLicense{SPDXID: "NOASSERTION"},
		Topics:    []string{"a", "b"},
		CreatedAt: time.Date(2024, 5, 1, 8, 0, 0, 0, time.UTC),
		PushedAt:  time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC),
		Owner: &struct {
			Login string `json:"login"`
		}{Login: "Xiaoxusheng"},
	}
	repo := convertGitHubRepo(raw, featured)
	if !repo.Featured {
		t.Errorf("featured 应命中（大小写不敏感）")
	}
	if repo.License != "" {
		t.Errorf("NOASSERTION 许可证应为空: %q", repo.License)
	}
	if repo.UpdatedAt != "0001-01-01T00:00:00Z" {
		t.Errorf("零值 UpdatedAt 应保持零值序列化: %q", repo.UpdatedAt)
	}
	if repo.Homepage != "https://example.com" || repo.Owner != "Xiaoxusheng" {
		t.Errorf("字段转换不符: %+v", repo)
	}

	raw.License.SPDXID = "MIT"
	if convertGitHubRepo(raw, nil).License != "MIT" {
		t.Errorf("MIT 许可证应保留")
	}
}

func TestGitHubOverviewPicksFeaturedThenStars(t *testing.T) {
	setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "name": "plain-star", "full_name": "Xiaoxusheng/plain-star", "html_url": "u1", "stargazers_count": 99, "pushed_at": "2026-01-01T00:00:00Z", "owner": map[string]any{"login": "Xiaoxusheng"}},
			{"id": 2, "name": "Server-Status", "full_name": "Xiaoxusheng/Server-Status", "html_url": "u2", "stargazers_count": 1, "pushed_at": "2026-01-01T00:00:00Z", "owner": map[string]any{"login": "Xiaoxusheng"}},
			{"id": 3, "name": "plain-old", "full_name": "Xiaoxusheng/plain-old", "html_url": "u3", "stargazers_count": 50, "pushed_at": "2026-01-01T00:00:00Z", "owner": map[string]any{"login": "Xiaoxusheng"}},
			{"id": 4, "name": "plain-mid", "full_name": "Xiaoxusheng/plain-mid", "html_url": "u4", "stargazers_count": 60, "pushed_at": "2026-01-01T00:00:00Z", "owner": map[string]any{"login": "Xiaoxusheng"}},
		})
	})

	rec := httptest.NewRecorder()
	githubOverviewHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/overview?limit=2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
	var resp struct {
		Data GitHubReposResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Data.Repos) != 2 {
		t.Fatalf("期望 2 个概览仓库，实际 %d", len(resp.Data.Repos))
	}
	if resp.Data.Repos[0].Name != "Server-Status" {
		t.Errorf("featured 应排第一: %+v", resp.Data.Repos[0])
	}
	if resp.Data.Repos[1].Name != "plain-star" {
		t.Errorf("其余应按 Stars 最多补足: %+v", resp.Data.Repos[1])
	}
}

func TestGitHubConcurrentRequestsDeduplicated(t *testing.T) {
	release := make(chan struct{})
	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		<-release // 挂住首个请求，制造并发窗口
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
			codes[i] = rec.Code
		}(i)
	}
	time.Sleep(100 * time.Millisecond) // 等待并发请求全部进入 inflight
	close(release)
	wg.Wait()

	if hits.Load() != 1 {
		t.Errorf("并发请求应合并为 1 次 GitHub 调用，实际 %d 次", hits.Load())
	}
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("并发请求 %d 期望 200，实际 %d", i, code)
		}
	}
}

func TestGitHubETagConditionalRequest(t *testing.T) {
	const etagValue = `"abc123"`
	var mu sync.Mutex
	var sawIfNoneMatch []string

	_, hits := setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawIfNoneMatch = append(sawIfNoneMatch, r.Header.Get("If-None-Match"))
		mu.Unlock()
		// 携带匹配的 If-None-Match 时返回 304（模拟 GitHub 条件请求命中）
		if r.Header.Get("If-None-Match") == etagValue {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etagValue)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	do := func() GitHubProfileResponse {
		rec := httptest.NewRecorder()
		githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d，body: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data GitHubProfileResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		return resp.Data
	}

	// 首次请求：无条件头，响应携带 ETag 并入缓存
	d := do()
	if d.Profile == nil || d.Profile.Login != "Xiaoxusheng" {
		t.Fatalf("首次请求数据不符: %+v", d.Profile)
	}
	githubCache.mu.Lock()
	entry, ok := githubCache.entries["profile:xiaoxusheng"]
	githubCache.mu.Unlock()
	if !ok || entry.etag != etagValue {
		t.Fatalf("ETag 应入缓存: %+v", entry)
	}

	// 缓存过期 → 第二次请求应携带 If-None-Match，GitHub 返回 304 → 旧数据续命
	githubCache.mu.Lock()
	entry.expiresAt = time.Now().Add(-time.Second)
	githubCache.entries["profile:xiaoxusheng"] = entry
	githubCache.mu.Unlock()

	d = do()
	if hits.Load() != 2 {
		t.Fatalf("缓存过期后应发起条件请求，mock 被调用 %d 次", hits.Load())
	}
	mu.Lock()
	sent := sawIfNoneMatch[1]
	mu.Unlock()
	if sent != etagValue {
		t.Fatalf("第二次请求应携带 If-None-Match %s，实际 %q", etagValue, sent)
	}
	if d.Profile == nil || d.Profile.Login != "Xiaoxusheng" {
		t.Fatalf("304 后应沿用旧数据: %+v", d.Profile)
	}
	if d.Stale {
		t.Errorf("304 续命属于正常新鲜数据，不应标记 stale")
	}

	// 304 续命后缓存重新有效：第三次请求不应再打 GitHub
	do()
	if hits.Load() != 2 {
		t.Errorf("304 续命后应命中缓存，mock 被调用 %d 次", hits.Load())
	}
}

func TestGitHubETagChangedFallsBackToFreshFetch(t *testing.T) {
	var calls atomic.Int64
	_, _ = setupGitHubTest(t, testGitHubConfig, "", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("If-None-Match") == `"old"` {
			// 数据已变化：GitHub 会忽略条件头返回 200 + 新内容 + 新 ETag
			w.Header().Set("ETag", `"new"`)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprint(w, `{"login":"Xiaoxusheng","name":"NewName","html_url":"https://github.com/Xiaoxusheng","public_repos":9,"followers":1,"following":1}`)
			return
		}
		w.Header().Set("ETag", `"old"`)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, mockProfileJSON())
	})

	do := func() GitHubProfileResponse {
		rec := httptest.NewRecorder()
		githubProfileHandler(rec, httptest.NewRequest(http.MethodGet, "/api/github/profile", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", rec.Code)
		}
		var resp struct {
			Data GitHubProfileResponse `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Data
	}

	do()
	githubCache.mu.Lock()
	entry := githubCache.entries["profile:xiaoxusheng"]
	entry.expiresAt = time.Now().Add(-time.Second)
	githubCache.entries["profile:xiaoxusheng"] = entry
	githubCache.mu.Unlock()

	d := do()
	if d.Profile == nil || d.Profile.Name != "NewName" {
		t.Fatalf("ETag 失配时应取回新数据: %+v", d.Profile)
	}
	githubCache.mu.Lock()
	newEtag := githubCache.entries["profile:xiaoxusheng"].etag
	githubCache.mu.Unlock()
	if newEtag != `"new"` {
		t.Errorf("新 ETag 应写入缓存: %q", newEtag)
	}
}
