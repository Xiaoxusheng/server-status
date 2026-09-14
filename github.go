package main

// ==================== GitHub 项目展示模块 ====================
// 职责：
//   - 代理 GitHub 公开 API（profile / repos / repo 详情 / README），浏览器不直连 GitHub
//   - 进程内缓存（缓存优先、失败回旧缓存、失败冷却避免高频穿透）
//   - 自定义 DTO（不透传 GitHub 原始 JSON）
//   - 安全边界：Token 仅后端持有（不落日志/响应），owner 仅限配置用户（防 SSRF/任意代理）
//
// 配置：config.json 的 "github" 段，可用环境变量覆盖（SERVER_STATUS_GITHUB_*）。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHub 配置常量
const (
	githubReposTTL          = 10 * time.Minute // 仓库列表缓存
	githubCooldown          = 30 * time.Second // 请求失败后的冷却期（避免每次刷新都穿透到 GitHub）
	githubRateLimitCooldown = 60 * time.Second
	githubReadmeMaxChars    = 6000    // README 服务端截断上限（前端再折叠展示）
	githubBodyLimit         = 4 << 20 // 单次响应体读取上限 4MB
	githubPer25Page         = 100     // GitHub 单页最大仓库数
	githubMaxPages          = 10      // 分页上限保护
)

// errGitHubNotModified 表示 GitHub 对 If-None-Match 条件请求返回 304：
// 数据未变化且该响应不消耗速率配额，调用方应沿用旧缓存数据。
var errGitHubNotModified = errors.New("GitHub 数据未变化（304）")

// GitHubFileConfig 对应 config.json 中 "github" 段（指针字段区分「未配置」与「配置为 false」）。
type GitHubFileConfig struct {
	Enabled              *bool    `json:"enabled"`
	Username             string   `json:"username"`
	Token                string   `json:"token"`
	CacheTTL             int      `json:"cache_ttl"` // 秒；profile/README 缓存，仓库列表固定 10 分钟
	RepoLimit            int      `json:"repo_limit"`
	ShowForks            *bool    `json:"show_forks"`
	ShowArchived         *bool    `json:"show_archived"`
	Featured             []string `json:"featured"`
	StarSnapshotInterval int      `json:"star_snapshot_interval"` // 秒；Star 快照采集间隔（默认 86400）
}

// githubFileWrapper 仅解析 config.json 的 "github" 段。
type githubFileWrapper struct {
	GitHub *GitHubFileConfig `json:"github"`
}

// GitHubConfig 运行时配置（默认值 + config.json + 环境变量合并结果）。
type GitHubConfig struct {
	Enabled      bool
	Username     string
	Token        string
	CacheTTL     time.Duration
	RepoLimit    int
	ShowForks    bool
	ShowArchived bool
	Featured     []string
	// StarSnapshotInterval Star 快照采集间隔（默认 24h）。
	// 采集器本身按分钟 tick 并叠加「跨天 + 达到间隔」双重判定，这里作为下限保护。
	StarSnapshotInterval time.Duration
}

// loadGitHubConfig 依次从默认值、config.json "github" 段、环境变量加载配置。
// 默认启用并展示 Xiaoxusheng 的公开项目；未部署/不展示时在配置中 enabled=false 即可。
func loadGitHubConfig() GitHubConfig {
	cfg := GitHubConfig{
		Enabled:              true,
		Username:             "Xiaoxusheng",
		CacheTTL:             30 * time.Minute,
		RepoLimit:            100,
		StarSnapshotInterval: 24 * time.Hour,
	}

	data, err := os.ReadFile(filepath.Join(privateRoot(), "config.json"))
	if err == nil {
		var fileCfg githubFileWrapper
		if jsonErr := json.Unmarshal(data, &fileCfg); jsonErr != nil {
			log.Printf("⚠️ config.json 解析失败，GitHub 使用默认配置: %v", jsonErr)
		} else if gh := fileCfg.GitHub; gh != nil {
			if gh.Enabled != nil {
				cfg.Enabled = *gh.Enabled
			}
			if gh.Username != "" {
				cfg.Username = strings.TrimSpace(gh.Username)
			}
			if gh.Token != "" {
				cfg.Token = strings.TrimSpace(gh.Token)
			}
			if gh.CacheTTL > 0 {
				cfg.CacheTTL = time.Duration(gh.CacheTTL) * time.Second
			}
			if gh.RepoLimit > 0 {
				cfg.RepoLimit = gh.RepoLimit
			}
			if gh.ShowForks != nil {
				cfg.ShowForks = *gh.ShowForks
			}
			if gh.ShowArchived != nil {
				cfg.ShowArchived = *gh.ShowArchived
			}
			if gh.StarSnapshotInterval > 0 {
				cfg.StarSnapshotInterval = time.Duration(gh.StarSnapshotInterval) * time.Second
			}
			cfg.Featured = append(cfg.Featured, gh.Featured...)
		}
	}

	if value := os.Getenv("SERVER_STATUS_GITHUB_ENABLED"); value != "" {
		if parsed, parseErr := strconv.ParseBool(strings.TrimSpace(value)); parseErr == nil {
			cfg.Enabled = parsed
		}
	}
	if value := os.Getenv("SERVER_STATUS_GITHUB_USERNAME"); value != "" {
		cfg.Username = strings.TrimSpace(value)
	}
	if value := os.Getenv("SERVER_STATUS_GITHUB_TOKEN"); value != "" {
		cfg.Token = strings.TrimSpace(value)
	}

	if cfg.CacheTTL < time.Minute {
		cfg.CacheTTL = time.Minute
	}
	if cfg.CacheTTL > 6*time.Hour {
		cfg.CacheTTL = 6 * time.Hour
	}
	if cfg.RepoLimit < 1 {
		cfg.RepoLimit = 100
	}
	if cfg.RepoLimit > 1000 {
		cfg.RepoLimit = 1000
	}
	// Star 快照间隔保底 1 小时，避免配置错误导致高频采集
	if cfg.StarSnapshotInterval < time.Hour {
		cfg.StarSnapshotInterval = 24 * time.Hour
	}
	return cfg
}

var (
	githubCfgOnce sync.Once
	githubCfg     GitHubConfig
	githubClient  = &http.Client{Timeout: 10 * time.Second}
	githubAPIBase = "https://api.github.com" // 测试中替换为 httptest 服务

	// githubRateLimitMu 保护最近一次 GitHub 响应头中的限流快照。
	// 只记录真实响应头，绝不猜测配额。
	githubRateLimitMu sync.RWMutex
	githubLastLimit   githubRateLimitSnapshot
	githubHasLimit    bool
)

// githubRateLimitSnapshot GitHub 限流响应头快照（X-RateLimit-*）。
type githubRateLimitSnapshot struct {
	Remaining int
	Limit     int
	ResetAt   time.Time
}

// githubRecordRateLimit 记录最近一次 GitHub 响应中的限流头（无头则忽略）。
func githubRecordRateLimit(h http.Header) {
	remaining, okR := parseHeaderInt(h.Get("X-RateLimit-Remaining"))
	limit, okL := parseHeaderInt(h.Get("X-RateLimit-Limit"))
	if !okR && !okL {
		return
	}
	snap := githubRateLimitSnapshot{Remaining: remaining, Limit: limit}
	if reset, ok := parseHeaderInt(h.Get("X-RateLimit-Reset")); ok && reset > 0 {
		snap.ResetAt = time.Unix(int64(reset), 0)
	}
	githubRateLimitMu.Lock()
	githubLastLimit, githubHasLimit = snap, true
	githubRateLimitMu.Unlock()
}

// githubLastRateLimit 返回最近一次限流快照（无记录时 ok=false）。
func githubLastRateLimit() (githubRateLimitSnapshot, bool) {
	githubRateLimitMu.RLock()
	defer githubRateLimitMu.RUnlock()
	return githubLastLimit, githubHasLimit
}

// parseHeaderInt 解析响应头中的整数（失败返回 false）。
func parseHeaderInt(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// githubConfig 惰性加载配置（进程内仅加载一次）。
func githubConfig() GitHubConfig {
	githubCfgOnce.Do(func() { githubCfg = loadGitHubConfig() })
	return githubCfg
}

// ==================== DTO ====================

// GitHubProfile GitHub 用户公开资料（自定义 DTO，不透传原始 JSON）。
type GitHubProfile struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
	Bio         string `json:"bio"`
	HTMLURL     string `json:"html_url"`
	PublicRepos int    `json:"public_repos"`
	Followers   int    `json:"followers"`
	Following   int    `json:"following"`
}

// GitHubRepository 仓库 DTO。
type GitHubRepository struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"`
	FullName      string   `json:"full_name"`
	Description   string   `json:"description"`
	HTMLURL       string   `json:"html_url"`
	Homepage      string   `json:"homepage,omitempty"`
	Owner         string   `json:"owner"`
	Fork          bool     `json:"fork"`
	Archived      bool     `json:"archived"`
	Stars         int      `json:"stars"`
	Watchers      int      `json:"watchers"`
	Forks         int      `json:"forks"`
	Issues        int      `json:"issues"`
	Language      string   `json:"language,omitempty"`
	DefaultBranch string   `json:"default_branch,omitempty"`
	License       string   `json:"license,omitempty"`
	Topics        []string `json:"topics,omitempty"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
	PushedAt      string   `json:"pushed_at"`
	Featured      bool     `json:"featured"`
}

// GitHubReadme README DTO（content 已服务端截断）。
type GitHubReadme struct {
	Name      string `json:"name"`
	HTMLURL   string `json:"html_url"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}

// GitHubReposResponse 仓库列表响应（带数据状态标记，前端据此提示缓存/限流）。
type GitHubReposResponse struct {
	Stale       bool               `json:"stale"`
	RateLimited bool               `json:"rate_limited"`
	Username    string             `json:"username"`
	Total       int                `json:"total"`
	Repos       []GitHubRepository `json:"repos"`
}

// GitHubProfileResponse 用户资料响应。
type GitHubProfileResponse struct {
	Stale       bool           `json:"stale"`
	RateLimited bool           `json:"rate_limited"`
	Profile     *GitHubProfile `json:"profile"`
}

// GitHubRepoResponse 单仓库详情响应。
type GitHubRepoResponse struct {
	Stale       bool              `json:"stale"`
	RateLimited bool              `json:"rate_limited"`
	Repo        *GitHubRepository `json:"repo"`
}

// GitHubReadmeResponse README 响应。
type GitHubReadmeResponse struct {
	Stale       bool          `json:"stale"`
	RateLimited bool          `json:"rate_limited"`
	Readme      *GitHubReadme `json:"readme"`
}

// ==================== GitHub 原始响应（仅内部解析） ====================

type githubRawUser struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
	Bio         string `json:"bio"`
	HTMLURL     string `json:"html_url"`
	PublicRepos int    `json:"public_repos"`
	Followers   int    `json:"followers"`
	Following   int    `json:"following"`
}

type githubRawLicense struct {
	SPDXID string `json:"spdx_id"`
}

type githubRawRepo struct {
	ID            int64             `json:"id"`
	Name          string            `json:"name"`
	FullName      string            `json:"full_name"`
	Description   string            `json:"description"`
	HTMLURL       string            `json:"html_url"`
	Homepage      string            `json:"homepage"`
	Fork          bool              `json:"fork"`
	Archived      bool              `json:"archived"`
	Stargazers    int               `json:"stargazers_count"`
	Watchers      int               `json:"watchers_count"`
	ForksCount    int               `json:"forks_count"`
	OpenIssues    int               `json:"open_issues_count"`
	Language      string            `json:"language"`
	DefaultBranch string            `json:"default_branch"`
	License       *githubRawLicense `json:"license"`
	Topics        []string          `json:"topics"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	PushedAt      time.Time         `json:"pushed_at"`
	Owner         *struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type githubRawReadme struct {
	Name     string `json:"name"`
	HTMLURL  string `json:"html_url"`
	Content  string `json:"content"` // base64
	Encoding string `json:"encoding"`
}

// ==================== 错误定义 ====================

var (
	errGitHubDisabled  = errors.New("GitHub 功能未启用")
	errGitHubNoUser    = errors.New("未配置 GitHub 用户名")
	errGitHubRateLimit = errors.New("GitHub API 请求次数已达到限制")
	errGitHubNotFound  = errors.New("GitHub 资源不存在")
)

// ==================== 缓存（含请求失败冷却与并发去重） ====================

type githubCacheEntry struct {
	data      any
	etag      string // GitHub ETag：缓存过期后用于 If-None-Match 条件请求（304 不消耗配额）
	expiresAt time.Time
}

type githubInflightCall struct {
	done  chan struct{}
	data  any
	stale bool
	rl    bool
	err   error
}

type githubCooldownEntry struct {
	until     time.Time
	rateLimit bool
}

type githubMemCache struct {
	mu       sync.Mutex
	entries  map[string]githubCacheEntry
	cooldown map[string]githubCooldownEntry
	inflight map[string]*githubInflightCall
}

func newGitHubMemCache() *githubMemCache {
	return &githubMemCache{
		entries:  map[string]githubCacheEntry{},
		cooldown: map[string]githubCooldownEntry{},
		inflight: map[string]*githubInflightCall{},
	}
}

var githubCache = newGitHubMemCache()

// githubCollectorContext 后台采集器专用上下文：与 HTTP 请求无关，
// 独立超时，保证 GitHub 不可达时采集协程不会被无限挂起。
func githubCollectorContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// githubGetOrFetch 缓存优先的通用取数：
//  1. 命中未过期缓存直接返回；
//  2. 处于失败冷却期时不请求 GitHub，回旧缓存（stale）或返回类型化错误；
//  3. 未命中则携带旧 ETag 发起条件请求（同 key 并发请求合并为一次），成功写缓存；
//     GitHub 返回 304 时数据未变且不消耗速率配额，直接用旧数据续命；
//  4. 请求失败时优先回旧缓存并标记 stale，完全无数据才返回错误。
//
// fetch 收到旧的 ETag（可能为空），返回 (数据, 新ETag, 错误)。
func githubGetOrFetch(ctx context.Context, key string, ttl time.Duration, fetch func(context.Context, string) (any, string, error)) (data any, stale bool, rateLimited bool, err error) {
	githubCache.mu.Lock()
	entry, hasEntry := githubCache.entries[key]
	if hasEntry && time.Now().Before(entry.expiresAt) {
		githubCache.mu.Unlock()
		return entry.data, false, false, nil
	}
	if cd, ok := githubCache.cooldown[key]; ok && time.Now().Before(cd.until) {
		githubCache.mu.Unlock()
		if hasEntry {
			return entry.data, true, cd.rateLimit, nil
		}
		if cd.rateLimit {
			return nil, false, true, errGitHubRateLimit
		}
		return nil, false, false, fmt.Errorf("GitHub 请求冷却中")
	}
	if call, ok := githubCache.inflight[key]; ok {
		githubCache.mu.Unlock()
		<-call.done
		return call.data, call.stale, call.rl, call.err
	}
	call := &githubInflightCall{done: make(chan struct{})}
	githubCache.inflight[key] = call
	githubCache.mu.Unlock()

	fetched, etag, fetchErr := fetch(ctx, entry.etag)
	// 304 Not Modified：数据未变且不消耗配额，用旧缓存续命
	if errors.Is(fetchErr, errGitHubNotModified) {
		if hasEntry {
			fetched, etag, fetchErr = entry.data, entry.etag, nil
		} else {
			fetchErr = fmt.Errorf("GitHub 返回 304 但本地无缓存数据")
		}
	}
	rl := errors.Is(fetchErr, errGitHubRateLimit)

	githubCache.mu.Lock()
	delete(githubCache.inflight, key)
	if fetchErr == nil {
		githubCache.entries[key] = githubCacheEntry{data: fetched, etag: etag, expiresAt: time.Now().Add(ttl)}
		delete(githubCache.cooldown, key)
	} else {
		cooldown := githubCooldown
		if rl {
			cooldown = githubRateLimitCooldown
		}
		githubCache.cooldown[key] = githubCooldownEntry{until: time.Now().Add(cooldown), rateLimit: rl}
	}
	githubCache.mu.Unlock()

	switch {
	case fetchErr == nil:
		call.data, call.stale, call.rl, call.err = fetched, false, false, nil
	case hasEntry:
		call.data, call.stale, call.rl, call.err = entry.data, true, rl, nil
	default:
		call.data, call.stale, call.rl, call.err = nil, false, rl, fetchErr
	}
	close(call.done)
	return call.data, call.stale, call.rl, call.err
}

// ==================== GitHub HTTP 客户端 ====================

// githubGet 请求 GitHub API。Token 通过 Authorization 头发送，绝不写入日志/响应。
// etag 非空时携带 If-None-Match 条件请求：GitHub 返回 304 表示数据未变（不消耗速率配额）。
// 返回 (响应体, 本次响应的 ETag, 错误)。
func githubGet(ctx context.Context, path, accept, etag string) ([]byte, string, error) {
	cfg := githubConfig()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIBase+path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("构造 GitHub 请求失败: %w", err)
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "server-status")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	resp, err := githubClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GitHub 请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 记录真实限流头（供前端展示「剩余 N 次 / 预计重置」）
	githubRecordRateLimit(resp.Header)

	body, err := io.ReadAll(io.LimitReader(resp.Body, githubBodyLimit))
	if err != nil {
		return nil, "", fmt.Errorf("读取 GitHub 响应失败: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		return body, resp.Header.Get("ETag"), nil
	case resp.StatusCode == http.StatusNotModified:
		return nil, "", errGitHubNotModified
	case resp.StatusCode == http.StatusNotFound:
		return nil, "", errGitHubNotFound
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" {
			return nil, "", errGitHubRateLimit
		}
		return nil, "", fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	default:
		return nil, "", fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	}
}

// ==================== 业务取数 ====================

// githubFetchProfile 获取用户公开资料（支持 ETag 条件请求）。
func githubFetchProfile(ctx context.Context, etag string) (any, string, error) {
	cfg := githubConfig()
	body, etagOut, err := githubGet(ctx, "/users/"+url.PathEscape(cfg.Username), "application/vnd.github+json", etag)
	if err != nil {
		return nil, "", err
	}
	var raw githubRawUser
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", fmt.Errorf("解析 GitHub 用户数据失败: %w", err)
	}
	return &GitHubProfile{
		Login:       raw.Login,
		Name:        raw.Name,
		AvatarURL:   raw.AvatarURL,
		Bio:         raw.Bio,
		HTMLURL:     raw.HTMLURL,
		PublicRepos: raw.PublicRepos,
		Followers:   raw.Followers,
		Following:   raw.Following,
	}, etagOut, nil
}

// githubFetchRepos 分页拉取当前配置用户的公开仓库并转换为 DTO。
// 分页列表的 ETag 条件语义不可靠（304 只代表首页未变），这里不使用条件请求，
// 频率由固定 TTL + 失败冷却控制。
func githubFetchRepos(ctx context.Context, _ string) (any, string, error) {
	cfg := githubConfig()
	featured := githubFeaturedSet(cfg)
	perPage := githubPer25Page
	maxPages := (cfg.RepoLimit + perPage - 1) / perPage
	if maxPages > githubMaxPages {
		maxPages = githubMaxPages
	}

	repos := make([]GitHubRepository, 0, 32)
	for page := 1; page <= maxPages; page++ {
		path := fmt.Sprintf("/users/%s/repos?per_page=%d&page=%d&type=owner&sort=pushed",
			url.PathEscape(cfg.Username), perPage, page)
		body, _, err := githubGet(ctx, path, "application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		var raw []githubRawRepo
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, "", fmt.Errorf("解析 GitHub 仓库数据失败: %w", err)
		}
		for i := range raw {
			repo := convertGitHubRepo(&raw[i], featured)
			if !cfg.ShowForks && repo.Fork {
				continue
			}
			if !cfg.ShowArchived && repo.Archived {
				continue
			}
			repos = append(repos, repo)
		}
		if len(raw) < perPage || len(repos) >= cfg.RepoLimit {
			break
		}
	}
	if len(repos) > cfg.RepoLimit {
		repos = repos[:cfg.RepoLimit]
	}
	return repos, "", nil
}

func convertGitHubRepo(raw *githubRawRepo, featured map[string]bool) GitHubRepository {
	license := ""
	if raw.License != nil && raw.License.SPDXID != "" && raw.License.SPDXID != "NOASSERTION" {
		license = raw.License.SPDXID
	}
	owner := ""
	if raw.Owner != nil {
		owner = raw.Owner.Login
	}
	repo := GitHubRepository{
		ID:            raw.ID,
		Name:          raw.Name,
		FullName:      raw.FullName,
		Description:   raw.Description,
		HTMLURL:       raw.HTMLURL,
		Homepage:      raw.Homepage,
		Owner:         owner,
		Fork:          raw.Fork,
		Archived:      raw.Archived,
		Stars:         raw.Stargazers,
		Watchers:      raw.Watchers,
		Forks:         raw.ForksCount,
		Issues:        raw.OpenIssues,
		Language:      raw.Language,
		DefaultBranch: raw.DefaultBranch,
		License:       license,
		Topics:        raw.Topics,
		CreatedAt:     raw.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     raw.UpdatedAt.UTC().Format(time.RFC3339),
		PushedAt:      raw.PushedAt.UTC().Format(time.RFC3339),
	}
	if featured != nil && featured[strings.ToLower(raw.Name)] {
		repo.Featured = true
	}
	return repo
}

// githubFetchRepoDetail 获取单个仓库详情（owner 必须等于配置用户，防止任意代理/SSRF）。
func githubFetchRepoDetail(ctx context.Context, owner, name, etag string) (any, string, error) {
	if err := githubValidateOwnerRepo(owner, name); err != nil {
		return nil, "", err
	}
	body, etagOut, err := githubGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), "application/vnd.github+json", etag)
	if err != nil {
		return nil, "", err
	}
	var raw githubRawRepo
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", fmt.Errorf("解析 GitHub 仓库数据失败: %w", err)
	}
	repo := convertGitHubRepo(&raw, githubFeaturedSet(githubConfig()))
	return &repo, etagOut, nil
}

// githubFetchReadme 获取仓库 README（base64 解码 + 服务端截断，支持 ETag 条件请求）。
func githubFetchReadme(ctx context.Context, owner, name, etag string) (any, string, error) {
	if err := githubValidateOwnerRepo(owner, name); err != nil {
		return nil, "", err
	}
	body, etagOut, err := githubGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/readme", "application/vnd.github+json", etag)
	if err != nil {
		return nil, "", err
	}
	var raw githubRawReadme
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, "", fmt.Errorf("解析 GitHub README 失败: %w", err)
	}
	content := ""
	if raw.Encoding == "base64" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.ReplaceAll(raw.Content, "\n", ""))
		if decodeErr != nil {
			return nil, "", fmt.Errorf("解码 GitHub README 失败: %w", decodeErr)
		}
		content = string(decoded)
	}
	truncated := len([]rune(content)) > githubReadmeMaxChars
	if truncated {
		content = githubTruncateRunes(content, githubReadmeMaxChars)
	}
	return &GitHubReadme{
		Name:      raw.Name,
		HTMLURL:   raw.HTMLURL,
		Content:   content,
		Truncated: truncated,
	}, etagOut, nil
}

// githubTruncateRunes 按字符安全截断（不切断多字节字符）。
func githubTruncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

var githubRepoNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// githubValidateOwnerRepo 校验 owner/repo：owner 仅允许配置用户（禁止任意 URL 代理），
// repo 限制为 GitHub 合法命名字符，杜绝路径穿越与 SSRF。
func githubValidateOwnerRepo(owner, name string) error {
	cfg := githubConfig()
	if !strings.EqualFold(owner, cfg.Username) {
		return errGitHubNotFound // 不暴露配置边界，按不存在处理
	}
	if !githubRepoNameRe.MatchString(name) {
		return errGitHubNotFound
	}
	return nil
}

func githubFeaturedSet(cfg GitHubConfig) map[string]bool {
	if len(cfg.Featured) == 0 {
		return nil
	}
	set := make(map[string]bool, len(cfg.Featured))
	for _, name := range cfg.Featured {
		set[strings.ToLower(strings.TrimSpace(name))] = true
	}
	return set
}

// ==================== HTTP Handler ====================

func githubPageHandler(w http.ResponseWriter, r *http.Request) { serveOpsPage(w, r, "github.html") }

// githubEnsureEnabled 前置校验：功能启用 + 已配置用户名。返回 false 表示已写响应。
func githubEnsureEnabled(w http.ResponseWriter) bool {
	cfg := githubConfig()
	if !cfg.Enabled {
		writeJSONError(w, http.StatusNotFound, "GitHub 功能未启用")
		return false
	}
	if cfg.Username == "" {
		writeJSONError(w, http.StatusBadRequest, "未配置 GitHub 用户名")
		return false
	}
	return true
}

// githubWriteError 将取数错误映射为友好错误响应（绝不透出内部错误细节）。
func githubWriteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errGitHubRateLimit):
		writeJSONError(w, http.StatusTooManyRequests, "GitHub API 请求次数已达到限制，请稍后再试")
	case errors.Is(err, errGitHubNotFound):
		writeJSONError(w, http.StatusNotFound, "GitHub 仓库不存在")
	case errors.Is(err, errGitHubDisabled):
		writeJSONError(w, http.StatusNotFound, "GitHub 功能未启用")
	case errors.Is(err, errGitHubNoUser):
		writeJSONError(w, http.StatusBadRequest, "未配置 GitHub 用户名")
	default:
		log.Printf("GitHub API 获取失败: %v", err)
		writeJSONError(w, http.StatusBadGateway, "暂时无法获取 GitHub 项目")
	}
}

// githubProfileHandler GET /api/github/profile
func githubProfileHandler(w http.ResponseWriter, r *http.Request) {
	if !githubEnsureEnabled(w) {
		return
	}
	cfg := githubConfig()
	data, stale, rl, err := githubGetOrFetch(r.Context(),
		"profile:"+strings.ToLower(cfg.Username), cfg.CacheTTL, githubFetchProfile)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	profile, _ := data.(*GitHubProfile)
	writeJSON(w, http.StatusOK, "获取成功", &GitHubProfileResponse{
		Stale: stale, RateLimited: rl, Profile: profile,
	})
}

// githubReposHandler GET /api/github/repos（默认按 pushed_at 倒序，前端可再排序/过滤）
func githubReposHandler(w http.ResponseWriter, r *http.Request) {
	if !githubEnsureEnabled(w) {
		return
	}
	cfg := githubConfig()
	data, stale, rl, err := githubGetOrFetch(r.Context(),
		"repos:"+strings.ToLower(cfg.Username), githubReposTTL, githubFetchRepos)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	repos, _ := data.([]GitHubRepository)
	writeJSON(w, http.StatusOK, "获取成功", &GitHubReposResponse{
		Stale: stale, RateLimited: rl, Username: cfg.Username,
		Total: len(repos), Repos: repos,
	})
}

// githubOverviewHandler GET /api/github/overview?limit=3
// 首页轻量概览：featured（配置顺序）优先，其余按 Stars 最多 + 最近更新补足。
func githubOverviewHandler(w http.ResponseWriter, r *http.Request) {
	if !githubEnsureEnabled(w) {
		return
	}
	cfg := githubConfig()
	limit := 3
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 6 {
		limit = 6
	}
	data, stale, rl, err := githubGetOrFetch(r.Context(),
		"repos:"+strings.ToLower(cfg.Username), githubReposTTL, githubFetchRepos)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	repos, _ := data.([]GitHubRepository)
	writeJSON(w, http.StatusOK, "获取成功", &GitHubReposResponse{
		Stale: stale, RateLimited: rl, Username: cfg.Username,
		Total: len(repos), Repos: githubPickOverview(repos, limit),
	})
}

// githubPickOverview 选取概览仓库：featured 优先，其余按 Stars/最近更新补足。
func githubPickOverview(repos []GitHubRepository, limit int) []GitHubRepository {
	if len(repos) <= limit {
		return repos
	}
	picked := make([]GitHubRepository, 0, limit)
	used := make(map[int64]bool, limit)
	for _, repo := range repos {
		if len(picked) >= limit {
			break
		}
		if repo.Featured {
			picked = append(picked, repo)
			used[repo.ID] = true
		}
	}
	if len(picked) < limit {
		rest := make([]GitHubRepository, 0, len(repos))
		for _, repo := range repos {
			if !used[repo.ID] {
				rest = append(rest, repo)
			}
		}
		sort.SliceStable(rest, func(i, j int) bool {
			if rest[i].Stars != rest[j].Stars {
				return rest[i].Stars > rest[j].Stars
			}
			return rest[i].PushedAt > rest[j].PushedAt
		})
		for _, repo := range rest {
			if len(picked) >= limit {
				break
			}
			picked = append(picked, repo)
		}
	}
	return picked
}

// githubRepoDetailHandler GET /api/github/repos/{owner}/{repo}
func githubRepoDetailHandler(w http.ResponseWriter, r *http.Request) {
	if !githubEnsureEnabled(w) {
		return
	}
	owner := r.PathValue("owner")
	name := r.PathValue("repo")
	if err := githubValidateOwnerRepo(owner, name); err != nil {
		githubWriteError(w, err)
		return
	}
	key := "repo:" + strings.ToLower(owner) + "/" + strings.ToLower(name)
	data, stale, rl, err := githubGetOrFetch(r.Context(), key, githubReposTTL,
		func(ctx context.Context, etag string) (any, string, error) {
			return githubFetchRepoDetail(ctx, owner, name, etag)
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	repo, _ := data.(*GitHubRepository)
	writeJSON(w, http.StatusOK, "获取成功", &GitHubRepoResponse{
		Stale: stale, RateLimited: rl, Repo: repo,
	})
}

// githubReadmeHandler GET /api/github/repos/{owner}/{repo}/readme
func githubReadmeHandler(w http.ResponseWriter, r *http.Request) {
	if !githubEnsureEnabled(w) {
		return
	}
	owner := r.PathValue("owner")
	name := r.PathValue("repo")
	if err := githubValidateOwnerRepo(owner, name); err != nil {
		githubWriteError(w, err)
		return
	}
	cfg := githubConfig()
	key := "readme:" + strings.ToLower(owner) + "/" + strings.ToLower(name)
	data, stale, rl, err := githubGetOrFetch(r.Context(), key, cfg.CacheTTL,
		func(ctx context.Context, etag string) (any, string, error) {
			return githubFetchReadme(ctx, owner, name, etag)
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	readme, _ := data.(*GitHubReadme)
	writeJSON(w, http.StatusOK, "获取成功", &GitHubReadmeResponse{
		Stale: stale, RateLimited: rl, Readme: readme,
	})
}
