package main

// ==================== GitHub Developer Dashboard（取数层） ====================
//
// 扩展 github.go 的取数能力，全部复用既有基础设施：
//   - githubGetOrFetch（缓存 / stale 回退 / 冷却 / 并发去重 / ETag 条件请求）
//   - githubGet（Token 注入、错误映射、限流识别）
//   - githubValidateOwnerRepo（owner 白名单，防 SSRF）
//
// 缓存 TTL 遵循 spec 建议，集中在 githubTTL* 常量中，避免散落魔数。
//
// 性能原则：任何「批量」接口都只做 1 次 GitHub 请求（除分页外），
// 前端按需触发（点击项目后才拉详情数据），杜绝首屏 N×M 请求。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------- 缓存 TTL（spec 第二十五章） ----------------

const (
	githubTTLProfile      = 30 * time.Minute // 用户资料
	githubTTLDetail       = 10 * time.Minute // 仓库详情
	githubTTLCommits      = 10 * time.Minute
	githubTTLReleases     = 10 * time.Minute
	githubTTLActions      = 5 * time.Minute
	githubTTLReadme       = 30 * time.Minute
	githubTTLLanguages    = 30 * time.Minute
	githubTTLContributors = 30 * time.Minute
	githubTTLActivity     = 5 * time.Minute
	githubTTLStarHistory  = 5 * time.Minute // 本地 SQLite 查询结果缓存

	githubCommitWindowDays = 90 // Commit 活跃度最大窗口
	githubContributorTopN  = 5  // 贡献者展示上限
	githubActivityDefault  = 20 // 最近活动默认条数
	githubActivityMax      = 60 // 最近活动单次上限

	githubReleaseBodyChars = 6000 // Release Notes 服务端截断上限（与 README 一致量级）
)

// githubCommitSHAre 提交 SHA 校验（40 位十六进制，兼容短哈希 7~40 位），杜绝路径注入。
var githubCommitSHAre = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// githubLogWarn 统一 GitHub 模块告警日志（Token 绝不进入日志）。
func githubLogWarn(format string, args ...any) {
	log.Printf("⚠️ "+format, args...)
}

// githubCollectorEnabled 采集器是否处于工作状态（功能启用 + 配置了用户名）。
// 用于前端提示「正在建立 Star 历史数据」而非误报错误。
func githubCollectorEnabled() bool {
	cfg := githubConfig()
	return cfg.Enabled && cfg.Username != ""
}

// ==================== DTO：Commit ====================

// GitHubCommit 单条提交 DTO。
type GitHubCommit struct {
	SHA          string `json:"sha"`
	ShortSHA     string `json:"short_sha"`
	Message      string `json:"message"` // 首行
	AuthorName   string `json:"author_name"`
	AuthorLogin  string `json:"author_login,omitempty"`
	AuthorAvatar string `json:"author_avatar,omitempty"`
	HTMLURL      string `json:"html_url"`
	Date         string `json:"date"`
	Additions    int    `json:"additions,omitempty"`
	Deletions    int    `json:"deletions,omitempty"`
	FilesChanged int    `json:"files_changed,omitempty"`
	Verified     bool   `json:"verified"`
}

// GitHubCommitsResponse Commit 活跃度响应（含窗口统计与日粒度序列）。
type GitHubCommitsResponse struct {
	Stale       bool                             `json:"stale"`
	RateLimited bool                             `json:"rate_limited"`
	Owner       string                           `json:"owner"`
	Repo        string                           `json:"repo"`
	Activity    *GitHubCommitActivity            `json:"activity"` // 默认 30 天
	Windows     map[string]*GitHubCommitActivity `json:"windows"`  // 7/30/90
	Recent      []GitHubCommit                   `json:"recent"`
}

// ==================== DTO：Release ====================

// GitHubReleaseAsset 发布附件 DTO（下载量来自 GitHub 真实数据）。
type GitHubReleaseAsset struct {
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	DownloadCount int    `json:"download_count"`
	ContentType   string `json:"content_type,omitempty"`
}

// GitHubRelease 单个 Release DTO。
type GitHubRelease struct {
	ID          int64                `json:"id"`
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	Body        string               `json:"body"` // Release Notes（已截断）
	Truncated   bool                 `json:"truncated"`
	Prerelease  bool                 `json:"prerelease"`
	Draft       bool                 `json:"draft"`
	CreatedAt   string               `json:"created_at"`
	PublishedAt string               `json:"published_at"`
	HTMLURL     string               `json:"html_url"`
	Author      string               `json:"author,omitempty"`
	Assets      []GitHubReleaseAsset `json:"assets"`
	AssetCount  int                  `json:"asset_count"`
	Downloads   int                  `json:"downloads"` // 该版本所有附件下载量之和
	Latest      bool                 `json:"latest"`
}

// GitHubReleasesResponse Releases 列表响应。
type GitHubReleasesResponse struct {
	Stale          bool            `json:"stale"`
	RateLimited    bool            `json:"rate_limited"`
	Owner          string          `json:"owner"`
	Repo           string          `json:"repo"`
	Total          int             `json:"total"`
	TotalDownloads int             `json:"total_downloads"`
	Latest         *GitHubRelease  `json:"latest"`
	Releases       []GitHubRelease `json:"releases"`
}

// ==================== DTO：Actions ====================

// GitHubWorkflowRun 单次工作流运行 DTO。
type GitHubWorkflowRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Event      string `json:"event"`
	Status     string `json:"status"`     // queued/in_progress/completed
	Conclusion string `json:"conclusion"` // success/failure/cancelled/skipped/timed_out/action_required
	Branch     string `json:"branch"`
	SHA        string `json:"sha"`
	ShortSHA   string `json:"short_sha"`
	Actor      string `json:"actor,omitempty"`
	HTMLURL    string `json:"html_url"`
	RunNumber  int    `json:"run_number"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	DurationMS int64  `json:"duration_ms"`
}

// GitHubActionsSummary CI 状态摘要（项目顶部徽标用）。
type GitHubActionsSummary struct {
	Available    bool   `json:"available"` // 项目是否配置了 Actions
	Status       string `json:"status"`    // passing/failing/running/mixed/none
	Label        string `json:"label"`     // ✓ Passing / ⚠ 1 workflow failed / No GitHub Actions
	Passed       int    `json:"passed"`
	Failed       int    `json:"failed"`
	Running      int    `json:"running"`
	WorkflowName string `json:"workflow_name,omitempty"` // 最近一次运行的工作流名
}

// GitHubActionsResponse Actions 响应。
type GitHubActionsResponse struct {
	Stale       bool                   `json:"stale"`
	RateLimited bool                   `json:"rate_limited"`
	Owner       string                 `json:"owner"`
	Repo        string                 `json:"repo"`
	Summary     *GitHubActionsSummary  `json:"summary"`
	Runs        []GitHubWorkflowRun    `json:"runs"`
	Workflows   []GitHubWorkflowStatus `json:"workflows"` // 按工作流名聚合的最近状态
}

// GitHubWorkflowStatus 按工作流名聚合的状态（Build / Test / Docker ...）。
type GitHubWorkflowStatus struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // passed/failed/running/unknown
	Conclusion string `json:"conclusion"`
	Branch     string `json:"branch"`
	ShortSHA   string `json:"short_sha"`
	HTMLURL    string `json:"html_url"`
	CreatedAt  string `json:"created_at"`
	DurationMS int64  `json:"duration_ms"`
	RunNumber  int    `json:"run_number"`
}

// ==================== DTO：Languages / Contributors / Activity ====================

// GitHubLanguage 语言占比项。
type GitHubLanguage struct {
	Name    string  `json:"name"`
	Bytes   int64   `json:"bytes"`
	Percent float64 `json:"percent"`
}

// GitHubLanguagesResponse 语言分布响应。
type GitHubLanguagesResponse struct {
	Stale       bool             `json:"stale"`
	RateLimited bool             `json:"rate_limited"`
	Owner       string           `json:"owner"`
	Repo        string           `json:"repo"`
	TotalBytes  int64            `json:"total_bytes"`
	Languages   []GitHubLanguage `json:"languages"`
}

// GitHubContributorsResponse 贡献者响应。
type GitHubContributorsResponse struct {
	Stale        bool                `json:"stale"`
	RateLimited  bool                `json:"rate_limited"`
	Owner        string              `json:"owner"`
	Repo         string              `json:"repo"`
	Total        int                 `json:"total"`
	RestCount    int                 `json:"rest_count"` // Top N 之外的人数
	TotalCommits int                 `json:"total_commits"`
	Contributors []GitHubContributor `json:"contributors"`
}

// GitHubActivityItem 最近活动条目（Commit / Release / Issue / PR / Workflow）。
type GitHubActivityItem struct {
	Type      string `json:"type"` // commit/release/issue/pull_request/workflow
	Title     string `json:"title"`
	Subtitle  string `json:"subtitle,omitempty"`
	Author    string `json:"author,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Ref       string `json:"ref,omitempty"` // SHA / tag / #编号
	HTMLURL   string `json:"html_url"`
	Time      string `json:"time"`
	Status    string `json:"status,omitempty"` // success/failure/open/closed...
}

// GitHubActivityResponse 最近活动响应。
type GitHubActivityResponse struct {
	Stale       bool                 `json:"stale"`
	RateLimited bool                 `json:"rate_limited"`
	Owner       string               `json:"owner"`
	Repo        string               `json:"repo"`
	Offset      int                  `json:"offset"`
	Limit       int                  `json:"limit"`
	HasMore     bool                 `json:"has_more"`
	Items       []GitHubActivityItem `json:"items"`
}

// ==================== DTO：Stats / Star 趋势 ====================

// GitHubRepoStats 项目综合统计（spec 第三十六章统一 DTO）。
type GitHubRepoStats struct {
	Stars        int `json:"stars"`
	Forks        int `json:"forks"`
	Issues       int `json:"issues"`
	PullRequests int `json:"pull_requests"`
	Commits30d   int `json:"commits_30d"`
	Contributors int `json:"contributors"`
	Releases     int `json:"releases"`
	HeatScore    int `json:"heat_score"`
	Watchers     int `json:"watchers"`
}

// GitHubStarTrend Star 趋势响应（含增长分析与绘图点）。
type GitHubStarTrend struct {
	Stale       bool              `json:"stale"`
	RateLimited bool              `json:"rate_limited"`
	Owner       string            `json:"owner"`
	Repo        string            `json:"repo"`
	Window      int               `json:"window"` // 天数，0=ALL
	Growth      GitHubStarGrowth  `json:"growth"`
	Points      []GitHubStarPoint `json:"points"`
	Current     int               `json:"current"`
	Recording   bool              `json:"recording"` // 采集器是否正在工作（用于「正在建立」提示）
}

// ==================== GitHub 原始响应（仅内部解析） ====================

type githubRawCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			Date  time.Time `json:"date"`
		} `json:"author"`
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	} `json:"commit"`
	Author *struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	} `json:"author"`
	HTMLURL string `json:"html_url"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

// githubRawCommitDetail 单提交详情（含 diff 统计，需要额外一次请求，仅在展开时拉取）。
type githubRawCommitDetail struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Stats   struct {
		Additions int `json:"additions"`
		Deletions int `json:"deletions"`
		Total     int `json:"total"`
	} `json:"stats"`
	Files []struct {
		Filename string `json:"filename"`
	} `json:"files"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name string    `json:"name"`
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	Author *struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	} `json:"author"`
}

type githubRawRelease struct {
	ID          int64     `json:"id"`
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Author      *struct {
		Login string `json:"login"`
	} `json:"author"`
	Assets []struct {
		Name          string `json:"name"`
		Size          int64  `json:"size"`
		DownloadCount int    `json:"download_count"`
		ContentType   string `json:"content_type"`
	} `json:"assets"`
}

// githubRawWorkflowRun 单次工作流运行原始结构（列表解析复用）。
type githubRawWorkflowRun struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Event        string    `json:"event"`
	Status       string    `json:"status"`
	Conclusion   string    `json:"conclusion"`
	HeadBranch   string    `json:"head_branch"`
	HeadSHA      string    `json:"head_sha"`
	RunNumber    int       `json:"run_number"`
	HTMLURL      string    `json:"html_url"`
	RunStartedAt time.Time `json:"run_started_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Actor        *struct {
		Login string `json:"login"`
	} `json:"actor"`
}

type githubRawWorkflowRuns struct {
	TotalCount   int                    `json:"total_count"`
	WorkflowRuns []githubRawWorkflowRun `json:"workflow_runs"`
}

type githubRawContributor struct {
	Login         string `json:"login"`
	AvatarURL     string `json:"avatar_url"`
	HTMLURL       string `json:"html_url"`
	Contributions int    `json:"contributions"`
	Type          string `json:"type"`
}

type githubRawIssue struct {
	Number      int        `json:"number"`
	Title       string     `json:"title"`
	State       string     `json:"state"`
	HTMLURL     string     `json:"html_url"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ClosedAt    *time.Time `json:"closed_at"`
	PullRequest *struct {
		MergedAt *time.Time `json:"merged_at"`
		HTMLURL  string     `json:"html_url"`
	} `json:"pull_request"`
	User *struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	} `json:"user"`
}

// githubRawRepoExtra 仓库详情中的计数补充字段（复用 detail 响应，不额外请求）。
type githubRawRepoExtra struct {
	OpenIssues  int `json:"open_issues_count"`
	Subscribers int `json:"subscribers_count"` // watchers
}

// ==================== 取数实现 ====================

// githubValidateRepoInput 统一 guard：启用校验 + owner/repo 校验。
func githubValidateRepoInput(owner, repo string) error {
	if err := githubValidateOwnerRepo(owner, repo); err != nil {
		return err
	}
	return nil
}

// githubFetchCommits 拉取提交：
//  1. /repos/{o}/{r}/commits?since=90d前&per_page=100 分页最多 3 页（按需详情调用）
//  2. 聚合出 7/30/90 天窗口统计与日粒度序列
//
// 一次详情打开最多 3 次 GitHub 请求，且结果缓存 10 分钟。
func githubFetchCommits(ctx context.Context, owner, repo string) (*GitHubCommitsResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	since := time.Now().UTC().AddDate(0, 0, -githubCommitWindowDays).Format(time.RFC3339)

	const perPage = 100
	const maxPages = 3
	byDay := map[string]int{}
	recent := make([]GitHubCommit, 0, githubActivityDefault)
	seen := map[string]bool{}

	for page := 1; page <= maxPages; page++ {
		path := fmt.Sprintf("/repos/%s/%s/commits?since=%s&per_page=%d&page=%d",
			url.PathEscape(owner), url.PathEscape(repo), url.QueryEscape(since), perPage, page)
		body, _, err := githubGet(ctx, path, "application/vnd.github+json", "")
		if err != nil {
			return nil, err
		}
		var raw []githubRawCommit
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("解析 GitHub 提交数据失败: %w", err)
		}
		for i := range raw {
			c := raw[i]
			if c.SHA != "" {
				if seen[c.SHA] {
					continue
				}
				seen[c.SHA] = true
			}
			if c.Commit.Author.Date.IsZero() {
				continue
			}
			day := c.Commit.Author.Date.UTC().Format("2006-01-02")
			byDay[day]++
			if len(recent) < githubActivityDefault {
				recent = append(recent, convertGitHubCommit(&c))
			}
		}
		if len(raw) < perPage {
			break
		}
	}

	now := time.Now()
	windows := map[string]*GitHubCommitActivity{}
	for _, d := range []int{7, 30, githubCommitWindowDays} {
		act := githubAggregateCommitDays(byDay, d, now)
		windows[strconv.Itoa(d)] = &act
	}
	main := windows["30"]
	return &GitHubCommitsResponse{
		Owner: owner, Repo: repo,
		Activity: main, Windows: windows, Recent: recent,
	}, nil
}

func convertGitHubCommit(raw *githubRawCommit) GitHubCommit {
	login, avatar := "", ""
	if raw.Author != nil {
		login, avatar = raw.Author.Login, raw.Author.AvatarURL
	}
	msg := strings.TrimSpace(raw.Commit.Message)
	if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
		msg = msg[:idx]
	}
	return GitHubCommit{
		SHA:          raw.SHA,
		ShortSHA:     githubShortSHA(raw.SHA),
		Message:      msg,
		AuthorName:   raw.Commit.Author.Name,
		AuthorLogin:  login,
		AuthorAvatar: avatar,
		HTMLURL:      raw.HTMLURL,
		Date:         raw.Commit.Author.Date.UTC().Format(time.RFC3339),
		Verified:     raw.Commit.Verification.Verified,
	}
}

// githubFetchCommitDetail 单提交详情（diff 统计）。按需调用，缓存 30 分钟。
func githubFetchCommitDetail(ctx context.Context, owner, repo, sha string) (*GitHubCommit, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	if !githubCommitSHAre.MatchString(sha) {
		return nil, errGitHubNotFound
	}
	body, _, err := githubGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/commits/"+url.PathEscape(sha),
		"application/vnd.github+json", "")
	if err != nil {
		return nil, err
	}
	var raw githubRawCommitDetail
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 GitHub 提交详情失败: %w", err)
	}
	login, avatar := "", ""
	if raw.Author != nil {
		login, avatar = raw.Author.Login, raw.Author.AvatarURL
	}
	msg := strings.TrimSpace(raw.Commit.Message)
	if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
		msg = msg[:idx]
	}
	return &GitHubCommit{
		SHA: raw.SHA, ShortSHA: githubShortSHA(raw.SHA), Message: msg,
		AuthorName: raw.Commit.Author.Name, AuthorLogin: login, AuthorAvatar: avatar,
		HTMLURL: raw.HTMLURL, Date: raw.Commit.Author.Date.UTC().Format(time.RFC3339),
		Additions: raw.Stats.Additions, Deletions: raw.Stats.Deletions,
		FilesChanged: len(raw.Files),
	}, nil
}

// githubFetchReleases 拉取 Releases（默认 30 条），并计算最新版与总下载量。
func githubFetchReleases(ctx context.Context, owner, repo string) (*GitHubReleasesResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/repos/%s/%s/releases?per_page=30", url.PathEscape(owner), url.PathEscape(repo))
	body, _, err := githubGet(ctx, path, "application/vnd.github+json", "")
	if err != nil {
		return nil, err
	}
	var raw []githubRawRelease
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 GitHub Releases 失败: %w", err)
	}

	resp := &GitHubReleasesResponse{Owner: owner, Repo: repo, Releases: make([]GitHubRelease, 0, len(raw))}
	for i := range raw {
		rel := convertGitHubRelease(&raw[i])
		resp.TotalDownloads += rel.Downloads
		resp.Releases = append(resp.Releases, rel)
	}
	// GitHub 已按 published_at 倒序；Latest = 第一个非 prerelease/draft
	for i := range resp.Releases {
		if !resp.Releases[i].Prerelease && !resp.Releases[i].Draft {
			resp.Releases[i].Latest = true
			latest := resp.Releases[i]
			resp.Latest = &latest
			break
		}
	}
	resp.Total = len(resp.Releases)
	return resp, nil
}

func convertGitHubRelease(raw *githubRawRelease) GitHubRelease {
	assets := make([]GitHubReleaseAsset, 0, len(raw.Assets))
	downloads := 0
	for _, a := range raw.Assets {
		assets = append(assets, GitHubReleaseAsset{
			Name: a.Name, Size: a.Size, DownloadCount: a.DownloadCount, ContentType: a.ContentType,
		})
		downloads += a.DownloadCount
	}
	body := strings.TrimSpace(raw.Body)
	truncated := len([]rune(body)) > githubReleaseBodyChars
	if truncated {
		body = githubTruncateRunes(body, githubReleaseBodyChars)
	}
	author := ""
	if raw.Author != nil {
		author = raw.Author.Login
	}
	name := strings.TrimSpace(raw.Name)
	if name == "" {
		name = raw.TagName
	}
	published := raw.PublishedAt
	if published.IsZero() {
		published = raw.CreatedAt
	}
	return GitHubRelease{
		ID: raw.ID, TagName: raw.TagName, Name: name, Body: body, Truncated: truncated,
		Prerelease: raw.Prerelease, Draft: raw.Draft,
		CreatedAt:   raw.CreatedAt.UTC().Format(time.RFC3339),
		PublishedAt: published.UTC().Format(time.RFC3339),
		HTMLURL:     raw.HTMLURL, Author: author,
		Assets: assets, AssetCount: len(assets), Downloads: downloads,
	}
}

// githubFetchActions 拉取最近 workflow runs 并聚合状态摘要。
// 项目未配置 Actions 时 GitHub 返回 404，这里按「无 Actions」优雅降级，不报错。
func githubFetchActions(ctx context.Context, owner, repo string) (*GitHubActionsResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/repos/%s/%s/actions/runs?per_page=30", url.PathEscape(owner), url.PathEscape(repo))
	body, _, err := githubGet(ctx, path, "application/vnd.github+json", "")
	if err != nil {
		if err == errGitHubNotFound {
			return &GitHubActionsResponse{
				Owner: owner, Repo: repo,
				Summary: &GitHubActionsSummary{Available: false, Status: "none", Label: "No GitHub Actions"},
				Runs:    []GitHubWorkflowRun{}, Workflows: []GitHubWorkflowStatus{},
			}, nil
		}
		return nil, err
	}
	var raw githubRawWorkflowRuns
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 GitHub Actions 数据失败: %w", err)
	}

	runs := make([]GitHubWorkflowRun, 0, len(raw.WorkflowRuns))
	for i := range raw.WorkflowRuns {
		runs = append(runs, convertGitHubWorkflowRun(&raw.WorkflowRuns[i]))
	}
	return &GitHubActionsResponse{
		Owner: owner, Repo: repo,
		Summary:   githubSummarizeActions(runs),
		Runs:      runs,
		Workflows: githubAggregateWorkflows(runs),
	}, nil
}

func convertGitHubWorkflowRun(raw *githubRawWorkflowRun) GitHubWorkflowRun {
	actor := ""
	if raw.Actor != nil {
		actor = raw.Actor.Login
	}
	duration := int64(0)
	if !raw.UpdatedAt.IsZero() && !raw.RunStartedAt.IsZero() && raw.UpdatedAt.After(raw.RunStartedAt) {
		duration = raw.UpdatedAt.Sub(raw.RunStartedAt).Milliseconds()
	}
	return GitHubWorkflowRun{
		ID: raw.ID, Name: raw.Name, Event: raw.Event, Status: raw.Status,
		Conclusion: raw.Conclusion, Branch: raw.HeadBranch, SHA: raw.HeadSHA,
		ShortSHA: githubShortSHA(raw.HeadSHA), Actor: actor, HTMLURL: raw.HTMLURL,
		RunNumber:  raw.RunNumber,
		CreatedAt:  raw.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:  raw.UpdatedAt.UTC().Format(time.RFC3339),
		DurationMS: duration,
	}
}

// githubSummarizeActions 计算 CI 状态摘要（基于最近 30 次运行）。
func githubSummarizeActions(runs []GitHubWorkflowRun) *GitHubActionsSummary {
	s := &GitHubActionsSummary{Available: len(runs) > 0}
	if len(runs) == 0 {
		s.Status, s.Label = "none", "No GitHub Actions"
		return s
	}
	for _, r := range runs {
		switch {
		case r.Status == "in_progress" || r.Status == "queued":
			s.Running++
		case r.Conclusion == "success":
			s.Passed++
		case r.Conclusion == "failure" || r.Conclusion == "timed_out":
			s.Failed++
		}
	}
	// 以最新一次运行为主判据（GitHub 已按 created_at 倒序）
	newest := runs[0]
	switch {
	case newest.Status == "in_progress" || newest.Status == "queued":
		s.Status = "running"
		s.Label = "Running"
	case newest.Conclusion == "success":
		if s.Failed > 0 {
			s.Status = "mixed"
			s.Label = fmt.Sprintf("%d workflow failed", s.Failed)
		} else {
			s.Status = "passing"
			s.Label = "Passing"
		}
	case newest.Conclusion == "failure" || newest.Conclusion == "timed_out":
		s.Status = "failing"
		s.Label = fmt.Sprintf("%d workflow failed", maxInt(s.Failed, 1))
	default:
		s.Status = "mixed"
		s.Label = "Unknown"
	}
	s.WorkflowName = newest.Name
	return s
}

// githubAggregateWorkflows 按工作流名聚合最近一次运行状态（Build / Test / Docker）。
func githubAggregateWorkflows(runs []GitHubWorkflowRun) []GitHubWorkflowStatus {
	if len(runs) == 0 {
		return []GitHubWorkflowStatus{}
	}
	seen := map[string]bool{}
	out := make([]GitHubWorkflowStatus, 0, 6)
	for _, r := range runs {
		name := strings.TrimSpace(r.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, GitHubWorkflowStatus{
			Name: name, Status: githubRunStatusKey(r), Conclusion: r.Conclusion,
			Branch: r.Branch, ShortSHA: r.ShortSHA, HTMLURL: r.HTMLURL,
			CreatedAt: r.CreatedAt, DurationMS: r.DurationMS, RunNumber: r.RunNumber,
		})
		if len(out) >= 6 {
			break
		}
	}
	return out
}

// githubRunStatusKey 归一化运行状态为前端使用的键。
func githubRunStatusKey(r GitHubWorkflowRun) string {
	switch {
	case r.Status == "in_progress" || r.Status == "queued":
		return "running"
	case r.Conclusion == "success":
		return "passed"
	case r.Conclusion == "failure" || r.Conclusion == "timed_out":
		return "failed"
	case r.Conclusion == "cancelled":
		return "cancelled"
	default:
		return "unknown"
	}
}

// githubFetchLanguages 获取语言分布（/languages）+ 计算占比。
func githubFetchLanguages(ctx context.Context, owner, repo string) (*GitHubLanguagesResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	body, _, err := githubGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/languages",
		"application/vnd.github+json", "")
	if err != nil {
		return nil, err
	}
	var raw map[string]int64
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 GitHub 语言数据失败: %w", err)
	}

	resp := &GitHubLanguagesResponse{Owner: owner, Repo: repo, Languages: []GitHubLanguage{}}
	for name, bytes := range raw {
		if bytes <= 0 || strings.TrimSpace(name) == "" {
			continue
		}
		resp.TotalBytes += bytes
		resp.Languages = append(resp.Languages, GitHubLanguage{Name: name, Bytes: bytes})
	}
	for i := range resp.Languages {
		if resp.TotalBytes > 0 {
			resp.Languages[i].Percent = round1(float64(resp.Languages[i].Bytes) / float64(resp.TotalBytes) * 100)
		}
	}
	sort.SliceStable(resp.Languages, func(i, j int) bool { return resp.Languages[i].Bytes > resp.Languages[j].Bytes })
	return resp, nil
}

// githubFetchContributors 获取贡献者（/contributors?per_page=100），计算占比并取 Top N。
func githubFetchContributors(ctx context.Context, owner, repo string) (*GitHubContributorsResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	body, _, err := githubGet(ctx,
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contributors?per_page=100&anon=0",
		"application/vnd.github+json", "")
	if err != nil {
		if err == errGitHubNotFound { // 空仓库
			return &GitHubContributorsResponse{Owner: owner, Repo: repo, Contributors: []GitHubContributor{}}, nil
		}
		return nil, err
	}
	var raw []githubRawContributor
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 GitHub 贡献者数据失败: %w", err)
	}

	all := make([]GitHubContributor, 0, len(raw))
	for _, c := range raw {
		if strings.EqualFold(c.Type, "Bot") {
			continue // 机器人不算「谁在贡献」
		}
		all = append(all, GitHubContributor{
			Login: c.Login, AvatarURL: c.AvatarURL, HTMLURL: c.HTMLURL, Commits: c.Contributions,
		})
	}
	top, rest, totalCommits := githubNormalizeContributors(all, githubContributorTopN)
	return &GitHubContributorsResponse{
		Owner: owner, Repo: repo, Total: len(all), RestCount: rest,
		TotalCommits: totalCommits, Contributors: top,
	}, nil
}

// githubFetchActivity 汇总最近活动：
//   - commits（复用 commits 接口的 Recent，已按时间倒序）
//   - releases（复用 releases 接口）
//   - issues / PR（/issues?state=all&sort=updated）
//   - workflow runs（复用 actions 接口）
//
// 合并后按时间倒序，内存分页（offset/limit），首次只取 limit 条，支持 Load more。
// 内部 4 个来源各自走缓存，重复打开详情不会重复打 GitHub。
func githubFetchActivity(ctx context.Context, owner, repo string, offset, limit int) (*GitHubActivityResponse, error) {
	if err := githubValidateRepoInput(owner, repo); err != nil {
		return nil, err
	}
	items := make([]GitHubActivityItem, 0, 64)

	// 1) commits
	if commits, err := githubCachedCommits(ctx, owner, repo); err == nil && commits != nil {
		for _, c := range commits.Recent {
			items = append(items, GitHubActivityItem{
				Type: "commit", Title: c.Message,
				Subtitle: c.ShortSHA, Author: firstNonEmpty(c.AuthorLogin, c.AuthorName),
				AvatarURL: c.AuthorAvatar, Ref: c.ShortSHA, HTMLURL: c.HTMLURL, Time: c.Date,
			})
		}
	}
	// 2) releases
	if rels, err := githubCachedReleases(ctx, owner, repo); err == nil && rels != nil {
		for _, r := range rels.Releases {
			items = append(items, GitHubActivityItem{
				Type: "release", Title: r.TagName, Subtitle: r.Name,
				Author: r.Author, Ref: r.TagName, HTMLURL: r.HTMLURL, Time: r.PublishedAt,
				Status: releaseStatusKey(r),
			})
		}
	}
	// 3) issues + PR
	if rawIssues, err := githubCachedIssues(ctx, owner, repo); err == nil {
		for i := range rawIssues {
			it := convertGitHubIssueActivity(&rawIssues[i])
			if it != nil {
				items = append(items, *it)
			}
		}
	}
	// 4) workflow runs
	if acts, err := githubCachedActions(ctx, owner, repo); err == nil && acts != nil {
		for _, r := range acts.Runs {
			items = append(items, GitHubActivityItem{
				Type: "workflow", Title: r.Name,
				Subtitle: "#" + strconv.Itoa(r.RunNumber) + " " + r.Branch,
				Author:   r.Actor, Ref: r.ShortSHA, HTMLURL: r.HTMLURL, Time: r.CreatedAt,
				Status: githubRunStatusKey(r),
			})
		}
	}

	sort.SliceStable(items, func(i, j int) bool { return items[i].Time > items[j].Time })

	resp := &GitHubActivityResponse{Owner: owner, Repo: repo, Offset: offset, Limit: limit}
	if offset < 0 {
		offset = 0
	}
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	resp.Items = items[offset:end]
	resp.HasMore = end < len(items)
	if resp.Items == nil {
		resp.Items = []GitHubActivityItem{}
	}
	return resp, nil
}

// githubCachedIssues 拉取 issues（含 PR）并缓存。GitHub /issues 同时返回 PR，
// 依据 pull_request 字段区分，避免额外请求。
func githubCachedIssues(ctx context.Context, owner, repo string) ([]githubRawIssue, error) {
	key := "issues:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLActivity, func(ctx context.Context, _ string) (any, string, error) {
		if err := githubValidateRepoInput(owner, repo); err != nil {
			return nil, "", err
		}
		body, _, err := githubGet(ctx,
			"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues?state=all&sort=updated&direction=desc&per_page=50",
			"application/vnd.github+json", "")
		if err != nil {
			return nil, "", err
		}
		var raw []githubRawIssue
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, "", fmt.Errorf("解析 GitHub Issue 数据失败: %w", err)
		}
		// 只保留 Issue 与 PR 的轻量字段，避免缓存过大
		out := make([]githubRawIssue, 0, len(raw))
		for _, it := range raw {
			item := it
			item.Title = githubTruncateRunes(item.Title, 200)
			out = append(out, item)
		}
		return out, "", nil
	})
	if err != nil {
		return nil, err
	}
	issues, _ := data.([]githubRawIssue)
	return issues, nil
}

func convertGitHubIssueActivity(raw *githubRawIssue) *GitHubActivityItem {
	if raw == nil || raw.Number == 0 {
		return nil
	}
	author, avatar := "", ""
	if raw.User != nil {
		author, avatar = raw.User.Login, raw.User.AvatarURL
	}
	if raw.PullRequest != nil {
		status := "open"
		if raw.ClosedAt != nil || raw.PullRequest.MergedAt != nil {
			status = "closed"
		}
		url := raw.HTMLURL
		if raw.PullRequest.HTMLURL != "" {
			url = raw.PullRequest.HTMLURL
		}
		return &GitHubActivityItem{
			Type: "pull_request", Title: raw.Title, Subtitle: "#" + strconv.Itoa(raw.Number),
			Author: author, AvatarURL: avatar, Ref: "#" + strconv.Itoa(raw.Number),
			HTMLURL: url, Time: raw.UpdatedAt.UTC().Format(time.RFC3339), Status: status,
		}
	}
	return &GitHubActivityItem{
		Type: "issue", Title: raw.Title, Subtitle: "#" + strconv.Itoa(raw.Number),
		Author: author, AvatarURL: avatar, Ref: "#" + strconv.Itoa(raw.Number),
		HTMLURL: raw.HTMLURL, Time: raw.UpdatedAt.UTC().Format(time.RFC3339),
		Status: State2Status(raw.State),
	}
}

// releaseStatusKey 将 Release 映射为前端状态键。
func releaseStatusKey(r GitHubRelease) string {
	switch {
	case r.Draft:
		return "draft"
	case r.Prerelease:
		return "prerelease"
	default:
		return "published"
	}
}

// githubCachedCommits / Releases / Actions：供 activity 复用的缓存读取入口。
func githubCachedCommits(ctx context.Context, owner, repo string) (*GitHubCommitsResponse, error) {
	key := "commits:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLCommits, func(ctx context.Context, _ string) (any, string, error) {
		resp, err := githubFetchCommits(ctx, owner, repo)
		return resp, "", err
	})
	if err != nil {
		return nil, err
	}
	resp, _ := data.(*GitHubCommitsResponse)
	return resp, nil
}

func githubCachedReleases(ctx context.Context, owner, repo string) (*GitHubReleasesResponse, error) {
	key := "releases:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLReleases, func(ctx context.Context, _ string) (any, string, error) {
		resp, err := githubFetchReleases(ctx, owner, repo)
		return resp, "", err
	})
	if err != nil {
		return nil, err
	}
	resp, _ := data.(*GitHubReleasesResponse)
	return resp, nil
}

func githubCachedActions(ctx context.Context, owner, repo string) (*GitHubActionsResponse, error) {
	key := "actions:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLActions, func(ctx context.Context, _ string) (any, string, error) {
		resp, err := githubFetchActions(ctx, owner, repo)
		return resp, "", err
	})
	if err != nil {
		return nil, err
	}
	resp, _ := data.(*GitHubActionsResponse)
	return resp, nil
}

func githubCachedLanguages(ctx context.Context, owner, repo string) (*GitHubLanguagesResponse, error) {
	key := "languages:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLLanguages, func(ctx context.Context, _ string) (any, string, error) {
		resp, err := githubFetchLanguages(ctx, owner, repo)
		return resp, "", err
	})
	if err != nil {
		return nil, err
	}
	resp, _ := data.(*GitHubLanguagesResponse)
	return resp, nil
}

func githubCachedContributors(ctx context.Context, owner, repo string) (*GitHubContributorsResponse, error) {
	key := "contributors:" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	data, _, _, err := githubGetOrFetch(ctx, key, githubTTLContributors, func(ctx context.Context, _ string) (any, string, error) {
		resp, err := githubFetchContributors(ctx, owner, repo)
		return resp, "", err
	})
	if err != nil {
		return nil, err
	}
	resp, _ := data.(*GitHubContributorsResponse)
	return resp, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// State2Status Issue 状态 → 前端状态键（保持命名显式，避免与字段名冲突）。
func State2Status(state string) string {
	if strings.EqualFold(state, "closed") {
		return "closed"
	}
	return "open"
}
