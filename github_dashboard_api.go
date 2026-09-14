package main

// ==================== GitHub Developer Dashboard（聚合与 HTTP 层） ====================
//
// 职责：
//   - 把各数据源聚合为「项目详情」所需的统一响应（stats / heat / age / 时间格式化）
//   - 提供新增 API 的 handler
//
// 设计要点：
//   - 详情聚合一次返回 repo + stats + heat + age，避免前端为同一信息发多次请求。
//   - stats 中的 commits_30d / contributors / releases 需要额外请求，但**全部走缓存**，
//     且失败时降级为 0 而不是让整个详情失败（部分成功优于整体失败）。
//   - 严格区分「真实 0」与「取不到」：取不到时 Stats 中对应项保持 -1（前端显示 —）。

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// githubStatsUnavailable 表示某项统计取不到（前端显示 "—" 而非误导性的 0）。
const githubStatsUnavailable = -1

// ==================== 详情聚合 DTO ====================

// GitHubRepoDetailResponse 项目详情聚合响应（一次请求拿到详情页首屏全部数据）。
type GitHubRepoDetailResponse struct {
	Stale       bool                  `json:"stale"`
	RateLimited bool                  `json:"rate_limited"`
	Repo        *GitHubRepository     `json:"repo"`
	Stats       *GitHubRepoStats      `json:"stats"`
	Heat        *GitHubHeatResult     `json:"heat"`
	Age         *GitHubRepoAge        `json:"age"`
	CI          *GitHubActionsSummary `json:"ci"`
	RateLimit   *GitHubRateLimitInfo  `json:"rate_limit,omitempty"`
}

// GitHubRateLimitInfo 来自 GitHub 响应头的真实限流信息（绝不猜测）。
type GitHubRateLimitInfo struct {
	Limited   bool   `json:"limited"`
	Remaining int    `json:"remaining"`
	Limit     int    `json:"limit"`
	ResetAt   string `json:"reset_at,omitempty"`
	ResetIn   string `json:"reset_in,omitempty"`
}

// ==================== 聚合逻辑 ====================

// githubBuildRepoStats 组装项目综合统计。
// 所有可获取的项来自缓存取数；取不到时用 githubStatsUnavailable 标记。
// heat 传入 nil 时（未计算）热度为 0 且不参与 stats。
func githubBuildRepoStats(ctx context.Context, owner, repo string, r *GitHubRepository, commits *GitHubCommitsResponse,
	releases *GitHubReleasesResponse, contributors *GitHubContributorsResponse, heat int) *GitHubRepoStats {
	stats := &GitHubRepoStats{
		Stars:        r.Stars,
		Forks:        r.Forks,
		Issues:       r.Issues, // 注意：GitHub 的 open_issues_count 含 PR，见下方修正
		PullRequests: githubStatsUnavailable,
		Commits30d:   githubStatsUnavailable,
		Contributors: githubStatsUnavailable,
		Releases:     githubStatsUnavailable,
		HeatScore:    heat,
		Watchers:     r.Watchers,
	}
	if commits != nil && commits.Windows != nil {
		if w, ok := commits.Windows["30"]; ok && w != nil {
			stats.Commits30d = w.Total
		}
	}
	if releases != nil {
		stats.Releases = releases.Total
	}
	if contributors != nil {
		if contributors.Total > 0 {
			stats.Contributors = contributors.Total
		} else {
			stats.Contributors = 0
		}
	}
	// GitHub 的 open_issues_count 实际是「未关闭 Issue + 未合并 PR」之和。
	// 若能从 issues 缓存里拆分，则拆开；否则保持合并值并把 PR 标记为不可用。
	if issues, err := githubCachedIssues(ctx, owner, repo); err == nil && len(issues) > 0 {
		openIssues, openPRs := 0, 0
		for i := range issues {
			if issues[i].State != "open" {
				continue
			}
			if issues[i].PullRequest != nil {
				openPRs++
			} else {
				openIssues++
			}
		}
		// 仅在拆分结果非零时才覆盖（避免 issues 列表被截断造成低估）
		if openIssues+openPRs > 0 {
			stats.Issues = openIssues
			stats.PullRequests = openPRs
		}
	}
	return stats
}

// githubBuildHeatInput 从各数据源构造热度评分输入。
func githubBuildHeatInput(r *GitHubRepository, growth *GitHubStarGrowth, commits *GitHubCommitsResponse,
	releases *GitHubReleasesResponse, stats *GitHubRepoStats, now time.Time) GitHubHeatInput {
	in := GitHubHeatInput{
		Stars:      r.Stars,
		Commits7D:  0,
		Commits30D: 0,
		Releases:   0,
		PushedAt:   githubParseISOTime(r.PushedAt),
		Now:        now,
	}
	if growth != nil {
		in.StarGrowth7D = growth.Growth7D
		in.StarGrowth30D = growth.Growth30D
	}
	if commits != nil && commits.Windows != nil {
		if w, ok := commits.Windows["7"]; ok && w != nil {
			in.Commits7D = w.Total
		}
		if w, ok := commits.Windows["30"]; ok && w != nil {
			in.Commits30D = w.Total
		}
	}
	if releases != nil {
		in.Releases = releases.Total
		if releases.Latest != nil {
			in.LastRelease = githubParseISOTime(releases.Latest.PublishedAt)
		}
	}
	if stats != nil {
		if stats.Issues > 0 {
			in.OpenIssues = stats.Issues
		}
		if stats.PullRequests > 0 {
			in.OpenPRs = stats.PullRequests
		}
	}
	return in
}

// githubBuildStarGrowth 读取持久化历史并计算增长（无历史时返回零值结构）。
// current 取 GitHub 实时值（权威），历史缺失时 HasHistory=false，前端据此提示「正在建立」。
// 存储键统一为 owner/repo，换用户后不会读到别人的历史。
func githubBuildStarGrowth(owner, repo string, current int) GitHubStarGrowth {
	store := githubGetStore()
	if store == nil {
		return GitHubStarGrowth{Current: current}
	}
	points, err := store.StarHistory(githubRepoKey(owner, repo))
	if err != nil {
		return GitHubStarGrowth{Current: current}
	}
	return githubStarGrowth(points, current)
}

// githubCollectRateLimit 从环境感知的最近一次 GitHub 响应头提取限流信息。
// 只在真实受限或剩余低于阈值时返回，避免前端无意义展示。
func githubCollectRateLimit() *GitHubRateLimitInfo {
	snap, ok := githubLastRateLimit()
	if !ok {
		return nil
	}
	info := &GitHubRateLimitInfo{
		Limited:   snap.Remaining == 0,
		Remaining: snap.Remaining,
		Limit:     snap.Limit,
	}
	if !snap.ResetAt.IsZero() {
		info.ResetAt = snap.ResetAt.UTC().Format(time.RFC3339)
		left := time.Until(snap.ResetAt)
		if left > 0 {
			info.ResetIn = formatDurationShort(left)
		}
	}
	if !info.Limited && info.Remaining > 100 {
		return nil // 配额充足，不展示
	}
	return info
}

// formatDurationShort 把时长格式化为「12 分 32 秒」这类中文短格式。
func formatDurationShort(d time.Duration) string {
	if d < 0 {
		return "0 秒"
	}
	d = d.Round(time.Second)
	sec := int(d.Seconds())
	if sec < 60 {
		return strconv.Itoa(sec) + " 秒"
	}
	if sec < 3600 {
		return strconv.Itoa(sec/60) + " 分 " + strconv.Itoa(sec%60) + " 秒"
	}
	return strconv.Itoa(sec/3600) + " 小时 " + strconv.Itoa((sec%3600)/60) + " 分"
}

// ==================== HTTP Handler ====================

// githubHandleRepoSub 统一处理 /api/github/repos/{owner}/{repo}/xxx 子资源的
// owner/repo 校验与错误映射，减少重复代码。
func githubHandleRepoSub(w http.ResponseWriter, r *http.Request) (owner, repo string, ok bool) {
	if !githubEnsureEnabled(w) {
		return "", "", false
	}
	owner = r.PathValue("owner")
	repo = r.PathValue("repo")
	if err := githubValidateRepoInput(owner, repo); err != nil {
		githubWriteError(w, err)
		return "", "", false
	}
	return owner, repo, true
}

// githubDetailHandler GET /api/github/repos/{owner}/{repo}/detail
// 聚合详情：repo + stats + heat + age + CI 摘要（一次请求，避免前端瀑布流）。
func githubDetailHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	// 1) 仓库基础信息（必需，失败即失败）
	repoData, stale, rl, err := githubGetOrFetch(ctx, "repo:"+strings.ToLower(owner)+"/"+strings.ToLower(repo),
		githubTTLDetail, func(ctx context.Context, etag string) (any, string, error) {
			return githubFetchRepoDetail(ctx, owner, repo, etag)
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	base, _ := repoData.(*GitHubRepository)
	if base == nil {
		githubWriteError(w, errGitHubNotFound)
		return
	}

	// 2) 附加数据：任一失败只降级对应分项，不影响整体详情
	now := time.Now()
	growth := githubBuildStarGrowth(owner, repo, base.Stars)

	var commits *GitHubCommitsResponse
	var releases *GitHubReleasesResponse
	var contributors *GitHubContributorsResponse
	var actions *GitHubActionsResponse
	if resp, err := githubCachedCommits(ctx, owner, repo); err == nil {
		commits = resp
	}
	if resp, err := githubCachedReleases(ctx, owner, repo); err == nil {
		releases = resp
	}
	if resp, err := githubCachedContributors(ctx, owner, repo); err == nil {
		contributors = resp
	}
	if resp, err := githubCachedActions(ctx, owner, repo); err == nil {
		actions = resp
	}
	// 降级标记：任一子请求处于 stale 或限流，整体标注（前端统一提示「数据来自缓存」）
	if commits == nil && releases == nil && contributors == nil && actions == nil {
		// 全部失败：保持 repo 基础信息可用，但标注数据不完整
		stale = true
	}

	stats := githubBuildRepoStats(ctx, owner, repo, base, commits, releases, contributors, 0)
	heat := githubHeatScore(githubBuildHeatInput(base, &growth, commits, releases, stats, now))
	stats.HeatScore = heat.Score
	age := githubRepoAge(githubParseISOTime(base.CreatedAt), now)

	var ci *GitHubActionsSummary
	if actions != nil {
		ci = actions.Summary
	}

	// 落地当日指标快照（幂等；沉淀 Issue/PR/Release/Heat 历史，不额外请求）
	githubPersistGauge(owner, repo, stats, heat.Score)

	writeJSON(w, http.StatusOK, "获取成功", &GitHubRepoDetailResponse{
		Stale: stale, RateLimited: rl,
		Repo: base, Stats: stats, Heat: &heat, Age: &age, CI: ci,
		RateLimit: githubCollectRateLimit(),
	})
}

// githubPersistGauge 把详情算出的指标写入当日快照（失败静默，不影响请求）。
func githubPersistGauge(owner, repo string, stats *GitHubRepoStats, heat int) {
	store := githubGetStore()
	if store == nil || stats == nil {
		return
	}
	g := GitHubGaugePoint{
		Repo: githubRepoKey(owner, repo), Stars: stats.Stars, Forks: stats.Forks,
		Releases:     maxInt(stats.Releases, 0),
		Commits30d:   maxInt(stats.Commits30d, 0),
		Contributors: maxInt(stats.Contributors, 0),
		HeatScore:    heat,
	}
	if stats.Issues > 0 {
		g.Issues = stats.Issues
	}
	if stats.PullRequests > 0 {
		g.PullRequests = stats.PullRequests
	}
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{g}, time.Now(), false); err != nil {
		// 快照失败只记日志，不影响用户请求
		githubLogWarn("GitHub 指标快照保存失败: %v", err)
	}
}

// githubStarsHandler GET /api/github/repos/{owner}/{repo}/stars?window=7|30|90|365|0
// 返回 Star 趋势点 + 增长分析。历史来自 SQLite 持久化快照，没有就明确告知。
func githubStarsHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	window := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("window")); err == nil {
		switch v {
		case 7, 30, 90, 365:
			window = v
		case 0:
			window = 0 // ALL
		}
	}

	// 当前 Star 以仓库详情缓存为准（权威），避免额外请求
	current := 0
	stale, rl := false, false
	if repoData, s, l, err := githubGetOrFetch(r.Context(),
		"repo:"+strings.ToLower(owner)+"/"+strings.ToLower(repo), githubTTLDetail,
		func(ctx context.Context, etag string) (any, string, error) {
			return githubFetchRepoDetail(ctx, owner, repo, etag)
		}); err == nil {
		if base, _ := repoData.(*GitHubRepository); base != nil {
			current = base.Stars
		}
		stale, rl = s, l
	} else {
		githubWriteError(w, err)
		return
	}

	store := githubGetStore()
	points := []GitHubStarPoint{}
	growth := GitHubStarGrowth{Current: current}
	if store != nil {
		all, err := store.StarHistory(githubRepoKey(owner, repo))
		if err == nil && len(all) > 0 {
			growth = githubStarGrowth(all, current)
			points = githubFilterStarPoints(all, window)
		}
	}

	writeJSON(w, http.StatusOK, "获取成功", &GitHubStarTrend{
		Stale: stale, RateLimited: rl, Owner: owner, Repo: repo,
		Window: window, Growth: growth, Points: points, Current: current,
		Recording: githubCollectorEnabled(),
	})
}

// githubCommitsHandler GET /api/github/repos/{owner}/{repo}/commits
func githubCommitsHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	data, stale, rl, err := githubGetOrFetch(r.Context(),
		"commits:"+strings.ToLower(owner)+"/"+strings.ToLower(repo), githubTTLCommits,
		func(ctx context.Context, _ string) (any, string, error) {
			resp, err := githubFetchCommits(ctx, owner, repo)
			return resp, "", err
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	resp, _ := data.(*GitHubCommitsResponse)
	if resp == nil {
		githubWriteError(w, errGitHubNotFound)
		return
	}
	resp.Stale, resp.RateLimited = stale, rl
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubCommitDetailHandler GET /api/github/repos/{owner}/{repo}/commits/{sha}
func githubCommitDetailHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	sha := r.PathValue("sha")
	if !githubCommitSHAre.MatchString(sha) {
		writeJSONError(w, http.StatusNotFound, "GitHub 提交不存在")
		return
	}
	key := "commit:" + strings.ToLower(owner) + "/" + strings.ToLower(repo) + "/" + strings.ToLower(sha)
	data, stale, rl, err := githubGetOrFetch(r.Context(), key, githubTTLReadme,
		func(ctx context.Context, _ string) (any, string, error) {
			resp, err := githubFetchCommitDetail(ctx, owner, repo, sha)
			return resp, "", err
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	commit, _ := data.(*GitHubCommit)
	writeJSON(w, http.StatusOK, "获取成功", map[string]any{
		"stale": stale, "rate_limited": rl, "commit": commit,
	})
}

// githubReleasesHandler GET /api/github/repos/{owner}/{repo}/releases
func githubReleasesHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	data, stale, rl, err := githubGetOrFetch(r.Context(),
		"releases:"+strings.ToLower(owner)+"/"+strings.ToLower(repo), githubTTLReleases,
		func(ctx context.Context, _ string) (any, string, error) {
			resp, err := githubFetchReleases(ctx, owner, repo)
			return resp, "", err
		})
	if err != nil {
		githubWriteError(w, err)
		return
	}
	resp, _ := data.(*GitHubReleasesResponse)
	if resp == nil {
		githubWriteError(w, errGitHubNotFound)
		return
	}
	resp.Stale, resp.RateLimited = stale, rl
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubActionsHandler GET /api/github/repos/{owner}/{repo}/actions
func githubActionsHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	resp, err := githubCachedActions(r.Context(), owner, repo)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubLanguagesHandler GET /api/github/repos/{owner}/{repo}/languages
func githubLanguagesHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	resp, err := githubCachedLanguages(r.Context(), owner, repo)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubContributorsHandler GET /api/github/repos/{owner}/{repo}/contributors
func githubContributorsHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	resp, err := githubCachedContributors(r.Context(), owner, repo)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubActivityHandler GET /api/github/repos/{owner}/{repo}/activity?offset=0&limit=20
// 最近活动：Commit / Release / Issue / PR / Workflow，按时间倒序，支持 Load more。
func githubActivityHandler(w http.ResponseWriter, r *http.Request) {
	owner, repo, ok := githubHandleRepoSub(w, r)
	if !ok {
		return
	}
	limit := githubActivityDefault
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > githubActivityMax {
		limit = githubActivityMax
	}
	offset := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = v
	}
	resp, err := githubFetchActivity(r.Context(), owner, repo, offset, limit)
	if err != nil {
		githubWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, "获取成功", resp)
}

// githubReadmeHandlerV2 说明：README 沿用 github.go 中既有的 githubReadmeHandler，
// 路径与响应结构完全一致（GET /api/github/repos/{owner}/{repo}/readme），此处不重复实现。
//
// 既有路径 GET /api/github/repos/{owner}/{repo} 由 github.go 的 githubRepoDetailHandler 提供；
// 聚合详情（含 stats/heat/age/CI）走 /detail，避免破坏既有前端调用方。
