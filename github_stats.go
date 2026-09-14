package main

// ==================== GitHub Developer Dashboard（统计与指标层） ====================
//
// 本文件是 github.go 的扩展，只负责「派生指标」：
//   - 项目年龄 / 时间格式化
//   - Star 增长分析（来自 github_star_history 持久化快照）
//   - Commit 活跃度统计
//   - 项目热度评分（Heat Score）
//   - 增长率、贡献者占比等纯计算
//
// 设计约束：
//   - 所有数值必须来自真实 GitHub 数据或真实历史快照，绝不随机/模拟/伪造。
//   - 无历史数据时返回明确的「无数据」标记，由前端提示「正在建立 Star 历史数据」。
//   - 纯函数优先，便于单元测试。

import (
	"math"
	"sort"
	"strings"
	"time"
)

// ==================== 项目年龄 ====================

// GitHubRepoAge 项目年龄的机器友好表示（前端也可直接用，避免重复实现）。
type GitHubRepoAge struct {
	Days       int    `json:"days"`
	Months     int    `json:"months"`
	Years      int    `json:"years"`
	Label      string `json:"label"`      // 「3 天」「2 个月」「1 年 3 个月」「今天创建」
	CreatedAt  string `json:"created_at"` // YYYY-MM-DD
	IsNewToday bool   `json:"is_new_today"`
}

// githubRepoAge 计算项目年龄。展示规则：
//
//	< 1 天   → 今天创建
//	< 30 天  → N 天
//	< 365 天 → N 个月
//	>= 365 天 → N 年 M 个月（M 为 0 时只显示 N 年）
func githubRepoAge(created time.Time, now time.Time) GitHubRepoAge {
	age := GitHubRepoAge{}
	if created.IsZero() {
		age.Label = "—"
		return age
	}
	created = created.UTC()
	now = now.UTC()
	age.CreatedAt = created.Format("2006-01-02")
	if now.Before(created) {
		age.IsNewToday = true
		age.Label = "今天创建"
		return age
	}

	totalDays := int(now.Sub(created).Hours() / 24)
	age.Days = totalDays

	// 自然月差（按日历计算，避免 30 天近似造成的「1 年 13 个月」）
	years := now.Year() - created.Year()
	months := int(now.Month()) - int(created.Month())
	if now.Day() < created.Day() {
		months--
	}
	if months < 0 {
		years--
		months += 12
	}
	if years < 0 {
		years, months = 0, 0
	}
	age.Years, age.Months = years, months

	switch {
	case totalDays < 1 && years == 0 && months == 0:
		age.IsNewToday = true
		age.Label = "今天创建"
	case years > 0 && months > 0:
		age.Label = itoa(years) + " 年 " + itoa(months) + " 个月"
	case years > 0:
		age.Label = itoa(years) + " 年"
	case months > 0:
		age.Label = itoa(months) + " 个月"
	default:
		age.Label = itoa(totalDays) + " 天"
	}
	return age
}

// itoa 轻量整数转字符串（避免在热点路径引入 strconv 依赖歧义）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ==================== Star 增长分析 ====================

// GitHubStarGrowth Star 增长分析结果。
type GitHubStarGrowth struct {
	HasHistory bool `json:"has_history"` // false = 历史数据尚未建立
	Points     int  `json:"points"`      // 历史快照点数

	Current     int     `json:"current"`
	Growth7D    int     `json:"growth_7d"`
	Growth30D   int     `json:"growth_30d"`
	Growth90D   int     `json:"growth_90d"`
	GrowthTotal int     `json:"growth_total"` // 有史以来
	Rate30D     float64 `json:"rate_30d"`     // 30 天增长率（%），基于 30 天前的基数
	Rate7D      float64 `json:"rate_7d"`
	Since       string  `json:"since"` // 最早快照日期
}

// githubStarGrowth 基于历史快照计算增长。current 为 GitHub 实时数值（权威）。
// points 需按日期升序。历史不足以覆盖某个窗口时，该窗口增长返回 0 并在
// HasHistory=false 时由前端整体提示「正在建立 Star 历史数据」。
func githubStarGrowth(points []GitHubStarPoint, current int) GitHubStarGrowth {
	g := GitHubStarGrowth{Current: current}
	if len(points) == 0 {
		return g
	}
	// 仅当存在 >= 2 个不同日期的快照时，趋势才有意义
	distinct := map[string]bool{}
	for _, p := range points {
		distinct[p.Date] = true
	}
	if len(distinct) < 2 {
		return g
	}
	g.HasHistory = true
	g.Points = len(points)
	g.Since = points[0].Date

	// 窗口起点：取「日期 <= 窗口起点」的最后一条快照作为基数（容错缺采）
	baseBefore := func(days int) (int, bool) {
		cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
		base, found := 0, false
		for _, p := range points {
			if p.Date <= cutoff {
				base, found = p.Stars, true
			}
		}
		return base, found
	}

	if base, ok := baseBefore(7); ok {
		g.Growth7D = current - base
		if base > 0 {
			g.Rate7D = round1(float64(g.Growth7D) / float64(base) * 100)
		}
	}
	if base, ok := baseBefore(30); ok {
		g.Growth30D = current - base
		if base > 0 {
			g.Rate30D = round1(float64(g.Growth30D) / float64(base) * 100)
		}
	}
	if base, ok := baseBefore(90); ok {
		g.Growth90D = current - base
	}
	g.GrowthTotal = current - points[0].Stars
	if g.GrowthTotal < 0 {
		g.GrowthTotal = 0 // Star 被取消属于异常，展示为 0 而非负数
	}
	return g
}

// round1 保留一位小数（增长率展示）。
func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

// githubFilterStarPoints 按窗口裁剪历史点用于绘图：days<=0 表示全部。
// 为保证曲线起点连续，会额外带上窗口起点之前最近的一个点作为基线。
func githubFilterStarPoints(points []GitHubStarPoint, days int) []GitHubStarPoint {
	if days <= 0 || len(points) == 0 {
		return points
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	out := make([]GitHubStarPoint, 0, len(points))
	baseline := -1
	for i, p := range points {
		if p.Date <= cutoff {
			baseline = i
		}
	}
	if baseline >= 0 {
		out = append(out, points[baseline])
	}
	for _, p := range points {
		if p.Date > cutoff {
			out = append(out, p)
		}
	}
	// 窗口内无任何点时，至少返回最后一个点，避免前端拿到空数组无法判断
	if len(out) == 0 {
		return points[len(points)-1:]
	}
	return out
}

// ==================== Commit 活跃度 ====================

// GitHubCommitDay 单日提交数（柱状图/热力图数据点）。
type GitHubCommitDay struct {
	Date    string `json:"date"` // YYYY-MM-DD
	Commits int    `json:"commits"`
}

// GitHubCommitActivity Commit 活跃度统计。
type GitHubCommitActivity struct {
	Days            int               `json:"days"` // 窗口天数（7/30/90）
	Total           int               `json:"total"`
	ActiveDays      int               `json:"active_days"`
	AvgPerDay       float64           `json:"avg_per_day"`
	MaxPerDay       int               `json:"max_per_day"`
	Daily           []GitHubCommitDay `json:"daily"`
	WindowFrom      string            `json:"window_from"`
	WindowTo        string            `json:"window_to"`
	HasPartialData  bool              `json:"has_partial_data,omitempty"` // 窗口超出可取范围时为 true
	ContributorHint int               `json:"contributor_hint,omitempty"`
}

// githubAggregateCommitDays 把「日期 → 提交数」聚合为窗口统计。
// days<=0 时使用全部数据。窗口内每一天（含 0 提交日）都会补全，便于柱状图连续。
func githubAggregateCommitDays(byDay map[string]int, days int, now time.Time) GitHubCommitActivity {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if days <= 0 {
		days = 90
	}
	from := today.AddDate(0, 0, -(days - 1))

	act := GitHubCommitActivity{
		Days:       days,
		Daily:      make([]GitHubCommitDay, 0, days),
		WindowFrom: from.Format("2006-01-02"),
		WindowTo:   today.Format("2006-01-02"),
	}
	for d := from; !d.After(today); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		n := byDay[key]
		if n < 0 {
			n = 0
		}
		act.Daily = append(act.Daily, GitHubCommitDay{Date: key, Commits: n})
		act.Total += n
		if n > 0 {
			act.ActiveDays++
		}
		if n > act.MaxPerDay {
			act.MaxPerDay = n
		}
	}
	if days > 0 {
		act.AvgPerDay = round1(float64(act.Total) / float64(days))
	}
	return act
}

// ==================== 项目热度评分 ====================
//
// 设计目标：权重集中在「近期行为」，不做 stars*10 这类线性堆叠。
// 各分项先归一化到 0~1（对数/饱和函数，避免大项目碾压小项目），
// 再乘权重求和，最后映射到 0~100。
//
// 分项与权重（合计 1.00）：
//
//	star_growth_7d   0.22  近 7 天 Star 增长（最高权重：社区热度）
//	star_growth_30d  0.12  近 30 天 Star 增长
//	commit_7d        0.20  近 7 天提交（最高权重：活跃开发）
//	commit_30d       0.12  近 30 天提交
//	release_recency  0.08  最近 Release 时间新鲜度
//	issue_activity   0.06  Issue 数（未关闭）
//	pr_activity      0.07  PR 数（未合并）
//	recent_update    0.13  最近 push 时间新鲜度（>90 天快速衰减）
//
// 衰减：最近更新时间超过 90 天，总分乘 0.6；超过 180 天乘 0.35。
// 沉寂项目因此会被显著压分，即便历史 Star 很高。

const (
	heatWeightStar7D     = 0.22
	heatWeightStar30D    = 0.12
	heatWeightCommit7D   = 0.20
	heatWeightCommit30D  = 0.12
	heatWeightRelease    = 0.08
	heatWeightIssue      = 0.06
	heatWeightPR         = 0.07
	heatWeightRecentPush = 0.13
)

// GitHubHeatInput 热度评分输入（全部来自真实数据）。
type GitHubHeatInput struct {
	Stars         int
	StarGrowth7D  int
	StarGrowth30D int
	Commits7D     int
	Commits30D    int
	OpenIssues    int
	OpenPRs       int
	Releases      int
	LastRelease   time.Time // 最近 Release 时间（零值表示无 Release）
	PushedAt      time.Time // 最近 push 时间
	Now           time.Time
}

// GitHubHeatResult 热度评分结果。
type GitHubHeatResult struct {
	Score int              `json:"score"` // 0~100
	Level string           `json:"level"` // 非常活跃/活跃/正常/较低/沉寂
	Label string           `json:"label"` // 展示文案，如「非常活跃」
	Parts []GitHubHeatPart `json:"parts"`
}

// GitHubHeatPart 分项得分（前端可展开解释「为什么是这个分」）。
type GitHubHeatPart struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Raw    float64 `json:"raw"`    // 原始值
	Score  float64 `json:"score"`  // 归一化后 0~100
	Weight float64 `json:"weight"` // 权重
}

// GitHubHeatLevel 返回热度等级文案。
func GitHubHeatLevel(score int) (string, string) {
	switch {
	case score >= 90:
		return "very_active", "非常活跃"
	case score >= 75:
		return "active", "活跃"
	case score >= 50:
		return "normal", "正常"
	case score >= 25:
		return "low", "较低"
	default:
		return "dormant", "沉寂"
	}
}

// githubHeatScore 计算项目热度（纯函数，便于测试）。
func githubHeatScore(in GitHubHeatInput) GitHubHeatResult {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	// 饱和归一化：sat(v, k) = v/(v+k)，v 很大时趋近 1 但永不越界
	sat := func(v float64, k float64) float64 {
		if v <= 0 {
			return 0
		}
		return v / (v + k)
	}
	// 新鲜度：age 小时内线性到 1，超过 horizon 小时线性衰减到 0
	fresh := func(t time.Time, horizon time.Duration) float64 {
		if t.IsZero() {
			return 0
		}
		age := now.Sub(t)
		if age < 0 {
			return 1
		}
		if age >= horizon {
			return 0
		}
		return 1 - float64(age)/float64(horizon)
	}

	parts := []GitHubHeatPart{
		{Key: "star_growth_7d", Label: "近 7 天 Star 增长", Raw: float64(in.StarGrowth7D),
			Score: sat(float64(in.StarGrowth7D), 5) * 100, Weight: heatWeightStar7D},
		{Key: "star_growth_30d", Label: "近 30 天 Star 增长", Raw: float64(in.StarGrowth30D),
			Score: sat(float64(in.StarGrowth30D), 20) * 100, Weight: heatWeightStar30D},
		{Key: "commit_7d", Label: "近 7 天提交", Raw: float64(in.Commits7D),
			Score: sat(float64(in.Commits7D), 4) * 100, Weight: heatWeightCommit7D},
		{Key: "commit_30d", Label: "近 30 天提交", Raw: float64(in.Commits30D),
			Score: sat(float64(in.Commits30D), 30) * 100, Weight: heatWeightCommit30D},
		{Key: "release", Label: "最近发布", Raw: float64(in.Releases),
			Score: fresh(in.LastRelease, 90*24*time.Hour) * 100, Weight: heatWeightRelease},
		{Key: "issues", Label: "待处理 Issue", Raw: float64(in.OpenIssues),
			Score: sat(float64(in.OpenIssues), 8) * 100, Weight: heatWeightIssue},
		{Key: "pulls", Label: "待处理 PR", Raw: float64(in.OpenPRs),
			Score: sat(float64(in.OpenPRs), 5) * 100, Weight: heatWeightPR},
		{Key: "recent_push", Label: "最近更新", Raw: 0,
			Score: fresh(in.PushedAt, 90*24*time.Hour) * 100, Weight: heatWeightRecentPush},
	}

	var total float64
	for _, p := range parts {
		total += p.Score * p.Weight
	}

	// 长期沉寂衰减：3 个月无更新大幅压分（避免「历史 Star 高 = 热度高」）
	if !in.PushedAt.IsZero() {
		idle := now.Sub(in.PushedAt)
		switch {
		case idle > 180*24*time.Hour:
			total *= 0.35
		case idle > 90*24*time.Hour:
			total *= 0.60
		}
	}

	score := int(math.Round(total))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	level, label := GitHubHeatLevel(score)
	return GitHubHeatResult{Score: score, Level: level, Label: label, Parts: parts}
}

// ==================== 贡献者占比 ====================

// GitHubContributor 贡献者 DTO。
type GitHubContributor struct {
	Login     string  `json:"login"`
	AvatarURL string  `json:"avatar_url"`
	HTMLURL   string  `json:"html_url"`
	Commits   int     `json:"commits"`
	Percent   float64 `json:"percent"` // 占总提交数百分比（0~100，一位小数）
	Top       bool    `json:"top,omitempty"`
}

// githubNormalizeContributors 计算占比并截断 Top N。
// 返回值：(Top N 列表, 剩余人数, 总提交数)。
func githubNormalizeContributors(all []GitHubContributor, topN int) ([]GitHubContributor, int, int) {
	if len(all) == 0 {
		return nil, 0, 0
	}
	list := make([]GitHubContributor, len(all))
	copy(list, all)
	// 已按 commits 降序（GitHub 默认），这里保证顺序稳定
	sort.SliceStable(list, func(i, j int) bool { return list[i].Commits > list[j].Commits })

	total := 0
	for _, c := range list {
		if c.Commits > 0 {
			total += c.Commits
		}
	}
	for i := range list {
		if total > 0 {
			list[i].Percent = round1(float64(list[i].Commits) / float64(total) * 100)
		}
	}
	top := list
	rest := 0
	if topN > 0 && len(list) > topN {
		top = list[:topN]
		rest = len(list) - topN
	}
	for i := range top {
		top[i].Top = true
	}
	return top, rest, total
}

// ==================== 时间格式化工具 ====================

// githubFormatDate 输出 YYYY-MM-DD（空/非法返回 "—"）。
func githubFormatDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02")
}

// githubParseISOTime 解析 DTO 中的 RFC3339 字符串（失败返回零值）。
func githubParseISOTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// githubShortSHA 截取提交短哈希（7 位）。
func githubShortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) <= 7 {
		return sha
	}
	return sha[:7]
}

// githubNormalizeTopics 清洗 Topics：去空、去重、限制数量，绝不生成假 Topic。
func githubNormalizeTopics(topics []string, limit int) []string {
	out := make([]string, 0, len(topics))
	seen := map[string]bool{}
	for _, t := range topics {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
