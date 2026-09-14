package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ==================== 项目年龄 ====================

func TestGitHubRepoAge(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		created   time.Time
		wantLabel string
		wantDays  int
		wantToday bool
	}{
		{"今天创建", now.Add(-3 * time.Hour), "今天创建", 0, true},
		{"1 天前", now.Add(-30 * time.Hour), "1 天", 1, false},
		{"3 天", now.Add(-3 * 24 * time.Hour), "3 天", 3, false},
		{"29 天仍按天", now.Add(-29 * 24 * time.Hour), "29 天", 29, false},
		{"2 个月", now.Add(-60 * 24 * time.Hour), "", 60, false},
		{"1 年 3 个月", now.Add(-(365 + 90) * 24 * time.Hour), "", 455, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := githubRepoAge(c.created, now)
			if got.IsNewToday != c.wantToday {
				t.Errorf("IsNewToday = %v, want %v", got.IsNewToday, c.wantToday)
			}
			if !c.wantToday && got.Days != c.wantDays {
				t.Errorf("Days = %d, want %d", got.Days, c.wantDays)
			}
			if c.wantLabel != "" && got.Label != c.wantLabel {
				t.Errorf("Label = %q, want %q", got.Label, c.wantLabel)
			}
			// 任何情况下 Label 都不能是裸 ISO 时间
			if got.Label == "" {
				t.Error("Label 为空")
			}
			if len(got.Label) >= 10 && got.Label[4] == '-' && got.Label[7] == '-' {
				t.Errorf("Label 不应回退为 ISO 时间: %q", got.Label)
			}
		})
	}
}

func TestGitHubRepoAgeMonthYearLabel(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	got := githubRepoAge(now.Add(-(365+90)*24*time.Hour), now)
	if got.Years != 1 || got.Months < 1 {
		t.Errorf("期望 1 年多，得到 Years=%d Months=%d", got.Years, got.Months)
	}
	if got.Label == "" || got.Label == "今天创建" {
		t.Errorf("Label 异常: %q", got.Label)
	}
}

// ==================== Star 增长 ====================

func TestGitHubStarGrowthEmptyHistory(t *testing.T) {
	got := githubStarGrowth(nil, 24)
	if got.HasHistory {
		t.Error("无历史点时 HasHistory 应为 false")
	}
	if got.Current != 24 {
		t.Errorf("Current = %d, want 24", got.Current)
	}
	if got.Points != 0 {
		t.Errorf("Points = %d, want 0", got.Points)
	}
}

func TestGitHubStarGrowthComputesDeltas(t *testing.T) {
	now := time.Now().UTC()
	mk := func(daysAgo, stars int) GitHubStarPoint {
		return GitHubStarPoint{Date: now.AddDate(0, 0, -daysAgo).Format("2006-01-02"), Stars: stars}
	}
	points := []GitHubStarPoint{
		mk(200, 5), mk(100, 10), mk(90, 12), mk(30, 18), mk(7, 21), mk(0, 24),
	}
	got := githubStarGrowth(points, 24)
	if !got.HasHistory {
		t.Fatal("HasHistory 应为 true")
	}
	if got.Points != len(points) {
		t.Errorf("Points = %d, want %d", got.Points, len(points))
	}
	if got.Growth30D <= 0 {
		t.Errorf("Growth30D 应 > 0，得到 %d", got.Growth30D)
	}
	if got.Growth7D < 0 {
		t.Errorf("Growth7D 不应为负，得到 %d", got.Growth7D)
	}
	if got.GrowthTotal != 24-5 {
		t.Errorf("GrowthTotal = %d, want %d", got.GrowthTotal, 19)
	}
}

func TestGitHubFilterStarPoints(t *testing.T) {
	now := time.Now().UTC()
	mk := func(daysAgo int) GitHubStarPoint {
		return GitHubStarPoint{Date: now.AddDate(0, 0, -daysAgo).Format("2006-01-02"), Stars: daysAgo}
	}
	pts := []GitHubStarPoint{mk(120), mk(80), mk(20), mk(3)}

	// 语义：窗口内的点 + 1 个窗口外「基线点」（用于折线起点有参照），
	// 因此 30 天窗口 = 基线(80) + 窗口内(20, 3) = 3 个点。
	got30 := githubFilterStarPoints(pts, 30)
	if len(got30) != 3 {
		t.Errorf("30 天窗口应有 3 点（含 1 个基线点），得到 %d: %+v", len(got30), got30)
	}
	// 必须至少包含窗口内的全部点
	dates := map[string]bool{}
	for _, p := range got30 {
		dates[p.Date] = true
	}
	if !dates[mk(20).Date] || !dates[mk(3).Date] {
		t.Errorf("30 天窗口必须包含窗口内的点，得到 %+v", got30)
	}
	// 窗口外过远的点（120 天前）不应出现
	if dates[mk(120).Date] {
		t.Errorf("120 天前的点不应出现在 30 天窗口: %+v", got30)
	}

	got90 := githubFilterStarPoints(pts, 90)
	if len(got90) != 4 {
		t.Errorf("90 天窗口应有 4 点（含基线 120），得到 %d", len(got90))
	}

	// days<=0 返回全部
	if got := githubFilterStarPoints(pts, 0); len(got) != len(pts) {
		t.Errorf("days<=0 应返回全部 %d 点，得到 %d", len(pts), len(got))
	}
	// 空输入不应 panic
	if got := githubFilterStarPoints(nil, 30); len(got) != 0 {
		t.Errorf("空输入应返回空，得到 %+v", got)
	}
	// 窗口内无点时，至少返回最后一个点，前端才不会拿到空数组
	old := []GitHubStarPoint{
		{Date: now.AddDate(0, 0, -400).Format("2006-01-02"), Stars: 1},
		{Date: now.AddDate(0, 0, -300).Format("2006-01-02"), Stars: 2},
	}
	if got := githubFilterStarPoints(old, 30); len(got) == 0 {
		t.Error("窗口内无点时应至少返回最后一个点，不能返回空")
	}
}

// ==================== Commit 聚合 ====================

func TestGitHubAggregateCommitDays(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	byDay := map[string]int{
		now.Format("2006-01-02"):                     3,
		now.AddDate(0, 0, -1).Format("2006-01-02"):   2,
		now.AddDate(0, 0, -40).Format("2006-01-02"):  7,
		now.AddDate(0, 0, -200).Format("2006-01-02"): 99, // 窗口外
	}
	got := githubAggregateCommitDays(byDay, 90, now)
	if len(got.Daily) != 90 {
		t.Errorf("Daily 长度 = %d, want 90", len(got.Daily))
	}
	if got.Total != 12 {
		t.Errorf("Total = %d, want 12（不含窗口外的 99）", got.Total)
	}
	if got.MaxPerDay != 7 {
		t.Errorf("MaxPerDay = %d, want 7", got.MaxPerDay)
	}
	if got.ActiveDays != 3 {
		t.Errorf("ActiveDays = %d, want 3", got.ActiveDays)
	}
	if got.Days != 90 {
		t.Errorf("Days = %d, want 90", got.Days)
	}
	if got.AvgPerDay <= 0 {
		t.Error("AvgPerDay 应 > 0")
	}
}

func TestGitHubAggregateCommitDaysEmpty(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	got := githubAggregateCommitDays(map[string]int{}, 7, now)
	if got.Total != 0 || got.ActiveDays != 0 || got.MaxPerDay != 0 {
		t.Errorf("空数据应全 0，得到 %+v", got)
	}
	if len(got.Daily) != 7 {
		t.Errorf("Daily 长度 = %d, want 7", len(got.Daily))
	}
}

// ==================== 热度等级 ====================

func TestGitHubHeatLevelBoundaries(t *testing.T) {
	cases := []struct {
		score int
		level string
	}{
		{100, "very_active"}, {90, "very_active"},
		{89, "active"}, {75, "active"},
		{74, "normal"}, {50, "normal"},
		{49, "low"}, {25, "low"},
		{24, "dormant"}, {0, "dormant"},
	}
	for _, c := range cases {
		gotLevel, gotLabel := GitHubHeatLevel(c.score)
		if gotLevel != c.level {
			t.Errorf("score=%d: level = %q, want %q", c.score, gotLevel, c.level)
		}
		if gotLabel == "" {
			t.Errorf("score=%d: label 不应为空", c.score)
		}
	}
}

// ==================== 热度计算（用户明确要求的核心用例） ====================

func baseHeatInput(now time.Time) GitHubHeatInput {
	return GitHubHeatInput{
		Stars:         100,
		StarGrowth7D:  2,
		StarGrowth30D: 8,
		Commits7D:     5,
		Commits30D:    20,
		OpenIssues:    3,
		OpenPRs:       1,
		Releases:      2,
		LastRelease:   now.AddDate(0, 0, -10),
		PushedAt:      now.AddDate(0, 0, -1),
		Now:           now,
	}
}

// 用例 1（用户明确要求）：相同 Stars，近期 Commit 更多的项目，热度必须更高。
func TestGitHubHeatMoreRecentCommitsWins(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

	quiet := baseHeatInput(now)
	quiet.Commits7D = 1
	quiet.Commits30D = 4

	busy := baseHeatInput(now)
	busy.Commits7D = 25
	busy.Commits30D = 90

	q := githubHeatScore(quiet)
	b := githubHeatScore(busy)

	if b.Score <= q.Score {
		t.Errorf("近期 Commit 更多应热度更高：busy=%d, quiet=%d", b.Score, q.Score)
	}
}

// 用例 2（用户明确要求）：很久没有更新的项目，热度必须下降。
func TestGitHubHeatLongIdleDecays(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

	fresh := baseHeatInput(now)
	fresh.PushedAt = now.AddDate(0, 0, -2)
	fresh.LastRelease = now.AddDate(0, 0, -5)

	stale := baseHeatInput(now)
	stale.PushedAt = now.AddDate(0, 0, -400) // 超过 180 天沉寂
	stale.LastRelease = now.AddDate(0, 0, -400)
	stale.Commits7D = 0
	stale.Commits30D = 0
	stale.StarGrowth7D = 0
	stale.StarGrowth30D = 0
	stale.Releases = 0

	f := githubHeatScore(fresh)
	s := githubHeatScore(stale)

	if s.Score >= f.Score {
		t.Errorf("长期未更新应热度更低：stale=%d, fresh=%d", s.Score, f.Score)
	}
	if s.Score > 49 {
		t.Errorf("沉寂项目热度应在 low/dormant 区间，得到 %d (%s)", s.Score, s.Level)
	}
}

// 用例 3：热度必须落在 0-100，且分项权重自洽。
func TestGitHubHeatScoreBounds(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	inputs := []GitHubHeatInput{
		{Now: now},
		baseHeatInput(now),
		{
			Stars: 99999, StarGrowth7D: 5000, StarGrowth30D: 20000,
			Commits7D: 5000, Commits30D: 50000, OpenIssues: 900, OpenPRs: 500,
			Releases: 400, LastRelease: now, PushedAt: now, Now: now,
		},
	}
	for i, in := range inputs {
		got := githubHeatScore(in)
		if got.Score < 0 || got.Score > 100 {
			t.Errorf("case %d: Score = %d 超出 0-100", i, got.Score)
		}
		if got.Level == "" || got.Label == "" {
			t.Errorf("case %d: Level/Label 为空", i)
		}
		if len(got.Parts) == 0 {
			t.Errorf("case %d: Parts 不应为空", i)
		}
		// 分项权重之和应接近 1（允许浮点误差）
		var sum float64
		for _, p := range got.Parts {
			sum += p.Weight
			if p.Score < -0.001 || p.Score > 100.001 {
				t.Errorf("case %d: part %s 归一化分越界: %v", i, p.Key, p.Score)
			}
		}
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("case %d: 权重和 = %.4f, 期望 ≈1", i, sum)
		}
	}
}

// 用例 4：星标增长应正向影响热度。
func TestGitHubHeatStarGrowthContributes(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	flat := baseHeatInput(now)
	flat.StarGrowth7D, flat.StarGrowth30D = 0, 0

	growing := baseHeatInput(now)
	growing.StarGrowth7D, growing.StarGrowth30D = 40, 120

	if githubHeatScore(growing).Score <= githubHeatScore(flat).Score {
		t.Error("Star 增长应提升热度")
	}
}

// 用例 5：沉寂衰减阈值 —— 90 天内不应触发衰减，越过 180 天必须触发。
func TestGitHubHeatIdleDecayThresholds(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

	mk := func(idleDays int) int {
		in := baseHeatInput(now)
		in.Commits7D, in.Commits30D = 0, 0
		in.StarGrowth7D, in.StarGrowth30D = 0, 0
		in.Releases = 0
		in.LastRelease = now
		in.PushedAt = now.AddDate(0, 0, -idleDays)
		return githubHeatScore(in).Score
	}

	recent := mk(30)
	mid := mk(120)
	old := mk(400)

	if mid > recent {
		t.Errorf("120 天应不高于 30 天：mid=%d, recent=%d", mid, recent)
	}
	if old >= mid {
		t.Errorf("越过 180 天衰减后应低于 120 天：old=%d, mid=%d", old, mid)
	}
}

// ==================== Topics 归一化 ====================

func TestGitHubNormalizeTopics(t *testing.T) {
	got := githubNormalizeTopics([]string{"go", "  docker ", "", "go", "templating"}, 4)
	want := []string{"go", "docker", "templating"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if r := githubNormalizeTopics(nil, 5); len(r) != 0 {
		t.Errorf("nil 输入应返回空切片，得到 %v", r)
	}
}

// ==================== Contributors 归一化 ====================

func TestGitHubNormalizeContributors(t *testing.T) {
	all := []GitHubContributor{
		{Login: "a", Commits: 50},
		{Login: "b", Commits: 30},
		{Login: "c", Commits: 10},
		{Login: "d", Commits: 5},
		{Login: "e", Commits: 3},
		{Login: "f", Commits: 2},
	}
	// 返回 (Top N 列表, 剩余人数, 总提交数)
	top, rest, total := githubNormalizeContributors(all, 5)
	if len(top) != 5 {
		t.Fatalf("top 长度 = %d, want 5", len(top))
	}
	if total != 100 {
		t.Errorf("total = %d, want 100", total)
	}
	if rest != 1 {
		t.Errorf("rest 人数 = %d, want 1", rest)
	}
	// 必须按提交数降序
	for i := 1; i < len(top); i++ {
		if top[i].Commits > top[i-1].Commits {
			t.Errorf("未按提交数降序: %v", top)
		}
	}
	// 占比之和（Top N + 其余）不应超过 100%
	var sum float64
	for _, c := range top {
		sum += c.Percent
	}
	if sum > 100.001 {
		t.Errorf("Top N 占比之和 = %.2f，超过 100%%", sum)
	}

	// 超出 topN 时，rest 应为剩余人数
	top2, rest2, total2 := githubNormalizeContributors(all, 2)
	if len(top2) != 2 || total2 != 100 || rest2 != 4 {
		t.Errorf("topN=2 结果异常: len=%d rest=%d total=%d", len(top2), rest2, total2)
	}
}

// ==================== DTO 转换 ====================

func TestConvertGitHubWorkflowRun(t *testing.T) {
	created := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	started := created
	updated := created.Add(16 * time.Second)

	raw := &githubRawWorkflowRun{
		Name:         "Go CI/CD",
		Status:       "completed",
		Conclusion:   "failure",
		HeadBranch:   "main",
		HeadSHA:      "27b3877aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Event:        "push",
		RunNumber:    80,
		HTMLURL:      "https://github.com/Xiaoxusheng/go-auto-uploader/actions/runs/1",
		CreatedAt:    created,
		UpdatedAt:    updated,
		RunStartedAt: started,
	}

	got := convertGitHubWorkflowRun(raw)
	if got.Name != "Go CI/CD" {
		t.Errorf("Name = %q, want Go CI/CD", got.Name)
	}
	if got.Status != "completed" || got.Conclusion != "failure" {
		t.Errorf("Status/Conclusion = %q/%q, want completed/failure", got.Status, got.Conclusion)
	}
	if got.Branch != "main" {
		t.Errorf("Branch = %q, want main", got.Branch)
	}
	// SHA 必须短化，不能原样透传 40 位
	if got.ShortSHA != "27b3877" {
		t.Errorf("ShortSHA = %q, want 27b3877", got.ShortSHA)
	}
	if len(got.ShortSHA) != 7 {
		t.Errorf("ShortSHA 长度 = %d, want 7", len(got.ShortSHA))
	}
	if got.DurationMS != 16000 {
		t.Errorf("DurationMS = %d, want 16000", got.DurationMS)
	}
	// 时间必须序列化为 RFC3339 字符串
	if _, err := time.Parse(time.RFC3339, got.CreatedAt); err != nil {
		t.Errorf("CreatedAt 不是 RFC3339: %q", got.CreatedAt)
	}
}

// ==================== Release 解析（Asset 下载量必须真实透传） ====================

func TestGitHubReleaseAssetDownloadCount(t *testing.T) {
	published := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	raw := githubRawRelease{
		TagName:     "v2.5.0",
		Name:        "v2.5.0",
		CreatedAt:   published,
		PublishedAt: published,
	}
	raw.Assets = []struct {
		Name          string `json:"name"`
		Size          int64  `json:"size"`
		DownloadCount int    `json:"download_count"`
		ContentType   string `json:"content_type"`
	}{
		{Name: "app-linux-amd64", Size: 1024, DownloadCount: 150, ContentType: "application/octet-stream"},
		{Name: "app-windows.exe", Size: 2048, DownloadCount: 53, ContentType: "application/octet-stream"},
	}

	got := convertGitHubRelease(&raw)
	if got.TagName != "v2.5.0" {
		t.Errorf("TagName = %q, want v2.5.0", got.TagName)
	}
	if len(got.Assets) != 2 {
		t.Fatalf("Assets 数量 = %d, want 2", len(got.Assets))
	}
	if got.AssetCount != 2 {
		t.Errorf("AssetCount = %d, want 2", got.AssetCount)
	}
	// 下载量必须逐条真实透传，禁止伪造/聚合失真
	total := 0
	for _, a := range got.Assets {
		total += a.DownloadCount
		if a.Size <= 0 {
			t.Errorf("Asset %s 的 Size 异常: %d", a.Name, a.Size)
		}
	}
	if total != 203 {
		t.Errorf("下载量合计 = %d, want 203（必须是真实值）", total)
	}
	if got.Downloads != 203 {
		t.Errorf("Downloads 汇总 = %d, want 203", got.Downloads)
	}
}

func TestGitHubReleaseTruncatesLongBody(t *testing.T) {
	long := make([]byte, githubReleaseBodyChars+500)
	for i := range long {
		long[i] = 'x'
	}
	raw := githubRawRelease{TagName: "v1.0.0", Body: string(long)}
	got := convertGitHubRelease(&raw)
	if !got.Truncated {
		t.Error("超长 Release Notes 应标记 Truncated")
	}
	if len(got.Body) > githubReleaseBodyChars {
		t.Errorf("Body 长度 = %d，应截断到 %d", len(got.Body), githubReleaseBodyChars)
	}

	short := convertGitHubRelease(&githubRawRelease{TagName: "v1.0.1", Body: "简短说明"})
	if short.Truncated {
		t.Error("短文本不应标记 Truncated")
	}
	if short.Body != "简短说明" {
		t.Errorf("短文本不应被改写，得到 %q", short.Body)
	}
}

// ==================== 工具函数 ====================

func TestGitHubShortSHA(t *testing.T) {
	if got := githubShortSHA("27b3877aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); got != "27b3877" {
		t.Errorf("= %q, want 27b3877", got)
	}
	if got := githubShortSHA("abc"); got != "abc" {
		t.Errorf("短 SHA 应原样返回，得到 %q", got)
	}
}

func TestGitHubParseISOTime(t *testing.T) {
	if got := githubParseISOTime(""); !got.IsZero() {
		t.Errorf("空串应为零值，得到 %v", got)
	}
	if got := githubParseISOTime("not-a-time"); !got.IsZero() {
		t.Errorf("非法输入应为零值，得到 %v", got)
	}
	got := githubParseISOTime("2026-09-14T01:30:00Z")
	if got.IsZero() || got.Year() != 2026 || got.Month() != time.September || got.Day() != 14 {
		t.Errorf("解析失败: %v", got)
	}
}

// ==================== Actions 状态归并 ====================

func TestGitHubRunStatusKey(t *testing.T) {
	cases := []struct {
		name       string
		status     string
		conclusion string
		want       string
	}{
		{"进行中", "in_progress", "", "running"},
		{"排队中", "queued", "", "running"},
		{"成功", "completed", "success", "passed"},
		{"失败", "completed", "failure", "failed"},
		{"超时", "completed", "timed_out", "failed"},
		{"取消", "completed", "cancelled", "cancelled"},
		{"跳过", "completed", "skipped", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := githubRunStatusKey(GitHubWorkflowRun{Status: c.status, Conclusion: c.conclusion})
			if got != c.want {
				t.Errorf("githubRunStatusKey(%s/%s) = %q, want %q", c.status, c.conclusion, got, c.want)
			}
		})
	}
}

// ==================== Actions 摘要聚合 ====================

func TestGitHubSummarizeActions(t *testing.T) {
	runs := []GitHubWorkflowRun{
		{Status: "in_progress", Conclusion: ""},
		{Status: "completed", Conclusion: "failure"},
		{Status: "completed", Conclusion: "success"},
		{Status: "completed", Conclusion: "success"},
	}
	got := githubSummarizeActions(runs)
	if got == nil {
		t.Fatal("返回 nil")
	}
	if !got.Available {
		t.Error("Available 应为 true")
	}
	if got.Passed != 2 {
		t.Errorf("Passed = %d, want 2", got.Passed)
	}
	if got.Failed != 1 {
		t.Errorf("Failed = %d, want 1", got.Failed)
	}
	if got.Running != 1 {
		t.Errorf("Running = %d, want 1", got.Running)
	}
	if got.Status == "" || got.Label == "" {
		t.Errorf("Status/Label 不应为空: %+v", got)
	}
}

func TestGitHubSummarizeActionsEmpty(t *testing.T) {
	got := githubSummarizeActions(nil)
	if got == nil {
		t.Fatal("返回 nil")
	}
	if got.Available {
		t.Error("空输入 Available 应为 false")
	}
	if got.Status != "none" {
		t.Errorf("空输入 Status = %q, want none", got.Status)
	}
	if got.Label == "" {
		t.Error("空输入 Label 不应为空（应为 No GitHub Actions）")
	}
}

// ==================== Star 快照持久化 ====================

func TestGitHubStoreStarSnapshot(t *testing.T) {
	store := newTestGitHubStore(t)
	day1 := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)

	if err := store.UpsertStarSnapshots(map[string]int{"repo-a": 10, "repo-b": 5}, day1); err != nil {
		t.Fatalf("第一次写入失败: %v", err)
	}
	// 同一天重复写入应更新而非插入新行（UNIQUE(repo, snapshot_date)）
	if err := store.UpsertStarSnapshots(map[string]int{"repo-a": 12, "repo-b": 5}, day1); err != nil {
		t.Fatalf("同日重复写入失败: %v", err)
	}
	if err := store.UpsertStarSnapshots(map[string]int{"repo-a": 20, "repo-b": 8}, day2); err != nil {
		t.Fatalf("第二次写入失败: %v", err)
	}

	pts, err := store.StarHistory("repo-a")
	if err != nil {
		t.Fatalf("读取 Star 历史失败: %v", err)
	}
	if len(pts) != 2 {
		t.Fatalf("repo-a 应只有 2 个快照点（同日去重），得到 %d: %+v", len(pts), pts)
	}
	if pts[0].Stars != 12 {
		t.Errorf("第一点应为同日覆盖后的 12，得到 %d", pts[0].Stars)
	}
	if pts[1].Stars != 20 {
		t.Errorf("第二点应为 20，得到 %d", pts[1].Stars)
	}
	// 必须按日期升序
	if pts[0].Date >= pts[1].Date {
		t.Errorf("Star 历史未按日期升序: %+v", pts)
	}
}

func TestGitHubStoreStarHistorySince(t *testing.T) {
	store := newTestGitHubStore(t)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 120; i++ {
		d := now.AddDate(0, 0, -i)
		if err := store.UpsertStarSnapshots(map[string]int{"r": i}, d); err != nil {
			t.Fatalf("写入第 %d 天失败: %v", i, err)
		}
	}
	got, err := store.StarHistorySince("r", 30, now)
	if err != nil {
		t.Fatalf("窗口查询失败: %v", err)
	}
	if len(got) > 31 || len(got) < 29 {
		t.Errorf("30 天窗口应约 30 点，得到 %d", len(got))
	}
}

func TestGitHubStoreRecordedRepos(t *testing.T) {
	store := newTestGitHubStore(t)
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	if err := store.UpsertStarSnapshots(map[string]int{"x": 1, "y": 2}, now); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got, err := store.StarHistoryRecordedRepos()
	if err != nil {
		t.Fatalf("查询已记录仓库失败: %v", err)
	}
	if !got["x"] || !got["y"] {
		t.Errorf("应包含 x/y，得到 %+v", got)
	}
	if got["z"] {
		t.Error("不应包含未记录的 z")
	}
}

func TestGitHubStoreRepoGauge(t *testing.T) {
	store := newTestGitHubStore(t)
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	g := GitHubGaugePoint{
		Repo: "repo-a", Stars: 24, Forks: 3, Issues: 1, PullRequests: 0,
		Releases: 20, Commits30d: 53, Contributors: 1, HeatScore: 40,
	}
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{g}, now, false); err != nil {
		t.Fatalf("写入 gauge 失败: %v", err)
	}
	// 同日覆盖
	g.Stars, g.HeatScore = 30, 55
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{g}, now, false); err != nil {
		t.Fatalf("同日覆盖写入失败: %v", err)
	}
	latest, err := store.LatestRepoGauge("repo-a")
	if err != nil {
		t.Fatalf("读取最新 gauge 失败: %v", err)
	}
	if latest == nil {
		t.Fatal("应读到 gauge，得到 nil")
	}
	if latest.Stars != 30 || latest.HeatScore != 55 {
		t.Errorf("同日应覆盖为 30/55，得到 %d/%d", latest.Stars, latest.HeatScore)
	}
	if latest.Commits30d != 53 || latest.Releases != 20 {
		t.Errorf("其余字段应保留：%+v", latest)
	}

	miss, err := store.LatestRepoGauge("never-recorded")
	if err != nil {
		t.Fatalf("查询不存在仓库应不报错: %v", err)
	}
	if miss != nil {
		t.Errorf("不存在的仓库应返回 nil，得到 %+v", miss)
	}
}

func newTestGitHubStore(t *testing.T) *GitHubStore {
	t.Helper()
	s, err := NewGitHubStore(filepath.Join(t.TempDir(), "gh_test.db"))
	if err != nil {
		t.Fatalf("打开测试存储失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ==================== 仓库键 owner/repo（开源部署隔离） ====================

func TestGitHubRepoKey(t *testing.T) {
	cases := []struct{ owner, repo, want string }{
		{"Xiaoxusheng", "server-status", "xiaoxusheng/server-status"},
		{"XiaoXuSheng", "Server-Status", "xiaoxusheng/server-status"}, // 统一小写
		{"  alice ", " blog ", "alice/blog"},                          // 去空白
		{"", "orphan", "orphan"},                                      // 无 owner 时退化
		{"alice", "", "alice"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := githubRepoKey(c.owner, c.repo); got != c.want {
			t.Errorf("githubRepoKey(%q,%q) = %q, want %q", c.owner, c.repo, got, c.want)
		}
	}
}

// 核心用例（开源场景）：两个不同用户有同名仓库，数据必须互不可见。
func TestGitHubStoreSameNameDifferentOwnerIsolated(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)

	alice := githubRepoKey("alice", "server-status")
	bob := githubRepoKey("bob", "server-status")
	if alice == bob {
		t.Fatal("不同 owner 的同名仓库键必须不同")
	}

	// 两人同一天各记一次，星数故意不同
	if err := store.UpsertStarSnapshots(map[string]int{alice: 10, bob: 999}, day); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	a, err := store.StarHistory(alice)
	if err != nil {
		t.Fatalf("读取 alice 失败: %v", err)
	}
	b, err := store.StarHistory(bob)
	if err != nil {
		t.Fatalf("读取 bob 失败: %v", err)
	}
	if len(a) != 1 || a[0].Stars != 10 {
		t.Errorf("alice 历史应为 [10]，得到 %+v", a)
	}
	if len(b) != 1 || b[0].Stars != 999 {
		t.Errorf("bob 历史应为 [999]，得到 %+v", b)
	}

	// gauge 同样隔离
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{
		{Repo: alice, Stars: 10, HeatScore: 20},
		{Repo: bob, Stars: 999, HeatScore: 80},
	}, day, false); err != nil {
		t.Fatalf("写入 gauge 失败: %v", err)
	}
	ga, err := store.LatestRepoGauge(alice)
	if err != nil || ga == nil || ga.HeatScore != 20 {
		t.Errorf("alice gauge 应为 heat 20，得到 %+v (err=%v)", ga, err)
	}
	gb, err := store.LatestRepoGauge(bob)
	if err != nil || gb == nil || gb.HeatScore != 80 {
		t.Errorf("bob gauge 应为 heat 80，得到 %+v (err=%v)", gb, err)
	}
}

// 历史数据（仅仓库名）应能被迁移为 owner/repo，且可重复执行。
func TestGitHubStoreMigrateRepoKeys(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)

	// 旧格式：仅仓库名
	if err := store.UpsertStarSnapshots(map[string]int{"old-repo": 7}, day); err != nil {
		t.Fatalf("写入旧格式失败: %v", err)
	}
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{{Repo: "old-repo", Stars: 7}}, day, false); err != nil {
		t.Fatalf("写入旧格式 gauge 失败: %v", err)
	}

	store.migrateRepoKeys("Xiaoxusheng")
	store.migrateRepoKeys("Xiaoxusheng") // 幂等：重复执行不应出错或二次加前缀

	key := "xiaoxusheng/old-repo"
	pts, err := store.StarHistory(key)
	if err != nil {
		t.Fatalf("迁移后读取失败: %v", err)
	}
	if len(pts) != 1 || pts[0].Stars != 7 {
		t.Errorf("迁移后应能按 owner/repo 读到，得到 %+v", pts)
	}
	// 旧键不应再有数据
	if old, _ := store.StarHistory("old-repo"); len(old) != 0 {
		t.Errorf("旧键应已无数据，得到 %+v", old)
	}
	g, err := store.LatestRepoGauge(key)
	if err != nil || g == nil || g.Stars != 7 {
		t.Errorf("gauge 迁移失败: %+v (err=%v)", g, err)
	}
	// 键不能被重复加前缀
	if strings.Contains(g.Repo, "xiaoxusheng/xiaoxusheng") {
		t.Errorf("重复迁移导致前缀叠加: %q", g.Repo)
	}
}

// 迁移不能破坏已经是新格式的数据。
func TestGitHubStoreMigrateRepoKeysKeepsNewFormat(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)

	newKey := githubRepoKey("alice", "repo")
	if err := store.UpsertStarSnapshots(map[string]int{newKey: 42}, day); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	store.migrateRepoKeys("alice")

	pts, err := store.StarHistory(newKey)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(pts) != 1 || pts[0].Stars != 42 {
		t.Errorf("新格式数据应保持不变，得到 %+v", pts)
	}
}

// 回归用例：每日采集器只掌握 Star/Fork/Issue，绝不能把详情页算出的
// releases / commits_30d / contributors / heat_score 覆盖成 0。
func TestGitHubStoreStarOnlyUpsertPreservesDetailMetrics(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	key := githubRepoKey("alice", "server-status")

	// 详情页写入完整指标
	full := GitHubGaugePoint{
		Repo: key, Stars: 100, Forks: 5, Issues: 2, PullRequests: 1,
		Releases: 7, Commits30d: 84, Contributors: 3, HeatScore: 45,
	}
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{full}, day, false); err != nil {
		t.Fatalf("写入完整指标失败: %v", err)
	}

	// 采集器随后跑（starOnly）：Star 涨了，但只带三项
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{
		{Repo: key, Stars: 105, Forks: 6, Issues: 2},
	}, day, true); err != nil {
		t.Fatalf("采集器写入失败: %v", err)
	}

	got, err := store.LatestRepoGauge(key)
	if err != nil || got == nil {
		t.Fatalf("读取失败: %+v (err=%v)", got, err)
	}
	// Star/Fork/Issue 应被刷新
	if got.Stars != 105 || got.Forks != 6 {
		t.Errorf("Star/Fork 应更新为 105/6，得到 %d/%d", got.Stars, got.Forks)
	}
	// 其余列必须原样保留
	if got.Releases != 7 {
		t.Errorf("Releases 被冲掉: %d, want 7", got.Releases)
	}
	if got.Commits30d != 84 {
		t.Errorf("Commits30d 被冲掉: %d, want 84", got.Commits30d)
	}
	if got.Contributors != 3 {
		t.Errorf("Contributors 被冲掉: %d, want 3", got.Contributors)
	}
	if got.HeatScore != 45 {
		t.Errorf("HeatScore 被冲掉: %d, want 45", got.HeatScore)
	}
}

// 完整模式（详情页）仍应能覆盖所有列。
func TestGitHubStoreFullUpsertOverwritesAll(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	key := githubRepoKey("bob", "repo")

	if err := store.UpsertRepoGauges([]GitHubGaugePoint{{Repo: key, Stars: 1, HeatScore: 90}}, day, false); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{{Repo: key, Stars: 2, HeatScore: 10}}, day, false); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	got, err := store.LatestRepoGauge(key)
	if err != nil || got == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got.Stars != 2 || got.HeatScore != 10 {
		t.Errorf("完整模式应覆盖为 2/10，得到 %d/%d", got.Stars, got.HeatScore)
	}
}

// 真实时序：采集器先建行（只有 Star/Fork/Issue，其余为 0）→ 用户打开详情页补齐完整指标
// → 次日采集器再跑。要求：详情页必须能把 0 覆盖成真实值，且之后不再被冲掉。
func TestGitHubStoreCollectorThenDetailThenCollector(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	nextDay := day.AddDate(0, 0, 1)
	key := githubRepoKey("xiaoxusheng", "server-status")

	// 1) 采集器先跑：建行，只有三项
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{
		{Repo: key, Stars: 24, Forks: 3, Issues: 1},
	}, day, true); err != nil {
		t.Fatalf("采集器首次写入失败: %v", err)
	}
	got, err := store.LatestRepoGauge(key)
	if err != nil || got == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got.HeatScore != 0 || got.Releases != 0 {
		t.Fatalf("采集器首次写入后热度/Release 应为 0（尚无详情数据），得到 heat=%d rel=%d", got.HeatScore, got.Releases)
	}

	// 2) 用户打开详情页：完整模式必须把 0 覆盖成真实值
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{
		{Repo: key, Stars: 24, Forks: 3, Issues: 1, PullRequests: 2, Releases: 5, Commits30d: 61, Contributors: 4, HeatScore: 45},
	}, day, false); err != nil {
		t.Fatalf("详情页写入失败: %v", err)
	}
	got, err = store.LatestRepoGauge(key)
	if err != nil || got == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if got.HeatScore != 45 || got.Releases != 5 || got.Commits30d != 61 || got.Contributors != 4 {
		t.Errorf("详情页应写满指标，得到 heat=%d rel=%d c30d=%d contrib=%d",
			got.HeatScore, got.Releases, got.Commits30d, got.Contributors)
	}

	// 3) 次日采集器再跑：只更新 Star/Fork/Issue，其余保持
	if err := store.UpsertRepoGauges([]GitHubGaugePoint{
		{Repo: key, Stars: 25, Forks: 3, Issues: 1},
	}, nextDay, true); err != nil {
		t.Fatalf("次日采集器写入失败: %v", err)
	}
	next, err := store.LatestRepoGauge(key)
	if err != nil || next == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if next.Stars != 25 || next.HeatScore != 0 {
		t.Errorf("次日应是新的一行（stars=25, heat=0），得到 stars=%d heat=%d", next.Stars, next.HeatScore)
	}
	// 当天那行的热度不能被回溯污染
	if got.HeatScore != 45 {
		t.Errorf("当天热度被污染: %d, want 45", got.HeatScore)
	}
}

// owner 为空时必须跳过迁移，不能把数据写成 "/repo"。
func TestGitHubStoreMigrateRepoKeysEmptyOwner(t *testing.T) {
	store := newTestGitHubStore(t)
	day := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	if err := store.UpsertStarSnapshots(map[string]int{"solo": 3}, day); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	store.migrateRepoKeys("")
	store.migrateRepoKeys("   ")

	pts, err := store.StarHistory("solo")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(pts) != 1 || pts[0].Stars != 3 {
		t.Errorf("owner 为空时不应改写数据，得到 %+v", pts)
	}
}
