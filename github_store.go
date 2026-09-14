package main

// ==================== GitHub 数据持久化（Star 历史） ====================
// 沿用项目既有 SQLite 方案（modernc.org/sqlite，纯 Go 无 CGO，与 ops_store 同模式）。
// Star 趋势必须持久化：服务器重启后历史不丢失。
// 表 github_star_history：repo + snapshot_date 唯一，一天最多一条快照。

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// GitHubStarPoint 单个 Star 快照点。
type GitHubStarPoint struct {
	Date  string `json:"date"` // YYYY-MM-DD
	Stars int    `json:"stars"`
}

// GitHubGaugePoint 仓库综合指标快照（用于在无额外请求的前提下沉淀 Issue/PR/Release 等计数）。
// 说明：GitHub 的仓库列表接口 open_issues_count 含 PR，无法拆分；这里把「详情响应中
// 拿到的真实计数」按天沉淀，作为统计的历史来源之一（不做趋势图，只做最新值兜底）。
type GitHubGaugePoint struct {
	Repo         string `json:"repo"`
	Date         string `json:"date"`
	Stars        int    `json:"stars"`
	Forks        int    `json:"forks"`
	Issues       int    `json:"issues"`
	PullRequests int    `json:"pull_requests"`
	Releases     int    `json:"releases"`
	Commits30d   int    `json:"commits_30d"`
	Contributors int    `json:"contributors"`
	HeatScore    int    `json:"heat_score"`
}

// GitHubStore GitHub 星标历史存储。
type GitHubStore struct {
	db *sql.DB
}

var (
	githubStoreOnce sync.Once
	githubStore     *GitHubStore
)

// githubGetStore 惰性打开存储（进程内单例）；打开失败时返回 nil，调用方降级为无历史数据。
func githubGetStore() *GitHubStore {
	githubStoreOnce.Do(func() {
		store, err := NewGitHubStore(filepath.Join(privateRoot(), "github_data.db"))
		if err != nil {
			log.Printf("⚠️ GitHub 数据存储不可用，Star 趋势将没有历史数据: %v", err)
			return
		}
		githubStore = store
	})
	return githubStore
}

// NewGitHubStore 打开（必要时创建）GitHub 数据库并建表。
func NewGitHubStore(path string) (*GitHubStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &GitHubStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *GitHubStore) Close() error {
	if s != nil && s.db != nil {
		return s.db.Close()
	}
	return nil
}

// githubRepoKey 生成仓库的唯一键：owner/repo（全小写）。
//
// 历史版本只用仓库名做键，这对开源部署是硬伤：换一个 username 后，
// 新旧用户只要存在同名仓库（如都有 server-status），Star 曲线和热度快照就会串在一起。
// 统一用 owner/repo 后，换人即自然隔离，同实例也可安全展示多个用户的数据。
func githubRepoKey(owner, repo string) string {
	owner = strings.ToLower(strings.TrimSpace(owner))
	repo = strings.ToLower(strings.TrimSpace(repo))
	if owner == "" {
		return repo
	}
	if repo == "" {
		return owner
	}
	return owner + "/" + repo
}

// migrateRepoKeys 把历史上「仅仓库名」的行补全为 owner/repo（一次性、幂等）。
// owner 取当前配置用户名；取不到时跳过，等下次启动配置就绪后再迁。
// 同一 (repo, date) 若已存在新格式行，用 OR IGNORE 保留新格式、丢弃旧格式行。
func (s *GitHubStore) migrateRepoKeys(owner string) {
	owner = strings.ToLower(strings.TrimSpace(owner))
	if owner == "" {
		return
	}
	for _, tbl := range []string{"github_star_history", "github_repo_gauge"} {
		if _, err := s.db.Exec(`UPDATE OR IGNORE `+tbl+` SET repo = ? || '/' || repo WHERE repo NOT LIKE '%/%'`, owner); err != nil {
			log.Printf("⚠️ GitHub 历史数据升级为 owner/repo 失败(%s): %v", tbl, err)
			return
		}
	}
}

// migrate 建表（幂等）。
func (s *GitHubStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS github_star_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	repo TEXT NOT NULL,
	snapshot_date TEXT NOT NULL,
	stars INTEGER NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(repo, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_github_star_history_repo_date ON github_star_history(repo, snapshot_date);
CREATE TABLE IF NOT EXISTS github_repo_gauge (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	repo TEXT NOT NULL,
	snapshot_date TEXT NOT NULL,
	stars INTEGER NOT NULL DEFAULT 0,
	forks INTEGER NOT NULL DEFAULT 0,
	issues INTEGER NOT NULL DEFAULT 0,
	pull_requests INTEGER NOT NULL DEFAULT 0,
	releases INTEGER NOT NULL DEFAULT 0,
	commits_30d INTEGER NOT NULL DEFAULT 0,
	contributors INTEGER NOT NULL DEFAULT 0,
	heat_score INTEGER NOT NULL DEFAULT 0,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(repo, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_github_repo_gauge_repo_date ON github_repo_gauge(repo, snapshot_date);`)
	if err != nil {
		return err
	}
	// 建表后顺带把旧格式（仅仓库名）升级为 owner/repo，避免换用户后数据串台
	s.migrateRepoKeys(githubConfig().Username)
	return nil
}

// UpsertStarSnapshots 批量记录当天快照（同 key 幂等：一天重复保存只更新数值）。
func (s *GitHubStore) UpsertStarSnapshots(stars map[string]int, now time.Time) error {
	if s == nil || s.db == nil || len(stars) == 0 {
		return nil
	}
	date := now.Format("2006-01-02")
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO github_star_history (repo, snapshot_date, stars, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(repo, snapshot_date) DO UPDATE SET stars = excluded.stars`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for repo, count := range stars {
		if repo == "" || count < 0 {
			continue
		}
		if _, err := stmt.Exec(strings.ToLower(repo), date, count, now.UTC()); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// StarHistory 返回某仓库全部快照（按日期升序）。
func (s *GitHubStore) StarHistory(repo string) ([]GitHubStarPoint, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT snapshot_date, stars FROM github_star_history WHERE repo = ? ORDER BY snapshot_date ASC`,
		strings.ToLower(repo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := make([]GitHubStarPoint, 0, 64)
	for rows.Next() {
		var p GitHubStarPoint
		if err := rows.Scan(&p.Date, &p.Stars); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// StarHistorySince 返回指定日期（含）之后的快照（按日期升序）。
// days<=0 表示不限；为保证曲线起点连续，会额外带上窗口前最近的一条基线快照。
func (s *GitHubStore) StarHistorySince(repo string, days int, now time.Time) ([]GitHubStarPoint, error) {
	all, err := s.StarHistory(repo)
	if err != nil || len(all) == 0 || days <= 0 {
		return all, err
	}
	cutoff := now.UTC().AddDate(0, 0, -days).Format("2006-01-02")
	baseline := -1
	for i, p := range all {
		if p.Date <= cutoff {
			baseline = i
		}
	}
	out := make([]GitHubStarPoint, 0, len(all))
	if baseline >= 0 {
		out = append(out, all[baseline])
	}
	for _, p := range all {
		if p.Date > cutoff {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = append(out, all[len(all)-1])
	}
	return out, nil
}

// StarHistoryRecordedRepos 返回已有快照记录的仓库名集合（用于判断采集是否在工作）。
func (s *GitHubStore) StarHistoryRecordedRepos() (map[string]bool, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT DISTINCT repo FROM github_star_history`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var repo string
		if err := rows.Scan(&repo); err == nil {
			out[repo] = true
		}
	}
	return out, rows.Err()
}

// UpsertRepoGauges 批量记录当天综合指标快照（repo + snapshot_date 唯一，重复保存只更新数值）。
//
// starOnly=true 表示调用方只掌握 Star/Fork/Issue（如每日采集器，它复用仓库列表缓存，
// 拿不到 Release/Commit/贡献者/热度）。此时只更新这三列，绝不覆盖其余列——
// 否则采集器每次启动都会把详情页辛苦算出的 releases/commits_30d/heat_score 冲成 0。
func (s *GitHubStore) UpsertRepoGauges(gauges []GitHubGaugePoint, now time.Time, starOnly bool) error {
	if s == nil || s.db == nil || len(gauges) == 0 {
		return nil
	}
	date := now.Format("2006-01-02")
	upsert := `ON CONFLICT(repo, snapshot_date) DO UPDATE SET
	stars = excluded.stars, forks = excluded.forks, issues = excluded.issues,
	pull_requests = excluded.pull_requests, releases = excluded.releases,
	commits_30d = excluded.commits_30d, contributors = excluded.contributors,
	heat_score = excluded.heat_score`
	if starOnly {
		upsert = `ON CONFLICT(repo, snapshot_date) DO UPDATE SET
	stars = excluded.stars, forks = excluded.forks, issues = excluded.issues`
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO github_repo_gauge
		(repo, snapshot_date, stars, forks, issues, pull_requests, releases, commits_30d, contributors, heat_score, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
` + upsert)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, g := range gauges {
		if strings.TrimSpace(g.Repo) == "" {
			continue
		}
		if _, err := stmt.Exec(strings.ToLower(g.Repo), date, g.Stars, g.Forks, g.Issues,
			g.PullRequests, g.Releases, g.Commits30d, g.Contributors, g.HeatScore, now.UTC()); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// LatestRepoGauge 返回某仓库最近一条综合指标快照（无记录时返回 nil, nil）。
func (s *GitHubStore) LatestRepoGauge(repo string) (*GitHubGaugePoint, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	row := s.db.QueryRow(`SELECT repo, snapshot_date, stars, forks, issues, pull_requests, releases,
		commits_30d, contributors, heat_score FROM github_repo_gauge
		WHERE repo = ? ORDER BY snapshot_date DESC LIMIT 1`, strings.ToLower(repo))
	var g GitHubGaugePoint
	if err := row.Scan(&g.Repo, &g.Date, &g.Stars, &g.Forks, &g.Issues, &g.PullRequests,
		&g.Releases, &g.Commits30d, &g.Contributors, &g.HeatScore); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

// githubCollectorLoop Star 快照采集器：启动时补当天快照，之后每天定时采集一次。
// 复用 repos 缓存（一次 GitHub 请求即可拿到全部仓库当前 star 数）。
func githubCollectorLoop() {
	interval := githubConfig().StarSnapshotInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	// 启动时立即补当天快照（幂等，已存在则只更新数值）
	githubSnapshotOnce()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	lastRun := time.Now()
	for range ticker.C {
		now := time.Now()
		if now.Sub(lastRun) < interval {
			continue
		}
		// 定时点对齐到每天 00:10（±1 分钟粒度）
		if now.Hour() == 0 && now.Minute() >= 10 && now.Minute() < 11 {
			githubSnapshotOnce()
			lastRun = now
		} else if now.Sub(lastRun) >= interval && now.Hour() == 0 {
			githubSnapshotOnce()
			lastRun = now
		}
	}
}

// githubSnapshotOnce 采集一次全部仓库的 Star 快照（复用 repos 缓存，失败静默降级）。
func githubSnapshotOnce() {
	store := githubGetStore()
	if store == nil {
		return
	}
	cfg := githubConfig()
	if !cfg.Enabled || cfg.Username == "" {
		return
	}
	ctx, cancel := githubCollectorContext()
	defer cancel()
	data, _, _, err := githubGetOrFetch(ctx, "repos:"+strings.ToLower(cfg.Username), githubReposTTL, githubFetchRepos)
	if err != nil {
		return // GitHub 不可达时跳过本轮，下轮再试
	}
	repos, ok := data.([]GitHubRepository)
	if !ok {
		return
	}
	stars := make(map[string]int, len(repos))
	gauges := make([]GitHubGaugePoint, 0, len(repos))
	for _, r := range repos {
		key := githubRepoKey(cfg.Username, r.Name)
		stars[key] = r.Stars
		gauges = append(gauges, GitHubGaugePoint{
			Repo: key, Stars: r.Stars, Forks: r.Forks, Issues: r.Issues,
		})
	}
	if err := store.UpsertStarSnapshots(stars, time.Now()); err != nil {
		log.Printf("⚠️ GitHub Star 快照保存失败: %v", err)
	}
	if err := store.UpsertRepoGauges(gauges, time.Now(), true); err != nil {
		log.Printf("⚠️ GitHub 项目指标快照保存失败: %v", err)
	}
}
