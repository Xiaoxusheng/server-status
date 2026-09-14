package main

// ==================== GitHub 数据持久化（Star 历史） ====================
// 沿用项目既有 SQLite 方案（modernc.org/sqlite，纯 Go 无 CGO，与 ops_store 同模式）。
// Star 趋势必须持久化：服务器重启后历史不丢失。
// 表 github_star_history：repo + snapshot_date 唯一，一天最多一条快照。

import (
	"database/sql"
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
CREATE INDEX IF NOT EXISTS idx_github_star_history_repo_date ON github_star_history(repo, snapshot_date);`)
	return err
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
	for _, r := range repos {
		stars[r.Name] = r.Stars
	}
	if err := store.UpsertStarSnapshots(stars, time.Now()); err != nil {
		log.Printf("⚠️ GitHub Star 快照保存失败: %v", err)
	}
}
