package main

// 隐藏私人空间（Private Notes）核心存储。
// 双层认证：普通登录 + 私人密码（bcrypt），private session 30 分钟无操作自动锁定。
// 私人文件保存在私有目录，图片/语音只能通过双层认证的 API 访问。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

// ==================== 配置 ====================

// PrivateNotesConfig 私人空间配置
type PrivateNotesConfig struct {
	Enabled          bool   `json:"enabled"`
	UnlockTimeout    string `json:"unlock_timeout"`
	MaxLoginAttempts int    `json:"max_login_attempts"`
	LockoutDuration  string `json:"lockout_duration"`
	StorageDir       string `json:"storage_dir"`
}

// CardsConfig 卡片配置
type CardsConfig struct {
	Enabled       bool `json:"enabled"`
	DefaultWidth  int  `json:"default_width"`
	DefaultHeight int  `json:"default_height"`
}

// PrivateNotesJSON 磁盘配置文件结构（禁止保存任何密码/密码 Hash）
type PrivateNotesJSON struct {
	PrivateNotes PrivateNotesConfig `json:"private_notes"`
	Cards        CardsConfig        `json:"cards"`
}

func defaultPrivateNotesJSON() PrivateNotesJSON {
	return PrivateNotesJSON{
		PrivateNotes: PrivateNotesConfig{
			Enabled:          true,
			UnlockTimeout:    "30m",
			MaxLoginAttempts: 5,
			LockoutDuration:  "1m",
			StorageDir:       "./data/notes",
		},
		Cards: CardsConfig{
			Enabled:       true,
			DefaultWidth:  1080,
			DefaultHeight: 1080,
		},
	}
}

// ==================== 数据模型 ====================

// PrivateNote 手记
type PrivateNote struct {
	ID           string            `json:"id"`
	UserID       string            `json:"-"`
	Title        string            `json:"title"`
	Content      string            `json:"content"`
	CreatedAt    string            `json:"created_at"`
	UpdatedAt    string            `json:"updated_at"`
	LocationName string            `json:"location_name"`
	Latitude     *float64          `json:"latitude"`
	Longitude    *float64          `json:"longitude"`
	Images       []PrivateImage    `json:"images"`
	Audio        []PrivateAudio    `json:"audio"`
	Tags         []string          `json:"tags"`
	Cards        []PrivateCardMeta `json:"cards,omitempty"`
}

// PrivateImage 手记图片
type PrivateImage struct {
	ID        string `json:"id"`
	NoteID    string `json:"note_id"`
	FilePath  string `json:"-"`
	URL       string `json:"url"`
	SortOrder int    `json:"sort_order"`
	CreatedAt string `json:"created_at"`
}

// PrivateAudio 手记语音
type PrivateAudio struct {
	ID        string  `json:"id"`
	NoteID    string  `json:"note_id"`
	FilePath  string  `json:"-"`
	URL       string  `json:"url"`
	Duration  float64 `json:"duration"`
	CreatedAt string  `json:"created_at"`
}

// PrivateCardMeta 卡片元信息
type PrivateCardMeta struct {
	ID        string `json:"id"`
	NoteID    string `json:"note_id"`
	Template  string `json:"template"`
	FilePath  string `json:"-"`
	URL       string `json:"url"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
}

// PrivateSession 私人空间会话
type PrivateSession struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	SessionHash  string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastAccessAt time.Time `json:"last_access_at"`
}

// PrivateShare 分享记录
type PrivateShare struct {
	ID             string     `json:"id"`
	NoteID         string     `json:"note_id"`
	CardID         string     `json:"card_id"`
	ShareTokenHash string     `json:"-"`
	PasswordHash   string     `json:"-"`
	ExpiresAt      *time.Time `json:"expires_at"`
	AllowDownload  bool       `json:"allow_download"`
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
}

// ==================== 存储 ====================

// PrivateStore 私人空间存储（SQLite + 文件系统）
type PrivateStore struct {
	mu         sync.RWMutex
	db         *sql.DB
	baseDir    string
	storageDir string
	config     PrivateNotesJSON
	failures   map[string]*privateFailCounter
}

type privateFailCounter struct {
	count       int
	lockedUntil time.Time
	last        time.Time
}

var privateStore *PrivateStore

var (
	privateErrLocked = fmt.Errorf("尝试次数过多，请稍后再试")
	privateErrAuth   = fmt.Errorf("密码错误")
)

// privateRoot 私人空间数据根目录（生产 /opt/server-status，开发可用 SERVER_STATUS_HOME 覆盖）
func privateRoot() string {
	if root := os.Getenv("SERVER_STATUS_HOME"); root != "" {
		return root
	}
	return "/opt/server-status"
}

// initPrivateNotes 初始化私人空间存储（main 启动时调用）
func initPrivateNotes() error {
	st, err := NewPrivateStore(privateRoot())
	if err != nil {
		log.Printf("⚠️ 私人空间初始化失败: %v", err)
		return err
	}
	privateStore = st
	log.Printf("🔒 私人空间已初始化 (db=%s)", st.dbPath())
	return nil
}

// NewPrivateStore 创建私人空间存储实例（可独立指定根目录，便于测试）
func NewPrivateStore(baseDir string) (*PrivateStore, error) {
	cfg := defaultPrivateNotesJSON()
	loadPrivateNotesJSON(baseDir, &cfg)

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	storageDir := cfg.PrivateNotes.StorageDir
	if !filepath.IsAbs(storageDir) {
		storageDir = filepath.Join(baseDir, storageDir)
	}
	storageDir = filepath.Clean(storageDir)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", filepath.Join(baseDir, "private_notes.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, err
	}

	st := &PrivateStore{
		db:         db,
		baseDir:    baseDir,
		storageDir: storageDir,
		config:     cfg,
		failures:   make(map[string]*privateFailCounter),
	}
	if err := st.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	st.applyEnvPassword()
	return st, nil
}

func loadPrivateNotesJSON(baseDir string, cfg *PrivateNotesJSON) {
	data, err := os.ReadFile(filepath.Join(baseDir, "private_notes.json"))
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("⚠️ private_notes.json 解析失败，使用默认配置: %v", err)
		return
	}
	if cfg.PrivateNotes.MaxLoginAttempts <= 0 {
		cfg.PrivateNotes.MaxLoginAttempts = 5
	}
}

func (s *PrivateStore) dbPath() string { return filepath.Join(s.baseDir, "private_notes.db") }
func (s *PrivateStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// migrate 建表（与需求文档一致，额外增加 user_id 归属字段）
func (s *PrivateStore) migrate() error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS private_settings (
			key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS notes (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
			content TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
			location_name TEXT NOT NULL DEFAULT '', latitude REAL, longitude REAL)`,
		`CREATE INDEX IF NOT EXISTS idx_notes_user_time ON notes(user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS note_images (
			id TEXT PRIMARY KEY, note_id TEXT NOT NULL, file_path TEXT NOT NULL,
			sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
			FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE)`,
		`CREATE INDEX IF NOT EXISTS idx_note_images_note ON note_images(note_id, sort_order)`,
		`CREATE TABLE IF NOT EXISTS note_audio (
			id TEXT PRIMARY KEY, note_id TEXT NOT NULL, file_path TEXT NOT NULL,
			duration REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
			FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE)`,
		`CREATE INDEX IF NOT EXISTS idx_note_audio_note ON note_audio(note_id)`,
		`CREATE TABLE IF NOT EXISTS note_tags (
			id INTEGER PRIMARY KEY AUTOINCREMENT, note_id TEXT NOT NULL, tag TEXT NOT NULL,
			FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_note_tags_unique ON note_tags(note_id, tag)`,
		`CREATE TABLE IF NOT EXISTS note_cards (
			id TEXT PRIMARY KEY, note_id TEXT, user_id TEXT NOT NULL, template TEXT NOT NULL,
			file_path TEXT NOT NULL, width INTEGER NOT NULL, height INTEGER NOT NULL,
			title TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
			FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE)`,
		`CREATE INDEX IF NOT EXISTS idx_note_cards_user ON note_cards(user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS note_shares (
			id TEXT PRIMARY KEY, note_id TEXT, card_id TEXT NOT NULL,
			share_token_hash TEXT NOT NULL UNIQUE, password_hash TEXT,
			expires_at TEXT, allow_download INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL, revoked_at TEXT,
			FOREIGN KEY(card_id) REFERENCES note_cards(id) ON DELETE CASCADE)`,
		`CREATE INDEX IF NOT EXISTS idx_note_shares_card ON note_shares(card_id)`,
		`CREATE TABLE IF NOT EXISTS private_note_sessions (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_access_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_private_sessions_user ON private_note_sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS private_note_audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL, created_at TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX IF NOT EXISTS idx_private_audit_time ON private_note_audit_logs(created_at DESC)`,
	}
	for _, q := range schema {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// applyEnvPassword 首次启动可通过环境变量 PRIVATE_NOTES_PASSWORD 初始化私人空间密码
func (s *PrivateStore) applyEnvPassword() {
	pw := os.Getenv("PRIVATE_NOTES_PASSWORD")
	if pw == "" {
		return
	}
	exists, err := s.settingExists("password_hash")
	if err != nil || exists {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("⚠️ 初始化私人空间密码失败: %v", err)
		return
	}
	if err := s.setSetting("password_hash", string(hash)); err != nil {
		log.Printf("⚠️ 保存私人空间密码失败: %v", err)
	}
}

// ==================== 设置项 ====================

func (s *PrivateStore) settingExists(key string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM private_settings WHERE key = ?`, key).Scan(&n)
	return n > 0, err
}

func (s *PrivateStore) getSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM private_settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *PrivateStore) setSetting(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO private_settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, nowUTC())
	return err
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ==================== 密码与解锁 ====================

// SetupPrivatePassword 设置私人空间密码（仅在未设置时允许）
func (s *PrivateStore) SetupPrivatePassword(password string) error {
	if len(password) < 4 || len(password) > 128 {
		return fmt.Errorf("密码长度需要在 4-128 位之间")
	}
	exists, err := s.settingExists("password_hash")
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("私人空间密码已设置")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.setSetting("password_hash", string(hash))
}

func (s *PrivateStore) passwordConfigured() bool {
	v, err := s.getSetting("password_hash")
	return err == nil && v != ""
}

// Unlock 解锁私人空间：校验密码并创建 private session
func (s *PrivateStore) Unlock(username, password, clientIP string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.PrivateNotes.Enabled || !s.passwordConfigured() {
		// 不区分“未配置/未启用/密码错误”，避免暴露私人空间存在性
		return "", privateErrAuth
	}

	key := username + "|" + clientIP
	fc := s.failures[key]
	if fc != nil && time.Now().Before(fc.lockedUntil) {
		return "", privateErrLocked
	}

	hash, _ := s.getSetting("password_hash")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		if fc == nil {
			fc = &privateFailCounter{}
			s.failures[key] = fc
		}
		fc.count++
		fc.last = time.Now()
		if fc.count >= s.config.PrivateNotes.MaxLoginAttempts {
			dur, _ := time.ParseDuration(s.config.PrivateNotes.LockoutDuration)
			if dur <= 0 {
				dur = time.Minute
			}
			fc.lockedUntil = time.Now().Add(dur)
			fc.count = 0
		}
		return "", privateErrAuth
	}

	delete(s.failures, key)
	return s.createSession(username)
}

func (s *PrivateStore) createSession(username string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	tokenHash := sha256Hex(token)
	timeout := s.sessionTimeout()
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO private_note_sessions (id, user_id, session_hash, created_at, expires_at, last_access_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		randomID("ps"), username, tokenHash, now.Format(time.RFC3339),
		now.Add(timeout).Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *PrivateStore) sessionTimeout() time.Duration {
	timeout, err := time.ParseDuration(s.config.PrivateNotes.UnlockTimeout)
	if err != nil || timeout <= 0 {
		return 30 * time.Minute
	}
	return timeout
}

// ValidateSession 校验 private session：存在、未过期、属于该用户；并刷新最后访问时间
func (s *PrivateStore) ValidateSession(username, token string) (*PrivateSession, bool) {
	if token == "" {
		return nil, false
	}
	var ps PrivateSession
	var created, expires, last string
	err := s.db.QueryRow(`
		SELECT id, user_id, session_hash, created_at, expires_at, last_access_at
		FROM private_note_sessions WHERE session_hash = ? AND user_id = ?`,
		sha256Hex(token), username).
		Scan(&ps.ID, &ps.UserID, &ps.SessionHash, &created, &expires, &last)
	if err != nil {
		return nil, false
	}
	ps.CreatedAt, _ = time.Parse(time.RFC3339, created)
	ps.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
	ps.LastAccessAt, _ = time.Parse(time.RFC3339, last)

	timeout := s.sessionTimeout()
	now := time.Now().UTC()
	if now.After(ps.LastAccessAt.Add(timeout)) || now.After(ps.ExpiresAt) {
		s.deleteSessionByHash(ps.SessionHash)
		return nil, false
	}
	if now.Sub(ps.LastAccessAt) > 30*time.Second {
		s.db.Exec(`UPDATE private_note_sessions SET last_access_at = ? WHERE id = ?`, now.Format(time.RFC3339), ps.ID)
	}
	return &ps, true
}

func (s *PrivateStore) deleteSessionByHash(hash string) {
	s.db.Exec(`DELETE FROM private_note_sessions WHERE session_hash = ?`, hash)
}

// Lock 锁定：立即删除当前用户的 private session
func (s *PrivateStore) Lock(username, token string) {
	if token == "" {
		s.db.Exec(`DELETE FROM private_note_sessions WHERE user_id = ?`, username)
		return
	}
	s.deleteSessionByHash(sha256Hex(token))
}

// cleanupExpiredSessions 清理过期 private session 与失效失败计数
func (s *PrivateStore) cleanupExpiredSessions() {
	s.db.Exec(`DELETE FROM private_note_sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
	s.mu.Lock()
	for k, fc := range s.failures {
		if time.Since(fc.last) > 10*time.Minute {
			delete(s.failures, k)
		}
	}
	s.mu.Unlock()
}

// StartMaintenance 后台维护：自动锁定过期 session
func (s *PrivateStore) StartMaintenance() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			if privateStore != nil {
				privateStore.cleanupExpiredSessions()
			}
		}
	}()
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randomID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return prefix + "-" + hex.EncodeToString(b)
}

// ==================== 审计 ====================

// auditPrivate 私人空间审计：只记录动作与元数据，严禁记录正文/图片/密码/密码 Hash
func (s *PrivateStore) auditPrivate(r *http.Request, username, action string) {
	ip := ""
	if r != nil {
		ip = getClientIP(r)
	}
	s.db.Exec(`INSERT INTO private_note_audit_logs (user_id, action, created_at, ip) VALUES (?, ?, ?, ?)`,
		username, action, nowUTC(), ip)
	log.Printf("PRIVATE-AUDIT user=%s action=%s ip=%s", username, action, ip)
}

// ==================== 路径与文件工具 ====================

func (s *PrivateStore) storageAbs() string {
	abs, _ := filepath.Abs(s.storageDir)
	return abs
}

// safeFilePath 规范化路径并防止路径穿越
func (s *PrivateStore) safeFilePath(rel string) (string, error) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" {
		return "", fmt.Errorf("空路径")
	}
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("非法路径")
	}
	base := s.storageAbs()
	abs, err := filepath.Abs(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("非法路径")
	}
	return abs, nil
}

func (s *PrivateStore) newNoteFilePath(ext string) (string, string, error) {
	now := time.Now()
	rel := fmt.Sprintf("%04d/%02d/%02d/%s%s", now.Year(), int(now.Month()), now.Day(), randomID("f"), ext)
	abs, err := s.safeFilePath(rel)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		return "", "", err
	}
	return rel, abs, nil
}

// decodeBase64Image 校验并解码前端卡片渲染器提交的 PNG
func decodeBase64Image(data string) ([]byte, error) {
	data = strings.TrimSpace(data)
	if idx := strings.Index(data, ","); idx >= 0 && strings.HasPrefix(data, "data:") {
		data = data[idx+1:]
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(data)
	}
	if err != nil {
		return nil, err
	}
	pngSig := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if len(raw) < len(pngSig) || string(raw[:len(pngSig)]) != string(pngSig) {
		return nil, fmt.Errorf("仅支持 PNG 图片")
	}
	return raw, nil
}

// hmacSign 分享密码校验 Cookie 签名（仅服务端持有密钥，绝不暴露给浏览器）
func hmacSign(payload string) string {
	m := hmac.New(sha256.New, []byte(serverSigningKey))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}
