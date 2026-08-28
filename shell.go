package main

// ==================== Web Shell / Web Terminal ====================
// 本文件实现一个真正的 Linux PTY 交互终端：
//   - 新增 /ws/shell 基于 gorilla/websocket 的双向实时通信
//   - 每次启动 Shell 都必须通过独立的二次认证（Shell 密码，bcrypt）
//   - 认证成功后颁发一次性（60 秒）Shell Token，Token 只保存 Hash
//   - RBAC 复用 system:exec 权限
//   - Shell 并发限制、空闲超时、最大生命周期、输出背压
//   - 会话/Token/PTY/子进程/goroutine/FD 完整清理
//   - 审计记录会话生命周期，绝不记录终端输入与输出
//
// 依赖 github.com/creack/pty（在 Linux 上提供真实 PTY；
// Windows 上该库仅返回 ErrUnsupported，不影响 Linux 部署）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// ==================== 配置（允许通过环境变量调整） ====================

var (
	// shellMaxPerUser 每用户最大并发 Shell（默认 3）
	shellMaxPerUser int
	// shellMaxGlobal 全局最大并发 Shell（默认 10）
	shellMaxGlobal int
	// shellIdleTimeout 空闲超时：一段时间无输入/输出则自动关闭（默认 30 分钟）
	shellIdleTimeout time.Duration
	// shellMaxLifetime 最大生命周期：即使用户一直有数据也会被关闭（默认 12 小时）
	shellMaxLifetime time.Duration
	// shellTokenTTL 一次性认证 Token 的有效期（默认 60 秒）
	shellTokenTTL time.Duration
)

// Shell 二次认证防爆破参数
const (
	shellMaxAuthFailures = 5 // 同一 key 连续失败阈值
	shellAuthWindow      = time.Minute
	shellAuthLockTime    = time.Minute
	shellMaxMsgSize      = 64 * 1024        // 单条输入消息最大字节数（超出立即关闭）
	shellPTYChunk        = 32 * 1024        // PTY 读取缓冲区
	shellOutputQueue     = 256              // PTY→WS 输出队列容量（自然背压）
	shellMaxResizeRows   = 500              // resize 行数上限
	shellMaxResizeCols   = 1000             // resize 列数上限
	shellResolveTimeout  = 15 * time.Second // 等待首帧 auth 消息的超时
)

// shellPasswordFilePath 保存 Shell 二次认证密码 bcrypt Hash 的路径（可用环境变量覆盖，便于测试与部署）
func shellPasswordFilePath() string {
	if v := getEnvOr("SHELL_PASSWORD_HASH_FILE", ""); v != "" {
		return v
	}
	return "/opt/server-status/shell_pw.dat"
}

// Shell close 原因（用于审计与状态展示）
const (
	closeReasonEOF         = "eof"
	closeReasonWSClosed    = "ws-closed"
	closeReasonClientClose = "client-close"
	closeReasonIdle        = "idle-timeout"
	closeReasonLifetime    = "max-lifetime"
	closeReasonKilled      = "admin-killed"
	closeReasonLogout      = "logout"
	closeReasonMsgTooLarge = "message-too-large"
)

func init() {
	shellMaxPerUser = getEnvInt("MAX_SHELLS_PER_USER", 3)
	shellMaxGlobal = getEnvInt("MAX_SHELLS_GLOBAL", 10)
	shellIdleTimeout = getEnvDuration("SHELL_IDLE_TIMEOUT", 30*time.Minute)
	shellMaxLifetime = getEnvDuration("SHELL_MAX_LIFETIME", 12*time.Hour)
	shellTokenTTL = getEnvDuration("SHELL_TOKEN_TTL", 60*time.Second)
}

// getEnvInt 读取整型环境变量，非法或为空时回退默认值
func getEnvInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// getEnvDuration 读取时长环境变量，非法或为空时回退默认值
func getEnvDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// ==================== 一次性 Shell Auth Token ====================

// ShellAuthSession 描述一个等待被 WebSocket 消费的一次性认证会话
type ShellAuthSession struct {
	ID        string    `json:"id"`         // 展示用认证会话 ID（撤销管理用）
	TokenHash string    `json:"-"`          // 服务端只保存 sha256(token)
	Username  string    `json:"username"`   // 绑定的用户
	RemoteIP  string    `json:"remote_ip"`  // 发起认证的 IP
	CreatedAt time.Time `json:"created_at"` // 创建时间
	ExpiresAt time.Time `json:"expires_at"` // 过期时间
	Used      bool      `json:"-"`          // 是否已消费（一次性）
	Revoked   bool      `json:"-"`          // 是否已撤销
}

// shellAuthStore 认证 Token 注册表（内存态）
type shellAuthStore struct {
	sync.RWMutex
	sessions map[string]*ShellAuthSession // key = sha256(token)
}

// put 登记一个新的一次性认证 Token（只存 Hash）
func (a *shellAuthStore) put(s *ShellAuthSession) {
	a.Lock()
	defer a.Unlock()
	a.sessions[s.TokenHash] = s
}

// consume 一次性消费认证 Token：校验未过期、未使用、未撤销后标记 Used。
// 无论成功失败均删除该 Hash 条目，确保不可重放。
func (a *shellAuthStore) consume(tokenHash string) (*ShellAuthSession, bool) {
	a.Lock()
	defer a.Unlock()
	s, ok := a.sessions[tokenHash]
	if !ok {
		return nil, false
	}
	delete(a.sessions, tokenHash)
	if s.Revoked || s.Used || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	s.Used = true
	return s, true
}

// revokeByUser 撤销某用户全部待消费的认证 Token
func (a *shellAuthStore) revokeByUser(username string) int {
	a.Lock()
	defer a.Unlock()
	n := 0
	for k, s := range a.sessions {
		if s.Username == username {
			s.Revoked = true
			delete(a.sessions, k)
			n++
		}
	}
	return n
}

// revokeAll 撤销全部待消费的认证 Token（管理员）
func (a *shellAuthStore) revokeAll() int {
	a.Lock()
	defer a.Unlock()
	n := len(a.sessions)
	for k, s := range a.sessions {
		s.Revoked = true
		delete(a.sessions, k)
	}
	return n
}

// revokeByID 按展示 ID 撤销单个（未消费）认证 Token；非管理员只能撤销自己的
func (a *shellAuthStore) revokeByID(id, username string, admin bool) bool {
	a.Lock()
	defer a.Unlock()
	for k, s := range a.sessions {
		if s.ID == id {
			if !admin && s.Username != username {
				return false
			}
			s.Revoked = true
			delete(a.sessions, k)
			return true
		}
	}
	return false
}

// getByID 查找认证会话（用于权限判断）
func (a *shellAuthStore) getByID(id string) (*ShellAuthSession, bool) {
	a.RLock()
	defer a.RUnlock()
	for _, s := range a.sessions {
		if s.ID == id {
			return s, true
		}
	}
	return nil, false
}

// shellTokenHash 计算 token 的 sha256 十六进制摘要（服务端仅保存此摘要）
func shellTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ==================== 运行中的 Shell 会话 ====================

// shellSession 描述一个正在运行的 PTY Shell 会话
type shellSession struct {
	hub        *shellHub
	ID         string // shell-<rand>
	Username   string
	RemoteIP   string
	pid        int
	startedAt  time.Time
	lastActive atomic.Int64 // unix nano
	mu         sync.Mutex
	conn       *websocket.Conn
	ptmx       *os.File
	cmd        *exec.Cmd
	outCh      chan []byte
	writeMu    sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
	reason     string
}

// touch 刷新最近活跃时间（空闲超时判定依据）
func (s *shellSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// lastActiveTime 返回最近活跃时间
func (s *shellSession) lastActiveTime() time.Time {
	return time.Unix(0, s.lastActive.Load())
}

// setReason 记录关闭原因（首个原因生效）
func (s *shellSession) setReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == "" {
		s.reason = reason
	}
}

// getReason 返回关闭原因
func (s *shellSession) getReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// start 启动读写与监控协程，并登记会话
func (s *shellSession) start() {
	s.hub.add(s)
	s.touch()
	// 认证阶段设置的 read deadline（shellResolveTimeout）必须在此清除，
	// 否则认证后 ~15 秒 ReadMessage 必因 deadline 超时关闭连接，
	// 导致每次都"用一会儿就要重新二次认证"。
	// 空闲超时由其由 watch goroutine 基于 lastActive 独立判定，不依赖读超时。
	if s.conn != nil {
		_ = s.conn.SetReadDeadline(time.Time{})
	}
	go s.copyPtyToWS()
	go s.writeWS()
	go s.readWS()
	go s.watch()
	go s.pingLoop()
}

// pingLoop 服务端主动发送 WebSocket 协议级 Ping 帧（浏览器原生自动回 Pong，不受 JS 定时器冻结影响）。
// 作用：当标签页被切换后台、前端 setInterval 心跳被浏览器节流/挂起时，
// 仍能维持 TCP / NAT / 反代(如 Nginx)上的连接活跃，避免空闲超时被断开而触发重新认证。
func (s *shellSession) pingLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.writeMu.Lock()
			_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
			s.writeMu.Unlock()
		}
	}
}

// copyPtyToWS 读取 PTY 输出 → 写入输出队列（队列满时阻塞，形成自然背压，避免输出洪水）
func (s *shellSession) copyPtyToWS() {
	buf := make([]byte, shellPTYChunk)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.touch()
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case s.outCh <- data:
			case <-s.done:
				s.close(closeReasonWSClosed)
				return
			}
		}
		if err != nil {
			s.close(closeReasonEOF)
			return
		}
	}
}

// writeWS 将输出队列逐块写入 WebSocket Binary Frame
func (s *shellSession) writeWS() {
	for {
		select {
		case data := <-s.outCh:
			s.writeMu.Lock()
			_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = s.conn.WriteMessage(websocket.BinaryMessage, data)
			s.writeMu.Unlock()
		case <-s.done:
			return
		}
	}
}

// readWS 读取浏览器输入并透传到 PTY stdin，处理 resize/ping/close
func (s *shellSession) readWS() {
	for {
		_, msg, err := s.conn.ReadMessage()
		if err != nil {
			s.close(closeReasonWSClosed)
			return
		}
		if len(msg) > shellMaxMsgSize {
			s.close(closeReasonMsgTooLarge)
			return
		}
		s.touch()
		var in struct {
			Type string `json:"type"`
			Data string `json:"data"`
			Rows int    `json:"rows"`
			Cols int    `json:"cols"`
		}
		if json.Unmarshal(msg, &in) != nil {
			continue
		}
		switch in.Type {
		case "input":
			if in.Data != "" {
				if _, werr := s.ptmx.WriteString(in.Data); werr != nil {
					s.close(closeReasonWSClosed)
					return
				}
			}
		case "resize":
			if in.Rows > 0 && in.Rows <= shellMaxResizeRows && in.Cols > 0 && in.Cols <= shellMaxResizeCols {
				_ = pty.Setsize(s.ptmx, &pty.Winsize{Rows: uint16(in.Rows), Cols: uint16(in.Cols)})
			}
		case "ping":
			s.writeMu.Lock()
			_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = s.conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pong"}`))
			s.writeMu.Unlock()
		case "close":
			s.close(closeReasonClientClose)
			return
		}
	}
}

// watch 空闲超时与最大生命周期监控
func (s *shellSession) watch() {
	idle := time.NewTicker(time.Minute)
	life := time.NewTicker(time.Minute)
	defer idle.Stop()
	defer life.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-idle.C:
			if time.Since(s.lastActiveTime()) > shellIdleTimeout {
				s.close(closeReasonIdle)
				return
			}
		case <-life.C:
			if time.Since(s.startedAt) > shellMaxLifetime {
				s.close(closeReasonLifetime)
				return
			}
		}
	}
}

// close 完整清理：结束进程树 → 关闭 PTY/FD → 关闭 WebSocket → Wait 回收 → 移除会话 → 审计
func (s *shellSession) close(reason string) {
	s.closeOnce.Do(func() {
		s.setReason(reason)
		killProcessTree(s.cmd)
		if s.ptmx != nil {
			_ = s.ptmx.Close()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.cmd != nil {
			_ = s.cmd.Wait()
		}
		s.hub.remove(s)
		close(s.done)
		s.auditClosed()
	})
}

// auditClosed 记录会话关闭审计（不记录任何终端输入/输出）。
// 此时无 HTTP 请求上下文，显式传入会话归属的用户与 IP，避免日志缺操作人。
func (s *shellSession) auditClosed() {
	dur := time.Since(s.startedAt).Round(time.Second).String()
	writeAuditEntry(s.Username, s.RemoteIP,
		"shell.session.closed",
		fmt.Sprintf(`shell_id=%s user=%s ip=%s pid=%d reason=%s duration=%s`, s.ID, s.Username, s.RemoteIP, s.pid, s.getReason(), dur))
}

// ==================== Shell Hub（并发控制与管理） ====================

// shellHub 管理所有运行中的 Shell 会话
type shellHub struct {
	sync.RWMutex
	shells map[string]*shellSession
	auth   *shellAuthStore
}

var shellHubState = &shellHub{
	shells: make(map[string]*shellSession),
	auth:   &shellAuthStore{sessions: make(map[string]*ShellAuthSession)},
}

// add 登记会话
func (h *shellHub) add(s *shellSession) {
	h.Lock()
	defer h.Unlock()
	h.shells[s.ID] = s
}

// remove 移除会话
func (h *shellHub) remove(s *shellSession) {
	h.Lock()
	defer h.Unlock()
	delete(h.shells, s.ID)
}

// get 按 ID 取会话
func (h *shellHub) get(id string) *shellSession {
	h.RLock()
	defer h.RUnlock()
	return h.shells[id]
}

// canStart 校验并发限制（每用户 max，全局 max）
func (h *shellHub) canStart(username string) bool {
	h.RLock()
	defer h.RUnlock()
	if len(h.shells) >= shellMaxGlobal {
		return false
	}
	cnt := 0
	for _, s := range h.shells {
		if s.Username == username {
			cnt++
		}
	}
	return cnt < shellMaxPerUser
}

// closeUserShells 关闭某用户的全部 Shell 并撤销其认证 Token（logout / 改密）
func (h *shellHub) closeUserShells(username string) {
	h.Lock()
	var toClose []*shellSession
	for id, s := range h.shells {
		if s.Username == username {
			toClose = append(toClose, s)
			delete(h.shells, id)
		}
	}
	h.Unlock()
	for _, s := range toClose {
		go s.close(closeReasonLogout)
	}
	h.auth.revokeByUser(username)
}

// ==================== 工具函数 ====================

// resolveShell 解析要启动的 Shell：优先 $SHELL，其次 /bin/bash，最后 /bin/sh
func resolveShell() string {
	if v := os.Getenv("SHELL"); v != "" {
		if st, err := os.Stat(v); err == nil && !st.IsDir() {
			return v
		}
	}
	for _, candidate := range []string{"/bin/bash", "/bin/sh"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return "/bin/sh"
}

// buildShellEnv 构造安全可控的 PTY 环境。
// 保留系统基础环境，但剥离 Server Status 的敏感环境变量，绝不回传浏览器。
func buildShellEnv() []string {
	env := make([]string, 0, 24)
	for _, kv := range os.Environ() {
		key := kv
		if i := strings.IndexByte(kv, '='); i > 0 {
			key = kv[:i]
		}
		// 剥离 Server Status 部署敏感项，避免 `env`/API 泄露密钥
		if strings.HasPrefix(key, "SERVER_STATUS_") {
			continue
		}
		if key == "SHELL_PASSWORD_HASH" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"SHELL="+resolveShell(),
	)
	return env
}

// validShellPassword 校验 Shell 密码强度：≥12 位、含字母、含数字、含特殊字符
func validShellPassword(pw string) bool {
	if len(pw) < 12 {
		return false
	}
	hasLetter, hasDigit, hasSpecial := false, false, false
	for _, c := range pw {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	return hasLetter && hasDigit && hasSpecial
}

var dummyHashCache []byte

// dummyBcryptHash 返回一个固定语义的 bcrypt Hash，用于“未初始化 / 密码错误”保持恒定时间比较，避免时序泄漏
func dummyBcryptHash() []byte {
	if len(dummyHashCache) == 0 {
		dummyHashCache, _ = bcrypt.GenerateFromPassword([]byte("dummy-shell-password-placeholder"), bcrypt.DefaultCost)
	}
	return dummyHashCache
}

// shellPasswordManagedByEnv 指示 Shell 密码由环境变量管理（此时禁止通过 API 修改/设置）
func shellPasswordManagedByEnv() bool {
	return os.Getenv("SHELL_PASSWORD_HASH") != ""
}

// loadShellPasswordHash 读取已保存的 bcrypt Hash：优先环境变量，其次加密持久化文件
func loadShellPasswordHash() (string, bool) {
	if v := os.Getenv("SHELL_PASSWORD_HASH"); v != "" {
		return v, true
	}
	raw, err := os.ReadFile(shellPasswordFilePath())
	if err != nil {
		return "", false
	}
	bs, err := decryptData(raw)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(bs))
	if s == "" {
		return "", false
	}
	return s, true
}

// saveShellPasswordHash 加密持久化 bcrypt Hash（0600 权限）
func saveShellPasswordHash(hash string) error {
	enc, err := encryptData([]byte(hash))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(shellPasswordFilePath()), 0700); err != nil {
		return err
	}
	return os.WriteFile(shellPasswordFilePath(), enc, 0600)
}

// isAdminUser 判断用户是否具有管理员权限（有效权限含通配符 *，或角色为 admin）
func isAdminUser(username string) bool {
	for _, p := range getUserEffectivePermissions(username) {
		if p == "*" {
			return true
		}
	}
	return false
}

var shellIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// validShellID 校验 Shell / 认证会话 ID，防止注入
func validShellID(id string) bool {
	return id != "" && len(id) <= 64 && shellIDPattern.MatchString(id)
}

// ==================== 二次认证 API ====================

// shellRateLimiter Shell 二次认证独立限速器（防爆破）
type shellRateLimiter struct {
	sync.Mutex
	fails map[string][]time.Time
	locks map[string]time.Time
}

var shellAuthRate = &shellRateLimiter{
	fails: make(map[string][]time.Time),
	locks: make(map[string]time.Time),
}

// locked 是否处于锁定状态（对外仍返回统一失败文案，避免信息泄漏）
func (l *shellRateLimiter) locked(key string) bool {
	l.Lock()
	defer l.Unlock()
	ts, ok := l.locks[key]
	return ok && time.Now().Before(ts)
}

// allowed 计数窗口内是否仍允许尝试
func (l *shellRateLimiter) allowed(key string) bool {
	l.Lock()
	defer l.Unlock()
	now := time.Now()
	if ts, ok := l.locks[key]; ok && now.Before(ts) {
		return false
	}
	keep := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if now.Sub(t) <= shellAuthWindow {
			keep = append(keep, t)
		}
	}
	l.fails[key] = keep
	return len(keep) < shellMaxAuthFailures
}

// fail 记录一次失败，达阈值后锁定
func (l *shellRateLimiter) fail(key string) {
	l.Lock()
	defer l.Unlock()
	now := time.Now()
	l.fails[key] = append(l.fails[key], now)
	if len(l.fails[key]) >= shellMaxAuthFailures {
		l.locks[key] = now.Add(shellAuthLockTime)
	} else {
		l.locks[key] = time.Time{}
	}
}

// success 成功后清零失败计数与锁定
func (l *shellRateLimiter) success(key string) {
	l.Lock()
	defer l.Unlock()
	delete(l.fails, key)
	delete(l.locks, key)
}

// shellAuthKeys 生成限速 key：用户、IP、用户+IP 三重维度
func shellAuthKeys(username, ip string) []string {
	return []string{"user:" + username, "ip:" + ip, "uip:" + username + "|" + ip}
}

// checkShellPassword 在统一错误语义下校验 Shell 密码（未初始化不可区分），返回是否通过
func checkShellPassword(password string) (ok bool) {
	hash, present := loadShellPasswordHash()
	target := []byte(dummyBcryptHash())
	if present {
		target = []byte(hash)
	}
	return bcrypt.CompareHashAndPassword(target, []byte(password)) == nil
}

// shellAuthHandler POST /api/shell/auth —— 二次认证，成功颁发一次性 Token
func shellAuthHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	username := session.Username
	ip := getClientIP(r)
	keys := shellAuthKeys(username, ip)

	// 防爆破：任一维度锁定即拒绝，统一失败文案，避免信息泄漏
	if shellAuthRate.locked(keys[0]) || shellAuthRate.locked(keys[1]) || shellAuthRate.locked(keys[2]) {
		auditAction(r, "shell.auth.locked", fmt.Sprintf("user=%s ip=%s", username, ip))
		writeJSONError(w, http.StatusUnauthorized, "Shell authentication failed")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	if !checkShellPassword(req.Password) {
		for _, k := range keys {
			shellAuthRate.fail(k)
		}
		auditAction(r, "shell.auth.failed", fmt.Sprintf("user=%s ip=%s", username, ip))
		writeJSONError(w, http.StatusUnauthorized, "Shell authentication failed")
		return
	}

	for _, k := range keys {
		shellAuthRate.success(k)
	}

	rawToken, err := generateSecureToken(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成认证凭证失败")
		return
	}
	idPart, _ := generateSecureToken(8)
	as := &ShellAuthSession{
		ID:        "sast-" + idPart,
		TokenHash: shellTokenHash(rawToken),
		Username:  username,
		RemoteIP:  ip,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(shellTokenTTL),
	}
	shellHubState.auth.put(as)

	auditAction(r, "shell.auth.success",
		fmt.Sprintf("user=%s ip=%s auth_id=%s expires_in=%ds", username, ip, as.ID, int(shellTokenTTL.Seconds())))

	writeJSON(w, http.StatusOK, "ok", map[string]interface{}{
		"shell_token": rawToken,
		"expires_in":  int(shellTokenTTL.Seconds()),
	})
}

// shellSetupPasswordHandler POST /api/shell/setup-password —— 初始化 Shell 密码（仅管理员）
func shellSetupPasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	username := session.Username
	ip := getClientIP(r)

	if !isAdminUser(username) {
		auditAction(r, "shell.permission.denied", fmt.Sprintf("action=setup user=%s ip=%s", username, ip))
		writeJSONError(w, http.StatusForbidden, "没有权限执行此操作")
		return
	}
	if shellPasswordManagedByEnv() {
		writeJSONError(w, http.StatusBadRequest, "Shell 密码由环境变量 SHELL_PASSWORD_HASH 管理，无法通过 API 设置")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if !validShellPassword(req.Password) {
		writeJSONError(w, http.StatusBadRequest, "密码不符合要求（至少 12 位，包含字母、数字与特殊字符）")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "密码处理失败")
		return
	}
	if err := saveShellPasswordHash(string(hash)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存失败")
		return
	}
	auditAction(r, "shell.password.changed", fmt.Sprintf("action=setup user=%s ip=%s", username, ip))
	writeJSON(w, http.StatusOK, "Shell 密码设置成功", nil)
}

// shellChangePasswordHandler POST /api/shell/change-password —— 修改 Shell 密码。
// 成功后立即撤销旧认证、关闭当前用户全部 Shell，防止旧认证延续。
func shellChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	username := session.Username
	ip := getClientIP(r)
	keys := shellAuthKeys(username, ip)

	if shellPasswordManagedByEnv() {
		writeJSONError(w, http.StatusBadRequest, "Shell 密码由环境变量 SHELL_PASSWORD_HASH 管理，无法通过 API 修改")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if !validShellPassword(req.NewPassword) {
		writeJSONError(w, http.StatusBadRequest, "新密码不符合要求（至少 12 位，包含字母、数字与特殊字符）")
		return
	}

	if !checkShellPassword(req.OldPassword) {
		for _, k := range keys {
			shellAuthRate.fail(k)
		}
		auditAction(r, "shell.auth.failed", fmt.Sprintf("action=change user=%s ip=%s", username, ip))
		writeJSONError(w, http.StatusUnauthorized, "Shell authentication failed")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "密码处理失败")
		return
	}
	if err := saveShellPasswordHash(string(newHash)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存失败")
		return
	}
	for _, k := range keys {
		shellAuthRate.success(k)
	}

	// 修改成功：撤销所有旧认证 + 关闭当前用户全部 Shell
	shellHubState.auth.revokeByUser(username)
	shellHubState.closeUserShells(username)

	auditAction(r, "shell.password.changed", fmt.Sprintf("action=change user=%s ip=%s", username, ip))
	writeJSON(w, http.StatusOK, "Shell 密码修改成功，已撤销旧认证并关闭原有 Shell", nil)
}

// ==================== Shell 会话管理 API ====================

// shellListSessionsHandler GET /api/shell/sessions —— 列出运行中的 Shell
func shellListSessionsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	admin := isAdminUser(session.Username)

	shellHubState.RLock()
	out := make([]map[string]interface{}, 0, len(shellHubState.shells))
	for _, s := range shellHubState.shells {
		if !admin && s.Username != session.Username {
			continue
		}
		out = append(out, map[string]interface{}{
			"id":            s.ID,
			"username":      s.Username,
			"remote_ip":     s.RemoteIP,
			"pid":           s.pid,
			"started_at":    s.startedAt.Format(time.RFC3339),
			"last_activity": s.lastActiveTime().Format(time.RFC3339),
			"status":        "connected",
		})
	}
	shellHubState.RUnlock()

	writeJSON(w, http.StatusOK, "ok", map[string]interface{}{"sessions": out})
}

// shellDeleteSessionHandler DELETE /api/shell/sessions/{id} —— 管理员/本人关闭指定 Shell
func shellDeleteSessionHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	admin := isAdminUser(session.Username)
	id := r.PathValue("id")
	if !validShellID(id) {
		writeJSONError(w, http.StatusBadRequest, "无效的 Shell ID")
		return
	}
	s := shellHubState.get(id)
	if s == nil {
		writeJSONError(w, http.StatusNotFound, "Shell 不存在")
		return
	}
	if !admin && s.Username != session.Username {
		auditAction(r, "shell.permission.denied", fmt.Sprintf("action=kill target=%s user=%s", id, session.Username))
		writeJSONError(w, http.StatusForbidden, "没有权限执行此操作")
		return
	}
	go s.close(closeReasonKilled)
	auditAction(r, "shell.session.killed", fmt.Sprintf("shell_id=%s target_user=%s by=%s", id, s.Username, session.Username))
	writeJSON(w, http.StatusOK, "Shell 已关闭", nil)
}

// shellDeleteAuthSessionHandler DELETE /api/shell/auth-sessions/{id} —— 撤销等待启动的认证
func shellDeleteAuthSessionHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	admin := isAdminUser(session.Username)
	id := r.PathValue("id")
	if !validShellID(id) {
		writeJSONError(w, http.StatusBadRequest, "无效的认证会话 ID")
		return
	}
	_, exists := shellHubState.auth.getByID(id)
	if !exists {
		writeJSONError(w, http.StatusNotFound, "认证会话不存在")
		return
	}
	if !shellHubState.auth.revokeByID(id, session.Username, admin) {
		writeJSONError(w, http.StatusForbidden, "没有权限执行此操作")
		return
	}
	auditAction(r, "shell.auth.expired", fmt.Sprintf("action=revoke auth_id=%s by=%s", id, session.Username))
	writeJSON(w, http.StatusOK, "已撤销认证会话", nil)
}

// shellRevokeAllHandler POST /api/shell/revoke-all —— 撤销全部待启动认证（管理员全量，普通人仅本人）
func shellRevokeAllHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionFromRequest(r)
	admin := isAdminUser(session.Username)
	var n int
	if admin {
		n = shellHubState.auth.revokeAll()
	} else {
		n = shellHubState.auth.revokeByUser(session.Username)
	}
	auditAction(r, "shell.auth.expired", fmt.Sprintf("action=revoke-all user=%s count=%d", session.Username, n))
	writeJSON(w, http.StatusOK, "已撤销全部待启动认证", map[string]interface{}{"revoked": n})
}

// shellPageHandler GET /shell.html —— 提供受保护且禁止缓存的 Web Shell 页面
func shellPageHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(indexPath, "shell.html"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// ==================== WebSocket 端点 ====================

// safeErrorMessage 统一的 WebSocket 认证失败提示（不区分具体原因）
const safeErrorMessage = "shell authentication failed"

// sendWSError 发送一条 JSON 错误帧后关闭连接
func sendWSError(conn *websocket.Conn, msg string, code int) {
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	payload, _ := json.Marshal(map[string]interface{}{"type": "error", "message": msg})
	_ = conn.WriteMessage(websocket.TextMessage, payload)
	_ = conn.Close()
}

// shellWSHandler GET /ws/shell —— WebSocket 终端入口。
// 流程：会话校验 → RBAC → Origin(升级时) → 等待 auth 首帧 → 一次性 Token 验证 → 创建 PTY → 双向 IO。
// 认证成功后才创建 PTY，严禁先建 Shell 再认证。
func shellWSHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)

	session, valid := getSessionFromRequest(r)
	if !valid {
		auditAction(r, "shell.websocket.rejected", "reject=no-session")
		writeJSONError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	if !hasPermission(session.Username, "system:exec") {
		auditAction(r, "shell.permission.denied", fmt.Sprintf("ws user=%s ip=%s", session.Username, getClientIP(r)))
		writeJSONError(w, http.StatusForbidden, "没有权限执行此操作")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebShell Upgrade Error: %v", err)
		return
	}

	ip := getClientIP(r)
	conn.SetReadLimit(shellMaxMsgSize)
	// 等待首帧 auth 消息的窗口（一次性 Token 60s + 裕量）
	conn.SetReadDeadline(time.Now().Add(shellResolveTimeout))

	_, msg, err := conn.ReadMessage()
	if err != nil {
		auditAction(r, "shell.websocket.rejected", fmt.Sprintf("user=%s ip=%s reject=no-auth-frame", session.Username, ip))
		sendWSError(conn, safeErrorMessage, websocket.ClosePolicyViolation)
		return
	}

	var first struct {
		Type  string `json:"type"`
		Token string `json:"token"`
		Rows  int    `json:"rows"`
		Cols  int    `json:"cols"`
	}
	if json.Unmarshal(msg, &first) != nil || first.Type != "auth" || first.Token == "" {
		auditAction(r, "shell.websocket.rejected", fmt.Sprintf("user=%s ip=%s reject=bad-auth-frame", session.Username, ip))
		sendWSError(conn, safeErrorMessage, websocket.ClosePolicyViolation)
		return
	}
	if len(first.Token) > 256 {
		sendWSError(conn, safeErrorMessage, websocket.ClosePolicyViolation)
		return
	}

	// 验证一次性 Token（同时完成过期/已用/撤销/用户匹配检查），立即失效
	as, ok := shellHubState.auth.consume(shellTokenHash(first.Token))
	if !ok {
		auditAction(r, "shell.auth.expired", fmt.Sprintf("user=%s ip=%s reason=token-invalid-or-used", session.Username, ip))
		sendWSError(conn, safeErrorMessage, websocket.ClosePolicyViolation)
		return
	}
	if as.Username != session.Username {
		auditAction(r, "shell.auth.expired", fmt.Sprintf("user=%s ip=%s reason=token-user-mismatch", session.Username, ip))
		sendWSError(conn, safeErrorMessage, websocket.ClosePolicyViolation)
		return
	}
	auditAction(r, "shell.session.used", fmt.Sprintf("user=%s ip=%s auth_id=%s", session.Username, ip, as.ID))

	// 认证成功后，创建 PTY 之前再次校验并发限制
	if !shellHubState.canStart(session.Username) {
		auditAction(r, "shell.session.killed", fmt.Sprintf("user=%s ip=%s reason=session-limit", session.Username, ip))
		sendWSError(conn, "Shell session limit reached", websocket.ClosePolicyViolation)
		return
	}

	// 创建 PTY（此处认证已通过才创建）
	cmd := exec.Command(resolveShell())
	cmd.Env = buildShellEnv()
	if home, err := os.UserHomeDir(); err == nil {
		if st, serr := os.Stat(home); serr == nil && st.IsDir() {
			cmd.Dir = home
		}
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("WebShell PTY Start Error: %v", err)
		auditAction(r, "shell.session.closed", fmt.Sprintf("user=%s ip=%s reason=pty-failed", session.Username, ip))
		sendWSError(conn, "PTY start failed", websocket.CloseInternalServerErr)
		return
	}

	rows, cols := first.Rows, first.Cols
	if rows <= 0 || rows > shellMaxResizeRows {
		rows = 24
	}
	if cols <= 0 || cols > shellMaxResizeCols {
		cols = 80
	}
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})

	s := &shellSession{
		hub:       shellHubState,
		ID:        "shell-" + newShellID(),
		Username:  session.Username,
		RemoteIP:  ip,
		pid:       cmd.Process.Pid,
		startedAt: time.Now(),
		conn:      conn,
		ptmx:      ptmx,
		cmd:       cmd,
		outCh:     make(chan []byte, shellOutputQueue),
		done:      make(chan struct{}),
	}
	s.touch()
	s.start()
	auditAction(r, "shell.session.created", fmt.Sprintf("shell_id=%s user=%s ip=%s pid=%d", s.ID, session.Username, ip, s.pid))

	<-s.done
	log.Printf("WebShell closed: user=%s shell_id=%s reason=%s", session.Username, s.ID, s.getReason())
}

// newShellID 生成随机会话 ID 片段
func newShellID() string {
	part, _ := generateSecureToken(8)
	return part
}
