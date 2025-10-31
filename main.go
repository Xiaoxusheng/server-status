package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	rand2 "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"golang.org/x/crypto/bcrypt"
)

// 配置项
const (
	mediaDir          = "/root/file/static"
	url               = "https://example.com:8081/static/"
	authToken         = "123456"
	dataFile          = "/root/os/server_data.json"
	rateLimit         = 10                                      // 每分钟最大请求数
	rateLimitDuration = time.Minute                             // 速率限制时间窗口
	logDir            = "/root/os/log"                          // 日志目录
	securityToken     = "redacted_anti_crawler_2024_security_key" // 反爬安全令牌
	signatureTimeout  = 30 * time.Second                        // 签名超时时间
	usersFile         = "/root/os/users.json"                   // 用户数据文件
	sessionTimeout    = 24 * time.Hour                          // 会话超时时间
	encryptionKey     = "redacted_user_data_encryption_key_2024"  // 用户数据加密密钥

	// 新增下载密钥配置
	downloadTokenExpiry = 30 * time.Minute                    // 下载令牌有效期
	downloadLimitBytes  = 3 * 1024 * 1024 * 1024              // 2GB 下载限制
	downloadTokenSecret = "redacted_download_token_secret_2024" // 下载令牌密钥
	downloadTokensFile  = "/root/os/download_tokens.json"     // 下载令牌存储文件
)

// 用户相关结构体
type Users struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"` // bcrypt加密后的密码
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
	IsActive    bool      `json:"is_active"`
	Permissions []string  `json:"permissions"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Session struct {
	SessionID  string    `json:"session_id"`
	Username   string    `json:"username"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_access"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type UserManager struct {
	sync.RWMutex
	UserInfos map[string]*Users   `json:"user_infos"`
	Sessions  map[string]*Session `json:"sessions"`
}

// 新增：下载令牌结构体
type DownloadToken struct {
	TokenID     string    `json:"token_id"`
	Token       string    `json:"token"`
	Username    string    `json:"username"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	UsedBytes   int64     `json:"used_bytes"`
	MaxBytes    int64     `json:"max_bytes"`
	IsActive    bool      `json:"is_active"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"user_agent"`
	Description string    `json:"description"`
}

// 下载令牌管理器
type DownloadTokenManager struct {
	sync.RWMutex
	Tokens map[string]*DownloadToken `json:"tokens"` // key: token_id
}

// 生成下载令牌请求
type GenerateDownloadTokenRequest struct {
	Description string `json:"description"` // 可选：令牌描述
}

// 下载令牌响应
type DownloadTokenResponse struct {
	TokenID   string `json:"token_id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	MaxBytes  int64  `json:"max_bytes"`
	UsedBytes int64  `json:"used_bytes"`
}

// 下载请求
type DownloadRequest struct {
	FilePath string `json:"file_path"` // 文件路径（相对于媒体目录）
	Token    string `json:"token"`     // 下载令牌
}

// 反爬配置
var (
	// 允许的User-Agent列表
	allowedUserAgents = []string{
		"Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera",
	}

	// 必须包含的请求头
	requiredHeaders = []string{
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
	}

	// 可疑的爬虫特征
	suspiciousPatterns = []string{
		"bot", "crawler", "spider", "scraper", "python", "curl", "wget",
		"java", "go-http", "node", "phantom", "selenium", "headless",
	}

	// 代理相关头部
	proxyHeaders = []string{
		"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
		"True-Client-IP", "X-Cluster-Client-IP",
	}
)

type ServerStatus struct {
	CPUUsage      float64          `json:"cpu_usage"`
	MemoryUsage   float64          `json:"memory_usage"`
	MemoryTotal   uint64           `json:"memory_total"`
	DiskUsage     float64          `json:"disk_usage"`
	DiskTotal     uint64           `json:"disk_total"`
	UploadSpeed   float64          `json:"upload_speed"`
	DownloadSpeed float64          `json:"download_speed"`
	TotalUpload   string           `json:"total_upload"`
	TotalDownload string           `json:"total_download"`
	ReadSpeed     float64          `json:"read_speed"`
	WriteSpeed    float64          `json:"write_speed"`
	Load1         float64          `json:"load1"`
	Load5         float64          `json:"load5"`
	Load15        float64          `json:"load15"`
	Uptime        string           `json:"uptime"`
	OnlineCount   int              `json:"online_count"`
	UniqueIPs     []string         `json:"unique_ips"`
	OnlineUsers   []OnlineUserInfo `json:"online_users"`
	// 新增主机信息字段
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Platform      string `json:"platform"`
	KernelVersion string `json:"kernel_version"`
	Architecture  string `json:"architecture"`
}

// OnlineUserInfo 用于WebSocket传输的在线用户信息结构
type OnlineUserInfo struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Since     string `json:"since"` // 格式化时间字符串
	Page      string `json:"page"`
}

// AccessStats 访问统计结构体
type AccessStats struct {
	sync.RWMutex
	DailyVisits    map[string]int
	WeeklyVisits   map[string]int
	UniqueVisitors map[string]map[string]bool
}

type AccessStatsSnapshot struct {
	DailyVisits  map[string]int `json:"daily_visits"`
	WeeklyVisits map[string]int `json:"weekly_visits"`
}

// OnlineUser 在线用户结构体
type OnlineUser struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Since     time.Time `json:"since"`
	Page      string    `json:"page"`
}

type OnlineUsers struct {
	sync.RWMutex
	Users map[string]*OnlineUser // key is IP+UserAgent to identify unique sessions
}

// PersistData 持久化结构体
type PersistData struct {
	TotalUploadAccum   uint64              `json:"total_upload_accum"`
	TotalDownloadAccum uint64              `json:"total_download_accum"`
	AccessStats        AccessStatsSnapshot `json:"access_stats"`
	StartTime          string              `json:"start_time"` // 服务器启动时间
}

// 反爬验证结构体
type AntiCrawler struct {
	sync.RWMutex
	blockedIPs         map[string]time.Time
	suspiciousIPs      map[string]int
	failedAttempts     map[string]int
	clientFingerprints map[string]*ClientProfile
	requestPatterns    map[string][]time.Time
}

// 客户端指纹档案
type ClientProfile struct {
	Fingerprint  string
	IP           string
	UserAgent    string
	FirstSeen    time.Time
	LastSeen     time.Time
	RequestCount int
	Score        int // 行为评分
	Blocked      bool
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return checkOrigin(r) && verifySecurityHeaders(r)
		},
	}
	// 移除全局startTime，使用持久化的启动时间
	lastNetStats       = map[string]NetStat{}
	lastDiskStats      = map[string]DiskStat{}
	totalUploadAccum   uint64
	totalDownloadAccum uint64
	accessStats        = &AccessStats{
		DailyVisits:    make(map[string]int),
		WeeklyVisits:   make(map[string]int),
		UniqueVisitors: make(map[string]map[string]bool),
	}
	onlineUsers = &OnlineUsers{
		Users: make(map[string]*OnlineUser),
	}
	antiCrawler = &AntiCrawler{
		blockedIPs:         make(map[string]time.Time),
		suspiciousIPs:      make(map[string]int),
		failedAttempts:     make(map[string]int),
		clientFingerprints: make(map[string]*ClientProfile),
		requestPatterns:    make(map[string][]time.Time),
	}

	// 用户管理器
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: make(map[string]*Users),
		Sessions:  make(map[string]*Session),
	}

	// 新增：下载令牌管理器
	downloadTokenManager = &DownloadTokenManager{
		Tokens: make(map[string]*DownloadToken),
	}

	//返回随机视频照片
	num   = 0
	key   = 0
	files []string

	// 主机信息缓存
	hostInfo      *host.InfoStat
	hostInfoErr   error
	hostInfoMutex sync.Mutex

	// 服务器启动时间（从持久化数据加载）
	serverStartTime time.Time

	// 保存队列，避免并发保存导致的死锁
	downloadTokenSaveChan = make(chan struct{}, 1)
	userSaveChan          = make(chan struct{}, 1)
)

type NetStat struct {
	BytesSent uint64
	BytesRecv uint64
	Time      time.Time
}

type DiskStat struct {
	ReadBytes  uint64
	WriteBytes uint64
	Time       time.Time
}

// EpubInfo 保存每本书的信息
type EpubInfo struct {
	FileName     string `json:"file_name"`
	Title        string `json:"title"`
	Author       string `json:"author"`
	ChapterCount int    `json:"chapter_count"`
	Url          string `json:"url"`
}

// 字节计数器
type byteCounter struct {
	total *int64
}

func (bc *byteCounter) Write(p []byte) (int, error) {
	*bc.total += int64(len(p))
	return len(p), nil
}

// ==================== 下载令牌功能 ====================

// 生成随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand2.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// 加密下载令牌
func encryptDownloadToken(token string, downloadToken *DownloadToken) (string, error) {
	data := fmt.Sprintf("%s|%s|%s|%d", token, downloadToken.TokenID, downloadToken.Username, downloadToken.CreatedAt.Unix())

	key := sha256.Sum256([]byte(downloadTokenSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand2.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// 验证下载令牌
func verifyDownloadToken(token string, downloadToken *DownloadToken) bool {
	// 简化实现：在实际生产环境中应该使用完整的加密验证
	// 这里为了简化，我们假设令牌是有效的
	return true
}

// 生成下载令牌
func generateDownloadToken(username string, r *http.Request, description string) (*DownloadTokenResponse, error) {
	tokenID := generateRandomString(16)
	token := generateRandomString(32)

	now := time.Now()
	expiresAt := now.Add(downloadTokenExpiry)

	downloadToken := &DownloadToken{
		TokenID:     tokenID,
		Token:       token,
		Username:    username,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		UsedBytes:   0,
		MaxBytes:    downloadLimitBytes,
		IsActive:    true,
		IP:          getClientIP(r),
		UserAgent:   r.UserAgent(),
		Description: description,
	}

	// 存储令牌
	downloadTokenManager.Lock()
	downloadTokenManager.Tokens[tokenID] = downloadToken
	downloadTokenManager.Unlock()

	// 异步保存到文件
	go scheduleSaveDownloadTokens()

	return &DownloadTokenResponse{
		TokenID:   tokenID,
		Token:     token,
		ExpiresAt: expiresAt.Format("2006-01-02 15:04:05"),
		MaxBytes:  downloadLimitBytes,
		UsedBytes: 0,
	}, nil
}

// 验证下载令牌
func validateDownloadToken(tokenID, token string, r *http.Request) (*DownloadToken, error) {
	downloadTokenManager.RLock()
	downloadToken, exists := downloadTokenManager.Tokens[tokenID]
	//log.Println("验证token",downloadTokenManager.Tokens)
	downloadTokenManager.RUnlock()

	if !exists {
		return nil, fmt.Errorf("令牌不存在")
	}

	if !downloadToken.IsActive {
		return nil, fmt.Errorf("令牌已失效")
	}

	if time.Now().After(downloadToken.ExpiresAt) {
		// 标记为失效
		downloadTokenManager.Lock()
		downloadToken.IsActive = false
		downloadTokenManager.Unlock()
		go scheduleSaveDownloadTokens()
		return nil, fmt.Errorf("令牌已过期")
	}

	// 验证令牌内容
	if !verifyDownloadToken(token, downloadToken) {
		return nil, fmt.Errorf("令牌验证失败")
	}

	// 检查下载量限制
	if downloadToken.UsedBytes >= downloadToken.MaxBytes {
		downloadTokenManager.Lock()
		downloadToken.IsActive = false
		downloadTokenManager.Unlock()
		go scheduleSaveDownloadTokens()
		return nil, fmt.Errorf("下载量已达上限")
	}

	return downloadToken, nil
}

// 更新令牌使用量
func updateTokenUsage(tokenID string, bytes int64) {
	downloadTokenManager.Lock()
	if token, exists := downloadTokenManager.Tokens[tokenID]; exists {
		token.UsedBytes += bytes

		// 如果超过限制，停用令牌
		if token.UsedBytes >= token.MaxBytes {
			token.IsActive = false
		}
	}
	downloadTokenManager.Unlock()

	// 异步保存，使用队列避免并发
	go scheduleSaveDownloadTokens()
}

// 清理过期下载令牌
func cleanupExpiredDownloadTokens() {
	downloadTokenManager.Lock()

	now := time.Now()
	expiredTokens := make([]string, 0)

	for tokenID, token := range downloadTokenManager.Tokens {
		if now.After(token.ExpiresAt) || (!token.IsActive && now.After(token.ExpiresAt.Add(24*time.Hour))) {
			expiredTokens = append(expiredTokens, tokenID)
		}
	}

	// 批量删除过期令牌
	for _, tokenID := range expiredTokens {
		delete(downloadTokenManager.Tokens, tokenID)
	}

	downloadTokenManager.Unlock()

	if len(expiredTokens) > 0 {
		log.Printf("✅ 清理 %d 个过期下载令牌", len(expiredTokens))
		// 异步保存
		go scheduleSaveDownloadTokens()
	}
}

// 保存下载令牌到文件
func saveDownloadTokens() error {
	// 先复制数据，尽快释放锁
	downloadTokenManager.RLock()
	data, err := json.Marshal(downloadTokenManager)
	if err != nil {
		downloadTokenManager.RUnlock()
		return fmt.Errorf("序列化下载令牌数据失败: %v", err)
	}
	downloadTokenManager.RUnlock()

	encryptedData, err := encryptData(data)
	if err != nil {
		return fmt.Errorf("加密下载令牌数据失败: %v", err)
	}

	// 确保目录存在
	dir := filepath.Dir(downloadTokensFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 使用临时文件写入，避免文件损坏
	tempFile := downloadTokensFile + ".tmp"
	file, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("打开临时文件失败: %v", err)
	}

	if _, err := file.Write(encryptedData); err != nil {
		file.Close()
		os.Remove(tempFile)
		return fmt.Errorf("写入临时文件失败: %v", err)
	}

	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tempFile)
		return fmt.Errorf("同步文件失败: %v", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("关闭文件失败: %v", err)
	}

	// 原子性重命名
	if err := os.Rename(tempFile, downloadTokensFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	return nil
}

// 加载下载令牌
func loadDownloadTokens() {
	if _, err := os.Stat(downloadTokensFile); os.IsNotExist(err) {
		log.Println("下载令牌文件不存在，将创建新文件")
		return
	}

	file, err := os.Open(downloadTokensFile)
	if err != nil {
		log.Printf("读取下载令牌文件失败: %v", err)
		return
	}
	defer file.Close()

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		log.Printf("读取加密数据失败: %v", err)
		return
	}

	decryptedData, err := decryptData(encryptedData)
	if err != nil {
		log.Printf("解密下载令牌数据失败: %v", err)
		return
	}

	downloadTokenManager.Lock()
	defer downloadTokenManager.Unlock()

	if err := json.Unmarshal(decryptedData, downloadTokenManager); err != nil {
		log.Printf("解析下载令牌数据失败: %v", err)
		return
	}

	log.Printf("✅ 下载令牌数据加载完成，共 %d 个令牌", len(downloadTokenManager.Tokens))
}

// 初始化下载令牌管理器
func initDownloadTokenManager() {
	loadDownloadTokens()

	// 启动定期清理过期令牌的goroutine
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredDownloadTokens()
		}
	}()
}

// 安全检查文件路径
func isSafeFilePath(filePath, baseDir string) bool {
	// 解析文件路径
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	// 解析基础目录
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}

	// 检查文件路径是否在基础目录内
	relPath, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return false
	}

	// 防止路径遍历攻击
	if strings.Contains(relPath, "..") {
		return false
	}

	return true
}

// ==================== 下载相关HTTP处理函数 ====================

// 生成下载令牌接口
func generateDownloadTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	session, valid := getSessionFromRequest(r)
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusUnauthorized,
			"message": "请先登录",
		})
		return
	}

	var req GenerateDownloadTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	tokenResponse, err := generateDownloadToken(session.Username, r, req.Description)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": fmt.Sprintf("生成令牌失败: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "下载令牌生成成功",
		"data":    tokenResponse,
	})
}

// 安全下载接口
func secureDownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	// 从查询参数获取令牌和文件路径
	token := r.URL.Query().Get("token_id")
	TokenValues := r.URL.Query().Get("token")
	filePath := r.URL.Query().Get("file")

	if token == "" || filePath == "" || TokenValues == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "缺少令牌或文件参数",
		})
		return
	}

	// 提取tokenID（简化实现：假设token就是tokenID）

	// 验证令牌
	downloadToken, err := validateDownloadToken(token, TokenValues, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": fmt.Sprintf("下载令牌验证失败: %v", err),
		})
		return
	}

	// 构建完整文件路径
	fullPath := filepath.Join(mediaDir, path.Base(filePath))
	log.Println("file_url:", fullPath)
	// 安全检查：确保文件路径在允许的目录内
	if !isSafeFilePath(fullPath, mediaDir) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "文件路径不安全",
		})
		return
	}

	// 检查文件是否存在
	fileInfo, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusNotFound,
			"message": "文件不存在",
		})
		return
	}

	// 检查文件大小是否超过剩余配额
	if downloadToken.UsedBytes+fileInfo.Size() > downloadToken.MaxBytes {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "下载此文件将超过流量限制",
		})
		return
	}

	// 设置下载头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filePath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// 记录下载开始
	recordAccess(r)
	updateOnlineUser(r, "secure-download")

	// 使用TeeReader来统计下载量
	file, err := os.Open(fullPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": "无法打开文件",
		})
		return
	}
	defer file.Close()

	// 创建带统计的reader
	var bytesDownloaded int64
	teeReader := io.TeeReader(file, &byteCounter{&bytesDownloaded})

	// 复制文件内容到响应
	_, err = io.Copy(w, teeReader)
	if err != nil {
		log.Printf("下载文件出错: %v", err)
		return
	}

	// 更新令牌使用量
	updateTokenUsage(downloadToken.TokenID, bytesDownloaded)

	log.Printf("✅ 用户 %s 下载文件 %s, 大小: %d bytes", downloadToken.Username, filePath, bytesDownloaded)
}

// 获取用户下载令牌列表
func listDownloadTokensHandler(w http.ResponseWriter, r *http.Request) {
	session, valid := getSessionFromRequest(r)
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusUnauthorized,
			"message": "请先登录",
		})
		return
	}

	downloadTokenManager.RLock()
	defer downloadTokenManager.RUnlock()

	userTokens := make([]*DownloadToken, 0)
	for _, token := range downloadTokenManager.Tokens {
		if token.Username == session.Username {
			userTokens = append(userTokens, token)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取令牌列表成功",
		"data":    userTokens,
	})
}

// 撤销下载令牌
func revokeDownloadTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	session, valid := getSessionFromRequest(r)
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusUnauthorized,
			"message": "请先登录",
		})
		return
	}

	tokenID := r.URL.Query().Get("token_id")
	if tokenID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "缺少令牌ID参数",
		})
		return
	}

	downloadTokenManager.Lock()
	defer downloadTokenManager.Unlock()

	token, exists := downloadTokenManager.Tokens[tokenID]
	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusNotFound,
			"message": "令牌不存在",
		})
		return
	}

	if token.Username != session.Username {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "无权操作此令牌",
		})
		return
	}

	token.IsActive = false
	go scheduleSaveDownloadTokens()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "令牌已撤销",
	})
}

// ==================== 用户身份验证功能 ====================

// 加密数据
func encryptData(data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(encryptionKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand2.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// 解密数据
func decryptData(ciphertext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(encryptionKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// 加载用户数据
func loadUsers() {
	// 确保目录存在
	dir := filepath.Dir(usersFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("创建用户数据目录失败: %v", err)
		createDefaultAdmin()
		return
	}

	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		log.Println("用户数据文件不存在，创建默认管理员用户")
		createDefaultAdmin()
		return
	}

	file, err := os.Open(usersFile)
	if err != nil {
		log.Printf("读取用户数据文件失败: %v", err)
		return
	}
	defer file.Close()

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		log.Printf("读取加密数据失败: %v", err)
		return
	}

	decryptedData, err := decryptData(encryptedData)
	if err != nil {
		log.Printf("解密用户数据失败: %v", err)
		return
	}

	userManager.Lock()
	defer userManager.Unlock()

	if err := json.Unmarshal(decryptedData, userManager); err != nil {
		log.Printf("解析用户数据失败: %v", err)
		return
	}

	log.Printf("✅ 用户数据加载完成，共 %d 个用户", len(userManager.UserInfos))
}

// 保存用户数据
func saveUsers() error {
	// 先复制数据，尽快释放锁
	userManager.RLock()
	data, err := json.Marshal(userManager)
	userManager.RUnlock()

	if err != nil {
		return fmt.Errorf("序列化用户数据失败: %v", err)
	}

	encryptedData, err := encryptData(data)
	if err != nil {
		return fmt.Errorf("加密用户数据失败: %v", err)
	}

	// 确保目录存在
	dir := filepath.Dir(usersFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 使用临时文件
	tempFile := usersFile + ".tmp"
	file, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("打开临时文件失败: %v", err)
	}

	if _, err := file.Write(encryptedData); err != nil {
		file.Close()
		os.Remove(tempFile)
		return fmt.Errorf("写入临时文件失败: %v", err)
	}

	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tempFile)
		return fmt.Errorf("同步文件失败: %v", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("关闭文件失败: %v", err)
	}

	// 原子性重命名
	if err := os.Rename(tempFile, usersFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	return nil
}

// 创建默认管理员用户
func createDefaultAdmin() {
	userManager.Lock()
	defer userManager.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("创建默认管理员用户时加密密码失败: %v", err)
		return
	}

	userManager.UserInfos["admin"] = &Users{
		Username:    "admin",
		Password:    string(hashedPassword),
		Email:       "admin@example.com",
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Permissions: []string{"admin", "read", "write", "execute"},
	}

	if err := saveUsers(); err != nil {
		log.Printf("保存默认管理员用户失败: %v", err)
	} else {
		log.Println("✅ 创建默认管理员用户: admin / admin123")
	}
}

// 生成会话ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand2.Read(b)
	return hex.EncodeToString(b)
}

// 验证会话
func validateSession(sessionID string) (*Session, bool) {
	userManager.RLock()
	defer userManager.RUnlock()

	session, exists := userManager.Sessions[sessionID]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		// 会话已过期
		delete(userManager.Sessions, sessionID)
		return nil, false
	}

	// 更新最后访问时间
	session.LastAccess = time.Now()
	session.ExpiresAt = time.Now().Add(sessionTimeout)

	return session, true
}

// 创建会话
func createSession(username string, r *http.Request) string {
	sessionID := generateSessionID()
	now := time.Now()

	session := &Session{
		SessionID:  sessionID,
		Username:   username,
		IP:         getClientIP(r),
		UserAgent:  r.UserAgent(),
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(sessionTimeout),
	}

	userManager.Lock()
	userManager.Sessions[sessionID] = session
	if user, exists := userManager.UserInfos[username]; exists {
		user.LastLogin = now
	}
	userManager.Unlock()

	// 异步保存用户数据
	go scheduleSaveUsers()

	return sessionID
}

// 删除会话
func deleteSession(sessionID string) {
	userManager.Lock()
	defer userManager.Unlock()

	delete(userManager.Sessions, sessionID)
	go scheduleSaveUsers()
}

// 登录处理
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	userManager.RLock()
	user, exists := userManager.UserInfos[strings.TrimSpace(req.Username)]
	userManager.RUnlock()

	if !exists || !user.IsActive {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	// 创建会话
	sessionID := createSession(req.Username, r)

	// 设置会话Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(sessionTimeout),
		HttpOnly: true,
		Secure:   true,                 // 仅在HTTPS下传输
		SameSite: http.SameSiteLaxMode, // 或者 http.SameSiteNoneMode
		Path:     "/",
		Domain:   ".example.com", // 关键：添加顶级域名，注意前面的点
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "登录成功",
		"user": map[string]interface{}{
			"username":    user.Username,
			"email":       user.Email,
			"permissions": user.Permissions,
		},
	})
}

// 登出处理
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		deleteSession(cookie.Value)
	}

	// 清除Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "登出成功",
	})
}

// 检查登录状态
func checkAuthHandler(w http.ResponseWriter, r *http.Request) {
	session, valid := getSessionFromRequest(r)
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusUnauthorized,
			"message": "未登录",
		})
		return
	}

	userManager.RLock()
	user, exists := userManager.UserInfos[session.Username]
	userManager.RUnlock()

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusUnauthorized,
			"message": "用户不存在",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "已登录",
		"user": map[string]interface{}{
			"username":    user.Username,
			"email":       user.Email,
			"permissions": user.Permissions,
			"last_login":  user.LastLogin.Format("2006-01-02 15:04:05"),
		},
	})
}

// 从请求中获取会话
func getSessionFromRequest(r *http.Request) (*Session, bool) {
	// 首先尝试从Cookie获取
	cookie, err := r.Cookie("session_id")
	if err == nil {
		return validateSession(cookie.Value)
	}

	// 然后尝试从Authorization头获取
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return validateSession(parts[1])
		}
	}

	return nil, false
}

// 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 允许登录和检查认证状态的请求通过
		if r.URL.Path == "/login" || r.URL.Path == "/check-auth" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		session, valid := getSessionFromRequest(r)
		if !valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    http.StatusUnauthorized,
				"message": "请先登录",
			})
			return
		}

		// 将会话信息添加到请求上下文
		ctx := context.WithValue(r.Context(), "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ==================== 注册功能 ====================

// 注册请求结构体
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// 注册处理函数
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	// 验证输入
	if err := validateRegistration(req.Username, req.Email, req.Password); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": err.Error(),
		})
		return
	}

	// 检查用户名是否已存在
	userManager.RLock()
	_, exists := userManager.UserInfos[strings.TrimSpace(req.Username)]
	userManager.RUnlock()

	if exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusConflict,
			"message": "用户名已存在",
		})
		return
	}

	// 检查邮箱是否已存在
	if isEmailExists(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusConflict,
			"message": "邮箱已被注册",
		})
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("密码加密失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": "系统错误，请稍后重试",
		})
		return
	}

	// 创建新用户
	newUser := &Users{
		Username:    strings.TrimSpace(req.Username),
		Password:    string(hashedPassword),
		Email:       strings.ToLower(strings.TrimSpace(req.Email)),
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Permissions: []string{"read"}, // 默认权限
	}

	// 保存用户
	userManager.Lock()
	userManager.UserInfos[newUser.Username] = newUser
	err = saveUsers()
	userManager.Unlock()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": "系统错误，请稍后重试",
		})
		return
	}

	log.Printf("✅ 新用户注册成功: %s (%s)", newUser.Username, newUser.Email)

	// 创建会话并自动登录
	sessionID := createSession(newUser.Username, r)

	// 设置会话Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(sessionTimeout),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "注册成功",
		"user": map[string]interface{}{
			"username":    newUser.Username,
			"email":       newUser.Email,
			"permissions": newUser.Permissions,
		},
	})
}

// 验证注册信息
func validateRegistration(username, email, password string) error {
	// 验证用户名
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 20 {
		return fmt.Errorf("用户名长度应在3-20个字符之间")
	}

	// 用户名只能包含字母、数字、下划线和连字符
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return fmt.Errorf("用户名只能包含字母、数字、下划线和连字符")
	}

	// 验证邮箱
	email = strings.ToLower(strings.TrimSpace(email))
	if !isValidEmail(email) {
		return fmt.Errorf("请输入有效的邮箱地址")
	}

	// 验证密码
	if len(password) < 8 {
		return fmt.Errorf("密码长度至少8位")
	}

	// 密码必须包含字母和数字
	hasLetter := false
	hasNumber := false
	for _, char := range password {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
		if char >= '0' && char <= '9' {
			hasNumber = true
		}
	}
	if !hasLetter || !hasNumber {
		return fmt.Errorf("密码必须包含字母和数字")
	}

	return nil
}

// 验证邮箱格式
func isValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	return regexp.MustCompile(emailRegex).MatchString(email)
}

// 检查邮箱是否已存在
func isEmailExists(email string) bool {
	userManager.RLock()
	defer userManager.RUnlock()

	email = strings.ToLower(strings.TrimSpace(email))
	for _, user := range userManager.UserInfos {
		if strings.ToLower(user.Email) == email {
			return true
		}
	}
	return false
}

// ==================== 反爬核心功能 ====================

// 生成客户端指纹
func generateClientFingerprint(r *http.Request) string {
	ip := getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")

	data := fmt.Sprintf("%s|%s|%s|%s|%s", ip, userAgent, accept, acceptLanguage, acceptEncoding)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// 验证请求签名
func verifyRequestSignature(r *http.Request) bool {
	timestamp := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")
	signature := r.Header.Get("X-Signature")
	if timestamp == "" || nonce == "" || signature == "" {
		return false
	}

	// 检查时间戳是否在合理范围内（防止重放攻击）
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}

	requestTime := time.Unix(ts, 0)
	if time.Since(requestTime).Abs() > signatureTimeout {
		return false
	}

	// 生成期望的签名
	path := r.URL.Path
	data := fmt.Sprintf("%s|%s|%s|%s", timestamp, nonce, path, securityToken)
	expectedSignature := generateHMACSignature(data)

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// 生成HMAC签名
func generateHMACSignature(data string) string {
	h := hmac.New(sha256.New, []byte(securityToken))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 检查User-Agent
func checkUserAgent(r *http.Request) bool {
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))

	if userAgent == "" {
		return false
	}

	// 检查是否包含允许的浏览器标识
	hasValidAgent := false
	for _, agent := range allowedUserAgents {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(agent)) {
			hasValidAgent = true
			break
		}
	}

	if !hasValidAgent {
		return false
	}

	// 检查是否包含可疑的爬虫特征
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgent, pattern) {
			return false
		}
	}

	return true
}

// 检查必要的请求头
func checkRequiredHeaders(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")
	if userAgent == "" || accept == "" || acceptEncoding == "" || acceptLanguage == "" {
		return false
	}
	return true
}

// 检查IP是否被封锁
func isIPBlocked(ip string) bool {
	antiCrawler.RLock()
	defer antiCrawler.RUnlock()

	if blockTime, exists := antiCrawler.blockedIPs[ip]; exists {
		if time.Since(blockTime) < time.Hour {
			return true
		}
		// 超过1小时，解除封锁
		antiCrawler.RUnlock()
		antiCrawler.Lock()
		delete(antiCrawler.blockedIPs, ip)
		antiCrawler.Unlock()
		antiCrawler.RLock()
	}
	return false
}

// 检测代理
func detectProxy(r *http.Request) bool {
	// 检查代理相关头部
	for _, header := range proxyHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}

	// 检查IP是否为已知代理范围
	ip := getClientIP(r)
	if isKnownProxyIP(ip) {
		return true
	}

	return false
}

// 已知代理IP检测（简化版）
func isKnownProxyIP(ip string) bool {
	// 这里可以集成IP数据库或已知代理IP列表
	// 简化实现：检查是否为内网IP或已知代理范围
	privateIPBlocks := []string{
		"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
	}

	for _, block := range privateIPBlocks {
		if strings.HasPrefix(ip, block) {
			return true
		}
	}

	return false
}

// 行为分析
func analyzeBehavior(r *http.Request, fingerprint string) bool {
	antiCrawler.Lock()
	defer antiCrawler.Unlock()

	now := time.Now()
	ip := getClientIP(r)

	// 记录请求模式
	antiCrawler.requestPatterns[ip] = append(antiCrawler.requestPatterns[ip], now)

	// 清理过期记录
	var validRequests []time.Time
	for _, t := range antiCrawler.requestPatterns[ip] {
		if now.Sub(t) <= 5*time.Minute {
			validRequests = append(validRequests, t)
		}
	}
	antiCrawler.requestPatterns[ip] = validRequests

	// 检查请求频率（5分钟内超过100次请求视为异常）
	if len(validRequests) > 100 {
		antiCrawler.blockedIPs[ip] = now
		log.Printf("🚫 IP %s 因高频请求被封锁", ip)
		return false
	}

	// 更新客户端档案
	if profile, exists := antiCrawler.clientFingerprints[fingerprint]; exists {
		profile.LastSeen = now
		profile.RequestCount++

		// 行为评分逻辑
		if profile.RequestCount > 1000 {
			profile.Score += 10
		}
		if detectProxy(r) {
			profile.Score += 20
		}
		if !checkUserAgent(r) {
			profile.Score += 30
		}

		if profile.Score > 50 {
			profile.Blocked = true
			antiCrawler.blockedIPs[ip] = now
			log.Printf("🚫 客户端 %s 因行为异常被封锁，评分: %d", fingerprint, profile.Score)
			return false
		}
	} else {
		// 创建新客户端档案
		antiCrawler.clientFingerprints[fingerprint] = &ClientProfile{
			Fingerprint:  fingerprint,
			IP:           ip,
			UserAgent:    r.Header.Get("User-Agent"),
			FirstSeen:    now,
			LastSeen:     now,
			RequestCount: 1,
			Score:        0,
			Blocked:      false,
		}
	}

	return true
}

// 安全头部验证
func verifySecurityHeaders(r *http.Request) bool {
	// 允许登录相关请求通过
	if r.URL.Path == "/login" || r.URL.Path == "/check-auth" || r.URL.Path == "/logout" {
		return true
	}

	// 1. 检查必要头部
	if !checkRequiredHeaders(r) && r.URL.Path != "/ws" {
		log.Printf("🚫 缺少必要请求头 from %s", getClientIP(r))
		return false
	}

	// 2. 检查User-Agent
	if !checkUserAgent(r) {
		log.Printf("🚫 无效User-Agent from %s: %s", getClientIP(r), r.Header.Get("User-Agent"))
		return false
	}

	// 3. 检查IP是否被封锁
	ip := getClientIP(r)
	if isIPBlocked(ip) {
		log.Printf("🚫 已封锁IP访问: %s", ip)
		return false
	}

	// 4. 生成客户端指纹
	fingerprint := generateClientFingerprint(r)

	// 5. 行为分析
	if !analyzeBehavior(r, fingerprint) {
		return false
	}

	// 6. 对于敏感端点，强制签名验证
	sensitiveEndpoints := []string{"/exec", "/status-ifaces"}
	currentPath := r.URL.Path
	for _, endpoint := range sensitiveEndpoints {
		if currentPath == endpoint {
			if !verifyRequestSignature(r) {
				log.Printf("🚫 签名验证失败 from %s for %s", ip, currentPath)
				return false
			}
		}
	}

	return true
}

// 跨域检查
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // 允许没有Origin头的请求（可能是同源请求）
	}

	// 允许的域名列表
	allowedDomains := []string{
		"https://example.com",
		"https://www.example.com",
		"http://localhost:9000",
		"http://127.0.0.1:9000",
	}

	for _, domain := range allowedDomains {
		if strings.HasPrefix(origin, domain) {
			return true
		}
	}

	log.Printf("🚫 阻止跨域请求: %s from %s", origin, getClientIP(r))
	return false
}

// 安全中间件
func securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 安全验证
		if !verifySecurityHeaders(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    http.StatusForbidden,
				"message": "Access denied",
			})
			return
		}

		// 添加安全头部
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	}
}

// ==================== 保存队列管理 ====================

// 安排保存下载令牌（使用队列避免并发保存）
func scheduleSaveDownloadTokens() {
	select {
	case downloadTokenSaveChan <- struct{}{}:
		// 启动保存
		go func() {
			defer func() {
				<-downloadTokenSaveChan
			}()
			if err := saveDownloadTokens(); err != nil {
				log.Printf("保存下载令牌失败: %v", err)
			}
		}()
	default:
		// 已经有保存任务在运行，跳过
	}
}

// 安排保存用户数据（使用队列避免并发保存）
func scheduleSaveUsers() {
	select {
	case userSaveChan <- struct{}{}:
		go func() {
			defer func() {
				<-userSaveChan
			}()
			if err := saveUsers(); err != nil {
				log.Printf("保存用户数据失败: %v", err)
			}
		}()
	default:
		// 已经有保存任务在运行
	}
}

// ==================== 原有功能（增加认证中间件） ====================

// 获取主机信息函数
func getHostInfo() (*host.InfoStat, error) {
	hostInfoMutex.Lock()
	defer hostInfoMutex.Unlock()

	// 如果已经获取过且没有错误，直接返回缓存的信息
	if hostInfo != nil && hostInfoErr == nil {
		return hostInfo, nil
	}

	// 重新获取主机信息
	hostInfo, hostInfoErr = host.Info()
	if hostInfoErr != nil {
		log.Printf("获取主机信息失败: %v", hostInfoErr)
		return nil, hostInfoErr
	}

	return hostInfo, nil
}

func enableCORSh(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// 加载持久化数据
func loadData() {
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		// 如果数据文件不存在，设置启动时间为当前时间
		serverStartTime = time.Now()
		saveData()
		log.Printf("✅ 创建新的数据文件，启动时间: %s", serverStartTime.Format("2006-01-02 15:04:05"))
		return
	}

	file, err := os.Open(dataFile)
	if err != nil {
		log.Println("读取数据文件失败:", err)
		// 如果读取失败，使用当前时间作为启动时间
		serverStartTime = time.Now()
		return
	}
	defer file.Close()

	var data PersistData
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		log.Println("解析数据文件失败:", err)
		// 如果解析失败，使用当前时间作为启动时间
		serverStartTime = time.Now()
		return
	}

	totalUploadAccum = data.TotalUploadAccum
	totalDownloadAccum = data.TotalDownloadAccum
	accessStats.DailyVisits = data.AccessStats.DailyVisits
	accessStats.WeeklyVisits = data.AccessStats.WeeklyVisits

	// 解析启动时间
	if data.StartTime != "" {
		parsedTime, err := time.Parse("2006-01-02 15:04:05", data.StartTime)
		if err != nil {
			log.Printf("解析启动时间失败: %v，使用当前时间", err)
			serverStartTime = time.Now()
		} else {
			serverStartTime = parsedTime
		}
	} else {
		// 如果启动时间不存在，设置为当前时间
		serverStartTime = time.Now()
	}

	log.Printf("✅ 数据加载完成，服务器启动时间: %s", serverStartTime.Format("2006-01-02 15:04:05"))
}

// 保存持久化数据
func saveData() {
	accessStats.RLock()
	data := PersistData{
		TotalUploadAccum:   totalUploadAccum,
		TotalDownloadAccum: totalDownloadAccum,
		AccessStats: AccessStatsSnapshot{
			DailyVisits:  accessStats.DailyVisits,
			WeeklyVisits: accessStats.WeeklyVisits,
		},
		StartTime: serverStartTime.Format("2006-01-02 15:04:05"),
	}
	accessStats.RUnlock()

	file, err := os.OpenFile(dataFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Println("保存数据文件失败:", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Println("写入数据文件失败:", err)
	}
}

// 速率限制器结构体
type RateLimiter struct {
	sync.RWMutex
	requests    map[string][]time.Time
	limit       int
	window      time.Duration
	cleanupTick *time.Ticker
}

// 创建新的速率限制器
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	// 启动定期清理过期记录的goroutine
	rl.cleanupTick = time.NewTicker(time.Minute * 5)
	go rl.cleanupExpired()

	return rl
}

// 检查是否允许请求
func (rl *RateLimiter) Allow(ip string) bool {
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()

	// 清理过期请求
	var validRequests []time.Time
	for _, t := range rl.requests[ip] {
		if now.Sub(t) <= rl.window {
			validRequests = append(validRequests, t)
		}
	}
	rl.requests[ip] = validRequests

	// 检查是否超过限制
	if len(rl.requests[ip]) >= rl.limit {
		return false
	}

	// 添加新请求
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// 定期清理过期记录
func (rl *RateLimiter) cleanupExpired() {
	for range rl.cleanupTick.C {
		rl.Lock()
		now := time.Now()
		for ip, requests := range rl.requests {
			var validRequests []time.Time
			for _, t := range requests {
				if now.Sub(t) <= rl.window {
					validRequests = append(validRequests, t)
				}
			}
			if len(validRequests) == 0 {
				delete(rl.requests, ip)
			} else {
				rl.requests[ip] = validRequests
			}
		}
		rl.Unlock()
	}
}

// 停止清理goroutine
func (rl *RateLimiter) Stop() {
	if rl.cleanupTick != nil {
		rl.cleanupTick.Stop()
	}
}

// 全局速率限制器实例
var globalRateLimiter = NewRateLimiter(rateLimit, rateLimitDuration)

/*--------------------日志-------------------------*/
var logFile *os.File

func init() {
	setupLog()
	go scheduleLogRotation()
}

func setupLog() {
	// 创建日志目录（如果不存在）
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("创建日志目录失败: %v", err)
	}

	// 关闭旧日志文件（如果存在）
	if logFile != nil {
		logFile.Close()
	}

	// 创建新的日志文件，使用当前日期作为文件名
	logFileName := time.Now().Format(time.DateOnly) + ".log"
	logFilePath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("打开日志文件失败: %v", err)
	}

	logFile = file

	// 设置输出到控制台和新日志文件
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
}

func scheduleLogRotation() {
	// 计算到下一个0点的时间
	next := nextMidnight()
	timer := time.NewTimer(next)

	for {
		<-timer.C
		setupLog()

		// 重新计算到下一个0点的时间并重置定时器
		next = nextMidnight()
		timer.Reset(next)
	}
}

func nextMidnight() time.Duration {
	now := time.Now()
	// 计算下一个0点时间
	next := now.Add(24 * time.Hour)
	next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
	return next.Sub(now)
}

// 清理过期会话
func cleanupExpiredSessions() {
	userManager.Lock()
	defer userManager.Unlock()

	now := time.Now()
	for sessionID, session := range userManager.Sessions {
		if now.After(session.ExpiresAt) {
			delete(userManager.Sessions, sessionID)
		}
	}
	log.Println("✅ 过期会话清理完成")
}

// 清理反爬数据
func cleanupAntiCrawlerData() {
	antiCrawler.Lock()
	defer antiCrawler.Unlock()

	now := time.Now()

	// 清理过期的封锁IP
	for ip, blockTime := range antiCrawler.blockedIPs {
		if now.Sub(blockTime) > 24*time.Hour {
			delete(antiCrawler.blockedIPs, ip)
		}
	}

	// 清理过期的请求模式数据
	for ip, requests := range antiCrawler.requestPatterns {
		var validRequests []time.Time
		for _, t := range requests {
			if now.Sub(t) <= time.Hour {
				validRequests = append(validRequests, t)
			}
		}
		if len(validRequests) == 0 {
			delete(antiCrawler.requestPatterns, ip)
		} else {
			antiCrawler.requestPatterns[ip] = validRequests
		}
	}

	log.Println("✅ 反爬数据清理完成")
}

func listEpubs(w http.ResponseWriter, r *http.Request) {
	dir := "/root/file/static" // EPUB 文件所在目录
	var urls []string

	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理 .epub 文件
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".epub") {
			urls = append(urls, url+info.Name())
		}
		return nil
	})

	if err != nil {
		http.Error(w, "读取 EPUB 目录失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(urls)
}

// ---------------- 在线用户处理 ----------------
func updateOnlineUser(r *http.Request, page string) {
	ip := getClientIP(r)
	userAgent := r.UserAgent()
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// 创建唯一标识符：IP + UserAgent
	userKey := fmt.Sprintf("%s|%s", ip, userAgent)

	onlineUsers.Lock()
	defer onlineUsers.Unlock()

	// 更新或添加用户
	onlineUsers.Users[userKey] = &OnlineUser{
		IP:        ip,
		UserAgent: userAgent,
		Since:     time.Now(),
		Page:      page,
	}
}

func getClientIP(r *http.Request) string {
	// 首先检查 X-Forwarded-For 头
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// 取第一个 IP（可能有多个，用逗号分隔）
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// 如果是 IPv6 地址且被方括号包围（如 [::1]），去除方括号
			if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
				return ip[1 : len(ip)-1]
			}
			return ip
		}
	}

	// 如果没有代理，直接从 RemoteAddr 获取
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 如果分割失败，尝试直接使用（可能是没有端口的情况）
		return r.RemoteAddr
	}

	// 处理 IPv6 地址（可能带有方括号）
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}

	return host
}

// 获取在线用户统计信息和详细列表
func getOnlineUsersStats() (int, []string, []OnlineUserInfo) {
	onlineUsers.RLock()
	defer onlineUsers.RUnlock()

	onlineCount := len(onlineUsers.Users)
	ipSet := make(map[string]bool)
	userList := make([]OnlineUserInfo, 0, onlineCount)

	for _, user := range onlineUsers.Users {
		ipSet[user.IP] = true
		// 添加用户详细信息到列表
		userList = append(userList, OnlineUserInfo{
			IP:        user.IP,
			UserAgent: user.UserAgent,
			Since:     user.Since.Format("2006-01-02 15:04:05"),
			Page:      user.Page,
		})
	}

	// 获取唯一IP列表
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}

	return onlineCount, ipList, userList
}

// ---------------- 访问统计 ----------------
func accessStatsHandler(w http.ResponseWriter, r *http.Request) {
	accessStats.RLock()
	defer accessStats.RUnlock()

	recentDays := make(map[string]int)
	now := time.Now()
	for i := 0; i < 7; i++ {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		recentDays[date] = accessStats.DailyVisits[date]
	}

	recentWeeks := make(map[string]int)
	for i := 0; i < 4; i++ {
		week := now.AddDate(0, 0, -7*i).Format("2006-01")
		recentWeeks[week] = accessStats.WeeklyVisits[week]
	}

	totalVisits := 0
	for _, count := range accessStats.DailyVisits {
		totalVisits += count
	}

	stats := map[string]interface{}{
		"daily_visits":  recentDays,
		"weekly_visits": recentWeeks,
		"total_visits":  totalVisits,
		"start_time":    serverStartTime.Format("2006-01-02 15:04:05"), // 添加启动时间到响应
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func resetDailyStats() {
	for {
		now := time.Now()
		next := now.Add(24 * time.Hour)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
		duration := next.Sub(now)
		time.Sleep(duration)

		accessStats.Lock()
		week := now.Format("2006-01")
		accessStats.WeeklyVisits[week] += accessStats.DailyVisits[now.Format("2006-01-02")]
		today := time.Now().Format("2006-01-02")
		accessStats.DailyVisits[today] = 0
		accessStats.UniqueVisitors[today] = make(map[string]bool)
		accessStats.Unlock()
	}
}

func recordAccess(r *http.Request) {
	ip := getClientIP(r)

	today := time.Now().Format("2006-01-02")

	accessStats.Lock()
	defer accessStats.Unlock()

	if _, exists := accessStats.UniqueVisitors[today]; !exists {
		accessStats.UniqueVisitors[today] = make(map[string]bool)
	}

	if !accessStats.UniqueVisitors[today][ip] {
		accessStats.UniqueVisitors[today][ip] = true
		accessStats.DailyVisits[today]++
	}
}

// ---------------- 媒体文件 ----------------
func randomMediaHandler(w http.ResponseWriter, r *http.Request) {
	// 添加速率限制检查
	clientIP := getClientIP(r)
	if !globalRateLimiter.Allow(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": http.StatusTooManyRequests,
			"msg":  "Rate limit exceeded. Please try again later.",
		})
		return
	}

	//记录访问
	recordAccess(r)
	updateOnlineUser(r, "random-media")

	type fileUrl struct {
		Src  string `json:"src"`
		Code int32  `json:"code"`
	}
	s := new(fileUrl)
	rand.NewSource(time.Now().UnixNano())

	if num != 0 && len(files) == 0 {
		s.Code = 1
		json.NewEncoder(w).Encode(s)
		return
	}

	if num > 0 && key <= 10 {
		key++
		randIdx := rand.Intn(len(files))
		s.Code = http.StatusOK
		s.Src = url + files[randIdx]
		json.NewEncoder(w).Encode(s)
	} else {
		key = 0
		num = 0
		files = nil
		files = make([]string, 0, 40)
		err := filepath.WalkDir(mediaDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext == ".jpg" || ext == ".png" || ext == ".jpeg" || ext == ".mp4" || ext == ".webm" {
				files = append(files, d.Name())
				num++
			}
			return nil
		})
		if err != nil {
			log.Println(err)
			http.Error(w, "Error reading media folder", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if len(files) == 0 {
			s.Code = 1
			json.NewEncoder(w).Encode(s)
			return
		}

		randIdx := rand.Intn(len(files))
		s.Code = http.StatusOK
		s.Src = url + files[randIdx]
		json.NewEncoder(w).Encode(s)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "video")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData, err := os.ReadFile("/root/os/templates/video.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取 HTML 文件: %v", err), http.StatusInternalServerError)
		log.Printf("读取 video.html 失败: %v", err)
		return
	}
	_, err = w.Write(htmlData)
	if err != nil {
		http.Error(w, fmt.Sprintf("err: %v", err), http.StatusInternalServerError)
		log.Printf("写入响应失败: %v", err)
	}
}

func ifacesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "status-ifaces")
	ifaces, err := psnet.Interfaces()
	if err != nil {
		http.Error(w, "Error fetching interfaces", http.StatusInternalServerError)
		return
	}
	names := []string{}
	for _, i := range ifaces {
		if len(i.HardwareAddr) > 0 {
			names = append(names, i.Name)
		}
	}
	json.NewEncoder(w).Encode(names)
}

// ---------------- WebSocket ----------------
func wsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "websocket")
	//token := r.URL.Query().Get("token")
	//if token != authToken {
	//	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	//	return
	//}
	iface := r.URL.Query().Get("iface")
	if iface == "" {
		http.Error(w, "iface required", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket Upgrade Error:", err)
		return
	}

	// 获取用户标识
	ip := getClientIP(r)
	userAgent := r.UserAgent()
	userKey := fmt.Sprintf("%s|%s", ip, userAgent)

	// 设置连接参数
	conn.SetReadLimit(512)                                 // 限制消息大小
	conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // 设置读超时
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	ticker := time.NewTicker(1 * time.Second)
	pingTicker := time.NewTicker(30 * time.Second) // 每30秒发送一次ping
	defer func() {
		ticker.Stop()
		pingTicker.Stop()
		// 连接关闭时移除用户
		onlineUsers.Lock()
		delete(onlineUsers.Users, userKey)
		onlineUsers.Unlock()
		conn.Close()
	}()

	for {
		select {
		case <-ticker.C:
			// 更新在线用户时间
			updateOnlineUser(r, "websocket")

			status, err := getServerStatus(iface)
			if err != nil {
				log.Println("Error getting status:", err)
				return
			}

			// 设置写超时
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			data, err := json.Marshal(status)
			if err != nil {
				log.Println("JSON Marshal Error:", err)
				return
			}

			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println("WebSocket Write Error:", err)
				return
			}
		case <-pingTicker.C:
			// 发送ping消息检测连接状态
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("WebSocket Ping Error:", err)
				return
			}
		}
	}
}

// ---------------- Server Status ----------------
func getServerStatus(iface string) (*ServerStatus, error) {
	now := time.Now()

	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	loadAvg, err := load.Avg()
	if err != nil {
		return nil, err
	}

	netIOs, err := psnet.IOCounters(true)
	if err != nil {
		return nil, err
	}
	var uploadSpeed, downloadSpeed float64
	for _, io := range netIOs {
		if io.Name != iface {
			continue
		}
		last := lastNetStats[iface]
		if !last.Time.IsZero() {
			secs := now.Sub(last.Time).Seconds()
			if secs > 0 {
				uploadSpeed = float64(io.BytesSent-last.BytesSent) / 1024 / secs
				downloadSpeed = float64(io.BytesRecv-last.BytesRecv) / 1024 / secs
				totalUploadAccum += uint64(io.BytesSent-last.BytesSent) / 1024
				totalDownloadAccum += uint64(io.BytesRecv-last.BytesRecv) / 1024
			}
		}
		lastNetStats[iface] = NetStat{
			BytesSent: io.BytesSent,
			BytesRecv: io.BytesRecv,
			Time:      now,
		}
		break
	}

	diskIOs, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}
	var readSpeed, writeSpeed float64
	for name, io := range diskIOs {
		last := lastDiskStats[name]
		if !last.Time.IsZero() {
			secs := now.Sub(last.Time).Seconds()
			if secs > 0 {
				readSpeed += float64(io.ReadBytes-last.ReadBytes) / 1024 / secs
				writeSpeed += float64(io.WriteBytes-last.WriteBytes) / 1024 / secs
			}
		}
		lastDiskStats[name] = DiskStat{
			ReadBytes:  io.ReadBytes,
			WriteBytes: io.WriteBytes,
			Time:       now,
		}
	}

	// 使用持久化的服务器启动时间计算运行时间
	uptime := time.Since(serverStartTime)
	hours := int(uptime.Hours())
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60
	uptimeStr := fmt.Sprintf("%d小时%d分%d秒", hours, minutes, seconds)

	// 获取在线用户统计信息和详细列表
	onlineCount, uniqueIPs, onlineUsersList := getOnlineUsersStats()

	// 获取主机信息
	hostInfo, err := getHostInfo()
	var hostname, osName, platform, kernelVersion string

	if err == nil && hostInfo != nil {
		hostname = hostInfo.Hostname
		osName = hostInfo.OS
		platform = hostInfo.Platform
		kernelVersion = hostInfo.KernelVersion
	} else {
		// 如果获取失败，使用备用方法
		hostname, _ = os.Hostname()
		osName = runtime.GOOS
		platform = runtime.GOOS
		kernelVersion = "unknown"
	}

	return &ServerStatus{
		CPUUsage:      cpuPercent[0],
		MemoryUsage:   memInfo.UsedPercent,
		MemoryTotal:   memInfo.Total / 1024 / 1024,
		DiskUsage:     diskInfo.UsedPercent,
		DiskTotal:     diskInfo.Total / 1024 / 1024 / 1024,
		UploadSpeed:   uploadSpeed,
		DownloadSpeed: downloadSpeed,
		TotalUpload:   formatBytes(totalUploadAccum),
		TotalDownload: formatBytes(totalDownloadAccum),
		ReadSpeed:     readSpeed,
		WriteSpeed:    writeSpeed,
		Load1:         loadAvg.Load1,
		Load5:         loadAvg.Load5,
		Load15:        loadAvg.Load15,
		Uptime:        uptimeStr,
		OnlineCount:   onlineCount,
		UniqueIPs:     uniqueIPs,
		OnlineUsers:   onlineUsersList,
		Hostname:      hostname,
		OS:            osName,
		Platform:      platform,
		KernelVersion: kernelVersion,
		Architecture:  runtime.GOARCH,
	}, nil
}

func formatBytes(kb uint64) string {
	const (
		KB = 1
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case kb >= GB:
		return fmt.Sprintf("%.2f GB", float64(kb)/float64(GB))
	case kb >= MB:
		return fmt.Sprintf("%.2f MB", float64(kb)/float64(MB))
	default:
		return fmt.Sprintf("%d KB", kb)
	}
}

// ---------------- 安全命令执行接口 ----------------
var allowedCommands = map[string][]string{
	"uptime": {},
	"df":     {"-h"},
	"free":   {"-m"},
	"who":    {},
	"uname":  {"-a"},
	"ls":     {"-lh", "/"},
}

func execHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "exec")

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token != authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cmdName := r.URL.Query().Get("command")
	if cmdName == "" {
		http.Error(w, "Missing command parameter", http.StatusBadRequest)
		return
	}

	args, ok := allowedCommands[cmdName]
	if !ok {
		http.Error(w, "Command not allowed", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdName, args...)
	output, err := cmd.CombinedOutput()

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
			"output":  string(output),
		})
		return
	}

	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"output": string(output),
	})
	if err != nil {
		log.Println("err:", err)
		return
	}
}

// ==================== 主函数 ====================
func main() {
	// 初始化用户系统
	loadUsers()

	// 初始化数据
	loadData()

	// 初始化下载令牌系统
	initDownloadTokenManager()

	// 确保在程序退出时停止速率限制器的清理goroutine
	defer globalRateLimiter.Stop()

	// 启动时获取主机信息
	go func() {
		_, err := getHostInfo()
		if err != nil {
			log.Printf("初始化主机信息失败: %v", err)
		} else {
			log.Println("✅ 主机信息获取完成")
		}
	}()

	// 定时保存数据
	go func() {
		for {
			time.Sleep(30 * time.Second)
			saveData()
		}
	}()

	// 定时清理过期会话
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()

	// 监听退出信号
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		saveData()
		log.Println("程序退出，数据已保存")
		os.Exit(0)
	}()

	// 每日统计重置
	go resetDailyStats()

	// 定期清理反爬数据
	go func() {
		ticker := time.NewTicker(time.Hour)
		for range ticker.C {
			cleanupAntiCrawlerData()
		}
	}()

	// 注册认证相关路由
	http.HandleFunc("/login", securityMiddleware(loginHandler))
	http.HandleFunc("/logout", securityMiddleware(logoutHandler))
	http.HandleFunc("/register", securityMiddleware(registerHandler))
	http.HandleFunc("/check-auth", securityMiddleware(checkAuthHandler))

	// 注册下载相关路由
	http.HandleFunc("/generate-download-token", authMiddleware(securityMiddleware(generateDownloadTokenHandler)))
	http.HandleFunc("/download", securityMiddleware(secureDownloadHandler))
	http.HandleFunc("/list-download-tokens", authMiddleware(securityMiddleware(listDownloadTokensHandler)))
	http.HandleFunc("/revoke-download-token", authMiddleware(securityMiddleware(revokeDownloadTokenHandler)))

	// 使用认证中间件和安全中间件包装所有处理函数
	http.Handle("/", http.FileServer(http.Dir("/root/os/templates")))
	//http.HandleFunc("/location", authMiddleware(securityMiddleware(handleWebSocket)))
	http.HandleFunc("/health", authMiddleware(securityMiddleware(healthCheck)))
	http.HandleFunc("/ws", authMiddleware(securityMiddleware(wsHandler)))
	http.HandleFunc("/video", authMiddleware(securityMiddleware(homeHandler)))
	http.HandleFunc("/status-ifaces", enableCORSh(authMiddleware(securityMiddleware(ifacesHandler))))
	http.HandleFunc("/random-media", enableCORSh(authMiddleware(securityMiddleware(randomMediaHandler))))
	http.HandleFunc("/access-stats", authMiddleware(securityMiddleware(accessStatsHandler)))
	http.HandleFunc("/exec", authMiddleware(securityMiddleware(execHandler)))
	http.HandleFunc("/epubs", enableCORSh(authMiddleware(securityMiddleware(listEpubs))))

	fmt.Println("Server running at https://localhost:9000")
	log.Printf("服务器启动时间: %s", serverStartTime.Format("2006-01-02 15:04:05"))
	log.Fatal(http.ListenAndServeTLS(":9000", "/root/ssl/example.com.pem", "/root/ssl/example.com.key", nil))
}
