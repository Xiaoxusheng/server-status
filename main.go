package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	rand2 "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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
	psprocess "github.com/shirou/gopsutil/v3/process"
	"golang.org/x/crypto/bcrypt"
)

// ==================== 可配置项 ====================
// 编译期不再绑定任何域名 / 路径 / 端口，全部支持环境变量覆盖（详见 README「配置说明」）：
//
//	SERVER_STATUS_HOME             数据根目录（模板 / 数据文件 / 日志 / TLS 证书默认都在它下面）
//	SERVER_STATUS_MEDIA_DIR        媒体文件目录（默认 <数据根目录>/media）
//	SERVER_STATUS_TLS_CERT / _KEY  TLS 证书与私钥（默认 <数据根目录>/tls/cert.pem、key.pem）
//	SERVER_STATUS_DOMAIN           对外域名（跨域白名单、证书探测显示；localhost 表示本机调试）
//	SERVER_STATUS_LISTEN_ADDR      HTTPS 监听地址（默认 :9000）
//	SERVER_STATUS_STATIC_BASE_URL  随机媒体外链基地址（留空回退为同源会话鉴权的 /api/media）
//	SERVER_STATUS_EXTRA_ORIGINS    额外跨域白名单 Origin，逗号分隔
var (
	mediaDir          = getEnvOr("SERVER_STATUS_MEDIA_DIR", filepath.Join(dataRoot(), "media"))
	indexPath         = getEnvOr("SERVER_STATUS_TEMPLATES_DIR", filepath.Join(dataRoot(), "templates")) //index.html 文件所在目录
	dataFile          = filepath.Join(dataRoot(), "server_data.json")                                   //服务器数据保存路径
	rateLimit         = 10                                                                              // 每分钟最大请求数
	rateLimitDuration = time.Minute                                                                     // 速率限制时间窗口
	usersFile         = filepath.Join(dataRoot(), "users.json")                                         // 用户数据文件
	sessionTimeout    = 24 * time.Hour                                                                  // 会话超时时间

	dir = mediaDir // EPUB 文件所在目录（与媒体目录共用）
	// TLS 证书配置
	tlsCertFile = getEnvOr("SERVER_STATUS_TLS_CERT", filepath.Join(dataRoot(), "tls", "cert.pem")) // TLS 证书文件路径
	tlsKeyFile  = getEnvOr("SERVER_STATUS_TLS_KEY", filepath.Join(dataRoot(), "tls", "key.pem"))   // TLS 私钥文件路径
	tlsDomain   = getEnvOr("SERVER_STATUS_DOMAIN", "localhost")                                    // 证书绑定的主域名（SNI / 跨域白名单用）
	listenAddr  = getEnvOr("SERVER_STATUS_LISTEN_ADDR", ":9000")                                   // HTTPS 监听地址
	// 随机媒体外链基地址：留空时回退为同源 /api/media（会话鉴权，无需额外静态服务器）
	staticBaseURL = getEnvOr("SERVER_STATUS_STATIC_BASE_URL", "")
	// 下载令牌配置
	downloadTokenExpiry = 30 * time.Minute                                  // 下载令牌有效期
	downloadLimitBytes  = 3 * 1024 * 1024 * 1024                            // 下载限制
	downloadTokensFile  = filepath.Join(dataRoot(), "download_tokens.json") // 下载令牌存储文件
)

// dataRoot 数据根目录：模板、运行数据、日志、TLS 证书的默认存放位置。
// 生产默认 /opt/server-status，可用 SERVER_STATUS_HOME 整体覆盖（Docker / 本地开发常用）。
func dataRoot() string {
	if root := os.Getenv("SERVER_STATUS_HOME"); root != "" {
		return root
	}
	return "/opt/server-status"
}

// CSRF 相关标识
const (
	csrfCookieName = "csrf_token" // 会话绑定 CSRF Token 的 Cookie（JS 可读）
	csrfHeaderName = "X-CSRF-Token"
)

// 仅服务端持有的密钥与签名材料。
// 说明：以下值属于密码学密钥（不是浏览器可见的普通配置），不得硬编码为固定密钥。
// 生产环境请通过环境变量注入；默认值仅为向后兼容旧部署，一旦配置应尽量保持不变。
var (
	// encryptionKey 用户数据（私人手记等）AES-GCM 加密密钥。环境变量：SERVER_STATUS_ENCRYPT_KEY
	encryptionKey = getEnvOr("SERVER_STATUS_ENCRYPT_KEY", "server_status_user_data_encryption_key_2024")
	// downloadTokenSecret 下载令牌签名密钥。环境变量：SERVER_STATUS_DOWNLOAD_TOKEN_SECRET
	downloadTokenSecret = getEnvOr("SERVER_STATUS_DOWNLOAD_TOKEN_SECRET", "server_status_download_token_secret_2024")
	// serverSigningKey 仅服务端持有的 HMAC 签名密钥（私有入口 Cookie、分享密码 Cookie、下载令牌）。
	// 优先取环境变量 SERVER_STATUS_SIGNING_KEY；未设置时用 crypto/rand 随机生成并告警。
	serverSigningKey = initSigningKey()
)

// getEnvOr 读取环境变量，若为空则返回 fallback 默认值。
func getEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// initSigningKey 初始化仅服务端持有的签名密钥：优先取环境变量，否则用 crypto/rand 随机生成。
func initSigningKey() string {
	if v := os.Getenv("SERVER_STATUS_SIGNING_KEY"); v != "" {
		return v
	}
	b := make([]byte, 32)
	if _, err := rand2.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	// crypto/rand 几乎不会失败；此处仅作极端兜底，绝不回落到任何固定字符串。
	return fmt.Sprintf("%s:rand-fallback", fallbackSigningDigest(time.Now().UnixNano()+int64(os.Getpid())))
}

// fallbackSigningDigest 对整数做 SHA-256 散列，仅用于签名密钥的极端兜底场景。
func fallbackSigningDigest(n int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", n, runtime.NumGoroutine())))
	return hex.EncodeToString(h[:])
}

// logDir 日志目录（默认 <数据根目录>/log，可用 SERVER_STATUS_HOME 覆盖便于本地测试/开发）
var logDir = defaultLogDir()

// 版本信息（由 CI 通过 -ldflags "-X" 注入，本地构建时为 dev）
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func defaultLogDir() string {
	return filepath.Join(dataRoot(), "log")
}

// 用户相关结构体
type Users struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"` // bcrypt加密后的密码
	Email       string    `json:"email"`
	RoleID      string    `json:"role_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
	IsActive    bool      `json:"is_active"`
	Permissions []string  `json:"permissions"`
}

// PermissionDef 权限定义
type PermissionDef struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Group       string `json:"group"`
	Description string `json:"description"`
}

// Role 角色定义
type Role struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// RBACManager 角色权限管理器
type RBACManager struct {
	sync.RWMutex
	Roles map[string]*Role `json:"roles"`
}

// ==================== RBAC 权限管理核心 ====================

// allPermissions 系统支持的权限定义
var allPermissions = []PermissionDef{
	{Key: "system:view", Name: "查看服务器状态", Group: "系统", Description: "查看实时监控、网络接口、访问统计"},
	{Key: "system:exec", Name: "执行系统命令", Group: "系统", Description: "执行白名单内的系统管理命令"},
	{Key: "system:log", Name: "查看系统日志", Group: "系统", Description: "在线查看与检索服务器运行日志及历史归档"},
	{Key: "files:view", Name: "查看媒体文件", Group: "文件", Description: "查看视频、电子书、随机媒体等内容"},
	{Key: "files:download", Name: "下载文件", Group: "文件", Description: "通过安全下载页或下载令牌下载服务器文件"},
	{Key: "files:manage", Name: "管理文件", Group: "文件", Description: "浏览、上传、删除服务器文件目录"},
	{Key: "token:view", Name: "查看下载令牌", Group: "文件", Description: "查看全部用户的下载令牌列表"},
	{Key: "token:revoke", Name: "撤销下载令牌", Group: "文件", Description: "撤销任意用户的下载令牌（高危操作，默认仅超级管理员）"},
	{Key: "token:issue", Name: "下发下载令牌", Group: "文件", Description: "为自己签发下载令牌，并设置有效期和流量上限"},
	{Key: "system:process", Name: "查看进程列表", Group: "系统", Description: "查看服务器进程占用情况（CPU/内存）"},
	{Key: "system:kill", Name: "结束进程", Group: "系统", Description: "结束/强制结束服务器进程（高危操作，默认仅超级管理员）"},
	{Key: "ip:manage", Name: "管理IP封禁", Group: "系统", Description: "查看访问IP并封禁/解封异常IP"},
	{Key: "user:view", Name: "查看用户", Group: "用户", Description: "查看系统用户列表"},
	{Key: "user:manage", Name: "管理用户", Group: "用户", Description: "创建、编辑、禁用、删除用户"},
	{Key: "role:manage", Name: "管理角色", Group: "用户", Description: "创建、编辑、删除角色及其权限"},
	{Key: "service:view", Name: "查看服务与端口", Group: "服务与端口", Description: "查看 systemd 服务列表、状态、日志与监听端口"},
	{Key: "service:manage", Name: "管理服务", Group: "服务与端口", Description: "创建/编辑服务，启停、重启、切换开机自启"},
	{Key: "service:delete", Name: "删除服务", Group: "服务与端口", Description: "删除本系统创建的服务定义"},
	{Key: "port:view", Name: "查看端口", Group: "服务与端口", Description: "查看监听端口、端口详情与变化"},
	{Key: "port:manage", Name: "管理端口", Group: "服务与端口", Description: "开放/关闭端口公网访问，管理端口规则"},
	{Key: "trojan:manage", Name: "管理 Trojan-Go", Group: "服务与端口", Description: "查看 Trojan-Go 状态并管理用户"},
	{Key: "docker:view", Name: "查看 Docker 容器", Group: "服务与端口", Description: "查看容器列表、状态、资源占用与日志"},
	{Key: "docker:manage", Name: "管理 Docker 容器", Group: "服务与端口", Description: "启动、停止、重启容器"},
	{Key: "private:view", Name: "访问隐藏私人空间", Group: "系统", Description: "通过隐藏入口进入私人空间（默认仅超级管理员拥有）"},
}

// defaultRoles 返回系统内置的默认角色
func defaultRoles() map[string]*Role {
	now := time.Now()
	return map[string]*Role{
		"admin": {
			RoleID:      "admin",
			Name:        "超级管理员",
			Description: "拥有系统全部权限",
			Permissions: []string{"*"},
			IsSystem:    true,
			CreatedAt:   now,
		},
		"operator": {
			RoleID:      "operator",
			Name:        "运维人员",
			Description: "负责服务器日常运维，可查看状态并执行命令",
			Permissions: []string{"system:view", "system:log", "system:exec", "files:view", "files:download", "token:issue", "token:view", "token:revoke", "user:view", "trojan:manage", "docker:view", "docker:manage"},
			IsSystem:    true,
			CreatedAt:   now,
		},
		"user": {
			RoleID:      "user",
			Name:        "普通用户",
			Description: "可查看服务器状态及下载媒体文件",
			Permissions: []string{"system:view", "files:view", "files:download", "token:view"},
			IsSystem:    true,
			CreatedAt:   now,
		},
	}
}

// ensureDefaultRoles 确保系统内置角色始终存在，并对存量角色做一次性权限迁移
func ensureDefaultRoles() {
	rbacManager.Lock()
	defer rbacManager.Unlock()

	changed := false
	for roleID, role := range defaultRoles() {
		if _, exists := rbacManager.Roles[roleID]; !exists {
			rbacManager.Roles[roleID] = role
			changed = true
		}
	}

	// 一次性迁移：存量 operator 角色补充新增权限（system:log 查看日志 / token:issue 签发令牌）
	if role, ok := rbacManager.Roles["operator"]; ok {
		permSet := make(map[string]bool, len(role.Permissions))
		for _, p := range role.Permissions {
			permSet[p] = true
		}
		for _, need := range []string{"system:log", "token:issue"} {
			if !permSet[need] {
				role.Permissions = append(role.Permissions, need)
				changed = true
			}
		}
	}

	if changed {
		go scheduleSaveRBAC()
	}
}

// loadRBAC 从加密文件加载角色数据
func loadRBAC() {
	if _, err := os.Stat(rbacFile); os.IsNotExist(err) {
		log.Println("角色数据文件不存在，创建默认角色")
		ensureDefaultRoles()
		return
	}

	file, err := os.Open(rbacFile)
	if err != nil {
		log.Printf("读取角色数据文件失败: %v", err)
		return
	}
	defer file.Close()

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		log.Printf("读取加密角色数据失败: %v", err)
		return
	}

	decryptedData, err := decryptData(encryptedData)
	if err != nil {
		log.Printf("解密角色数据失败: %v", err)
		return
	}

	rbacManager.Lock()
	if err := json.Unmarshal(decryptedData, rbacManager); err != nil {
		rbacManager.Unlock()
		log.Printf("解析角色数据失败: %v", err)
		return
	}
	if rbacManager.Roles == nil {
		rbacManager.Roles = make(map[string]*Role)
	}
	// 权限迁移：token:manage（查看/撤销）拆分为 token:view + token:revoke
	// 旧 manage 本就只能查看全部 + 撤销自己名下（撤销自己现在走属主分支，无需权限），故保守映射为 token:view
	for _, role := range rbacManager.Roles {
		migrated := false
		for i, p := range role.Permissions {
			if p == "token:manage" {
				role.Permissions[i] = "token:view"
				migrated = true
			}
		}
		if migrated {
			log.Printf("角色权限迁移: %s 的 token:manage 已拆分为 token:view", role.RoleID)
		}
	}
	rbacManager.Unlock()

	// 确保默认角色存在
	ensureDefaultRoles()
	log.Printf("角色数据加载完成，共 %d 个角色", len(rbacManager.Roles))
}

// saveRBAC 将角色数据加密写入本地文件
func saveRBAC() error {
	rbacManager.RLock()
	data, err := json.Marshal(rbacManager)
	rbacManager.RUnlock()

	if err != nil {
		return fmt.Errorf("序列化角色数据失败: %v", err)
	}

	encryptedData, err := encryptData(data)
	if err != nil {
		return fmt.Errorf("加密角色数据失败: %v", err)
	}

	dir := filepath.Dir(rbacFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建角色数据目录失败: %v", err)
	}

	tempFile := rbacFile + ".tmp"
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

	if err := os.Rename(tempFile, rbacFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	return nil
}

// scheduleSaveRBAC 异步保存角色数据，避免频繁磁盘写入
func scheduleSaveRBAC() {
	select {
	case rbacSaveChan <- struct{}{}:
		go func() {
			defer func() {
				<-rbacSaveChan
			}()
			if err := saveRBAC(); err != nil {
				log.Printf("保存角色数据失败: %v", err)
			}
		}()
	default:
		// 已有保存任务在运行
	}
}

// initRBAC 初始化角色系统
func initRBAC() {
	loadRBAC()
}

// isValidPermission 校验权限 key 是否合法
func isValidPermission(perm string) bool {
	if perm == "*" {
		return true
	}
	for _, p := range allPermissions {
		if p.Key == perm {
			return true
		}
	}
	return false
}

// getUserEffectivePermissions 计算用户实际拥有的权限（角色权限 + 用户附加权限）
func getUserEffectivePermissions(username string) []string {
	userManager.RLock()
	user, exists := userManager.UserInfos[username]
	var roleID string
	var legacyPerms []string
	if exists {
		roleID = user.RoleID
		legacyPerms = user.Permissions
	}
	userManager.RUnlock()

	if !exists {
		return nil
	}

	permSet := make(map[string]bool)
	if roleID != "" {
		rbacManager.RLock()
		if role, ok := rbacManager.Roles[roleID]; ok {
			for _, p := range role.Permissions {
				permSet[p] = true
			}
		}
		rbacManager.RUnlock()
	}

	// 兼容旧版本直接挂载在用户上的权限
	for _, p := range legacyPerms {
		permSet[p] = true
	}

	// 兜底：admin 用户即使角色缺失也拥有全部权限
	if roleID == "" && username == "admin" {
		permSet["*"] = true
	}

	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	sort.Strings(perms)
	return perms
}

// hasPermission 判断用户是否拥有指定权限（支持 * 通配）
func hasPermission(username, perm string) bool {
	perms := getUserEffectivePermissions(username)
	for _, p := range perms {
		if p == "*" || p == perm {
			return true
		}
	}
	return false
}

// getRoleName 获取角色显示名称
func getRoleName(roleID string) string {
	if roleID == "" {
		return ""
	}
	rbacManager.RLock()
	defer rbacManager.RUnlock()
	if role, ok := rbacManager.Roles[roleID]; ok {
		return role.Name
	}
	return roleID
}

// requirePermission 基于 RBAC 的接口权限中间件
func requirePermission(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if !hasPermission(session.Username, perm) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    http.StatusForbidden,
				"message": "没有权限执行此操作",
				"require": perm,
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}

// requireAnyPermission 权限中间件：满足任意一个权限即可通过
func requireAnyPermission(perms []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		for _, p := range perms {
			if hasPermission(session.Username, p) {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "没有权限执行此操作",
		})
	}
}

// ==================== RBAC API 接口 ====================

// RoleListItem 角色列表项（含用户数）
type RoleListItem struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UserCount   int       `json:"user_count"`
}

// UserListItem 用户列表项（含角色信息）
type UserListItem struct {
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	RoleID            string    `json:"role_id"`
	RoleName          string    `json:"role_name"`
	Permissions       []string  `json:"permissions"`
	DirectPermissions []string  `json:"direct_permissions,omitempty"` // 历史遗留的用户直挂权限（隐蔽提权面，需可见治理）
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
	LastLogin         time.Time `json:"last_login"`
}

// StringList 兼容权限字段同时支持 JSON 数组和逗号分隔字符串两种格式
type StringList []string

// UnmarshalJSON 兼容常见请求格式：数组 或 "a,b,c" 字符串
func (s *StringList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		parts := strings.Split(str, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		*s = out
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*s = arr
	return nil
}

// CreateRoleRequest 创建角色请求
type CreateRoleRequest struct {
	RoleID      string     `json:"role_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Permissions StringList `json:"permissions"`
}

// UpdateRoleRequest 更新角色请求
type UpdateRoleRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Permissions StringList `json:"permissions"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleID   string `json:"role_id"`
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Email    string `json:"email"`
	RoleID   string `json:"role_id"`
	Password string `json:"password"`
	IsActive *bool  `json:"is_active"`
}

// listPermissionsHandler 返回系统全部权限定义
func listPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取权限列表成功",
		"data":    allPermissions,
	})
}

// onlineCountHandler GET /api/rbac/online-count 返回当前在线用户数
func onlineCountHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	count, _, _ := getOnlineUsersStats()
	writeJSON(w, http.StatusOK, "获取在线用户数成功", map[string]interface{}{"count": count})
}

// listRolesHandler 返回角色列表（含用户数）
func listRolesHandler(w http.ResponseWriter, r *http.Request) {
	rbacManager.RLock()
	roleList := make([]RoleListItem, 0, len(rbacManager.Roles))
	for _, role := range rbacManager.Roles {
		roleList = append(roleList, RoleListItem{
			RoleID:      role.RoleID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: append([]string(nil), role.Permissions...),
			IsSystem:    role.IsSystem,
			CreatedAt:   role.CreatedAt,
		})
	}
	rbacManager.RUnlock()

	// 统计每个角色下的用户数
	userManager.RLock()
	userCounts := make(map[string]int)
	for _, user := range userManager.UserInfos {
		if user.RoleID != "" {
			userCounts[user.RoleID]++
		}
	}
	userManager.RUnlock()

	for i := range roleList {
		roleList[i].UserCount = userCounts[roleList[i].RoleID]
	}

	sort.Slice(roleList, func(i, j int) bool {
		return roleList[i].RoleID < roleList[j].RoleID
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取角色列表成功",
		"data":    roleList,
	})
}

// getRoleHandler 返回单个角色详情（含权限）
func getRoleHandler(w http.ResponseWriter, r *http.Request) {
	roleID := r.PathValue("role_id")
	if roleID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少角色ID")
		return
	}

	rbacManager.RLock()
	role, exists := rbacManager.Roles[roleID]
	if !exists {
		rbacManager.RUnlock()
		writeJSONError(w, http.StatusNotFound, "角色不存在")
		return
	}
	item := RoleListItem{
		RoleID:      role.RoleID,
		Name:        role.Name,
		Description: role.Description,
		Permissions: append([]string(nil), role.Permissions...),
		IsSystem:    role.IsSystem,
		CreatedAt:   role.CreatedAt,
	}
	rbacManager.RUnlock()

	// 统计该角色下的用户数
	userManager.RLock()
	for _, user := range userManager.UserInfos {
		if user.RoleID == roleID {
			item.UserCount++
		}
	}
	userManager.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取角色成功",
		"data":    item,
	})
}

// createRoleHandler 创建新角色
func createRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许 POST 请求", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req CreateRoleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("⚠️ 创建角色请求体解析失败 err=%v body=%q", err, string(body))
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	req.RoleID = strings.TrimSpace(req.RoleID)
	req.Name = strings.TrimSpace(req.Name)
	if req.RoleID == "" || req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "角色ID和角色名称不能为空")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(req.RoleID) {
		writeJSONError(w, http.StatusBadRequest, "角色ID只能包含字母、数字、下划线和连字符（1-32位）")
		return
	}

	for _, p := range req.Permissions {
		if !isValidPermission(p) {
			writeJSONError(w, http.StatusBadRequest, "包含未知权限: "+p)
			return
		}
		// 通配权限仅允许内置 admin 角色持有，防止通过自建角色等价提权
		if p == "*" {
			writeJSONError(w, http.StatusForbidden, "通配权限仅限内置管理员角色")
			return
		}
	}

	rbacManager.Lock()
	if _, exists := rbacManager.Roles[req.RoleID]; exists {
		rbacManager.Unlock()
		writeJSONError(w, http.StatusConflict, "角色ID已存在")
		return
	}
	rbacManager.Roles[req.RoleID] = &Role{
		RoleID:      req.RoleID,
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		Permissions: []string(req.Permissions),
		IsSystem:    false,
		CreatedAt:   time.Now(),
	}
	rbacManager.Unlock()

	go scheduleSaveRBAC()
	log.Printf("创建角色成功: %s (%s)", req.Name, req.RoleID)
	auditAction(r, "rbac.role.create", fmt.Sprintf("role=%s permissions=%v", req.RoleID, req.Permissions))

	writeJSON(w, http.StatusOK, "角色创建成功", nil)
}

// updateRoleHandler 更新角色
func updateRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "只允许 PUT 请求", http.StatusMethodNotAllowed)
		return
	}

	roleID := r.PathValue("role_id")
	if roleID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少角色ID")
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req UpdateRoleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("⚠️ 更新角色请求体解析失败 role_id=%s err=%v body=%q", roleID, err, string(body))
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}

	for _, p := range req.Permissions {
		if !isValidPermission(p) {
			writeJSONError(w, http.StatusBadRequest, "包含未知权限: "+p)
			return
		}
	}

	// 通配权限仅允许内置 admin 角色持有，防止通过编辑非 admin 角色等价提权
	if roleID != "admin" {
		for _, p := range req.Permissions {
			if p == "*" {
				writeJSONError(w, http.StatusForbidden, "通配权限仅限内置管理员角色")
				return
			}
		}
	}

	rbacManager.Lock()
	role, exists := rbacManager.Roles[roleID]
	if !exists {
		rbacManager.Unlock()
		writeJSONError(w, http.StatusNotFound, "角色不存在")
		return
	}

	if strings.TrimSpace(req.Name) != "" {
		role.Name = strings.TrimSpace(req.Name)
	}
	role.Description = strings.TrimSpace(req.Description)

	// 内置 admin 角色强制保留全部权限，防止误操作锁死系统
	if role.RoleID == "admin" && role.IsSystem {
		role.Permissions = []string{"*"}
	} else {
		role.Permissions = []string(req.Permissions)
	}
	rbacManager.Unlock()

	go scheduleSaveRBAC()
	log.Printf("更新角色成功: %s", roleID)
	auditAction(r, "rbac.role.update", fmt.Sprintf("role=%s permissions=%v", roleID, req.Permissions))

	writeJSON(w, http.StatusOK, "角色更新成功", nil)
}

// deleteRoleHandler 删除角色
func deleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "只允许 DELETE 请求", http.StatusMethodNotAllowed)
		return
	}

	roleID := r.PathValue("role_id")
	if roleID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少角色ID")
		return
	}

	rbacManager.Lock()
	role, exists := rbacManager.Roles[roleID]
	if !exists {
		rbacManager.Unlock()
		writeJSONError(w, http.StatusNotFound, "角色不存在")
		return
	}
	if role.IsSystem {
		rbacManager.Unlock()
		writeJSONError(w, http.StatusForbidden, "系统内置角色不能删除")
		return
	}
	delete(rbacManager.Roles, roleID)
	rbacManager.Unlock()

	// 将该角色下的用户迁移到普通用户角色
	userManager.Lock()
	for _, user := range userManager.UserInfos {
		if user.RoleID == roleID {
			user.RoleID = "user"
		}
	}
	userManager.Unlock()

	go scheduleSaveRBAC()
	go scheduleSaveUsers()
	log.Printf("删除角色成功: %s", roleID)
	auditAction(r, "rbac.role.delete", "role="+roleID)

	writeJSON(w, http.StatusOK, "角色删除成功", nil)
}

// ==================== 系统日志查看 ====================

// listLogFilesHandler GET /api/logs/files
// 列出日志目录下的 .log 归档文件（名称/大小/修改时间），供日志查看页选择
func listLogFilesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(logDir)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取日志目录失败")
		return
	}

	files := make([]map[string]interface{}, 0, 16)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, map[string]interface{}{
			"name":        e.Name(),
			"size":        info.Size(),
			"modified_at": info.ModTime().Format(time.RFC3339),
		})
	}

	// 按文件名倒序（日期命名 → 最新在前）
	sort.Slice(files, func(i, j int) bool {
		return files[i]["name"].(string) > files[j]["name"].(string)
	})

	writeJSON(w, http.StatusOK, "获取日志文件列表成功", files)
}

// logContentHandler GET /api/logs?file=2026-08-28.log&tail=262144&filter=
// 读取指定日志文件末尾 tail 字节（默认 256KB，上限 2MB），支持关键字过滤，避免一次性加载超大日志
func logContentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	// 文件名安全校验：仅允许纯文件名且必须以 .log 结尾，杜绝目录穿越
	name := filepath.Base(r.URL.Query().Get("file"))
	if name == "" || name == "." || !strings.HasSuffix(name, ".log") || strings.ContainsAny(name, `/\`) {
		writeJSONError(w, http.StatusBadRequest, "非法的日志文件名")
		return
	}

	tail := int64(256 * 1024)
	if n, err := strconv.ParseInt(r.URL.Query().Get("tail"), 10, 64); err == nil && n > 0 {
		tail = n
	}
	const maxTail = int64(2 * 1024 * 1024)
	if tail > maxTail {
		tail = maxTail
	}
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	fullPath := filepath.Join(logDir, name)
	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		writeJSONError(w, http.StatusNotFound, "日志文件不存在")
		return
	}

	f, err := os.Open(fullPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "打开日志文件失败")
		return
	}
	defer f.Close()

	// 只读末尾 tail 字节；若从中间截断则丢弃首行（避免半行乱码）
	var truncated bool
	var offset int64
	if info.Size() > tail {
		truncated = true
		offset = info.Size() - tail
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取日志失败")
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, tail))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取日志失败")
		return
	}
	content := string(data)
	if truncated {
		if idx := strings.IndexByte(content, '\n'); idx >= 0 {
			content = content[idx+1:]
		}
	}

	// 关键字过滤（大小写不敏感，逐行包含匹配）
	if filter != "" {
		lower := strings.ToLower(filter)
		lines := strings.Split(content, "\n")
		kept := make([]string, 0, len(lines))
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), lower) {
				kept = append(kept, line)
			}
		}
		content = strings.Join(kept, "\n")
	}

	writeJSON(w, http.StatusOK, "获取日志内容成功", map[string]interface{}{
		"file":      name,
		"size":      info.Size(),
		"truncated": truncated,
		"content":   content,
	})
}

// listRbacUsersHandler 返回用户列表（含角色信息）
func listRbacUsersHandler(w http.ResponseWriter, r *http.Request) {
	userManager.RLock()
	userList := make([]UserListItem, 0, len(userManager.UserInfos))
	for _, user := range userManager.UserInfos {
		item := UserListItem{
			Username:  user.Username,
			Email:     user.Email,
			RoleID:    user.RoleID,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			LastLogin: user.LastLogin,
		}
		// 暴露历史遗留的直挂权限（不经角色、无管理界面，属隐蔽提权面，需可见可治理）
		if len(user.Permissions) > 0 {
			item.DirectPermissions = append([]string(nil), user.Permissions...)
		}
		userList = append(userList, item)
	}
	userManager.RUnlock()

	for i := range userList {
		userList[i].RoleName = getRoleName(userList[i].RoleID)
		userList[i].Permissions = getUserEffectivePermissions(userList[i].Username)
	}

	sort.Slice(userList, func(i, j int) bool {
		return userList[i].Username < userList[j].Username
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取用户列表成功",
		"data":    userList,
	})
}

// createRbacUserHandler 管理员创建用户
func createRbacUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许 POST 请求", http.StatusMethodNotAllowed)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if err := validateRegistration(req.Username, req.Email, req.Password); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.RoleID = strings.TrimSpace(req.RoleID)
	if req.RoleID == "" {
		req.RoleID = "user"
	}

	rbacManager.RLock()
	_, roleExists := rbacManager.Roles[req.RoleID]
	rbacManager.RUnlock()
	if !roleExists {
		writeJSONError(w, http.StatusBadRequest, "指定的角色不存在")
		return
	}

	userManager.RLock()
	_, userExists := userManager.UserInfos[strings.TrimSpace(req.Username)]
	emailExists := false
	for _, u := range userManager.UserInfos {
		if strings.EqualFold(u.Email, strings.TrimSpace(req.Email)) {
			emailExists = true
			break
		}
	}
	userManager.RUnlock()

	if userExists {
		writeJSONError(w, http.StatusConflict, "用户名已存在")
		return
	}
	if emailExists {
		writeJSONError(w, http.StatusConflict, "邮箱已被注册")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("密码加密失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "系统错误，请稍后重试")
		return
	}

	newUser := &Users{
		Username:    strings.TrimSpace(req.Username),
		Password:    string(hashedPassword),
		Email:       strings.ToLower(strings.TrimSpace(req.Email)),
		RoleID:      req.RoleID,
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Permissions: nil,
	}

	userManager.Lock()
	userManager.UserInfos[newUser.Username] = newUser
	userManager.Unlock()
	err = saveUsers()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "系统错误，请稍后重试")
		return
	}

	log.Printf("管理员创建用户成功: %s (%s)，角色: %s", newUser.Username, newUser.Email, req.RoleID)
	auditAction(r, "rbac.user.create", fmt.Sprintf("user=%s role=%s", newUser.Username, req.RoleID))
	writeJSON(w, http.StatusOK, "用户创建成功", nil)
}

// updateRbacUserHandler 更新用户（角色、邮箱、状态、密码）
func updateRbacUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "只允许 PUT 请求", http.StatusMethodNotAllowed)
		return
	}

	username := r.PathValue("username")
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户名")
		return
	}

	session, _ := getSessionFromRequest(r)

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	userManager.RLock()
	user, exists := userManager.UserInfos[username]
	userManager.RUnlock()
	if !exists {
		writeJSONError(w, http.StatusNotFound, "用户不存在")
		return
	}

	// 校验新角色
	if req.RoleID != "" && req.RoleID != user.RoleID {
		// 内置管理员账号的角色不可修改（防止被降级后系统失去管理入口）
		if username == "admin" {
			writeJSONError(w, http.StatusForbidden, "不能修改内置管理员账号的角色")
			return
		}
		rbacManager.RLock()
		_, roleExists := rbacManager.Roles[req.RoleID]
		rbacManager.RUnlock()
		if !roleExists {
			writeJSONError(w, http.StatusBadRequest, "指定的角色不存在")
			return
		}
	}

	// 校验邮箱
	if req.Email != "" && strings.ToLower(strings.TrimSpace(req.Email)) != user.Email {
		if !isValidEmail(req.Email) {
			writeJSONError(w, http.StatusBadRequest, "请输入有效的邮箱地址")
			return
		}
		userManager.RLock()
		for _, u := range userManager.UserInfos {
			if u.Username != username && strings.EqualFold(u.Email, strings.TrimSpace(req.Email)) {
				userManager.RUnlock()
				writeJSONError(w, http.StatusConflict, "邮箱已被其他用户使用")
				return
			}
		}
		userManager.RUnlock()
	}

	// 校验密码强度
	if req.Password != "" {
		if len(req.Password) < 8 {
			writeJSONError(w, http.StatusBadRequest, "密码长度至少8位")
			return
		}
		hasLetter, hasNumber := false, false
		for _, ch := range req.Password {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
				hasLetter = true
			}
			if ch >= '0' && ch <= '9' {
				hasNumber = true
			}
		}
		if !hasLetter || !hasNumber {
			writeJSONError(w, http.StatusBadRequest, "密码必须包含字母和数字")
			return
		}
	}

	var hashedPassword string
	if req.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "密码加密失败")
			return
		}
		hashedPassword = string(hashed)
	}

	userManager.Lock()
	if req.Email != "" {
		user.Email = strings.ToLower(strings.TrimSpace(req.Email))
	}
	if req.RoleID != "" {
		user.RoleID = req.RoleID
	}
	if hashedPassword != "" {
		user.Password = hashedPassword
	}
	if req.IsActive != nil {
		// 不允许管理员禁用自己
		if session != nil && session.Username == username && !*req.IsActive {
			userManager.Unlock()
			writeJSONError(w, http.StatusForbidden, "不能禁用当前登录的账号")
			return
		}
		user.IsActive = *req.IsActive
		// 禁用用户时立即吊销其全部会话（配合 validateSession 的 IsActive 检查双保险）
		if !*req.IsActive {
			for sessionID, s := range userManager.Sessions {
				if s.Username == username {
					delete(userManager.Sessions, sessionID)
				}
			}
		}
	}
	userManager.Unlock()
	err := saveUsers()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "系统错误，请稍后重试")
		return
	}

	// 高危变更写入审计日志
	auditAction(r, "rbac.user.update", fmt.Sprintf("user=%s role=%s active=%v password_changed=%v",
		username, req.RoleID, user.IsActive, req.Password != ""))

	log.Printf("更新用户成功: %s", username)
	writeJSON(w, http.StatusOK, "用户更新成功", nil)
}

// deleteRbacUserHandler 删除用户
func deleteRbacUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "只允许 DELETE 请求", http.StatusMethodNotAllowed)
		return
	}

	username := r.PathValue("username")
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少用户名")
		return
	}

	session, valid := getSessionFromRequest(r)
	if valid && session.Username == username {
		writeJSONError(w, http.StatusForbidden, "不能删除当前登录的账号")
		return
	}
	if username == "admin" {
		writeJSONError(w, http.StatusForbidden, "不能删除内置管理员账号")
		return
	}

	userManager.Lock()
	if _, exists := userManager.UserInfos[username]; !exists {
		userManager.Unlock()
		writeJSONError(w, http.StatusNotFound, "用户不存在")
		return
	}
	delete(userManager.UserInfos, username)
	// 同时删除该用户的所有会话
	for sessionID, session := range userManager.Sessions {
		if session.Username == username {
			delete(userManager.Sessions, sessionID)
		}
	}
	userManager.Unlock()
	err := saveUsers()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "系统错误，请稍后重试")
		return
	}

	log.Printf("删除用户成功: %s", username)
	auditAction(r, "rbac.user.delete", "user="+username)
	writeJSON(w, http.StatusOK, "用户删除成功", nil)
}

// writeJSON 统一 JSON 响应
func writeJSON(w http.ResponseWriter, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    code,
		"message": message,
		"data":    data,
	})
}

// writeJSONError 统一 JSON 错误响应
func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    code,
		"message": message,
	})
}

// ==================== 文件管理功能 ====================

// FileEntry 文件/目录条目
type FileEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Ext     string    `json:"ext"`
}

// listFilesHandler 列出媒体目录下的文件
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	relPath := strings.Trim(r.URL.Query().Get("path"), "/")
	fullPath := filepath.Join(mediaDir, relPath)

	if !isSafeFilePath(fullPath, mediaDir) {
		writeJSONError(w, http.StatusForbidden, "路径不合法")
		return
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取目录失败: "+err.Error())
		return
	}

	fileList := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		rel := relPath
		if rel != "" {
			rel += "/"
		}
		rel += e.Name()
		fileList = append(fileList, FileEntry{
			Name:    e.Name(),
			Path:    rel,
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Ext:     strings.ToLower(filepath.Ext(e.Name())),
		})
	}

	// 目录在前，其余按名称排序
	sort.Slice(fileList, func(i, j int) bool {
		if fileList[i].IsDir != fileList[j].IsDir {
			return fileList[i].IsDir
		}
		return fileList[i].Name < fileList[j].Name
	})

	writeJSON(w, http.StatusOK, "获取文件列表成功", map[string]interface{}{
		"path":  relPath,
		"files": fileList,
	})
}

// uploadFileHandler 上传文件到指定目录
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 限制上传大小 1GB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "解析上传数据失败: "+err.Error())
		return
	}

	dirPath := strings.Trim(r.FormValue("path"), "/")
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "未找到上传文件")
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	if filename == "" || filename == "." {
		writeJSONError(w, http.StatusBadRequest, "文件名不合法")
		return
	}

	// 阻止上传可在浏览器中执行的活跃内容，防止存储型XSS/钓鱼页面
	blockedUploadExts := map[string]bool{
		".html": true, ".htm": true, ".php": true, ".phtml": true,
		".php3": true, ".php4": true, ".php5": true, ".phar": true,
		".js": true, ".mjs": true, ".jsp": true, ".asp": true, ".aspx": true,
		".sh": true, ".pl": true, ".py": true, ".rb": true,
		".svg": true, ".xml": true, ".xhtml": true,
	}
	if blockedUploadExts[strings.ToLower(filepath.Ext(filename))] {
		writeJSONError(w, http.StatusForbidden, "该文件类型禁止上传（可执行/脚本/网页文件）")
		return
	}

	fullPath := filepath.Join(mediaDir, dirPath, filename)
	if !isSafeFilePath(fullPath, mediaDir) {
		writeJSONError(w, http.StatusForbidden, "路径不合法")
		return
	}

	dst, err := os.Create(fullPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "创建文件失败: "+err.Error())
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入文件失败: "+err.Error())
		return
	}

	log.Printf("上传文件成功: %s (%d bytes)", fullPath, header.Size)
	auditAction(r, "file.upload", fmt.Sprintf("path=%s size=%d", strings.TrimPrefix(fullPath, mediaDir+"/"), header.Size))
	writeJSON(w, http.StatusOK, "上传成功", map[string]string{"path": fullPath})
}

// MkdirRequest 新建目录请求
type MkdirRequest struct {
	Path string `json:"path"`
}

// mkdirFileHandler 新建目录
func mkdirFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	var req MkdirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	req.Path = strings.Trim(req.Path, "/")
	if req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "目录名不能为空")
		return
	}

	fullPath := filepath.Join(mediaDir, req.Path)
	if !isSafeFilePath(fullPath, mediaDir) {
		writeJSONError(w, http.StatusForbidden, "路径不合法")
		return
	}

	if err := os.MkdirAll(fullPath, 0755); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "创建目录失败: "+err.Error())
		return
	}

	auditAction(r, "file.mkdir", "path="+req.Path)
	writeJSON(w, http.StatusOK, "目录创建成功", nil)
}

// deleteFileHandler 删除文件或空目录
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "只允许DELETE请求", http.StatusMethodNotAllowed)
		return
	}

	relPath := strings.Trim(r.URL.Query().Get("path"), "/")
	if relPath == "" {
		writeJSONError(w, http.StatusBadRequest, "请指定要删除的文件路径")
		return
	}

	fullPath := filepath.Join(mediaDir, relPath)
	if !isSafeFilePath(fullPath, mediaDir) {
		writeJSONError(w, http.StatusForbidden, "路径不合法")
		return
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		writeJSONError(w, http.StatusNotFound, "文件不存在")
		return
	}

	if info.IsDir() {
		// 只允许删除空目录
		entries, err := os.ReadDir(fullPath)
		if err == nil && len(entries) > 0 {
			writeJSONError(w, http.StatusBadRequest, "目录非空，不能删除")
			return
		}
	}

	if err := os.Remove(fullPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	if info.IsDir() {
		auditAction(r, "file.delete.dir", "path="+relPath)
	} else {
		auditAction(r, "file.delete", fmt.Sprintf("path=%s size=%d", relPath, info.Size()))
	}
	log.Printf("删除文件成功: %s", fullPath)
	writeJSON(w, http.StatusOK, "删除成功", nil)
}

// ==================== 进程监控功能 ====================

// ProcessInfo 进程信息
type ProcessInfo struct {
	User        string `json:"user"`
	PID         string `json:"pid"`
	CPU         string `json:"cpu"`
	MemPct      string `json:"mem_pct"`
	RSSMB       string `json:"rss_mb"`
	VSZMB       string `json:"vsz_mb"`
	Elapsed     string `json:"elapsed"`
	Command     string `json:"command"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	ParentPID   string `json:"parent_pid"`
	StartTime   string `json:"start_time"`
	ServiceName string `json:"service_name"`
}

// ProcessDetail 进程详情（可执行文件/工作目录/父进程/子进程/服务/端口）
type ProcessDetail struct {
	ProcessInfo
	ParentName string        `json:"parent_name"`
	Exe        string        `json:"exe"`
	Cwd        string        `json:"working_directory"`
	Ports      []PortInfo    `json:"ports"`
	Children   []ProcessInfo `json:"children"`
}

// parseEtime 解析 ps etime（MM:SS / HH:MM:SS / D-HH:MM:SS）为时长
func parseEtime(s string) (time.Duration, bool) {
	days := 0
	rest := s
	if i := strings.Index(s, "-"); i > 0 {
		d, err := strconv.Atoi(s[:i])
		if err != nil {
			return 0, false
		}
		days = d
		rest = s[i+1:]
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	sec, err1 := strconv.Atoi(parts[len(parts)-1])
	min, err2 := strconv.Atoi(parts[len(parts)-2])
	if err1 != nil || err2 != nil || sec < 0 || min < 0 {
		return 0, false
	}
	hrs := 0
	if len(parts) == 3 {
		hrs, err1 = strconv.Atoi(parts[0])
		if err1 != nil || hrs < 0 {
			return 0, false
		}
	}
	return time.Duration(days)*24*time.Hour +
		time.Duration(hrs)*time.Hour +
		time.Duration(min)*time.Minute +
		time.Duration(sec)*time.Second, true
}

// mapProcStatus ps 状态字符 → 可读状态
func mapProcStatus(stat string) string {
	if stat == "" {
		return "unknown"
	}
	switch stat[0] {
	case 'R':
		return "running"
	case 'S', 'I':
		return "sleeping"
	case 'D':
		return "uninterruptible"
	case 'Z':
		return "zombie"
	case 'T', 't':
		return "stopped"
	case 'X':
		return "dead"
	default:
		return "unknown"
	}
}

// collectProcesses 通过 ps 采集进程列表（含进程名/状态/父PID/启动时间/所属服务）
func collectProcesses(sortBy string, top int) ([]ProcessInfo, error) {
	psSort := "pcpu"
	if sortBy == "mem" {
		psSort = "pmem"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-eo", "user,pid,ppid,pcpu,pmem,rss,vsz,etime,stat,comm,args", "--sort=-"+psSort)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	svcMap := pidServiceMap()
	now := time.Now()
	lines := strings.Split(string(output), "\n")
	processes := make([]ProcessInfo, 0, top)
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// 0 user 1 pid 2 ppid 3 pcpu 4 pmem 5 rss 6 vsz 7 etime 8 stat 9 comm 10+ args
		command := fields[9]
		if len(fields) > 10 {
			command = strings.Join(fields[10:], " ")
		}
		if len(command) > 200 {
			command = command[:200] + "..."
		}
		startTime := ""
		if d, ok := parseEtime(fields[7]); ok {
			startTime = now.Add(-d).Format("2006-01-02 15:04:05")
		}
		ppid := ""
		if _, err := strconv.Atoi(fields[2]); err == nil {
			ppid = fields[2]
		}
		processes = append(processes, ProcessInfo{
			User:      fields[0],
			PID:       fields[1],
			ParentPID: ppid,
			CPU:       fields[3],
			MemPct:    fields[4],
			RSSMB:     fmt.Sprintf("%.1f", parseKbToMb(fields[5])),
			VSZMB:     fmt.Sprintf("%.1f", parseKbToMb(fields[6])),
			Elapsed:   fields[7],
			Status:    mapProcStatus(fields[8]),
			Name:      fields[9],
			Command:   command,
			StartTime: startTime,
		})
		if pidInt, err := strconv.Atoi(fields[1]); err == nil {
			if svc, ok := svcMap[int32(pidInt)]; ok {
				processes[len(processes)-1].ServiceName = svc + ".service"
			}
		}
		if len(processes) >= top {
			break
		}
	}
	return processes, nil
}

// listProcessesHandler 返回按 CPU/内存排序的进程列表
func listProcessesHandler(w http.ResponseWriter, r *http.Request) {
	sortBy := r.URL.Query().Get("sort")
	if sortBy != "mem" {
		sortBy = "cpu"
	}
	top := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && n > 0 && n <= 1000 {
		top = n
	}
	processes, err := collectProcesses(sortBy, top)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取进程列表失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "获取进程列表成功", processes)
}

// getProcessDetailHandler 返回单个进程详情（可执行文件/工作目录/父子/服务/端口）
func getProcessDetailHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	pid, err := strconv.Atoi(r.PathValue("pid"))
	if err != nil || pid < 1 {
		writeJSONError(w, http.StatusBadRequest, "无效的进程PID")
		return
	}
	all, err := collectProcesses("cpu", 1000)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取进程信息失败: "+err.Error())
		return
	}
	var base *ProcessInfo
	for i := range all {
		if all[i].PID == strconv.Itoa(pid) {
			base = &all[i]
			break
		}
	}
	if base == nil {
		writeJSONError(w, http.StatusNotFound, "进程不存在")
		return
	}
	detail := ProcessDetail{ProcessInfo: *base}
	detail.Ports = portsForPID(int32(pid))
	for i := range all {
		if all[i].ParentPID == strconv.Itoa(pid) {
			detail.Children = append(detail.Children, all[i])
			if len(detail.Children) >= 20 {
				break
			}
		}
	}
	for i := range all {
		if all[i].PID == base.ParentPID {
			detail.ParentName = all[i].Name
			break
		}
	}
	if p, e := psprocess.NewProcess(int32(pid)); e == nil {
		if exe, err := p.Exe(); err == nil {
			detail.Exe = exe
		}
		if cwd, err := p.Cwd(); err == nil {
			detail.Cwd = cwd
		}
	}
	if detail.Exe == "" {
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			detail.Exe = exe
		}
	}
	if detail.Cwd == "" {
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
			detail.Cwd = cwd
		}
	}
	writeJSON(w, http.StatusOK, "获取进程详情成功", detail)
}

// parseKbToMb 将 KB 字符串转为 MB 数值
func parseKbToMb(kb string) float64 {
	v, err := strconv.ParseFloat(kb, 64)
	if err != nil {
		return 0
	}
	return v / 1024
}

// ipinfoProxyHandler 代理到 8081 端口的 ipinfo 服务，避免跨端口/跨域名在移动端不可达的问题
func ipinfoProxyHandler(w http.ResponseWriter, r *http.Request) {
	target := "https://127.0.0.1:8081/ipinfo"
	// 仅透传经过校验的 ip 参数，避免向内部服务注入其他参数
	if q := strings.TrimSpace(r.URL.Query().Get("ip")); q != "" && net.ParseIP(q) != nil {
		target += "?ip=" + url.QueryEscape(q)
	}

	// 127.0.0.1 上证书 CN 与主机名不匹配（自签 / 域名证书场景），需跳过证书校验
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(target)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "IP 数据服务暂不可用: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "读取 IP 数据失败")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// ==================== IP 封禁管理功能 ====================

// blockedIPsFile 手动封禁 IP 列表文件（默认 <数据根目录>/blocked_ips.json）
var blockedIPsFile = filepath.Join(dataRoot(), "blocked_ips.json")

// loadBlockedIPs 启动时加载手动封禁的 IP 列表
func loadBlockedIPs() {
	loadIPSecurity()
}

// saveBlockedIPs 持久化手动封禁的 IP 列表
func saveBlockedIPs() {
	saveIPSecurity()
}

// BlockIPRequest 封禁/解封请求
type BlockIPRequest struct {
	IP              string `json:"ip"`
	Duration        string `json:"duration"`         // 10m/1h/6h/24h/7d/30d/permanent
	DurationMinutes int    `json:"duration_minutes"` // 自定义时长（分钟）
	Reason          string `json:"reason"`
	Note            string `json:"note"`
}

// blockIPHandler 手动封禁 IP
func blockIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(req.IP)
	if net.ParseIP(ip) == nil {
		writeJSONError(w, http.StatusBadRequest, "无效的IP地址")
		return
	}

	duration := strings.TrimSpace(req.Duration)
	if duration == "" {
		duration = "1h"
	}
	until := time.Now()
	durLabel := duration
	if duration == "permanent" {
		until = until.AddDate(100, 0, 0)
		durLabel = "permanent"
	} else if duration == "custom" {
		if req.DurationMinutes < 1 || req.DurationMinutes > 525600 {
			writeJSONError(w, http.StatusBadRequest, "自定义时长需在 1 ~ 525600 分钟之间")
			return
		}
		until = until.Add(time.Duration(req.DurationMinutes) * time.Minute)
		durLabel = fmt.Sprintf("%dm", req.DurationMinutes)
	} else {
		d, ok := parseBlockDuration(duration)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "封禁时长不合法")
			return
		}
		until = until.Add(d)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "管理员手动封禁"
	}
	username := ""
	if s, ok := getSessionFromRequest(r); ok {
		username = s.Username
	}
	antiCrawler.Lock()
	antiCrawler.blockedIPs[ip] = &BlockedIP{
		IP:           ip,
		BlockedAt:    time.Now(),
		BlockedUntil: until,
		Reason:       reason,
		Source:       "manual",
		Duration:     durLabel,
		Note:         strings.TrimSpace(req.Note),
		Trigger:      "manual",
	}
	antiCrawler.Unlock()
	saveBlockedIPs()
	auditAction(r, "ip.block.manual",
		fmt.Sprintf("手动封禁 IP=%s 时长=%s 原因=%s 备注=%s 操作人=%s", ip, durLabel, reason, req.Note, username))
	log.Printf("🚫 手动封禁IP: %s（%s）", ip, durLabel)
	writeJSON(w, http.StatusOK, "IP 已封禁", nil)
}

// unblockIPHandler 解封 IP
func unblockIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(req.IP)
	removeBlockedIP(ip, r)
	writeJSON(w, http.StatusOK, "IP 已解封", nil)
}

// ==================== 进程结束功能 ====================

// KillProcessRequest 结束进程请求
type KillProcessRequest struct {
	PID   int  `json:"pid"`
	Force bool `json:"force"`
}

// killProcessHandler 结束指定进程
func killProcessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req KillProcessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.PID <= 1 {
		writeJSONError(w, http.StatusBadRequest, "无效的进程PID")
		return
	}
	if req.PID == os.Getpid() {
		writeJSONError(w, http.StatusBadRequest, "不能结束服务器自身进程")
		return
	}
	// 检查进程是否存在（signal 0 仅探测）
	proc, err := os.FindProcess(req.PID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "进程不存在")
		return
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		writeJSONError(w, http.StatusNotFound, "进程不存在或无权操作")
		return
	}
	sig := syscall.SIGTERM
	msg := "已发送终止信号"
	if req.Force {
		sig = syscall.SIGKILL
		msg = "已强制结束进程"
	}
	if err := proc.Signal(sig); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "结束进程失败: "+err.Error())
		return
	}
	auditAction(r, "process.kill", fmt.Sprintf("结束进程 PID=%d force=%v", req.PID, req.Force))
	log.Printf("%s给进程 %d", msg, req.PID)
	writeJSON(w, http.StatusOK, msg, nil)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"` // 记住我：延长会话空闲超时与绝对寿命（30 天），否则 24h/7d
}

type Session struct {
	SessionID  string    `json:"session_id"`
	Username   string    `json:"username"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_access"`
	ExpiresAt  time.Time `json:"expires_at"`
	CSRFToken  string    `json:"csrf_token,omitempty"` // 会话绑定的随机 CSRF Token（不与浏览器共享密钥）
	Remember   bool      `json:"remember,omitempty"`   // 记住我：空闲超时 30 天/绝对寿命 30 天，否则 24h/7d
}

type UserManager struct {
	sync.RWMutex
	UserInfos map[string]*Users   `json:"user_infos"`
	Sessions  map[string]*Session `json:"sessions"`
}

// 下载令牌结构体
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
	FilePath    string    `json:"file_path"` // 绑定的文件相对路径（规范化后的 slash 路径；空表示历史令牌不绑定）
}

// 下载令牌管理器
type DownloadTokenManager struct {
	sync.RWMutex
	Tokens map[string]*DownloadToken `json:"tokens"` // key: token_id
}

// 生成下载令牌请求
type GenerateDownloadTokenRequest struct {
	Description string `json:"description"` // 可选：令牌描述
	Username    string `json:"username"`    // 可选：签发给指定用户（管理员签发时使用）
	ExpiresIn   int64  `json:"expires_in"`  // 可选：有效期（分钟），0 表示使用默认值 30 分钟
	MaxBytes    int64  `json:"max_bytes"`   // 可选：流量上限（字节），0 表示使用默认值 3GB
	FilePath    string `json:"file_path"`   // 可选：绑定的文件相对路径（签发后该令牌仅可下载此文件）
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

// DiskPartition 磁盘分区使用情况明细（仪表盘展示用）
type DiskPartition struct {
	Mount       string  `json:"mount"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

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
	Hostname      string           `json:"hostname"`
	OS            string           `json:"os"`
	Platform      string           `json:"platform"`
	KernelVersion string           `json:"kernel_version"`
	Architecture  string           `json:"architecture"`
	ServerIP      string           `json:"server_ip"`
	Trojan        TrojanStatus     `json:"trojan"`
	Disks         []DiskPartition  `json:"disks"`
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

// OnlineUser 在线用户结构体，增加了 ConnCount 防止多标签页假性下线
type OnlineUser struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Since     time.Time `json:"since"`
	Page      string    `json:"page"`
	ConnCount int       `json:"-"` // WebSocket 连接计数器
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
	blockedIPs         map[string]*BlockedIP
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

	// 优化：引入服务器状态读写锁和缓存，解决高并发性能瓶颈和 Data Race
	serverStatsMutex sync.RWMutex
	statusCache      = make(map[string]*ServerStatus)
	statusCacheTime  = make(map[string]time.Time)

	lastNetStats       = map[string]NetStat{}
	lastDiskStats      = map[string]DiskStat{}
	totalUploadAccum   uint64
	totalDownloadAccum uint64

	accessStats = &AccessStats{
		DailyVisits:    make(map[string]int),
		WeeklyVisits:   make(map[string]int),
		UniqueVisitors: make(map[string]map[string]bool),
	}
	onlineUsers = &OnlineUsers{
		Users: make(map[string]*OnlineUser),
	}
	antiCrawler = &AntiCrawler{
		blockedIPs:         make(map[string]*BlockedIP),
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

	// 下载令牌管理器
	downloadTokenManager = &DownloadTokenManager{
		Tokens: make(map[string]*DownloadToken),
	}

	// 优化：为媒体生成逻辑引入互斥锁，避免并发修改切片导致的崩溃
	mediaMutex sync.Mutex
	num        = 0
	key        = 0
	files      []string

	// 主机信息缓存
	hostInfo      *host.InfoStat
	hostInfoErr   error
	hostInfoMutex sync.Mutex

	// 服务器启动时间（从持久化数据加载）
	serverStartTime time.Time

	// 保存队列，避免并发保存导致的死锁
	downloadTokenSaveChan = make(chan struct{}, 1)
	userSaveChan          = make(chan struct{}, 1)

	// RBAC 角色权限管理器
	rbacManager = &RBACManager{
		Roles: make(map[string]*Role),
	}
	rbacSaveChan = make(chan struct{}, 1)
	rbacFile     = filepath.Join(dataRoot(), "rbac.json")
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
	Url          string `json:"urls"`
}

// countingResponseWriter 包装 ResponseWriter 统计实际写出字节数（兼容 Range/206 断点续传场景）
type countingResponseWriter struct {
	http.ResponseWriter
	n      int64 // 已实际写出的字节数
	remain int64 // 剩余可用配额（字节），<=0 时拒绝继续写出
}

// Write 写入响应并计数，超出剩余配额时写满余量后中断传输（配合 Content-Length 使客户端可感知下载不完整）
func (cw *countingResponseWriter) Write(p []byte) (int, error) {
	if cw.remain <= 0 {
		return 0, fmt.Errorf("下载量已达上限")
	}
	// 本块超过剩余配额时截断写入，并返回错误让 ServeContent 停止后续拷贝
	truncated := int64(len(p)) > cw.remain
	if truncated {
		p = p[:cw.remain]
	}
	n, err := cw.ResponseWriter.Write(p)
	cw.n += int64(n)
	cw.remain -= int64(n)
	if err == nil && truncated {
		return n, fmt.Errorf("下载量已达上限")
	}
	return n, err
}

// downloadFailStat 单个 IP 的令牌验证失败统计
type downloadFailStat struct {
	count    int
	windowAt time.Time
}

// downloadFailLimiter 按 IP 记录令牌验证失败次数，防止 token_id 暴力枚举
var downloadFailLimiter = struct {
	sync.Mutex
	fails map[string]*downloadFailStat
}{fails: make(map[string]*downloadFailStat)}

// downloadFailLimitWindow 失败计数窗口
const downloadFailLimitWindow = 15 * time.Minute

// downloadFailLimitMax 窗口内允许的最大失败次数
const downloadFailLimitMax = 10

// downloadFailLimited 判断该 IP 是否已触发限速
func downloadFailLimited(ip string) bool {
	downloadFailLimiter.Lock()
	defer downloadFailLimiter.Unlock()
	st, ok := downloadFailLimiter.fails[ip]
	if !ok {
		return false
	}
	if time.Since(st.windowAt) > downloadFailLimitWindow {
		delete(downloadFailLimiter.fails, ip)
		return false
	}
	return st.count >= downloadFailLimitMax
}

// recordDownloadFail 记录一次令牌验证失败（成功验证后调用 clearDownloadFail 复位）
func recordDownloadFail(ip string) {
	downloadFailLimiter.Lock()
	defer downloadFailLimiter.Unlock()
	now := time.Now()
	st, ok := downloadFailLimiter.fails[ip]
	if !ok || now.Sub(st.windowAt) > downloadFailLimitWindow {
		downloadFailLimiter.fails[ip] = &downloadFailStat{count: 1, windowAt: now}
		return
	}
	st.count++
}

// clearDownloadFail 验证成功后清除该 IP 的失败计数
func clearDownloadFail(ip string) {
	downloadFailLimiter.Lock()
	defer downloadFailLimiter.Unlock()
	delete(downloadFailLimiter.fails, ip)
}

// cleanupDownloadFailLimiter 周期清理过期的失败记录，防止 map 无限增长
func cleanupDownloadFailLimiter() {
	downloadFailLimiter.Lock()
	defer downloadFailLimiter.Unlock()
	for ip, st := range downloadFailLimiter.fails {
		if time.Since(st.windowAt) > downloadFailLimitWindow {
			delete(downloadFailLimiter.fails, ip)
		}
	}
}

// ==================== 下载令牌功能 ====================

// generateRandomString 生成指定长度的随机字符串，采用高强度密码学随机生成器
// 使用 rejection sampling 消除 256 % 62 != 0 带来的取模统计偏差
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 只接受 < maxValid 的随机字节，保证每个字符概率严格相等
	const maxValid = byte(256 - (256 % len(charset)))
	out := make([]byte, 0, length)
	buf := make([]byte, 128)
	for len(out) < length {
		if _, err := rand2.Read(buf); err != nil {
			// crypto/rand 读取失败属于系统级异常，直接 panic 终止而非降级生成弱随机
			panic("crypto/rand 读取失败: " + err.Error())
		}
		for _, b := range buf {
			if b >= maxValid {
				continue
			}
			out = append(out, charset[int(b)%len(charset)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out)
}

// verifyDownloadToken 验证下载令牌合法性（恒定时间比较，防止时序侧信道逐位猜测）
func verifyDownloadToken(token string, downloadToken *DownloadToken) bool {
	// 令牌明文本就存储于服务端（加密持久化），此处做常数时间严格比对即可，
	// 历史 AES-GCM 无状态令牌方案未启用，已移除死代码避免误导。
	return subtle.ConstantTimeCompare([]byte(token), []byte(downloadToken.Token)) == 1
}

// generateDownloadToken 生成新的下载令牌授权票据（filePath 非空时令牌与文件绑定）
func generateDownloadToken(username, filePath string, r *http.Request, description string, expiresIn time.Duration, maxBytes int64) (*DownloadTokenResponse, error) {
	tokenID := generateRandomString(16)
	token := generateRandomString(32)

	now := time.Now()
	expiresAt := now.Add(expiresIn)

	downloadToken := &DownloadToken{
		TokenID:     tokenID,
		Token:       token,
		Username:    username,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		UsedBytes:   0,
		MaxBytes:    maxBytes,
		IsActive:    true,
		IP:          getClientIP(r),
		UserAgent:   r.UserAgent(),
		Description: description,
		FilePath:    filePath,
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
		MaxBytes:  maxBytes,
		UsedBytes: 0,
	}, nil
}

// validateDownloadToken 验证下载令牌的可用性与额度状态
func validateDownloadToken(tokenID, token string, r *http.Request) (*DownloadToken, error) {
	downloadTokenManager.RLock()
	downloadToken, exists := downloadTokenManager.Tokens[tokenID]
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

// updateTokenUsage 实时累加更新当前令牌的已使用流量
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

// cleanupExpiredDownloadTokens 周期性清理系统中已经过期的历史下载令牌
func cleanupExpiredDownloadTokens() {
	downloadTokenManager.Lock()

	now := time.Now()
	expiredTokens := make([]string, 0)

	// 仅清理失效且过期超过 24 小时的令牌：过期令牌保留一段时间供审计（UsedBytes 等），validate 阶段已拒绝过期令牌
	for tokenID, token := range downloadTokenManager.Tokens {
		if now.After(token.ExpiresAt.Add(24 * time.Hour)) {
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

// saveDownloadTokens 将系统中的下载令牌安全加密序列化后写入文件系统
func saveDownloadTokens() error {
	// 先复制数据，尽快释放锁（局部引用，避免锁与序列化期间全局指针被替换导致 RUnlock 失配）
	mgr := downloadTokenManager
	mgr.RLock()
	data, err := json.Marshal(mgr)
	mgr.RUnlock()

	if err != nil {
		return fmt.Errorf("序列化下载令牌数据失败: %v", err)
	}

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

// loadDownloadTokens 服务启动时从加密存储载入全部历史下载令牌
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

// initDownloadTokenManager 初始化下载令牌生命周期管控机制（包含定时清理功能）
func initDownloadTokenManager() {
	loadDownloadTokens()

	// 启动定期清理过期令牌的goroutine
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredDownloadTokens()
			cleanupDownloadFailLimiter()
		}
	}()
}

// isSafeFilePath 进行路径安全鉴定，防范目录穿越(Directory Traversal)风险
func isSafeFilePath(filePath, baseDir string) bool {
	// 优化：采用 filepath.Clean 全面清除潜在的穿越符号
	absPath, err := filepath.Abs(filepath.Clean(filePath))
	if err != nil {
		return false
	}

	absBase, err := filepath.Abs(filepath.Clean(baseDir))
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

// generateDownloadTokenHandler HTTP 端点：响应并下发一个新的下载授权令牌
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

	// 默认签发给当前登录用户；跨用户代签需要 user:manage 权限（防止普通用户互相批量发令牌）
	targetUsername := session.Username
	if req.Username != "" && req.Username != session.Username {
		if !hasPermission(session.Username, "user:manage") {
			writeJSONError(w, http.StatusForbidden, "仅管理员可以给其他用户签发令牌")
			return
		}
		userManager.RLock()
		targetUser, exists := userManager.UserInfos[req.Username]
		userManager.RUnlock()
		if !exists {
			writeJSONError(w, http.StatusBadRequest, "指定的用户不存在")
			return
		}
		if !targetUser.IsActive {
			writeJSONError(w, http.StatusBadRequest, "指定的用户已被禁用")
			return
		}
		targetUsername = targetUser.Username
	}

	// 绑定文件路径：规范化为相对媒体目录的 slash 路径并做目录穿越校验，签发后该令牌仅可下载此文件
	boundFilePath := ""
	if req.FilePath != "" {
		rel := strings.Trim(req.FilePath, "/")
		if strings.HasPrefix(rel, "static/") {
			rel = strings.TrimPrefix(rel, "static/")
		}
		rel = filepath.ToSlash(filepath.Clean("/" + rel))
		if rel == "" || rel == "/" || strings.HasPrefix(rel, "../") {
			writeJSONError(w, http.StatusBadRequest, "文件路径不合法")
			return
		}
		if !isSafeFilePath(filepath.Join(mediaDir, rel), mediaDir) {
			writeJSONError(w, http.StatusBadRequest, "文件路径不合法")
			return
		}
		boundFilePath = strings.TrimPrefix(rel, "/")
	}

	// 有效期：默认 30 分钟，最长 30 天
	expiresIn := downloadTokenExpiry
	if req.ExpiresIn > 0 {
		maxMinutes := int64((30 * 24 * time.Hour) / time.Minute)
		if req.ExpiresIn > maxMinutes {
			writeJSONError(w, http.StatusBadRequest, "有效期不能超过30天")
			return
		}
		expiresIn = time.Duration(req.ExpiresIn) * time.Minute
	}

	// 流量上限：默认 3GB，允许 1MB ~ 100GB
	maxBytes := int64(downloadLimitBytes)
	if req.MaxBytes > 0 {
		const minLimit = int64(1) * 1024 * 1024
		const maxLimit = int64(100) * 1024 * 1024 * 1024
		if req.MaxBytes < minLimit || req.MaxBytes > maxLimit {
			writeJSONError(w, http.StatusBadRequest, "流量上限需在1MB~100GB之间")
			return
		}
		maxBytes = req.MaxBytes
	}

	tokenResponse, err := generateDownloadToken(targetUsername, boundFilePath, r, req.Description, expiresIn, maxBytes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusInternalServerError,
			"message": fmt.Sprintf("生成令牌失败: %v", err),
		})
		return
	}

	auditAction(r, "token.issue", fmt.Sprintf("target=%s file=%s expiry_min=%d quota_bytes=%d",
		targetUsername, boundFilePath, int(expiresIn.Minutes()), maxBytes))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "下载令牌生成成功",
		"data":    tokenResponse,
	})
}

// secureDownloadHandler HTTP 端点：接收并验证令牌，建立文件安全下发通道
func secureDownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)

	// 暴力枚举防护：同一 IP 短窗口内令牌验证失败过多则直接限速
	if downloadFailLimited(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusTooManyRequests,
			"message": "下载失败次数过多，请稍后再试",
		})
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

	// 验证令牌
	downloadToken, err := validateDownloadToken(token, TokenValues, r)
	if err != nil {
		recordDownloadFail(clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": fmt.Sprintf("下载令牌验证失败: %v", err),
		})
		return
	}
	clearDownloadFail(clientIP)

	// RBAC 授权校验：令牌所属账号必须仍拥有文件下载权限
	if !hasPermission(downloadToken.Username, "files:download") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "该账号没有文件下载权限，请联系管理员授权",
		})
		return
	}

	// 处理文件路径：提取相对路径部分
	var relativePath string

	// 检查是否是完整的URL
	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		parsedURL, err := url.Parse(filePath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    http.StatusBadRequest,
				"message": "无效的文件URL",
			})
			return
		}
		path := parsedURL.Path
		if strings.HasPrefix(path, "/static/") {
			relativePath = strings.TrimPrefix(path, "/static/")
		} else {
			relativePath = strings.TrimPrefix(path, "/")
		}
	} else {
		relativePath = strings.TrimPrefix(filePath, "/static/")
		relativePath = strings.TrimPrefix(relativePath, "/")
	}

	// 规范化为相对媒体目录的 slash 路径（与签发时的绑定格式一致）
	relativePath = strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+relativePath)), "/")

	// 令牌与文件绑定校验：签发时绑定了文件路径的令牌只能下载该文件
	if downloadToken.FilePath != "" && downloadToken.FilePath != relativePath {
		recordDownloadFail(clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "该令牌未授权下载此文件",
		})
		return
	}

	fullPath := filepath.Join(mediaDir, relativePath)

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
			"message": "文件不存在: " + fullPath,
		})
		return
	}

	// 检查是否是目录
	if fileInfo.IsDir() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "不能下载目录",
		})
		return
	}

	// 配额预检：非 Range 请求要求文件完整放入剩余配额（Range 断点续传由运行时配额截断兜底）
	isRangeRequest := r.Header.Get("Range") != ""
	if !isRangeRequest && downloadToken.UsedBytes+fileInfo.Size() > downloadToken.MaxBytes {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "下载此文件将超过流量限制",
		})
		return
	}

	// 设置下载头（清洗文件名防止响应头注入；非 ASCII 文件名补充 RFC 5987 filename* 编码，避免中文乱码）
	dlFilename := strings.NewReplacer("\"", "", "\r", "", "\n", "").Replace(filepath.Base(fullPath))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s",
		dlFilename, url.PathEscape(dlFilename)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// 记录下载开始
	recordAccess(r)
	updateOnlineUser(r, "secure-download")

	// 打开文件后交给 ServeContent：自动支持 Range/206 断点续传、If-Range、Content-Length
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

	// 带配额统计的 ResponseWriter：按实际写出字节计数，超出剩余配额自动中断
	cw := &countingResponseWriter{ResponseWriter: w, remain: downloadToken.MaxBytes - downloadToken.UsedBytes}
	http.ServeContent(cw, r, dlFilename, fileInfo.ModTime(), file)

	// 更新令牌使用量（断点续传时仅计入本次实际传输字节）
	updateTokenUsage(downloadToken.TokenID, cw.n)

	// 文件下载属于敏感外发操作，逐次记录审计（含实际传输字节与令牌归属）
	auditAction(r, "file.download", fmt.Sprintf("token_user=%s file=%s bytes=%d by_ip=%s",
		downloadToken.Username, relativePath, cw.n, clientIP))

	log.Printf("✅ 用户 %s 下载文件 %s, 大小: %d bytes", downloadToken.Username, relativePath, cw.n)
}

// downloadInfoHandler GET /download-info?token_id=&token=&file=
// 供独立下载页（download.html）使用的元信息接口：令牌即凭证，无需登录会话。
// 仅返回文件名/大小/有效期/剩余配额等展示信息，复用与 /download 相同的验证链与失败限速。
func downloadInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许GET请求", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	if downloadFailLimited(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusTooManyRequests,
			"message": "尝试次数过多，请稍后再试",
		})
		return
	}

	tokenID := r.URL.Query().Get("token_id")
	tokenValue := r.URL.Query().Get("token")
	filePath := r.URL.Query().Get("file")
	if tokenID == "" || tokenValue == "" || filePath == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "链接不完整，请确认使用完整链接访问",
		})
		return
	}

	downloadToken, err := validateDownloadToken(tokenID, tokenValue, r)
	if err != nil {
		recordDownloadFail(clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "下载令牌无效或已过期",
		})
		return
	}
	clearDownloadFail(clientIP)

	if !hasPermission(downloadToken.Username, "files:download") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "该账号没有文件下载权限",
		})
		return
	}

	// 与下载接口一致的路径规范化与令牌-文件绑定校验
	relativePath := strings.TrimPrefix(filePath, "/static/")
	relativePath = strings.TrimPrefix(relativePath, "/")
	relativePath = strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+relativePath)), "/")
	if downloadToken.FilePath != "" && downloadToken.FilePath != relativePath {
		recordDownloadFail(clientIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "该令牌未授权下载此文件",
		})
		return
	}

	fullPath := filepath.Join(mediaDir, relativePath)
	if !isSafeFilePath(fullPath, mediaDir) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusForbidden,
			"message": "文件路径不安全",
		})
		return
	}

	fileInfo, err := os.Stat(fullPath)
	if err != nil || fileInfo.IsDir() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusNotFound,
			"message": "文件不存在或已被删除",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "ok",
		"data": map[string]interface{}{
			"file_name":       fileInfo.Name(),
			"size":            fileInfo.Size(),
			"expires_at":      downloadToken.ExpiresAt.Format(time.RFC3339),
			"used_bytes":      downloadToken.UsedBytes,
			"max_bytes":       downloadToken.MaxBytes,
			"remaining_bytes": downloadToken.MaxBytes - downloadToken.UsedBytes,
			"description":     downloadToken.Description,
		},
	})
}

// listDownloadTokensHandler HTTP 端点：向用户返回其名下已创建的所有下载令牌
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

	// 管理员可查看全部令牌，普通用户仅查看自己名下的令牌
	canManageAll := hasPermission(session.Username, "token:issue")
	userTokens := make([]map[string]interface{}, 0)
	for _, token := range downloadTokenManager.Tokens {
		if !canManageAll && token.Username != session.Username {
			continue
		}
		// 令牌明文脱敏：仅令牌所有者可见完整 token（用于找回下载链接），其他人只显示前 4 位掩码
		masked := token.Token[:4] + "****"
		if token.Username == session.Username {
			masked = token.Token
		}
		userTokens = append(userTokens, map[string]interface{}{
			"token_id":    token.TokenID,
			"token":       masked,
			"username":    token.Username,
			"created_at":  token.CreatedAt,
			"expires_at":  token.ExpiresAt,
			"used_bytes":  token.UsedBytes,
			"max_bytes":   token.MaxBytes,
			"is_active":   token.IsActive,
			"description": token.Description,
			"file_path":   token.FilePath,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取令牌列表成功",
		"data":    userTokens,
	})
}

// revokeDownloadTokenHandler HTTP 端点：接受用户指令主动撤销并吊销指定的令牌
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

	if !hasPermission(session.Username, "token:revoke") && token.Username != session.Username {
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

	auditAction(r, "token.revoke", fmt.Sprintf("token_id=%s owner=%s by=%s", tokenID, token.Username, session.Username))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "令牌已撤销",
	})
}

// ==================== 用户身份验证功能 ====================

// encryptData 运用 AES-GCM 对称加密算法加密核心持久化数据
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

// decryptData 负责对持久化系统读取出的加密块进行解密还原
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

// loadUsers 启动时解析并挂载全量系统账户与权限档案
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

	// 迁移旧版数据：为没有角色ID的账号补齐默认角色
	migrated := false
	for _, u := range userManager.UserInfos {
		if u.RoleID == "" {
			if u.Username == "admin" {
				u.RoleID = "admin"
			} else {
				u.RoleID = "user"
			}
			migrated = true
		}
	}
	if migrated {
		go scheduleSaveUsers()
	}

	log.Printf("✅ 用户数据加载完成，共 %d 个用户", len(userManager.UserInfos))
}

// saveUsers 将驻留内存的用户数据经过原子操作与加密机制写入本地文件
func saveUsers() error {
	// 先复制数据，尽快释放锁。捕获同一实例，避免并发替换 userManager 时 RLock/RUnlock 不一致。
	um := userManager
	um.RLock()
	data, err := json.Marshal(um)
	um.RUnlock()

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

// createDefaultAdmin 当检测无用户档案存在时自动初始化最高权限管理员
func createDefaultAdmin() {
	userManager.Lock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("创建默认管理员用户时加密密码失败: %v", err)
		userManager.Unlock()
		return
	}

	userManager.UserInfos["admin"] = &Users{
		Username:    "admin",
		Password:    string(hashedPassword),
		Email:       "admin@example.com",
		RoleID:      "admin",
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Permissions: []string{"admin", "read", "write", "execute"},
	}
	userManager.Unlock()

	if err := saveUsers(); err != nil {
		log.Printf("保存默认管理员用户失败: %v", err)
	} else {
		log.Println("✅ 创建默认管理员用户: admin / admin123")
	}
}

// generateSessionID 构造高度分散不可预测的全局唯一会话标示
func generateSessionID() string {
	b := make([]byte, 32)
	rand2.Read(b)
	return hex.EncodeToString(b)
}

// validateSession 匹配会话状态及刷新访问热度与时效生命周期
// sessionMaxLifetime 会话绝对寿命上限：无论多活跃，超过上限必须重新登录（防止被盗 Cookie 永久有效）
const sessionMaxLifetime = 7 * 24 * time.Hour

// 记住我会话的空闲超时与绝对寿命（勾选后免登录窗口从 24h/7d 延长到 30 天/30 天）
const (
	rememberIdleTimeout = 30 * 24 * time.Hour
	rememberMaxLifetime = 30 * 24 * time.Hour
)

// sessionIdleTimeout 会话空闲超时：记住我 30 天，否则 24 小时
func sessionIdleTimeout(s *Session) time.Duration {
	if s != nil && s.Remember {
		return rememberIdleTimeout
	}
	return sessionTimeout
}

// sessionAbsoluteCap 会话绝对寿命：记住我 30 天，否则 7 天（到期强制重新登录）
func sessionAbsoluteCap(s *Session) time.Duration {
	if s != nil && s.Remember {
		return rememberMaxLifetime
	}
	return sessionMaxLifetime
}

func validateSession(sessionID string) (*Session, bool) {
	// 使用写锁：本函数会更新 LastAccess 并在失效时删除会话，读锁下写入属于数据竞争
	userManager.Lock()
	defer userManager.Unlock()

	session, exists := userManager.Sessions[sessionID]
	if !exists {
		return nil, false
	}

	now := time.Now()
	if now.After(session.ExpiresAt) {
		// 会话已过期
		delete(userManager.Sessions, sessionID)
		return nil, false
	}

	// 会话绝对寿命：自创建起超过上限强制失效（滑动续期不能突破）
	if now.Sub(session.CreatedAt) > sessionAbsoluteCap(session) {
		delete(userManager.Sessions, sessionID)
		return nil, false
	}

	// 被禁用或已删除的用户，其会话立即失效（管理员禁用账号即刻踢出）
	if user, ok := userManager.UserInfos[session.Username]; !ok || !user.IsActive {
		delete(userManager.Sessions, sessionID)
		return nil, false
	}

	// 更新最后访问时间（滑动续期按会话自身的记住我时长）
	session.LastAccess = now
	session.ExpiresAt = now.Add(sessionIdleTimeout(session))

	return session, true
}

// createSession 签发一个具备防篡改特性的新会话并挂载至活跃序列
func createSession(username string, remember bool, r *http.Request) string {
	sessionID := generateSessionID()
	now := time.Now()

	// 生成会话绑定的高强度随机 CSRF Token（crypto/rand）
	csrf, _ := generateSecureToken(32)
	session := &Session{
		SessionID:  sessionID,
		Username:   username,
		IP:         getClientIP(r),
		UserAgent:  r.UserAgent(),
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(sessionIdleTimeout(&Session{Remember: remember})),
		CSRFToken:  csrf,
		Remember:   remember,
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

// generateSecureToken 用 crypto/rand 生成 bytes 字节的高强度随机令牌（hex 编码）。
func generateSecureToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand2.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureSessionCSRFToken 确保会话持有随机 CSRF Token（缺失时生成），返回该 Token。
func ensureSessionCSRFToken(session *Session) string {
	if session == nil || session.CSRFToken != "" {
		if session != nil {
			return session.CSRFToken
		}
		return ""
	}
	tok, err := generateSecureToken(32)
	if err != nil {
		return ""
	}
	userManager.Lock()
	session.CSRFToken = tok
	userManager.Unlock()
	return tok
}

// setCSRFCookie 下发会话绑定 CSRF Token 的 Cookie（非 HttpOnly，JS 可读，供 Double-Submit 携带）。
func setCSRFCookie(w http.ResponseWriter, session *Session) {
	tok := ensureSessionCSRFToken(session)
	if tok == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		HttpOnly: false, // JS 需读取以作为 X-CSRF-Token 请求头（Double-Submit）
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Expires:  time.Now().Add(sessionTimeout), // 与会话 Cookie 对齐，避免浏览器重启后写请求因缺 CSRF Cookie 而误 403
	})
}

// isWriteMethod 判断是否为会产生状态变更的 HTTP 方法（需 CSRF 保护）。
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// validCSRFToken 校验请求头 X-CSRF-Token 是否与会话绑定的 Token 一致（恒定时间比较）。
func validCSRFToken(session *Session, r *http.Request) bool {
	if session == nil || session.CSRFToken == "" {
		return false
	}
	tok := r.Header.Get(csrfHeaderName)
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(session.CSRFToken)) == 1
}

// deleteSession 强行销毁一个处于活动范围内的指定会话令牌
func deleteSession(sessionID string) {
	userManager.Lock()
	defer userManager.Unlock()

	delete(userManager.Sessions, sessionID)
	go scheduleSaveUsers()
}

// loginGuard 登录/注册频控：同一IP失败次数过多时临时拒绝，防暴力破解
type loginGuard struct {
	sync.Mutex
	failures map[string][]time.Time
}

var loginLimiter = &loginGuard{failures: make(map[string][]time.Time)}

const (
	loginMaxFailures = 10
	loginFailWindow  = 15 * time.Minute
)

// allowed 检查指定 key（IP 或 reg:IP）是否仍允许继续尝试
func (g *loginGuard) allowed(key string) bool {
	g.Lock()
	defer g.Unlock()
	now := time.Now()
	valid := g.failures[key][:0]
	for _, t := range g.failures[key] {
		if now.Sub(t) <= loginFailWindow {
			valid = append(valid, t)
		}
	}
	g.failures[key] = valid
	return len(valid) < loginMaxFailures
}

func (g *loginGuard) fail(key string) {
	g.Lock()
	defer g.Unlock()
	g.failures[key] = append(g.failures[key], time.Now())
}

func (g *loginGuard) reset(key string) {
	g.Lock()
	defer g.Unlock()
	delete(g.failures, key)
}

// sessionCookieFor 为已验证会话构造会话 Cookie：有效期与会话空闲超时一致；
// 仅当配置了真实域名（非 localhost、非 IP 直连）时限定 Domain，便于子域共享会话
func sessionCookieFor(sessionID string, s *Session) *http.Cookie {
	c := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(sessionIdleTimeout(s)),
		HttpOnly: true,
		Secure:   true, // 仅在HTTPS下传输
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
	if tlsDomain != "localhost" && net.ParseIP(tlsDomain) == nil {
		c.Domain = tlsDomain
	}
	return c
}

// loginHandler HTTP 端点：响应前端登录凭据并赋予访问 Token Cookie
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	if !loginLimiter.allowed(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusTooManyRequests,
			"message": "登录尝试过于频繁，请15分钟后再试",
		})
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
		loginLimiter.fail(clientIP)
		// 登录失败无会话，显式记录尝试登录的用户名
		auditActionAs(r, strings.TrimSpace(req.Username), "auth.login.failed", fmt.Sprintf("user=%s ip=%s reason=user-not-found-or-disabled", strings.TrimSpace(req.Username), clientIP))
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		loginLimiter.fail(clientIP)
		auditActionAs(r, user.Username, "auth.login.failed", fmt.Sprintf("user=%s ip=%s reason=bad-password", user.Username, clientIP))
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	loginLimiter.reset(clientIP)

	// 创建会话（记住我 → 会话时长 30 天，否则 24 小时）
	sessionID := createSession(req.Username, req.Remember, r)
	session, _ := validateSession(sessionID)
	if session != nil {
		setCSRFCookie(w, session)
	}
	// 登录时 session 尚未随请求携带，显式指定操作人
	auditActionAs(r, user.Username, "auth.login", fmt.Sprintf("user=%s ip=%s remember=%v", user.Username, clientIP, req.Remember))

	// 设置会话Cookie（有效期与会话空闲超时一致）
	http.SetCookie(w, sessionCookieFor(sessionID, session))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "登录成功",
		"user": map[string]interface{}{
			"username":    user.Username,
			"email":       user.Email,
			"role_id":     user.RoleID,
			"role":        getRoleName(user.RoleID),
			"permissions": getUserEffectivePermissions(user.Username),
		},
	})
}

// logoutHandler HTTP 端点：移除浏览器持有凭证，清退登录状态
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		logoutUser := ""
		// 退出登录时关闭该用户全部 Web Shell，并撤销其待消费的 Shell 认证 Token
		if s, ok := validateSession(cookie.Value); ok {
			logoutUser = s.Username
			shellHubState.closeUserShells(s.Username)
		}
		deleteSession(cookie.Value)
		if logoutUser != "" {
			// 登出时会话已删除，显式指定操作人
			auditActionAs(r, logoutUser, "auth.logout", "user="+logoutUser)
		}
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

// checkAuthHandler HTTP 端点：供前端无感知校验本地缓存会话是否依旧合法有效
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

	// 确保 CSRF Cookie 已就绪（Double-Submit Token 来源）
	setCSRFCookie(w, session)
	// 滑动续期同步刷新浏览器 Cookie：服务端会话在续期，但 Cookie 若仍是登录时签发的
	// 固定 24h 有效期，会先于服务端过期，导致“明明还登录着却要求重新登录”
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		http.SetCookie(w, sessionCookieFor(cookie.Value, session))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusOK,
		"message": "已登录",
		"user": map[string]interface{}{
			"username":    user.Username,
			"email":       user.Email,
			"role_id":     user.RoleID,
			"role":        getRoleName(user.RoleID),
			"permissions": getUserEffectivePermissions(user.Username),
			"last_login":  user.LastLogin.Format("2006-01-02 15:04:05"),
		},
	})
}

// getSessionFromRequest 提取位于请求头或 Cookie 区块内承载的令牌标识
// sameUserAgent 宽松比较 User-Agent：取两者较短长度的前缀比较（浏览器小版本更新不强制下线，跨客户端重放则失效）
func sameUserAgent(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n > 64 {
		n = 64
	}
	return subtle.ConstantTimeCompare([]byte(a[:n]), []byte(b[:n])) == 1
}

// getSessionFromRequest 从 Cookie 或 Bearer 头解析并校验会话（含 User-Agent 绑定校验）
func getSessionFromRequest(r *http.Request) (*Session, bool) {
	var (
		session *Session
		valid   bool
	)

	// 首先尝试从Cookie获取
	cookie, err := r.Cookie("session_id")
	if err == nil {
		session, valid = validateSession(cookie.Value)
	} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// 然后尝试从Authorization头获取
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			session, valid = validateSession(parts[1])
		}
	}

	// User-Agent 绑定：会话签发时记录 UA，之后请求 UA 不一致视为 Cookie 被盗重放
	// （历史会话 UA 为空时跳过，避免登出死循环）
	if valid && session.UserAgent != "" && !sameUserAgent(session.UserAgent, r.UserAgent()) {
		return nil, false
	}

	return session, valid
}

// authMiddleware 全局会话认证拦截中间件，提供接口级别越权防卫体系
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

		// CSRF 防护：仅针对会产生状态变更的写请求（POST/PUT/PATCH/DELETE）。
		// 使用会话绑定的随机 CSRF Token（Double-Submit Cookie），恒定时间比较。
		if isWriteMethod(r.Method) {
			if !validCSRFToken(session, r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"code":    http.StatusForbidden,
					"message": "CSRF 校验失败，请刷新页面后重试",
				})
				return
			}
		}

		// 将会话信息添加到请求上下文
		ctx := context.WithValue(r.Context(), "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ==================== 注册功能 ====================

// RegisterRequest 定义注册接口期望的请求体结构
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// registerHandler HTTP 端点：容纳用户提供的新参数并构建新的身份关联
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	if !loginLimiter.allowed("reg:" + getClientIP(r)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    http.StatusTooManyRequests,
			"message": "注册过于频繁，请稍后再试",
		})
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
		RoleID:      "user",
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Permissions: nil,
	}

	// 保存用户
	userManager.Lock()
	userManager.UserInfos[newUser.Username] = newUser
	userManager.Unlock()
	err = saveUsers()

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
	// 注册时会话尚未建立，显式指定操作人
	auditActionAs(r, newUser.Username, "auth.register", fmt.Sprintf("user=%s email=%s ip=%s", newUser.Username, newUser.Email, getClientIP(r)))

	// 创建会话并自动登录
	sessionID := createSession(newUser.Username, false, r)
	if s, ok := validateSession(sessionID); ok {
		setCSRFCookie(w, s)
	}

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
			"role_id":     newUser.RoleID,
			"role":        getRoleName(newUser.RoleID),
			"permissions": getUserEffectivePermissions(newUser.Username),
		},
	})
}

// validateRegistration 核准新用户配置密码规范并检验长度规则
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

// isValidEmail 借助正则匹配评估给定字符流是否符合电邮标准规范
func isValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	return regexp.MustCompile(emailRegex).MatchString(email)
}

// isEmailExists 防止同一电子邮箱恶意套现及重复登记
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

// generateClientFingerprint 依据浏览器的环境特征进行散列求值获取独立软体指纹
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

// checkUserAgent 检测浏览器标识符以驳回显眼的恶意探查器与爬虫
func checkUserAgent(r *http.Request) bool {
	return checkUserAgentString(r.Header.Get("User-Agent"))
}

// checkUserAgentString 对 User-Agent 字符串做浏览器标识校验
func checkUserAgentString(ua string) bool {
	userAgent := strings.ToLower(ua)

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

// checkRequiredHeaders 过滤残缺或非标准的 HTTP 操作头组合
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

// isIPBlocked 判断指定客户端是否受制于防火墙主动断流策略
func isIPBlocked(ip string) bool {
	antiCrawler.RLock()
	b, exists := antiCrawler.blockedIPs[ip]
	antiCrawler.RUnlock()
	if !exists || b == nil {
		return false
	}
	if time.Now().Before(b.BlockedUntil) {
		return true
	}
	// 已过期：清理并归档历史
	expireBlockedIP(ip)
	return false
}

// detectProxy 从报文中寻找跳板、CDN以及透传网络的代理暴露项
func detectProxy(r *http.Request) bool {
	// 检查代理相关头部
	for _, header := range proxyHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}

	return false
}

// isKnownProxyIP 判断流量网关是否由特殊集群及专用私有云转入
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

// analyzeBehavior 统计高频访问的规律并针对性开展反机器人分析
func analyzeBehavior(r *http.Request, fingerprint string) bool {
	// 已登录的管理员会话不受反爬频率限制：
	// 管理后台（服务与端口中心等）需要高频轮询刷新实时状态，不应被误封
	if session, ok := r.Context().Value("session").(*Session); ok && session != nil && session.Username != "" {
		return true
	}

	now := time.Now()
	ip := getClientIP(r)

	antiCrawler.Lock()

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

	// 更新客户端档案
	profile := antiCrawler.clientFingerprints[fingerprint]
	if profile != nil {
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
	} else {
		// 创建新客户端档案
		profile = &ClientProfile{
			Fingerprint:  fingerprint,
			IP:           ip,
			UserAgent:    r.Header.Get("User-Agent"),
			FirstSeen:    now,
			LastSeen:     now,
			RequestCount: 1,
			Score:        0,
			Blocked:      false,
		}
		antiCrawler.clientFingerprints[fingerprint] = profile
	}

	// 白名单 IP 不允许被系统自动封禁
	if isWhitelisted(ip) {
		antiCrawler.Unlock()
		return true
	}

	// 触发自动封禁（记录详细原因/触发规则/请求数/评分/指纹）
	var auto *BlockedIP
	if len(validRequests) > 100 {
		profile.Blocked = true
		auto = &BlockedIP{
			IP:           ip,
			BlockedAt:    now,
			BlockedUntil: now.Add(time.Hour),
			Reason:       "高频请求",
			Trigger:      "rate_limit",
			Score:        profile.Score,
			RequestCount: len(validRequests),
			Fingerprint:  fingerprint,
			Source:       "auto",
			Duration:     "1h",
		}
	} else if profile.Score > 50 {
		profile.Blocked = true
		auto = &BlockedIP{
			IP:           ip,
			BlockedAt:    now,
			BlockedUntil: now.Add(time.Hour),
			Reason:       "异常行为评分",
			Trigger:      "behavior_score",
			Score:        profile.Score,
			RequestCount: profile.RequestCount,
			Fingerprint:  fingerprint,
			Source:       "auto",
			Duration:     "1h",
		}
	}
	antiCrawler.Unlock()

	if auto != nil {
		addAutoBlock(auto, r)
		return false
	}
	return true
}

// verifySecurityHeaders 全面贯通并拦截违背安全通讯条例的入站调用
func verifySecurityHeaders(r *http.Request) bool {
	// 允许登录相关请求通过
	if r.URL.Path == "/login" || r.URL.Path == "/check-auth" || r.URL.Path == "/logout" {
		return true
	}

	// 1. 检查必要头部
	if !checkRequiredHeaders(r) && !strings.HasPrefix(r.URL.Path, "/ws") {
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
		log.Printf("🚫 行为异常: %s", ip)
		return false
	}

	// 6. 状态修改类写请求由 authMiddleware 完成会话绑定 CSRF 校验（见 validCSRFToken），
	//    此处不再依赖浏览器可读取的共享 HMAC Secret。

	return true
}

// checkOrigin 抵御跨站伪造访问请求(CORS/CSRF)校验 Host 与 Origin
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // 允许没有Origin头的请求（可能是同源请求）
	}

	if isAllowedOrigin(origin) {
		return true
	}

	log.Printf("🚫 阻止跨域请求: %s from %s", origin, getClientIP(r))
	return false
}

// allowedOrigins 跨域白名单（精确匹配，防止 example.com.evil.com 之类的前缀绕过）。
// 由 SERVER_STATUS_DOMAIN 与 SERVER_STATUS_LISTEN_ADDR 推导，
// 本机回环地址始终放行；其余来源用 SERVER_STATUS_EXTRA_ORIGINS 追加（逗号分隔）。
var allowedOrigins = buildAllowedOrigins()

func buildAllowedOrigins() []string {
	port := listenPort()
	origins := []string{
		"http://localhost:" + port,
		"http://127.0.0.1:" + port,
	}
	if d := tlsDomain; d != "" && d != "localhost" {
		origins = append(origins,
			"https://"+d,          // 经 443 / 反向代理访问
			"https://"+d+":"+port, // 直连本服务端口
		)
	}
	if extra := os.Getenv("SERVER_STATUS_EXTRA_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
	}
	return origins
}

// listenPort 从监听地址中解析端口（":9000" / "0.0.0.0:9000" → 9000），解析失败按 443 处理。
func listenPort() string {
	if _, port, err := net.SplitHostPort(listenAddr); err == nil && port != "" {
		return port
	}
	return "443"
}

// isAllowedOrigin 精确校验 Origin 是否在白名单内
func isAllowedOrigin(origin string) bool {
	for _, domain := range allowedOrigins {
		if origin == domain {
			return true
		}
	}
	return false
}

// securityMiddleware 配置全链路安全防护 Header 响应策略拦截
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
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		next.ServeHTTP(w, r)
	}
}

// ==================== 保存队列管理 ====================

// scheduleSaveDownloadTokens 将更新过的代号通过 Channel 缓冲投递给异步刷盘器
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

// scheduleSaveUsers 构建防死锁非阻塞式的用户表盘刷新动作
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

// getHostInfo 提供高速缓存特性的服务器静态主机属性拉取
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

// enableCORSh 解除部分需要提供静态及富媒体数据接口的沙盒跨域局限
func enableCORSh(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// loadData 于程序初始化时尝试获取累加过往记录以对接长效服务器统计
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

	// 修复：读取全局状态时赋予锁机制避免早期读取风险
	serverStatsMutex.Lock()
	totalUploadAccum = data.TotalUploadAccum
	totalDownloadAccum = data.TotalDownloadAccum
	serverStatsMutex.Unlock()

	accessStats.Lock()
	accessStats.DailyVisits = data.AccessStats.DailyVisits
	accessStats.WeeklyVisits = data.AccessStats.WeeklyVisits
	accessStats.Unlock()

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

// saveData 将承载与累加的实时计数与运行指标定格存入硬盘文件
func saveData() {
	serverStatsMutex.RLock()
	upload := totalUploadAccum
	download := totalDownloadAccum
	serverStatsMutex.RUnlock()

	accessStats.RLock()
	data := PersistData{
		TotalUploadAccum:   upload,
		TotalDownloadAccum: download,
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

// NewRateLimiter 生成提供滑动窗口能力的访问限流阀
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

// Allow 在当前时序下判定某用户的操作频次是否依然具备安全通融性
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

// cleanupExpired 卸除失效或冗余的历史限流阀记忆提升性能
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

// Stop 用于安全解绑释放资源避免常驻内存挂起
func (rl *RateLimiter) Stop() {
	if rl.cleanupTick != nil {
		rl.cleanupTick.Stop()
	}
}

// 全局速率限制器实例
var globalRateLimiter = NewRateLimiter(rateLimit, rateLimitDuration)

/*--------------------日志-------------------------*/
var logFile *os.File

// init 初始化运行环境变量并在背景铺设各类调度
func init() {
	setupLog()
	go scheduleLogRotation()
}

// setupLog 打通操作台输出重定向至本地审计文档的管道链路
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

// scheduleLogRotation 执行不间断日志分割以免庞大文件致使操作迟滞
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

// nextMidnight 换算距离跨日点差值
func nextMidnight() time.Duration {
	now := time.Now()
	// 计算下一个0点时间
	next := now.Add(24 * time.Hour)
	next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
	return next.Sub(now)
}

// cleanupExpiredSessions 主动抹去无用户挂接或过久搁置的登录痕迹
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

// cleanupAntiCrawlerData 让防爬记录仪定期脱敏以维护可观查询速度
func cleanupAntiCrawlerData() {
	antiCrawler.Lock()
	defer antiCrawler.Unlock()

	now := time.Now()

	// 清理过期的封锁IP
	for ip, b := range antiCrawler.blockedIPs {
		if b == nil || now.After(b.BlockedUntil) {
			if b != nil && b.Source == "auto" {
				b.UnblockedAt = &now
				b.UnblockedBy = "auto"
				appendAutoHistory(b)
			}
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

// listEpubs 扫描预定文库区检索所有的 Epub 并反馈可取连接
func listEpubs(w http.ResponseWriter, r *http.Request) {

	var epubURLs []string

	// 检查目录是否存在
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		http.Error(w, "目录不存在: "+dir, http.StatusInternalServerError)
		return
	}

	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("访问路径错误: %v\n", err) // 添加日志
			return err
		}

		// 只处理 .epub 文件
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".epub") {
			// 返回本服务受保护的同源下载路径（不再暴露外部静态服务地址，且 epub 需登录后才能读取）
			epubURLs = append(epubURLs, "/epub?name="+url.QueryEscape(info.Name()))
			fmt.Printf("找到 EPUB 文件: %s\n", info.Name()) // 添加日志
		}
		return nil
	})

	if err != nil {
		fmt.Printf("遍历目录错误: %v\n", err) // 添加日志
		http.Error(w, "读取 EPUB 目录失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("总共找到 %d 个 EPUB 文件\n", len(epubURLs)) // 添加日志

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(epubURLs) // 修正变量名
}

// epubFileHandler GET /epub?name=xxx.epub
// 登录 + files:view 权限保护下从 EPUB 目录流式返回电子书文件（同源访问，epub.js 可正常拉取）。
func epubFileHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(filepath.Base(r.URL.Query().Get("name")), "/")
	if name == "" || name == "." || !strings.HasSuffix(strings.ToLower(name), ".epub") {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Join(dir, name)
	if !isSafeFilePath(fullPath, dir) {
		http.Error(w, "路径不合法", http.StatusForbidden)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/epub+zip")
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, fullPath)
}

// mediaStreamHandler GET /api/media?path=xxx
// 登录 + files:manage 权限保护下，从媒体目录同源流式返回文件（http.ServeFile 自带 Range/206 断点支持）。
// 供文件管理页 Drawer 内 <video>/<img> 预览及 mpegts.js 拉流播放 .ts 使用，避免依赖跨源且带 Basic Auth 的 8081 静态地址。
func mediaStreamHandler(w http.ResponseWriter, r *http.Request) {
	// 以 "/" 为基准 Clean，消除 .. 等路径穿越片段，再交由 isSafeFilePath 双重校验
	rel := filepath.Clean("/" + strings.Trim(r.URL.Query().Get("path"), "/"))
	if rel == "" || rel == "/" {
		http.Error(w, "路径不合法", http.StatusForbidden)
		return
	}
	fullPath := filepath.Join(mediaDir, rel)
	if !isSafeFilePath(fullPath, mediaDir) {
		http.Error(w, "路径不合法", http.StatusForbidden)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Accept-Ranges", "bytes")
	// Content-Type 由 ServeFile 按扩展名推断（Go 内建 .ts → video/mp2t），未知类型自动嗅探
	http.ServeFile(w, r, fullPath)
}

// ---------------- 在线用户处理 ----------------

// wsConnect (优化)精准添加并递增多页面并发用户 WebSocket 生命挂件
func wsConnect(userKey, ip, userAgent string) {
	onlineUsers.Lock()
	defer onlineUsers.Unlock()

	user, exists := onlineUsers.Users[userKey]
	if exists {
		user.ConnCount++
		user.Since = time.Now()
		user.Page = "websocket"
	} else {
		onlineUsers.Users[userKey] = &OnlineUser{
			IP:        ip,
			UserAgent: userAgent,
			Since:     time.Now(),
			Page:      "websocket",
			ConnCount: 1,
		}
	}
}

// wsDisconnect (优化)精准消减用户挂件引用，防范多开意外下线崩溃
func wsDisconnect(userKey string) {
	onlineUsers.Lock()
	defer onlineUsers.Unlock()

	user, exists := onlineUsers.Users[userKey]
	if exists {
		user.ConnCount--
		if user.ConnCount <= 0 {
			delete(onlineUsers.Users, userKey)
		}
	}
}

// updateOnlineUser 常规HTTP操作唤起时对特定页内用户的保活记录及位置指派
func updateOnlineUser(r *http.Request, page string) {
	ip := getClientIP(r)
	userAgent := r.UserAgent()
	if userAgent == "" {
		userAgent = "Unknown"
	}

	userKey := fmt.Sprintf("%s|%s", ip, userAgent)

	onlineUsers.Lock()
	defer onlineUsers.Unlock()

	user, exists := onlineUsers.Users[userKey]
	if exists {
		user.Since = time.Now()
		user.Page = page
	} else {
		// HTTP请求不追踪ConnCount，主要交由 WebSocket 调度
		onlineUsers.Users[userKey] = &OnlineUser{
			IP:        ip,
			UserAgent: userAgent,
			Since:     time.Now(),
			Page:      page,
			ConnCount: 0,
		}
	}
}

// getClientIP 穿透各类内网跳板机追踪目标公网唯一位置锚定源
func getClientIP(r *http.Request) string {
	// 仅信任直连地址，不解析 X-Forwarded-For，防止伪造头绕过限流/封禁
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	// 处理 IPv6 地址（可能带有方括号）
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}

	return host
}

// getOnlineUsersStats 分析并组装呈现全局在线客户大厅分布阵列图谱
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

// accessStatsHandler HTTP 端点：展示给客户端最近统计的报表大盘及流转状态
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

// resetDailyStats 在夜幕隐蔽点将即日流量清算封卷开启次日记录新篇章
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

// recordAccess 累加访问指标用以支撑全局看板访问人数的核算
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

// randomMediaHandler HTTP 端点：分发流媒体挂载链接（含严密高并发处理防竞争）
// mediaSrcURL 生成随机媒体的访问地址：
// 配置了 SERVER_STATUS_STATIC_BASE_URL 时使用外链基地址；
// 否则回退为同源 /api/media（会话 + files:view 鉴权），部署无需额外的静态文件服务器。
func mediaSrcURL(name string) string {
	if staticBaseURL != "" {
		return staticBaseURL + name
	}
	return "/api/media?path=" + url.QueryEscape(name)
}

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

	// 优化：引入媒体互斥锁，彻底防范 files 重新切片时的严重内存报错
	mediaMutex.Lock()
	defer mediaMutex.Unlock()

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
		s.Src = mediaSrcURL(files[randIdx])
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
		s.Src = mediaSrcURL(files[randIdx])
		json.NewEncoder(w).Encode(s)
	}
}

// homeHandler HTTP 端点：反馈特定视频承载框架以支撑定制页面展示
func homeHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "video")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData, err := os.ReadFile(filepath.Join(indexPath, "video.html"))
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

// ==================== 模板内存缓存与 gzip 加速 ====================

// templateCacheEntry 缓存单个模板文件：原始内容 + 预压缩内容 + 用于新鲜度判断的文件信息
type templateCacheEntry struct {
	raw     []byte    // 原始文件内容
	gzipped []byte    // 预压缩内容（gzip 最快压缩级别，启动/重载时一次性生成）
	modTime time.Time // 文件最后修改时间（用于检测磁盘上模板被更新）
	size    int64     // 文件大小（与 modTime 一起判断是否需要重载）
}

var (
	templateCacheMu   sync.RWMutex
	templateCache     map[string]*templateCacheEntry // key: 模板文件名（如 index.html）
	templateCacheInit sync.Once                      // 保证首次访问时完成一次加载
)

// loadTemplateCache 将模板目录全部文件读入内存并预压缩。
// 压缩使用 gzip.BestSpeed：压缩率略低但 CPU 开销最小，适合大 HTML 文件的一次性预压缩。
func loadTemplateCache() {
	entries, err := os.ReadDir(indexPath)
	if err != nil {
		log.Printf("模板缓存加载失败（将回退为磁盘直读）: %v", err)
		return
	}
	cache := make(map[string]*templateCacheEntry, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// 跳过备份文件：它们会被敏感文件守卫拦截，永远无法被访问，缓存徒增内存
		lowerName := strings.ToLower(e.Name())
		if strings.Contains(lowerName, ".bak") || strings.HasSuffix(lowerName, "~") {
			continue
		}
		entry := buildTemplateCacheEntry(filepath.Join(indexPath, e.Name()))
		if entry != nil {
			cache[e.Name()] = entry
		}
	}
	// 单文件缓存上限：超过 5MB 的文件（如误放的二进制、大资源）不缓存，回退磁盘直读，
	// 避免异常大文件占满内存
	const maxCacheFileSize = 5 << 20
	for name, entry := range cache {
		if entry.size > maxCacheFileSize {
			delete(cache, name)
		}
	}
	templateCacheMu.Lock()
	templateCache = cache
	templateCacheMu.Unlock()
	totalRaw, totalGz := 0, 0
	for _, c := range cache {
		totalRaw += len(c.raw)
		if c.gzipped != nil {
			totalGz += len(c.gzipped)
		}
	}
	log.Printf("模板缓存已加载: %d 个文件（原始 %dKB，gzip 后 %dKB）", len(cache), totalRaw/1024, totalGz/1024)
}

// buildTemplateCacheEntry 读取单个模板文件并生成预压缩副本；读取失败返回 nil
func buildTemplateCacheEntry(path string) *templateCacheEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	entry := &templateCacheEntry{raw: data, modTime: info.ModTime(), size: info.Size()}
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err == nil {
		if _, werr := gz.Write(data); werr == nil && gz.Close() == nil {
			entry.gzipped = buf.Bytes()
		}
	}
	return entry
}

// getTemplateEntry 返回指定模板文件的缓存条目；若磁盘文件已被更新（mtime/size 变化）则自动重载。
// 这样保留了「只更新模板文件、不重启服务立即生效」的部署习惯，同时避免每次请求都完整读盘。
func getTemplateEntry(name string) *templateCacheEntry {
	templateCacheInit.Do(loadTemplateCache)
	templateCacheMu.RLock()
	entry, ok := templateCache[name]
	templateCacheMu.RUnlock()
	if !ok {
		return nil
	}
	// 新鲜度检查：stat 是轻量系统调用，远比完整读文件便宜
	if info, err := os.Stat(filepath.Join(indexPath, name)); err == nil &&
		info.ModTime().Equal(entry.modTime) && info.Size() == entry.size {
		return entry
	}
	// 磁盘文件已变化：重读并预压缩
	fresh := buildTemplateCacheEntry(filepath.Join(indexPath, name))
	if fresh == nil {
		return entry // 重读失败时继续使用旧缓存，保证服务可用
	}
	templateCacheMu.Lock()
	templateCache[name] = fresh
	templateCacheMu.Unlock()
	return fresh
}

// serveTemplateCached 以内存缓存 + 按需 gzip 的方式提供模板文件。
// 带 ETag 协商缓存：模板未变时 If-None-Match 命中直接 304（0 字节回包），避免每次进页面完整重下；
// ETag 派生自 mtime+size，沿用「改模板文件即生效」的部署习惯——文件一变 ETag 随之变化，浏览器立刻拿到新版。
// 返回 false 表示缓存中不存在该文件，调用方需自行回退处理。
func serveTemplateCached(w http.ResponseWriter, r *http.Request, name string) bool {
	entry := getTemplateEntry(name)
	if entry == nil {
		return false
	}
	etag := `"` + strconv.FormatInt(entry.modTime.UnixNano(), 36) + "-" + strconv.FormatInt(entry.size, 36) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("Vary", "Accept-Encoding")
	// If-None-Match 可能带 W/ 前缀或列表，子串匹配已覆盖本服务产生的形态
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	// 按扩展名显式设置 Content-Type（等价于原 http.FileServer 行为）
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && entry.gzipped != nil {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(entry.gzipped)))
		w.Write(entry.gzipped)
		return true
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(entry.raw)))
	w.Write(entry.raw)
	return true
}

// ==================== SSL 证书到期检测 ====================

// certInfo 描述一张 TLS 证书的关键信息（JSON 返回给前端）
type certInfo struct {
	Domain    string   `json:"domain"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	DNSNames  []string `json:"dns_names"`
	Source    string   `json:"source"` // live=实时握手（当前生效）/ file=本地证书文件
	CheckedAt string   `json:"checked_at"`
}

// probeLiveCertificate 对本机监听地址发起真实 TLS 握手，获取进程当前实际生效的证书。
// 相比读文件，这能发现「证书文件已续期但服务未重启导致旧证书仍在线上」的情况。
func probeLiveCertificate() (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", listenPort()), &tls.Config{
		ServerName:         tlsDomain,
		InsecureSkipVerify: true, // 仅读取证书元数据，不做证书链校验
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("握手成功但服务端未返回证书")
	}
	return certs[0], nil
}

// loadFileCertificate 从磁盘证书文件解析证书（实时握手失败时的兜底来源）
func loadFileCertificate() (*x509.Certificate, error) {
	data, err := os.ReadFile(tlsCertFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("证书文件不是有效的 PEM 格式")
	}
	return x509.ParseCertificate(block.Bytes)
}

// sslExpiryHandler HTTP 端点：返回当前生效 TLS 证书的到期信息（需登录且具备 system:view 权限）
func sslExpiryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cert, err := probeLiveCertificate()
	source := "live"
	if err != nil {
		// 实时握手失败（如端口被防火墙限制）：回退读取本地证书文件
		source = "file"
		cert, err = loadFileCertificate()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("证书检测失败: %v", err)})
			return
		}
	}
	info := certInfo{
		Domain:    tlsDomain,
		NotBefore: cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:  cert.NotAfter.Format("2006-01-02 15:04:05"),
		DaysLeft:  int(math.Ceil(time.Until(cert.NotAfter).Hours() / 24)),
		Issuer:    cert.Issuer.CommonName,
		Subject:   cert.Subject.CommonName,
		DNSNames:  cert.DNSNames,
		Source:    source,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	if info.Issuer == "" && len(cert.Issuer.Organization) > 0 {
		info.Issuer = cert.Issuer.Organization[0]
	}
	json.NewEncoder(w).Encode(info)
}

// trojanPageHandler 提供 Trojan-Go 详情页（需登录且具备 trojan:manage 权限）
func trojanPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 优先走内存缓存 + gzip；缓存未命中（文件缺失）时回退磁盘直读并报错
	if serveTemplateCached(w, r, "trojan.html") {
		return
	}
	htmlData, err := os.ReadFile(filepath.Join(indexPath, "trojan.html"))
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取 Trojan-Go 页面: %v", err), http.StatusInternalServerError)
		log.Printf("读取 trojan.html 失败: %v", err)
		return
	}
	_, _ = w.Write(htmlData)
}

// ifacesHandler HTTP 端点：反馈后端系统探测获取到的有效活跃网卡池
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

// wsHandler 升级请求报头至长接状态通道，推送机器运作监控信息并防阻内存泄漏
func wsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)

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

	// 优化：在此处调用 wsConnect ，利用连接计数避免单端掉线抹去同源其他连线数据
	wsConnect(userKey, ip, userAgent)

	// 设置连接参数
	conn.SetReadLimit(512)                                 // 限制消息大小
	conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // 设置读超时
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	done := make(chan struct{})

	// 启动goroutine读取客户端消息（主要用于检测连接状态）
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				// 检查是否是正常关闭
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket读取错误: %v", err)
				}
				break
			}
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	pingTicker := time.NewTicker(30 * time.Second) // 每30秒发送一次ping
	defer func() {
		ticker.Stop()
		pingTicker.Stop()
		// 优化：利用 wsDisconnect 取消强制摧毁操作
		wsDisconnect(userKey)
		conn.Close()
	}()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
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
			if err = conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("WebSocket Ping Error:", err)
				return
			}
		}
	}
}

// ---------------- Server Status ----------------

func getInterfaceIP(iface string) string {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := netIface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return ""
}

// getServerStatus 查询深层探针系统状态。现已引入O(1)级全局锁定防并发灾变与1秒时效高能缓存调度体系
func getServerStatus(iface string) (*ServerStatus, error) {
	// ====== 高能缓存命中逻辑开始 ======
	serverStatsMutex.RLock()
	cTime := statusCacheTime[iface]
	cData := statusCache[iface]
	serverStatsMutex.RUnlock()

	// 若在 300ms TTL 之内存在高可用缓存数据，则避免执行底层开销极高的查询，直接折返
	// 注意：TTL 必须小于 WebSocket 1 秒的推送间隔，否则会推送重复/过期数据
	if time.Since(cTime) < 300*time.Millisecond && cData != nil {
		return cData, nil
	}
	// ===================================

	// ====== 硬件底层请求锁定 ======
	serverStatsMutex.Lock()
	defer serverStatsMutex.Unlock()

	// 双检锁，可能其他 Goroutine 刚刚获取并填充满了
	if time.Since(statusCacheTime[iface]) < 300*time.Millisecond && statusCache[iface] != nil {
		return statusCache[iface], nil
	}

	now := time.Now()

	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	var totalDisk uint64
	var usedDisk uint64
	var freeDisk uint64
	diskList := make([]DiskPartition, 0, 8)

	// 获取所有分区
	partitions, err := disk.Partitions(false)
	if err == nil {
		// 过滤掉虚拟文件系统
		excludedFsTypes := map[string]bool{
			"tmpfs":      true,
			"devtmpfs":   true,
			"proc":       true,
			"sysfs":      true,
			"overlay":    true,
			"cgroup":     true,
			"devpts":     true,
			"mqueue":     true,
			"hugetlbfs":  true,
			"autofs":     true,
			"squashfs":   true,
			"iso9660":    true,
			"fuse":       true,
			"fuse.sshfs": true,
		}

		// 用于去重，避免重复统计同一个设备
		processedDevices := make(map[string]bool)

		for _, partition := range partitions {
			if excludedFsTypes[partition.Fstype] {
				continue
			}
			if processedDevices[partition.Device] {
				continue
			}

			usage, err := disk.Usage(partition.Mountpoint)
			if err != nil {
				continue
			}

			processedDevices[partition.Device] = true
			totalDisk += usage.Total
			usedDisk += usage.Used
			freeDisk += usage.Free
			diskList = append(diskList, DiskPartition{
				Mount:       partition.Mountpoint,
				Total:       usage.Total,
				Used:        usage.Used,
				Free:        usage.Free,
				UsedPercent: usage.UsedPercent,
			})
		}
	} else {
		// 如果失败，回退到只获取根分区
		diskInfo, err := disk.Usage("/")
		if err != nil {
			return nil, err
		}
		totalDisk = diskInfo.Total
		usedDisk = diskInfo.Used
		freeDisk = diskInfo.Free
		diskList = append(diskList, DiskPartition{
			Mount:       "/",
			Total:       diskInfo.Total,
			Used:        diskInfo.Used,
			Free:        diskInfo.Free,
			UsedPercent: diskInfo.UsedPercent,
		})
	}

	// 分区按挂载点排序，展示顺序稳定
	sort.Slice(diskList, func(i, j int) bool { return diskList[i].Mount < diskList[j].Mount })

	// 计算磁盘使用百分比
	diskUsagePercent := 0.0
	if totalDisk > 0 {
		diskUsagePercent = float64(usedDisk) / float64(totalDisk) * 100
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

				// 在持有 serverStatsMutex 锁的环境下执行安全更新操作，消灭崩溃
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
	serverIP := getInterfaceIP(iface)

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

	// 拼装最终结果
	result := &ServerStatus{
		CPUUsage:      cpuPercent[0],
		MemoryUsage:   memInfo.UsedPercent,
		MemoryTotal:   memInfo.Total / 1024 / 1024,
		DiskUsage:     diskUsagePercent,
		DiskTotal:     totalDisk / 1024 / 1024 / 1024,
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
		ServerIP:      serverIP,
		Trojan: func() TrojanStatus {
			if trojanClient == nil {
				return TrojanStatus{}
			}
			return trojanClient.snapshot()
		}(),
		Disks: diskList,
	}

	// 填装入缓存并回写记录刻度
	statusCache[iface] = result
	statusCacheTime[iface] = time.Now()

	return result, nil
}

// formatBytes 辅助呈现将系统内耗的极小字阶自动上浮易读体量区间
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

// execHandler HTTP 端点：约束外部特权在允许且极短的防僵死闭包环境代操作命令行
func execHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "exec")

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	cmdName := r.URL.Query().Get("command")
	if cmdName == "" {
		http.Error(w, "Missing command parameter", http.StatusBadRequest)
		return
	}

	args, ok := allowedCommands[cmdName]
	if !ok {
		auditAction(r, "exec.denied", "command="+cmdName+" reason=not-whitelisted")
		http.Error(w, "Command not allowed", http.StatusForbidden)
		return
	}

	// 系统命令执行属高危操作，无论成败均记录审计
	defer auditAction(r, "exec.run", "command="+cmdName)

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

// main 主宰整个程序的挂载，驱动所有路由装配及守望守护协程开启
func main() {
	log.Printf("🚀 server-status 启动 version=%s commit=%s buildDate=%s", version, commit, buildDate)

	// 初始化用户系统
	loadUsers()

	// 初始化 Trojan-Go 客户端并启动状态刷新
	trojanClient = newTrojanClient()
	defer trojanClient.close()

	// 初始化数据
	loadData()

	// 初始化下载令牌系统
	initDownloadTokenManager()

	// 初始化 RBAC 角色权限系统
	initRBAC()

	// 初始化隐藏私人空间（双层认证 / SQLite / 卡片分享）
	if err := initPrivateNotes(); err != nil {
		log.Printf("⚠️ 私人空间未启用: %v", err)
	} else {
		privateStore.StartMaintenance()
	}

	// 加载手动封禁的 IP 列表
	loadBlockedIPs()

	// 定期清理过期的自动/手动封禁
	go ipSecurityPruneLoop()

	// 初始化服务与端口中心（托管服务注册表、防火墙状态、端口变化检测）
	loadManagedServices()
	loadFirewallState()
	go trackPortChangesLoop()

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

	// 启动时将模板读入内存并预压缩 gzip（消除每请求磁盘读与压缩开销）
	loadTemplateCache()

	// 启动时预热 Docker 缓存（docker stats 采集慢，预热后首屏秒开）
	go warmDockerCaches()

	// 定时保存数据
	go func() {
		t := time.NewTicker(time.Second * 30)
		for range t.C {
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
		if trojanClient != nil {
			if err := trojanClient.close(); err != nil {
				log.Printf("关闭 Trojan-Go 客户端失败: %v", err)
			}
		}
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
	http.HandleFunc("/generate-download-token", authMiddleware(requirePermission("token:issue", securityMiddleware(generateDownloadTokenHandler))))
	http.HandleFunc("/download", securityMiddleware(secureDownloadHandler))
	http.HandleFunc("/download-info", securityMiddleware(downloadInfoHandler))
	http.HandleFunc("/list-download-tokens", authMiddleware(requireAnyPermission([]string{"token:view", "token:issue"}, securityMiddleware(listDownloadTokensHandler))))
	// 撤销：登录即可进 handler，细粒度在 handler 内判定——token:revoke 可撤任意，普通用户仅能撤自己名下
	http.HandleFunc("/revoke-download-token", authMiddleware(securityMiddleware(revokeDownloadTokenHandler)))

	// 使用认证中间件和安全中间件包装所有处理函数
	// 静态文件服务：拦截备份/配置/源码等敏感文件，防止泄露
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lower := strings.ToLower(r.URL.Path)
		for _, pat := range []string{".bak", ".json", ".go", ".sh", ".key", ".pem", ".log", ".db", ".tmp", "~"} {
			if strings.Contains(lower, pat) {
				http.NotFound(w, r)
				return
			}
		}
		// 模板缓存命中时由 serveTemplateCached 设置 ETag 协商缓存（no-cache：每次校验、未变 304），
		// 未命中回退路径保持 no-store，防止敏感文件被缓存
		name := path.Base(r.URL.Path)
		if name == "/" || name == "." {
			name = "index.html"
		}
		if serveTemplateCached(w, r, name) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.FileServer(http.Dir(indexPath)).ServeHTTP(w, r)
	}))
	http.HandleFunc("/ws", authMiddleware(requirePermission("system:view", securityMiddleware(wsHandler))))
	http.HandleFunc("/video", authMiddleware(requirePermission("files:view", securityMiddleware(homeHandler))))
	http.HandleFunc("/status-ifaces", authMiddleware(requirePermission("system:view", securityMiddleware(ifacesHandler))))
	http.HandleFunc("GET /api/ssl/expiry", authMiddleware(requirePermission("system:view", securityMiddleware(sslExpiryHandler))))
	http.HandleFunc("/random-media", enableCORSh(authMiddleware(requirePermission("files:view", securityMiddleware(randomMediaHandler)))))
	http.HandleFunc("/access-stats", authMiddleware(requirePermission("system:view", securityMiddleware(accessStatsHandler))))
	http.HandleFunc("/exec", authMiddleware(requirePermission("system:exec", securityMiddleware(execHandler))))
	http.HandleFunc("/epubs", enableCORSh(authMiddleware(requirePermission("files:view", securityMiddleware(listEpubs)))))
	http.HandleFunc("GET /epub", authMiddleware(requirePermission("files:view", securityMiddleware(epubFileHandler))))

	// Trojan-Go 状态与用户管理接口
	http.HandleFunc("GET /api/trojan/status", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanStatusHandler))))
	http.HandleFunc("GET /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUsersHandler))))
	http.HandleFunc("POST /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUserMutationHandler))))
	http.HandleFunc("PUT /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUserMutationHandler))))
	http.HandleFunc("DELETE /api/trojan/users", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanUserMutationHandler))))
	http.HandleFunc("POST /api/trojan/users/traffic-reset", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanTrafficResetHandler))))
	http.HandleFunc("GET /api/trojan/users/{hash}/connection", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanConnectionHandler))))
	http.HandleFunc("POST /api/trojan/users/{hash}/credential", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanCredentialHandler))))
	http.HandleFunc("GET /api/trojan/users/{hash}/connection/test", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanConnectionTestHandler))))
	http.HandleFunc("GET /api/trojan/users/{hash}/clash/download", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanClashDownloadHandler))))
	http.HandleFunc("GET /api/trojan/users/{hash}/singbox/download", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanSingboxDownloadHandler))))
	http.HandleFunc("/trojan", authMiddleware(requirePermission("trojan:manage", securityMiddleware(trojanPageHandler))))

	// RBAC 权限管理接口
	http.HandleFunc("GET /api/rbac/permissions", authMiddleware(requirePermission("role:manage", securityMiddleware(listPermissionsHandler))))
	http.HandleFunc("GET /api/rbac/roles", authMiddleware(requireAnyPermission([]string{"role:manage", "user:manage", "user:view"}, securityMiddleware(listRolesHandler))))
	http.HandleFunc("GET /api/rbac/roles/{role_id}", authMiddleware(requireAnyPermission([]string{"role:manage", "user:manage", "user:view"}, securityMiddleware(getRoleHandler))))
	http.HandleFunc("POST /api/rbac/roles", authMiddleware(requirePermission("role:manage", securityMiddleware(createRoleHandler))))
	http.HandleFunc("PUT /api/rbac/roles/{role_id}", authMiddleware(requirePermission("role:manage", securityMiddleware(updateRoleHandler))))
	http.HandleFunc("DELETE /api/rbac/roles/{role_id}", authMiddleware(requirePermission("role:manage", securityMiddleware(deleteRoleHandler))))
	http.HandleFunc("GET /api/rbac/users", authMiddleware(requireAnyPermission([]string{"user:manage", "user:view"}, securityMiddleware(listRbacUsersHandler))))
	http.HandleFunc("POST /api/rbac/users", authMiddleware(requirePermission("user:manage", securityMiddleware(createRbacUserHandler))))
	http.HandleFunc("PUT /api/rbac/users/{username}", authMiddleware(requirePermission("user:manage", securityMiddleware(updateRbacUserHandler))))
	http.HandleFunc("DELETE /api/rbac/users/{username}", authMiddleware(requirePermission("user:manage", securityMiddleware(deleteRbacUserHandler))))
	http.HandleFunc("GET /api/rbac/online-count", authMiddleware(requireAnyPermission([]string{"role:manage", "user:manage", "user:view"}, securityMiddleware(onlineCountHandler))))
	http.HandleFunc("/api/audit", authMiddleware(requireAnyPermission([]string{"role:manage", "user:manage"}, securityMiddleware(auditQueryHandler))))
	http.HandleFunc("GET /api/logs/files", authMiddleware(requirePermission("system:log", securityMiddleware(listLogFilesHandler))))
	http.HandleFunc("GET /api/logs", authMiddleware(requirePermission("system:log", securityMiddleware(logContentHandler))))

	// 文件管理与进程监控接口
	http.HandleFunc("GET /api/files", authMiddleware(requirePermission("files:manage", securityMiddleware(listFilesHandler))))
	http.HandleFunc("POST /api/files/upload", authMiddleware(requirePermission("files:manage", securityMiddleware(uploadFileHandler))))
	http.HandleFunc("POST /api/files/mkdir", authMiddleware(requirePermission("files:manage", securityMiddleware(mkdirFileHandler))))
	http.HandleFunc("DELETE /api/files", authMiddleware(requirePermission("files:manage", securityMiddleware(deleteFileHandler))))
	// 文件收藏（按用户持久化到 favorites.json；写操作由 authMiddleware 做会话绑定 CSRF 校验）
	http.HandleFunc("GET /api/files/favorites", authMiddleware(requirePermission("files:manage", securityMiddleware(favoritesHandler))))
	http.HandleFunc("POST /api/files/favorites", authMiddleware(requirePermission("files:manage", securityMiddleware(favoritesHandler))))
	http.HandleFunc("DELETE /api/files/favorites", authMiddleware(requirePermission("files:manage", securityMiddleware(favoritesHandler))))
	http.HandleFunc("GET /api/media", authMiddleware(requirePermission("files:manage", securityMiddleware(mediaStreamHandler))))
	http.HandleFunc("GET /api/processes", authMiddleware(requirePermission("system:process", securityMiddleware(listProcessesHandler))))
	http.HandleFunc("GET /api/processes/{pid}", authMiddleware(requirePermission("system:process", securityMiddleware(getProcessDetailHandler))))
	http.HandleFunc("POST /api/processes/kill", authMiddleware(requirePermission("system:kill", securityMiddleware(killProcessHandler))))
	http.HandleFunc("GET /api/ip/blocked", authMiddleware(requirePermission("ip:manage", securityMiddleware(listBlockedIPsHandler))))
	http.HandleFunc("POST /api/ip/block", authMiddleware(requirePermission("ip:manage", securityMiddleware(blockIPHandler))))
	http.HandleFunc("POST /api/ip/unblock", authMiddleware(requirePermission("ip:manage", securityMiddleware(unblockIPHandler))))
	http.HandleFunc("GET /api/ipinfo", authMiddleware(requirePermission("system:view", securityMiddleware(ipinfoProxyHandler))))
	http.HandleFunc("GET /api/ip/blocked/history", authMiddleware(requirePermission("ip:manage", securityMiddleware(listBlockHistoryHandler))))
	http.HandleFunc("GET /api/ip/whitelist", authMiddleware(requirePermission("ip:manage", securityMiddleware(listWhitelistHandler))))
	http.HandleFunc("POST /api/ip/whitelist", authMiddleware(requirePermission("ip:manage", securityMiddleware(addWhitelistHandler))))
	http.HandleFunc("POST /api/ip/whitelist/remove", authMiddleware(requirePermission("ip:manage", securityMiddleware(removeWhitelistHandler))))
	http.HandleFunc("GET /api/ip/security/summary", authMiddleware(requirePermission("ip:manage", securityMiddleware(ipSecuritySummaryHandler))))
	http.HandleFunc("GET /ws/ip-events", authMiddleware(requirePermission("ip:manage", securityMiddleware(ipEventsWSHandler))))

	// 服务与端口中心 - 服务管理
	http.HandleFunc("GET /api/services", authMiddleware(requirePermission("service:view", securityMiddleware(listServicesHandler))))
	http.HandleFunc("GET /api/services/{name}", authMiddleware(requirePermission("service:view", securityMiddleware(getServiceHandler))))
	http.HandleFunc("POST /api/services", authMiddleware(requirePermission("service:manage", securityMiddleware(createServiceHandler))))
	http.HandleFunc("PUT /api/services/{name}", authMiddleware(requirePermission("service:manage", securityMiddleware(updateServiceHandler))))
	http.HandleFunc("DELETE /api/services/{name}", authMiddleware(requirePermission("service:delete", securityMiddleware(deleteServiceHandler))))
	http.HandleFunc("POST /api/services/{name}/start", authMiddleware(requirePermission("service:manage", securityMiddleware(serviceActionHandler("start")))))
	http.HandleFunc("POST /api/services/{name}/stop", authMiddleware(requirePermission("service:manage", securityMiddleware(serviceActionHandler("stop")))))
	http.HandleFunc("POST /api/services/{name}/restart", authMiddleware(requirePermission("service:manage", securityMiddleware(serviceActionHandler("restart")))))
	http.HandleFunc("POST /api/services/{name}/enable", authMiddleware(requirePermission("service:manage", securityMiddleware(serviceActionHandler("enable")))))
	http.HandleFunc("POST /api/services/{name}/disable", authMiddleware(requirePermission("service:manage", securityMiddleware(serviceActionHandler("disable")))))
	http.HandleFunc("GET /api/services/{name}/logs", authMiddleware(requirePermission("service:view", securityMiddleware(getServiceLogsHandler))))
	http.HandleFunc("GET /api/services/{name}/ports", authMiddleware(requirePermission("service:view", securityMiddleware(getServicePortsHandler))))
	// 服务与端口中心 - 端口管理
	http.HandleFunc("GET /api/ports", authMiddleware(requirePermission("port:view", securityMiddleware(listPortsHandler))))
	http.HandleFunc("GET /api/ports/changes", authMiddleware(requirePermission("port:view", securityMiddleware(listPortChangesHandler))))
	http.HandleFunc("GET /api/ports/{port}", authMiddleware(requirePermission("port:view", securityMiddleware(getPortDetailHandler))))
	http.HandleFunc("POST /api/ports/{port}/close", authMiddleware(requirePermission("port:manage", securityMiddleware(closePortHandler))))
	http.HandleFunc("POST /api/ports/{port}/open", authMiddleware(requirePermission("port:manage", securityMiddleware(openPortHandler))))
	http.HandleFunc("GET /api/firewall", authMiddleware(requirePermission("port:view", securityMiddleware(listFirewallHandler))))
	http.HandleFunc("POST /api/ports/rules", authMiddleware(requirePermission("port:manage", securityMiddleware(createPortRuleHandler))))
	http.HandleFunc("DELETE /api/ports/rules/{id}", authMiddleware(requirePermission("port:manage", securityMiddleware(deletePortRuleHandler))))
	// 服务与端口中心 - 实时服务日志
	http.HandleFunc("GET /ws/service-logs", authMiddleware(requirePermission("service:view", securityMiddleware(serviceLogsWSHandler))))
	// 服务与端口中心页面级数据推送（端口+服务，stale-first 缓存直推，按权限过滤字段）
	http.HandleFunc("GET /ws/ports", authMiddleware(requireAnyPermission([]string{"port:view", "service:view"}, securityMiddleware(portsWSHandler))))

	// ==================== Docker 容器监控与管理 ====================
	http.HandleFunc("GET /api/docker/containers", authMiddleware(requirePermission("docker:view", securityMiddleware(dockerListHandler))))
	http.HandleFunc("GET /api/docker/logs", authMiddleware(requirePermission("docker:view", securityMiddleware(dockerLogsHandler))))
	http.HandleFunc("GET /api/docker/overview", authMiddleware(requirePermission("docker:view", securityMiddleware(dockerOverviewHandler))))
	http.HandleFunc("GET /api/docker/inspect", authMiddleware(requirePermission("docker:view", securityMiddleware(dockerInspectHandler))))
	http.HandleFunc("POST /api/docker/action", authMiddleware(requirePermission("docker:manage", securityMiddleware(dockerActionHandler))))
	http.HandleFunc("POST /api/docker/remove", authMiddleware(requirePermission("docker:manage", securityMiddleware(dockerRemoveHandler))))
	http.HandleFunc("/docker", authMiddleware(requireAnyPermission([]string{"docker:view", "docker:manage"}, securityMiddleware(dockerPageHandler))))
	// 容器列表数据推送（纯缓存直推，替代阻塞式 HTTP 轮询首载）
	http.HandleFunc("GET /ws/docker", authMiddleware(requireAnyPermission([]string{"docker:view", "docker:manage"}, securityMiddleware(dockerWSHandler))))

	// ==================== Web Shell / Web Terminal ====================
	// 复用 system:exec 权限；每次启动 Shell 均需独立二次认证 + 一次性 Token
	http.HandleFunc("GET /shell.html", authMiddleware(requirePermission("system:exec", securityMiddleware(shellPageHandler))))
	http.HandleFunc("POST /api/shell/setup-password", authMiddleware(requirePermission("system:exec", securityMiddleware(shellSetupPasswordHandler))))
	http.HandleFunc("POST /api/shell/auth", authMiddleware(requirePermission("system:exec", securityMiddleware(shellAuthHandler))))
	http.HandleFunc("POST /api/shell/change-password", authMiddleware(requirePermission("system:exec", securityMiddleware(shellChangePasswordHandler))))
	http.HandleFunc("GET /api/shell/sessions", authMiddleware(requirePermission("system:exec", securityMiddleware(shellListSessionsHandler))))
	http.HandleFunc("DELETE /api/shell/sessions/{id}", authMiddleware(requirePermission("system:exec", securityMiddleware(shellDeleteSessionHandler))))
	http.HandleFunc("DELETE /api/shell/auth-sessions/{id}", authMiddleware(requirePermission("system:exec", securityMiddleware(shellDeleteAuthSessionHandler))))
	http.HandleFunc("POST /api/shell/revoke-all", authMiddleware(requirePermission("system:exec", securityMiddleware(shellRevokeAllHandler))))
	http.HandleFunc("GET /ws/shell", authMiddleware(requirePermission("system:exec", securityMiddleware(shellWSHandler))))

	// ==================== 隐藏私人空间路由 ====================
	registerPrivateRoutes(http.DefaultServeMux)

	// 密钥配置健康提示（不输出实际密钥值）
	if os.Getenv("SERVER_STATUS_SIGNING_KEY") == "" {
		log.Println("⚠️ 未设置 SERVER_STATUS_SIGNING_KEY，服务端签名密钥为启动时随机生成（重启后旧 Cookie 签名将失效）。")
	}
	if os.Getenv("SERVER_STATUS_ENCRYPT_KEY") != "" || os.Getenv("SERVER_STATUS_DOWNLOAD_TOKEN_SECRET") != "" {
		// OK：由环境变量显式注入
	} else {
		log.Println("⚠️ 建议通过环境变量 SERVER_STATUS_ENCRYPT_KEY / SERVER_STATUS_DOWNLOAD_TOKEN_SECRET 注入加密密钥，避免使用内置默认值。")
	}

	fmt.Printf("Server running on %s (HTTPS)\n", listenAddr)
	log.Printf("服务器启动时间: %s", serverStartTime.Format("2006-01-02 15:04:05"))
	// 启用 TLS 1.2+，禁用老旧弱协议。
	// NextProtos 仅声明 http/1.1：Go 内建 HTTP/2 服务端不支持 RFC 8441 extended CONNECT，
	// 若 ALPN 协商出 h2，浏览器 wss:// WebSocket 握手会以 protocol error 被静默掐断
	//（服务端无日志、前端表现为"正在连接"无限转圈）。禁 h2 换取全部 WS 端点可用。
	srv := &http.Server{
		Addr: listenAddr,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
	}
	log.Fatal(srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}
