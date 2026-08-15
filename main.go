package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	rand2 "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
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
	"golang.org/x/crypto/bcrypt"
)

// 配置项
const (
	mediaDir          = "/home/file/static"
	indexPath         = "/home/os/templates" //index.html 文件所在目录
	urls              = "https://xyx.homes:8081/static/"
	authToken         = "123456"
	dataFile          = "/home/os/server_data.json"             //服务器数据保存路径
	rateLimit         = 10                                      // 每分钟最大请求数
	rateLimitDuration = time.Minute                             // 速率限制时间窗口
	logDir            = "/home/os/log"                          // 日志目录
	securityToken     = "wustwu_anti_crawler_2024_security_key" // 反爬安全令牌
	signatureTimeout  = 30 * time.Second                        // 签名超时时间
	usersFile         = "/home/os/users.json"                   // 用户数据文件
	sessionTimeout    = 24 * time.Hour                          // 会话超时时间
	encryptionKey     = "wustwu_user_data_encryption_key_2024"  // 用户数据加密密钥

	dir = "/home/file/static" // EPUB 文件所在目录
	// 新增下载密钥配置
	downloadTokenExpiry = 30 * time.Minute                    // 下载令牌有效期
	downloadLimitBytes  = 3 * 1024 * 1024 * 1024              // 2GB 下载限制
	downloadTokenSecret = "wustwu_download_token_secret_2024" // 下载令牌密钥
	downloadTokensFile  = "/home/os/download_tokens.json"     // 下载令牌存储文件
)

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
	{Key: "files:view", Name: "查看媒体文件", Group: "文件", Description: "查看视频、电子书、随机媒体等内容"},
	{Key: "files:download", Name: "下载文件", Group: "文件", Description: "生成下载令牌并下载服务器文件"},
	{Key: "files:manage", Name: "管理文件", Group: "文件", Description: "浏览、上传、删除服务器文件目录"},
	{Key: "token:manage", Name: "管理下载令牌（查看/撤销）", Group: "文件", Description: "查看和撤销自己名下的下载令牌"},
	{Key: "token:issue", Name: "下发下载令牌", Group: "文件", Description: "为指定用户签发下载令牌，并设置有效期和流量上限"},
	{Key: "system:process", Name: "查看进程列表", Group: "系统", Description: "查看服务器进程占用情况（CPU/内存）"},
	{Key: "ip:manage", Name: "管理IP封禁", Group: "系统", Description: "查看访问IP并封禁/解封异常IP"},
	{Key: "user:view", Name: "查看用户", Group: "用户", Description: "查看系统用户列表"},
	{Key: "user:manage", Name: "管理用户", Group: "用户", Description: "创建、编辑、禁用、删除用户"},
	{Key: "role:manage", Name: "管理角色", Group: "用户", Description: "创建、编辑、删除角色及其权限"},
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
			Permissions: []string{"system:view", "system:exec", "files:view", "files:download", "token:manage", "user:view"},
			IsSystem:    true,
			CreatedAt:   now,
		},
		"user": {
			RoleID:      "user",
			Name:        "普通用户",
			Description: "可查看服务器状态及下载媒体文件",
			Permissions: []string{"system:view", "files:view", "files:download", "token:manage"},
			IsSystem:    true,
			CreatedAt:   now,
		},
	}
}

// ensureDefaultRoles 确保系统内置角色始终存在
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
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	RoleID      string    `json:"role_id"`
	RoleName    string    `json:"role_name"`
	Permissions []string  `json:"permissions"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
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

	writeJSON(w, http.StatusOK, "角色删除成功", nil)
}

// listRbacUsersHandler 返回用户列表（含角色信息）
func listRbacUsersHandler(w http.ResponseWriter, r *http.Request) {
	userManager.RLock()
	userList := make([]UserListItem, 0, len(userManager.UserInfos))
	for _, user := range userManager.UserInfos {
		userList = append(userList, UserListItem{
			Username:  user.Username,
			Email:     user.Email,
			RoleID:    user.RoleID,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			LastLogin: user.LastLogin,
		})
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
	}
	userManager.Unlock()
	err := saveUsers()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "系统错误，请稍后重试")
		return
	}

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

	log.Printf("删除文件成功: %s", fullPath)
	writeJSON(w, http.StatusOK, "删除成功", nil)
}

// ==================== 进程监控功能 ====================

// ProcessInfo 进程信息
type ProcessInfo struct {
	User    string `json:"user"`
	PID     string `json:"pid"`
	CPU     string `json:"cpu"`
	MemPct  string `json:"mem_pct"`
	RSSMB   string `json:"rss_mb"`
	VSZMB   string `json:"vsz_mb"`
	Elapsed string `json:"elapsed"`
	Command string `json:"command"`
}

// listProcessesHandler 返回按 CPU/内存排序的进程列表
func listProcessesHandler(w http.ResponseWriter, r *http.Request) {
	sortBy := r.URL.Query().Get("sort")
	if sortBy != "mem" {
		sortBy = "cpu"
	}
	psSort := "pcpu"
	if sortBy == "mem" {
		psSort = "pmem"
	}
	topStr := r.URL.Query().Get("top")
	top := 50
	if n, err := strconv.Atoi(topStr); err == nil && n > 0 && n <= 200 {
		top = n
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 使用 ps 获取进程列表，LC_ALL=C 避免本地化输出差异
	cmd := exec.CommandContext(ctx, "ps", "-eo", "user,pid,pcpu,pmem,rss,vsz,etime,comm,args", "--sort=-"+psSort)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err := cmd.Output()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取进程列表失败: "+err.Error())
		return
	}

	lines := strings.Split(string(output), "\n")
	processes := make([]ProcessInfo, 0, top)
	for i, line := range lines {
		if i == 0 { // 跳过表头
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// 0 user 1 pid 2 pcpu 3 pmem 4 rss(KB) 5 vsz(KB) 6 etime 7 comm 8+ args
		command := fields[7]
		if len(fields) > 8 {
			command = strings.Join(fields[8:], " ")
		}
		if command == "" {
			command = fields[7]
		}
		if len(command) > 200 {
			command = command[:200] + "..."
		}
		processes = append(processes, ProcessInfo{
			User:    fields[0],
			PID:     fields[1],
			CPU:     fields[2],
			MemPct:  fields[3],
			RSSMB:   fmt.Sprintf("%.1f", parseKbToMb(fields[4])),
			VSZMB:   fmt.Sprintf("%.1f", parseKbToMb(fields[5])),
			Elapsed: fields[6],
			Command: command,
		})
		if len(processes) >= top {
			break
		}
	}

	writeJSON(w, http.StatusOK, "获取进程列表成功", processes)
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

	// 127.0.0.1 上证书 CN=xyx.homes 与主机名不匹配，需跳过证书校验
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

const blockedIPsFile = "/home/os/blocked_ips.json"

// loadBlockedIPs 启动时加载手动封禁的 IP 列表
func loadBlockedIPs() {
	data, err := os.ReadFile(blockedIPsFile)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("读取封禁IP文件失败: %v", err)
		return
	}
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		log.Printf("解析封禁IP文件失败: %v", err)
		return
	}
	now := time.Now()
	antiCrawler.Lock()
	for _, ip := range ips {
		antiCrawler.blockedIPs[ip] = now.Add(365 * 24 * time.Hour)
	}
	antiCrawler.Unlock()
	if len(ips) > 0 {
		log.Printf("加载 %d 个手动封禁IP", len(ips))
	}
}

// saveBlockedIPs 持久化手动封禁的 IP 列表
func saveBlockedIPs() {
	antiCrawler.RLock()
	ips := make([]string, 0)
	for ip, expiry := range antiCrawler.blockedIPs {
		// 只持久化长期封禁（手动封禁标记为 365 天）
		if time.Until(expiry) > 30*24*time.Hour {
			ips = append(ips, ip)
		}
	}
	antiCrawler.RUnlock()

	data, err := json.Marshal(ips)
	if err != nil {
		return
	}
	if err := os.WriteFile(blockedIPsFile, data, 0600); err != nil {
		log.Printf("保存封禁IP文件失败: %v", err)
	}
}

// BlockIPRequest 封禁/解封请求
type BlockIPRequest struct {
	IP string `json:"ip"`
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
	antiCrawler.Lock()
	antiCrawler.blockedIPs[ip] = time.Now().Add(365 * 24 * time.Hour)
	antiCrawler.Unlock()
	saveBlockedIPs()
	log.Printf("手动封禁IP: %s", ip)
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
	antiCrawler.Lock()
	delete(antiCrawler.blockedIPs, ip)
	antiCrawler.Unlock()
	saveBlockedIPs()
	log.Printf("解封IP: %s", ip)
	writeJSON(w, http.StatusOK, "IP 已解封", nil)
}

// listBlockedIPsHandler 列出当前封禁的 IP
func listBlockedIPsHandler(w http.ResponseWriter, r *http.Request) {
	antiCrawler.RLock()
	list := make([]map[string]interface{}, 0)
	for ip, expiry := range antiCrawler.blockedIPs {
		list = append(list, map[string]interface{}{
			"ip":      ip,
			"expires": expiry.Format("2006-01-02 15:04:05"),
			"blocked": time.Now().Before(expiry),
		})
	}
	antiCrawler.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i]["ip"].(string) < list[j]["ip"].(string)
	})

	writeJSON(w, http.StatusOK, "获取封禁列表成功", list)
}

// ==================== 进程结束功能 ====================

// KillProcessRequest 结束进程请求
type KillProcessRequest struct {
	PID int `json:"pid"`
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
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "结束进程失败: "+err.Error())
		return
	}
	log.Printf("已发送终止信号给进程 %d", req.PID)
	writeJSON(w, http.StatusOK, "已发送终止信号", nil)
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
	Hostname      string           `json:"hostname"`
	OS            string           `json:"os"`
	Platform      string           `json:"platform"`
	KernelVersion string           `json:"kernel_version"`
	Architecture  string           `json:"architecture"`
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
	rbacFile     = "/home/os/rbac.json"
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

// 字节计数器
type byteCounter struct {
	total *int64
}

// Write 字节计数器写入方法，用于统计下载流量
func (bc *byteCounter) Write(p []byte) (int, error) {
	*bc.total += int64(len(p))
	return len(p), nil
}

// ==================== 下载令牌功能 ====================

// generateRandomString 生成指定长度的随机字符串，采用高强度密码学随机生成器
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand2.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// encryptDownloadToken 将下载令牌数据通过 AES-GCM 加密，确保令牌安全不可篡改
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

// verifyDownloadToken 验证下载令牌合法性
func verifyDownloadToken(token string, downloadToken *DownloadToken) bool {
	// 简化实现：在实际生产环境中应该使用完整的加密验证
	// 这里为了简化，我们假设令牌是有效的
	return true
}

// generateDownloadToken 生成新的下载令牌授权票据
func generateDownloadToken(username string, r *http.Request, description string, expiresIn time.Duration, maxBytes int64) (*DownloadTokenResponse, error) {
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

// saveDownloadTokens 将系统中的下载令牌安全加密序列化后写入文件系统
func saveDownloadTokens() error {
	// 先复制数据，尽快释放锁
	downloadTokenManager.RLock()
	data, err := json.Marshal(downloadTokenManager)
	downloadTokenManager.RUnlock()

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

	// 默认签发给当前登录用户；管理员可指定签发给其他用户
	targetUsername := session.Username
	if req.Username != "" && req.Username != session.Username {
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

	tokenResponse, err := generateDownloadToken(targetUsername, r, req.Description, expiresIn, maxBytes)
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

// secureDownloadHandler HTTP 端点：接收并验证令牌，建立文件安全下发通道
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

	// 构建完整文件路径
	fullPath := filepath.Join(mediaDir, relativePath)
	log.Printf("下载文件 - 原始路径: %s, 相对路径: %s, 完整路径: %s", filePath, relativePath, fullPath)

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

	// 设置下载头（清洗文件名，防止响应头注入）
	dlFilename := strings.NewReplacer("\"", "", "\r", "", "\n", "").Replace(filepath.Base(fullPath))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", dlFilename))
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

	log.Printf("✅ 用户 %s 下载文件 %s, 大小: %d bytes", downloadToken.Username, relativePath, bytesDownloaded)
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
	userTokens := make([]*DownloadToken, 0)
	for _, token := range downloadTokenManager.Tokens {
		if canManageAll || token.Username == session.Username {
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

	if !hasPermission(session.Username, "token:issue") && token.Username != session.Username {
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

// createSession 签发一个具备防篡改特性的新会话并挂载至活跃序列
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
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		loginLimiter.fail(clientIP)
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}
	loginLimiter.reset(clientIP)

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
		Domain:   ".xyx.homes", // 关键：添加顶级域名，注意前面的点
	})

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

// verifyRequestSignature 防护跨站及非授信调用，验证通讯参数的 HMAC 正确度
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

// generateHMACSignature 采用 SHA256 对参数块混淆产生一致性强检验体
func generateHMACSignature(data string) string {
	h := hmac.New(sha256.New, []byte(securityToken))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// checkUserAgent 检测浏览器标识符以驳回显眼的恶意探查器与爬虫
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
	defer antiCrawler.RUnlock()

	if blockTime, exists := antiCrawler.blockedIPs[ip]; exists {
		if time.Now().Before(blockTime) {
			return true
		}
		// 已过期，解除封锁
		antiCrawler.RUnlock()
		antiCrawler.Lock()
		delete(antiCrawler.blockedIPs, ip)
		antiCrawler.Unlock()
		antiCrawler.RLock()
	}
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
		antiCrawler.blockedIPs[ip] = now.Add(time.Hour)
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
			antiCrawler.blockedIPs[ip] = now.Add(time.Hour)
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

// verifySecurityHeaders 全面贯通并拦截违背安全通讯条例的入站调用
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
		log.Printf("🚫 行为异常: %s", ip)
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

// allowedOrigins 跨域白名单（精确匹配，防止 xyx.homes.evil.com 之类的前缀绕过）
var allowedOrigins = []string{
	"https://xyx.homes",
	"https://www.xyx.homes",
	"https://xyx.homes:9000",
	"https://xyx.homes:8081",
	"http://xyx.homes:8081",
	"https://192.168.5.14:9000",
	"http://192.168.5.14:9000",
	"http://localhost:9000",
	"http://127.0.0.1:9000",
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Timestamp, X-Nonce, X-Signature, Authorization")
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
	for ip, blockTime := range antiCrawler.blockedIPs {
		if now.After(blockTime) {
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
			// 确保 URLs 有正确的路径分隔符
			fullURL := urls
			if !strings.HasSuffix(urls, "/") {
				fullURL += "/"
			}
			fullURL += info.Name()
			epubURLs = append(epubURLs, fullURL)
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
		s.Src = urls + files[randIdx]
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
		s.Src = urls + files[randIdx]
		json.NewEncoder(w).Encode(s)
	}
}

// homeHandler HTTP 端点：反馈特定视频承载框架以支撑定制页面展示
func homeHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	updateOnlineUser(r, "video")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData, err := os.ReadFile("/home/os/templates/video.html")
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
	}

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

// main 主宰整个程序的挂载，驱动所有路由装配及守望守护协程开启
func main() {
	// 初始化用户系统
	loadUsers()

	// 初始化数据
	loadData()

	// 初始化下载令牌系统
	initDownloadTokenManager()

	// 初始化 RBAC 角色权限系统
	initRBAC()

	// 加载手动封禁的 IP 列表
	loadBlockedIPs()

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
	http.HandleFunc("/list-download-tokens", authMiddleware(requirePermission("token:manage", securityMiddleware(listDownloadTokensHandler))))
	http.HandleFunc("/revoke-download-token", authMiddleware(requirePermission("token:manage", securityMiddleware(revokeDownloadTokenHandler))))

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
		http.FileServer(http.Dir(indexPath)).ServeHTTP(w, r)
	}))
	http.HandleFunc("/ws", authMiddleware(requirePermission("system:view", securityMiddleware(wsHandler))))
	http.HandleFunc("/video", authMiddleware(requirePermission("files:view", securityMiddleware(homeHandler))))
	http.HandleFunc("/status-ifaces", authMiddleware(requirePermission("system:view", securityMiddleware(ifacesHandler))))
	http.HandleFunc("/random-media", enableCORSh(authMiddleware(requirePermission("files:view", securityMiddleware(randomMediaHandler)))))
	http.HandleFunc("/access-stats", authMiddleware(requirePermission("system:view", securityMiddleware(accessStatsHandler))))
	http.HandleFunc("/exec", authMiddleware(requirePermission("system:exec", securityMiddleware(execHandler))))
	http.HandleFunc("/epubs", enableCORSh(authMiddleware(requirePermission("files:view", securityMiddleware(listEpubs)))))

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

	// 文件管理与进程监控接口
	http.HandleFunc("GET /api/files", authMiddleware(requirePermission("files:manage", securityMiddleware(listFilesHandler))))
	http.HandleFunc("POST /api/files/upload", authMiddleware(requirePermission("files:manage", securityMiddleware(uploadFileHandler))))
	http.HandleFunc("POST /api/files/mkdir", authMiddleware(requirePermission("files:manage", securityMiddleware(mkdirFileHandler))))
	http.HandleFunc("DELETE /api/files", authMiddleware(requirePermission("files:manage", securityMiddleware(deleteFileHandler))))
	http.HandleFunc("GET /api/processes", authMiddleware(requirePermission("system:process", securityMiddleware(listProcessesHandler))))
	http.HandleFunc("POST /api/processes/kill", authMiddleware(requirePermission("system:process", securityMiddleware(killProcessHandler))))
	http.HandleFunc("GET /api/ip/blocked", authMiddleware(requirePermission("ip:manage", securityMiddleware(listBlockedIPsHandler))))
	http.HandleFunc("POST /api/ip/block", authMiddleware(requirePermission("ip:manage", securityMiddleware(blockIPHandler))))
	http.HandleFunc("POST /api/ip/unblock", authMiddleware(requirePermission("ip:manage", securityMiddleware(unblockIPHandler))))
	http.HandleFunc("GET /api/ipinfo", authMiddleware(securityMiddleware(ipinfoProxyHandler)))

	fmt.Println("Server running at https://localhost:9000")
	log.Printf("服务器启动时间: %s", serverStartTime.Format("2006-01-02 15:04:05"))
	// 启用 TLS 1.2+，禁用老旧弱协议
	srv := &http.Server{
		Addr:      ":9000",
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	log.Fatal(srv.ListenAndServeTLS("/home/ssl/xyx.homes.pem", "/home/ssl/xyx.homes.key"))
}
