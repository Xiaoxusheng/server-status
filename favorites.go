package main

// ==================== 文件管理收藏（后端持久化，按用户隔离） ====================
// 存储文件：<dataRoot>/favorites.json，结构 {"用户名":[{path,name,is_dir,added_at}]}
// 0600 权限 + 临时文件原子替换写入；并发由 favMu 串行化。
// 路由（注册见 main.go）：
//   GET    /api/files/favorites        列出当前用户收藏
//   POST   /api/files/favorites        新增/更新收藏（会话绑定 CSRF 校验）
//   DELETE /api/files/favorites?path=  删除指定收藏

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// favFile 收藏存储文件路径（与 download_tokens.json 等同目录）
var favFile = filepath.Join(dataRoot(), "favorites.json")

// favPerUserLimit 单用户收藏上限，防止恶意撑爆存储
const favPerUserLimit = 500

// FavEntry 收藏条目：文件/目录的媒体目录相对路径 + 展示元数据
type FavEntry struct {
	Path    string    `json:"path"`
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	AddedAt time.Time `json:"added_at"`
}

// favMu 串行化收藏文件的读改写，避免并发请求互相覆盖
var favMu sync.Mutex

// loadFavorites 读取全部用户收藏；文件缺失或损坏时返回空表（不视为致命错误）
func loadFavorites() map[string][]FavEntry {
	out := make(map[string][]FavEntry)
	data, err := os.ReadFile(favFile)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

// saveFavorites 原子写入收藏文件：临时文件 + rename，0600 权限防止其他用户读取
func saveFavorites(m map[string][]FavEntry) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := favFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, favFile)
}

// favoritesHandler 收藏 API 统一入口（方法分发），调用链已含会话认证 + files:manage RBAC + 写操作 CSRF
func favoritesHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := getSessionFromRequest(r)
	if !ok || session == nil {
		writeJSONError(w, http.StatusUnauthorized, "未登录")
		return
	}
	switch r.Method {
	case http.MethodGet:
		handleFavList(w, r, session.Username)
	case http.MethodPost:
		handleFavAdd(w, r, session.Username)
	case http.MethodDelete:
		handleFavRemove(w, r, session.Username)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "只允许GET/POST/DELETE请求")
	}
}

// handleFavList 返回当前用户的收藏列表（按收藏时间倒序，最新的在前）
func handleFavList(w http.ResponseWriter, r *http.Request, username string) {
	favMu.Lock()
	defer favMu.Unlock()
	m := loadFavorites()
	list := m[username]
	if list == nil {
		list = []FavEntry{}
	}
	// 倒序：最近收藏的排前面
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	writeJSON(w, http.StatusOK, "ok", list)
}

// handleFavAdd 新增收藏（幂等：同路径覆盖更新时间与元数据）
func handleFavAdd(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Path  string `json:"path"`
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" || len(req.Path) > 1024 || strings.ContainsAny(req.Path, "\x00\r\n") {
		writeJSONError(w, http.StatusBadRequest, "路径不合法")
		return
	}
	// 路径必须位于媒体目录内（防目录穿越；不要求文件仍存在，允许收藏已删除路径由前端兜底）
	if !isSafeFilePath(filepath.Join(mediaDir, req.Path), mediaDir) {
		writeJSONError(w, http.StatusForbidden, "路径不合法")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Path
	}
	if len(name) > 255 {
		name = name[:255]
	}

	favMu.Lock()
	defer favMu.Unlock()
	m := loadFavorites()
	list := m[username]
	// 同路径幂等覆盖；新条目检查上限
	replaced := false
	for i := range list {
		if list[i].Path == req.Path {
			list[i].Name, list[i].IsDir, list[i].AddedAt = name, req.IsDir, time.Now()
			replaced = true
			break
		}
	}
	if !replaced {
		if len(list) >= favPerUserLimit {
			writeJSONError(w, http.StatusBadRequest, "收藏数量已达上限")
			return
		}
		list = append(list, FavEntry{Path: req.Path, Name: name, IsDir: req.IsDir, AddedAt: time.Now()})
	}
	m[username] = list
	if err := saveFavorites(m); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存收藏失败")
		return
	}
	writeJSON(w, http.StatusOK, "已收藏", nil)
}

// handleFavRemove 删除指定路径的收藏（幂等：不存在也返回成功）
func handleFavRemove(w http.ResponseWriter, r *http.Request, username string) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少 path 参数")
		return
	}
	favMu.Lock()
	defer favMu.Unlock()
	m := loadFavorites()
	list := m[username]
	out := list[:0]
	for _, e := range list {
		if e.Path != path {
			out = append(out, e)
		}
	}
	m[username] = out
	if err := saveFavorites(m); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存收藏失败")
		return
	}
	writeJSON(w, http.StatusOK, "已取消收藏", nil)
}
