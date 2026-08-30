package main

// 私人空间 HTTP 处理器（解锁 / 锁定 / Session / 手记 / 图片 / 语音 / 搜索 / 导出）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
)

// privateEntryHandler POST /api/private/entry
// 隐藏入口（快捷键 / 连点 Logo）先调用本接口获取 5 分钟短期入口 Cookie，再进入 /private.html，
// 防止通过直接输入网址打开私人空间页面。
func privateEntryHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if _, ok := getSessionFromRequest(r); !ok {
		writeJSONError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "pv_entry", Value: hmacSign("pv_entry"), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
		MaxAge: 300,
	})
	writeJSON(w, http.StatusOK, "ok", map[string]interface{}{"entry": true})
}

// privatePageHandler GET /private.html
// 必须同时具备：有效普通登录 session + 短期入口 Cookie，否则跳回首页。
func privatePageHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("pv_entry"); err != nil || cookie.Value != hmacSign("pv_entry") {
		http.Redirect(w, r, "/index.html", http.StatusFound)
		return
	}
	// 必须已登录且拥有 private:view 权限；无权限静默弹回首页，不暴露页面存在
	session, ok := getSessionFromRequest(r)
	if !ok || !hasPermission(session.Username, "private:view") {
		http.Redirect(w, r, "/index.html", http.StatusFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(indexPath, "private.html"))
	if err != nil {
		http.Error(w, "页面不存在", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// registerPrivateRoutes 注册隐藏私人空间全部路由（含公开分享页）
func registerPrivateRoutes(mux *http.ServeMux) {
	// 隐藏入口：只有通过快捷键/连点 Logo 获得短期入口 Cookie 才能打开 /private.html
	// 且必须拥有 private:view 权限（默认仅超级管理员），普通用户请求直接 403
	mux.HandleFunc("POST /api/private/entry", authMiddleware(requirePermission("private:view", securityMiddleware(privateEntryHandler))))
	mux.HandleFunc("GET /private.html", securityMiddleware(privatePageHandler))

	// 解锁 / 锁定 / Session / 密码初始化（解锁同样要求 private:view，防止低权限用户凭密码硬闯）
	mux.HandleFunc("POST /api/private/unlock", authMiddleware(requirePermission("private:view", securityMiddleware(privateUnlockHandler))))
	mux.HandleFunc("POST /api/private/lock", authMiddleware(requirePermission("private:view", securityMiddleware(privateLockHandler))))
	mux.HandleFunc("GET /api/private/session", authMiddleware(requirePermission("private:view", securityMiddleware(privateSessionHandler))))
	mux.HandleFunc("POST /api/private/setup-password", authMiddleware(requirePermission("role:manage", securityMiddleware(privateSetupPasswordHandler))))
	mux.HandleFunc("GET /api/private/server-status", authMiddleware(securityMiddleware(privateAuthMiddleware(privateServerStatusHandler))))

	// 手记
	mux.HandleFunc("GET /api/private/notes", authMiddleware(securityMiddleware(privateAuthMiddleware(privateListNotesHandler))))
	mux.HandleFunc("POST /api/private/notes", authMiddleware(securityMiddleware(privateAuthMiddleware(privateCreateNoteHandler))))
	mux.HandleFunc("GET /api/private/notes/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateGetNoteHandler))))
	mux.HandleFunc("PUT /api/private/notes/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateUpdateNoteHandler))))
	mux.HandleFunc("DELETE /api/private/notes/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateDeleteNoteHandler))))

	// 图片
	mux.HandleFunc("POST /api/private/notes/{id}/images", authMiddleware(securityMiddleware(privateAuthMiddleware(privateUploadImageHandler))))
	mux.HandleFunc("PUT /api/private/notes/{id}/images/order", authMiddleware(securityMiddleware(privateAuthMiddleware(privateReorderImagesHandler))))
	mux.HandleFunc("DELETE /api/private/notes/{id}/images/{image_id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateDeleteImageHandler))))
	mux.HandleFunc("GET /api/private/notes/{id}/images/{image_id}/file", authMiddleware(securityMiddleware(privateAuthMiddleware(privateImageFileHandler))))

	// 语音
	mux.HandleFunc("POST /api/private/notes/{id}/audio", authMiddleware(securityMiddleware(privateAuthMiddleware(privateUploadAudioHandler))))
	mux.HandleFunc("DELETE /api/private/notes/{id}/audio/{audio_id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateDeleteAudioHandler))))
	mux.HandleFunc("GET /api/private/notes/{id}/audio/{audio_id}/file", authMiddleware(securityMiddleware(privateAuthMiddleware(privateAudioFileHandler))))

	// 标签 / 搜索 / 导出
	mux.HandleFunc("GET /api/private/tags", authMiddleware(securityMiddleware(privateAuthMiddleware(privateTagsHandler))))
	mux.HandleFunc("GET /api/private/search", authMiddleware(securityMiddleware(privateAuthMiddleware(privateSearchHandler))))
	mux.HandleFunc("GET /api/private/export/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateExportHandler))))

	// 卡片
	mux.HandleFunc("POST /api/private/cards", authMiddleware(securityMiddleware(privateAuthMiddleware(privateCreateCardHandler))))
	mux.HandleFunc("GET /api/private/cards", authMiddleware(securityMiddleware(privateAuthMiddleware(privateListCardsHandler))))
	mux.HandleFunc("GET /api/private/cards/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateGetCardHandler))))
	mux.HandleFunc("DELETE /api/private/cards/{id}", authMiddleware(securityMiddleware(privateAuthMiddleware(privateDeleteCardHandler))))
	mux.HandleFunc("GET /api/private/cards/{id}/image", authMiddleware(securityMiddleware(privateAuthMiddleware(privateCardImageHandler))))

	// 分享
	mux.HandleFunc("POST /api/private/cards/{id}/share", authMiddleware(securityMiddleware(privateAuthMiddleware(privateCreateShareHandler))))
	mux.HandleFunc("POST /api/private/shares", authMiddleware(securityMiddleware(privateAuthMiddleware(privateCreateShareAliasHandler))))
	mux.HandleFunc("GET /api/private/shares", authMiddleware(securityMiddleware(privateAuthMiddleware(privateListSharesHandler))))
	mux.HandleFunc("POST /api/private/shares/{token}/revoke", authMiddleware(securityMiddleware(privateAuthMiddleware(privateRevokeShareHandler))))

	// 公开分享（无需登录；密码分享需验证）
	mux.HandleFunc("GET /card/{token}", securityMiddleware(sharePageHandler))
	mux.HandleFunc("GET /api/share/{token}/data", securityMiddleware(shareDataHandler))
	mux.HandleFunc("POST /api/share/{token}/verify", securityMiddleware(shareVerifyHandler))
	mux.HandleFunc("GET /api/share/{token}/image", securityMiddleware(shareImageHandler))
	mux.HandleFunc("GET /api/share/{token}/qr", securityMiddleware(shareQRHandler))
}

// ==================== 解锁 / 锁定 / Session ====================

// privateUnlockHandler POST /api/private/unlock
func privateUnlockHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusForbidden, "密码错误")
		return
	}
	session, ok := getSessionFromRequest(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	token, err := privateStore.Unlock(session.Username, req.Password, getClientIP(r))
	if err == privateErrLocked {
		writeJSONError(w, http.StatusTooManyRequests, "尝试次数过多，请稍后再试")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "密码错误")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "private_session", Value: token, Path: "/api/private",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
		MaxAge: int(privateStore.sessionTimeout().Seconds()),
	})
	privateStore.auditPrivate(r, session.Username, "private_note.unlock")
	writeJSON(w, http.StatusOK, "解锁成功", map[string]interface{}{"unlocked": true})
}

// privateLockHandler POST /api/private/lock
func privateLockHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusForbidden, "私人空间不可用")
		return
	}
	if session, ok := getSessionFromRequest(r); ok {
		token := ""
		if cookie, err := r.Cookie("private_session"); err == nil {
			token = cookie.Value
		}
		privateStore.Lock(session.Username, token)
		privateStore.auditPrivate(r, session.Username, "private_note.lock")
	}
	http.SetCookie(w, &http.Cookie{
		Name: "private_session", Value: "", Path: "/api/private",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, "已锁定", map[string]interface{}{"unlocked": false})
}

// privateSessionHandler GET /api/private/session
func privateSessionHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil || !privateStore.config.PrivateNotes.Enabled {
		writeJSON(w, http.StatusOK, "未解锁", map[string]interface{}{"unlocked": false})
		return
	}
	session, ok := getSessionFromRequest(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "请先登录")
		return
	}
	cookie, err := r.Cookie("private_session")
	if err != nil {
		writeJSON(w, http.StatusOK, "未解锁", map[string]interface{}{"unlocked": false})
		return
	}
	ps, valid := privateStore.ValidateSession(session.Username, cookie.Value)
	if !valid {
		writeJSON(w, http.StatusOK, "未解锁", map[string]interface{}{"unlocked": false})
		return
	}
	writeJSON(w, http.StatusOK, "已解锁", map[string]interface{}{
		"unlocked":   true,
		"user":       session.Username,
		"expires_at": ps.ExpiresAt.Format(time.RFC3339),
	})
}

// privateSetupPasswordHandler POST /api/private/setup-password（管理员，仅首次未设置时可用）
func privateSetupPasswordHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusForbidden, "私人空间不可用")
		return
	}
	session, _ := getSessionFromRequest(r)
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if err := privateStore.SetupPrivatePassword(req.Password); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.setup_password")
	writeJSON(w, http.StatusOK, "私人空间密码设置成功", nil)
}

// privateAuthMiddleware 私人空间双层认证：普通登录 + private session
func privateAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if privateStore == nil || !privateStore.config.PrivateNotes.Enabled {
			writeJSONError(w, http.StatusForbidden, "私人空间不可用")
			return
		}
		session, ok := getSessionFromRequest(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "请先登录")
			return
		}
		cookie, err := r.Cookie("private_session")
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "未解锁")
			return
		}
		ps, valid := privateStore.ValidateSession(session.Username, cookie.Value)
		if !valid {
			writeJSONError(w, http.StatusForbidden, "未解锁")
			return
		}
		ctx := context.WithValue(r.Context(), "privateSession", ps)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ==================== 手记处理器 ====================

func privateListNotesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	notes, err := privateStore.listNotes(session.Username, r.URL.Query().Get("tag"), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取手记失败")
		return
	}
	if notes == nil {
		notes = []*PrivateNote{}
	}
	writeJSON(w, http.StatusOK, "获取手记成功", notes)
}

func privateGetNoteHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	n, err := privateStore.getNote(session.Username, r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "手记不存在")
		return
	}
	writeJSON(w, http.StatusOK, "获取手记成功", n)
}

func privateCreateNoteHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	var req createNoteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if len(req.Content) > 200000 || len(req.Title) > 500 {
		writeJSONError(w, http.StatusBadRequest, "内容过长")
		return
	}
	n, err := privateStore.createNote(session.Username, req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "创建手记失败")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.create")
	writeJSON(w, http.StatusOK, "创建手记成功", n)
}

func privateUpdateNoteHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	id := r.PathValue("id")
	var req createNoteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	n, err := privateStore.updateNote(session.Username, id, req)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "手记不存在")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.update")
	writeJSON(w, http.StatusOK, "更新手记成功", n)
}

func privateDeleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	if err := privateStore.deleteNote(session.Username, r.PathValue("id")); err != nil {
		writeJSONError(w, http.StatusNotFound, "手记不存在")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.delete")
	writeJSON(w, http.StatusOK, "手记已删除", nil)
}

// ==================== 图片处理器 ====================

// privateUploadImageHandler POST /api/private/notes/{id}/images
func privateUploadImageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	noteID := r.PathValue("id")
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "上传数据无效")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "缺少图片文件")
		return
	}
	defer file.Close()
	img, err := privateStore.addImage(session.Username, noteID, file, header)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	img.URL = fmt.Sprintf("/api/private/notes/%s/images/%s/file", noteID, img.ID)
	writeJSON(w, http.StatusOK, "图片上传成功", img)
}

func privateReorderImagesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if err := privateStore.reorderImages(session.Username, r.PathValue("id"), req.IDs); err != nil {
		writeJSONError(w, http.StatusBadRequest, "排序失败")
		return
	}
	writeJSON(w, http.StatusOK, "排序已保存", nil)
}

func privateDeleteImageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	if err := privateStore.deleteImage(session.Username, r.PathValue("id"), r.PathValue("image_id")); err != nil {
		writeJSONError(w, http.StatusNotFound, "图片不存在")
		return
	}
	writeJSON(w, http.StatusOK, "图片已删除", nil)
}

// privateImageFileHandler GET /api/private/notes/{id}/images/{image_id}/file
func privateImageFileHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	abs, name, err := privateStore.imageFilePath(session.Username, r.PathValue("id"), r.PathValue("image_id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "图片不存在")
		return
	}
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "private, max-age=300")
	servePrivateMediaFile(w, r, abs, name)
}

// ==================== 语音处理器 ====================

// privateUploadAudioHandler POST /api/private/notes/{id}/audio
func privateUploadAudioHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	noteID := r.PathValue("id")
	if err := r.ParseMultipartForm(34 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "上传数据无效")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "缺少音频文件")
		return
	}
	defer file.Close()
	duration, _ := strconv.ParseFloat(r.FormValue("duration"), 64)
	a, err := privateStore.addAudio(session.Username, noteID, file, header, duration)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.URL = fmt.Sprintf("/api/private/notes/%s/audio/%s/file", noteID, a.ID)
	writeJSON(w, http.StatusOK, "语音上传成功", a)
}

func privateDeleteAudioHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	if err := privateStore.deleteAudio(session.Username, r.PathValue("id"), r.PathValue("audio_id")); err != nil {
		writeJSONError(w, http.StatusNotFound, "语音不存在")
		return
	}
	writeJSON(w, http.StatusOK, "语音已删除", nil)
}

// privateAudioFileHandler GET /api/private/notes/{id}/audio/{audio_id}/file
func privateAudioFileHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	abs, name, err := privateStore.audioFilePath(session.Username, r.PathValue("id"), r.PathValue("audio_id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "语音不存在")
		return
	}
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "private, max-age=300")
	servePrivateMediaFile(w, r, abs, name)
}

// ==================== 标签 / 搜索 / 导出 ====================

func privateTagsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	tags, err := privateStore.listTags(session.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取标签失败")
		return
	}
	if tags == nil {
		tags = []string{}
	}
	writeJSON(w, http.StatusOK, "获取标签成功", tags)
}

func privateSearchHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, "搜索成功", []*PrivateNote{})
		return
	}
	notes, err := privateStore.listNotes(session.Username, "", q)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "搜索失败")
		return
	}
	if notes == nil {
		notes = []*PrivateNote{}
	}
	writeJSON(w, http.StatusOK, "搜索成功", notes)
}

func privateExportHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	base := "https://" + r.Host
	if r.TLS == nil {
		base = "http://" + r.Host
	}
	md, err := privateStore.exportNoteMarkdown(session.Username, r.PathValue("id"), base)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "手记不存在")
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=note-%s.md", r.PathValue("id")))
	w.Write([]byte(md))
}

// ==================== 服务器状态（服务器卡片数据）====================

// privateServerStatusHandler GET /api/private/server-status
func privateServerStatusHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	iface := ""
	if names, err := netInterfaces(); err == nil {
		for _, name := range names {
			if !strings.HasPrefix(name, "lo") && !strings.Contains(name, "docker") {
				iface = name
				break
			}
		}
	}
	status, err := getServerStatus(iface)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取服务器状态失败")
		return
	}
	writeJSON(w, http.StatusOK, "获取服务器状态成功", status)
}

func netInterfaces() ([]string, error) {
	ifaces, err := psnet.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, i := range ifaces {
		if len(i.HardwareAddr) > 0 {
			names = append(names, i.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// ==================== 上传校验工具 ====================

// imageExtForMIME 校验并返回合法图片扩展名
func imageExtForMIME(contentType, fileName string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(fileName))
	mime := strings.ToLower(strings.TrimSpace(contentType))
	switch ext {
	case ".jpg", ".jpeg":
		if mime == "image/jpeg" {
			return ".jpg", true
		}
	case ".png":
		if mime == "image/png" {
			return ".png", true
		}
	case ".webp":
		if mime == "image/webp" {
			return ".webp", true
		}
	case ".gif":
		if mime == "image/gif" {
			return ".gif", true
		}
	}
	return "", false
}

func audioExtForMIME(contentType, fileName string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(fileName))
	mime := strings.ToLower(strings.TrimSpace(contentType))
	if !strings.HasPrefix(mime, "audio/") && mime != "video/webm" && mime != "application/octet-stream" {
		return "", false
	}
	switch ext {
	case ".webm", ".m4a", ".mp3", ".ogg", ".wav":
		return ext, true
	}
	return "", false
}
