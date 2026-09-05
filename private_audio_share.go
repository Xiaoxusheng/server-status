package main

// 私人手记语音二维码分享：
// 生成卡片时，前端为「有语音的手记」申请一个语音分享令牌（32 字节随机数，库中仅存 SHA-256），
// 服务端返回指向 /audio/{token} 公开播放页的二维码 PNG，由前端绘制到卡片画布上；
// 扫码访客无需登录即可播放该手记的语音（媒体落盘为 AES-GCM 加密格式，接口读时解密、支持 Range）。
// 令牌永久有效（与卡片图片生命周期一致），手记删除时随 FK 级联清理。

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// AudioShare 语音分享记录
type AudioShare struct {
	ID        string
	NoteID    string
	UserID    string
	TokenHash string
	ExpiresAt *time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

// createAudioShare 为手记创建语音分享令牌，返回明文 token（仅此一次可见）
func (s *PrivateStore) createAudioShare(userID, noteID string) (string, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return "", fmt.Errorf("手记不存在")
	}
	// 无语音的手记没有可分享内容，直接拒绝避免产生无效二维码
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM note_audio WHERE note_id = ?`, noteID).Scan(&n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("该手记没有语音")
	}
	// 16 字节（128 位熵）经 base64url 编码仅 22 字符：token 越短 URL 越短，
	// 二维码模块数从 32 字节 hex 时的 Version 8（49×49）降到 Version 3（29×29），
	// 卡片缩放后仍易扫；防暴力猜测强度依旧足够（2^128）
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	_, err := s.db.Exec(`
		INSERT INTO note_audio_shares (id, note_id, user_id, token_hash, expires_at, created_at, revoked_at)
		VALUES (?, ?, ?, ?, NULL, ?, NULL)`,
		randomID("as"), noteID, userID, sha256Hex(token), nowUTC())
	if err != nil {
		return "", err
	}
	return token, nil
}

// getAudioShareByToken 按明文 token 查分享记录（token 仅存哈希，此处哈希后比对）
func (s *PrivateStore) getAudioShareByToken(token string) (*AudioShare, error) {
	if token == "" {
		return nil, fmt.Errorf("分享不存在")
	}
	var sh AudioShare
	var expires, revoked, created string
	if err := s.db.QueryRow(`
		SELECT id, note_id, user_id, token_hash, COALESCE(expires_at,''), created_at, COALESCE(revoked_at,'')
		FROM note_audio_shares WHERE token_hash = ?`, sha256Hex(token)).
		Scan(&sh.ID, &sh.NoteID, &sh.UserID, &sh.TokenHash, &expires, &created, &revoked); err != nil {
		return nil, err
	}
	sh.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if expires != "" {
		if t, err := time.Parse(time.RFC3339, expires); err == nil {
			sh.ExpiresAt = &t
		}
	}
	if revoked != "" {
		if t, err := time.Parse(time.RFC3339, revoked); err == nil {
			sh.RevokedAt = &t
		}
	}
	return &sh, nil
}

// audioShareInvalid 分享是否已失效（撤销 / 过期 / 手记已被删除）
func (s *PrivateStore) audioShareInvalid(sh *AudioShare, now time.Time) bool {
	if sh.RevokedAt != nil {
		return true
	}
	if sh.ExpiresAt != nil && now.After(*sh.ExpiresAt) {
		return true
	}
	return !s.noteExists(sh.NoteID)
}

// noteExists 手记是否仍存在（不校验用户，公开访客场景）
func (s *PrivateStore) noteExists(noteID string) bool {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM notes WHERE id = ?`, noteID).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// audioShareNoteTitle 手记标题（公开播放页展示用）
func (s *PrivateStore) audioShareNoteTitle(noteID string) string {
	var title string
	if err := s.db.QueryRow(`SELECT title FROM notes WHERE id = ?`, noteID).Scan(&title); err != nil {
		return ""
	}
	return title
}

// audioShareAudios 分享手记的语音列表（仅暴露 ID 与时长，不含文件路径）
func (s *PrivateStore) audioShareAudios(sh *AudioShare) []map[string]interface{} {
	rows, err := s.db.Query(`
		SELECT id, duration FROM note_audio WHERE note_id = ? ORDER BY created_at ASC`, sh.NoteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id string
		var dur float64
		if err := rows.Scan(&id, &dur); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"id":       id,
			"duration": dur,
		})
	}
	return out
}

// audioShareAudioFilePath 校验语音属于分享的手记后返回解密用绝对路径
func (s *PrivateStore) audioShareAudioFilePath(sh *AudioShare, audioID string) (string, error) {
	var rel string
	if err := s.db.QueryRow(`
		SELECT file_path FROM note_audio WHERE id = ? AND note_id = ?`, audioID, sh.NoteID).Scan(&rel); err != nil {
		return "", fmt.Errorf("语音不存在")
	}
	return s.safeFilePath(rel)
}

// ==================== 处理器 ====================

// privateAudioShareQRHandler GET /api/private/notes/{id}/audio-share/qr
// 登录 + 私人空间认证后调用：创建语音分享令牌并返回二维码 PNG（前端绘制到卡片）
func privateAudioShareQRHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	noteID := r.PathValue("id")
	token, err := privateStore.createAudioShare(session.Username, noteID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	shareURL := fmt.Sprintf("%s://%s/audio/%s", scheme, r.Host, token)
	// Highest 纠错 + 512px：卡片缩放/轻微遮挡后仍可扫（token 已缩短，高纠错不会明显加大密度）
	png, err := qrcode.Encode(shareURL, qrcode.Highest, 512)
	if err != nil {
		log.Printf("PRIVATE audio-share qr error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "二维码生成失败")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.audio_share.create")
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// audioSharePageHandler GET /audio/{token} 公开语音播放页（无需登录）
func audioSharePageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	data, err := os.ReadFile(filepath.Join(indexPath, "audio-share.html"))
	if err != nil {
		http.Error(w, "播放页面不存在", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Write(data)
}

// audioShareDataHandler GET /api/ashare/{token}/data 公开语音分享元数据
func audioShareDataHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	token := r.PathValue("token")
	sh, err := privateStore.getAudioShareByToken(token)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	invalid := privateStore.audioShareInvalid(sh, time.Now())
	audios := privateStore.audioShareAudios(sh)
	// 播放地址由 handler 用明文 token 拼接（存储层只有哈希，拿不到明文 token）
	for _, a := range audios {
		a["url"] = "/api/ashare/" + token + "/audio/" + a["id"].(string)
	}
	writeJSON(w, http.StatusOK, "获取语音分享成功", map[string]interface{}{
		"title":       privateStore.audioShareNoteTitle(sh.NoteID),
		"audio_count": len(audios),
		"audios":      audios,
		"expires_at":  timePtrString(sh.ExpiresAt),
		"created_at":  sh.CreatedAt.Format(time.RFC3339),
		"invalid":     invalid,
	})
}

// audioShareAudioHandler GET /api/ashare/{token}/audio/{aid} 公开语音播放（解密流式，支持 Range）
func audioShareAudioHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		http.NotFound(w, r)
		return
	}
	token := r.PathValue("token")
	sh, err := privateStore.getAudioShareByToken(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if privateStore.audioShareInvalid(sh, time.Now()) {
		http.NotFound(w, r)
		return
	}
	abs, err := privateStore.audioShareAudioFilePath(sh, r.PathValue("aid"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// 用原始文件名（保留扩展名），http.ServeContent 据此推断 Content-Type（webm/m4a/mp3 等）并支持 Range 断点播放
	w.Header().Set("Cache-Control", "private, no-store")
	servePrivateMediaFile(w, r, abs, filepath.Base(abs))
}
