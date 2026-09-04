package main

// 私人空间卡片：存储 / 分享 / 二维码 / 公开分享页。
// 卡片图片由前端 Card Renderer 渲染为 PNG 后提交，服务端只保存真实图片文件。
// 分享 Token 为 32 字节随机数，数据库只保存 Hash；密码使用 bcrypt。

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// ==================== 卡片 CRUD ====================

type createCardRequest struct {
	NoteID   string `json:"note_id"`
	Template string `json:"template"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Title    string `json:"title"`
	Image    string `json:"image"`
}

func validCardSize(w, h int) bool {
	if w < 100 || w > 4096 || h < 100 || h > 4096 {
		return false
	}
	switch {
	case w == 1080 && h == 1080:
	case w == 1080 && h == 1350:
	case w == 1080 && h == 1440:
	case w == 1170 && h == 2532:
	case w == 1080 && h == 1920:
	case w == 1280 && h == 720:
	case w == 1200 && h == 630:
	default:
		return false
	}
	return true
}

func (s *PrivateStore) createCard(userID string, req createCardRequest) (*PrivateCardMeta, error) {
	if !validCardSize(req.Width, req.Height) {
		return nil, fmt.Errorf("不支持的卡片尺寸")
	}
	if req.NoteID != "" && !s.noteOwnedBy(userID, req.NoteID) {
		return nil, fmt.Errorf("手记不存在")
	}
	raw, err := decodeBase64Image(req.Image)
	if err != nil {
		return nil, err
	}
	if len(raw) > 12*1024*1024 {
		return nil, fmt.Errorf("卡片图片过大")
	}
	now := time.Now()
	dir := filepath.Join(s.storageDir, "cards", fmt.Sprintf("%04d/%02d/%02d", now.Year(), int(now.Month()), now.Day()))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	id := randomID("card")
	abs := filepath.Join(dir, id+".png")
	enc, err := encryptMediaBytes(raw)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(abs, enc, 0644); err != nil {
		return nil, err
	}
	rel := filepath.ToSlash(strings.TrimPrefix(abs, s.storageAbs()+string(os.PathSeparator)))
	title := req.Title
	if len(title) > 200 {
		title = title[:200]
	}
	if _, err := s.db.Exec(`
		INSERT INTO note_cards (id, note_id, user_id, template, file_path, width, height, title, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nullIfEmpty(req.NoteID), userID, req.Template, rel, req.Width, req.Height, title, nowUTC()); err != nil {
		os.Remove(abs)
		return nil, err
	}
	return &PrivateCardMeta{
		ID: id, NoteID: req.NoteID, Template: req.Template, FilePath: rel,
		URL: "/api/private/cards/" + id + "/image", Width: req.Width, Height: req.Height,
		Title: title, CreatedAt: nowUTC(),
	}, nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (s *PrivateStore) listCards(userID string) ([]PrivateCardMeta, error) {
	rows, err := s.db.Query(`
		SELECT id, COALESCE(note_id,''), template, file_path, width, height, title, created_at
		FROM note_cards WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cards []PrivateCardMeta
	for rows.Next() {
		var c PrivateCardMeta
		if err := rows.Scan(&c.ID, &c.NoteID, &c.Template, &c.FilePath, &c.Width, &c.Height, &c.Title, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.URL = "/api/private/cards/" + c.ID + "/image"
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

func (s *PrivateStore) listCardsForNote(userID, noteID string) ([]PrivateCardMeta, error) {
	rows, err := s.db.Query(`
		SELECT id, COALESCE(note_id,''), template, file_path, width, height, title, created_at
		FROM note_cards WHERE user_id = ? AND note_id = ? ORDER BY created_at DESC`, userID, noteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cards []PrivateCardMeta
	for rows.Next() {
		var c PrivateCardMeta
		if err := rows.Scan(&c.ID, &c.NoteID, &c.Template, &c.FilePath, &c.Width, &c.Height, &c.Title, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.URL = "/api/private/cards/" + c.ID + "/image"
		cards = append(cards, c)
	}
	return cards, rows.Err()
}

func (s *PrivateStore) getCard(userID, cardID string) (*PrivateCardMeta, error) {
	var c PrivateCardMeta
	err := s.db.QueryRow(`
		SELECT id, COALESCE(note_id,''), template, file_path, width, height, title, created_at
		FROM note_cards WHERE id = ? AND user_id = ?`, cardID, userID).
		Scan(&c.ID, &c.NoteID, &c.Template, &c.FilePath, &c.Width, &c.Height, &c.Title, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.URL = "/api/private/cards/" + c.ID + "/image"
	return &c, nil
}

func (s *PrivateStore) deleteCard(userID, cardID string) error {
	c, err := s.getCard(userID, cardID)
	if err != nil {
		return err
	}
	if abs, err := s.safeFilePath(c.FilePath); err == nil {
		os.Remove(abs)
	}
	_, err = s.db.Exec(`DELETE FROM note_cards WHERE id = ? AND user_id = ?`, cardID, userID)
	return err
}

func (s *PrivateStore) cardFilePath(userID, cardID string) (string, string, error) {
	c, err := s.getCard(userID, cardID)
	if err != nil {
		return "", "", err
	}
	abs, err := s.safeFilePath(c.FilePath)
	return abs, filepath.Base(abs), err
}

// ==================== 分享 ====================

type createShareRequest struct {
	ExpiresIn     string `json:"expires_in"` // 10m / 1h / 24h / 7d / permanent
	Password      string `json:"password"`
	AllowDownload bool   `json:"allow_download"`
}

func shareExpiry(expiresIn string) (*time.Time, error) {
	expiresIn = strings.ToLower(strings.TrimSpace(expiresIn))
	var d time.Duration
	switch expiresIn {
	case "", "permanent", "0", "永久":
		return nil, nil
	case "10m", "10min":
		d = 10 * time.Minute
	case "1h", "1hour":
		d = time.Hour
	case "24h", "1d", "1day":
		d = 24 * time.Hour
	case "7d", "7day":
		d = 7 * 24 * time.Hour
	default:
		return nil, fmt.Errorf("无效的有效期")
	}
	t := time.Now().UTC().Add(d)
	return &t, nil
}

func (s *PrivateStore) createShare(userID, cardID string, req createShareRequest) (*PrivateShare, string, error) {
	c, err := s.getCard(userID, cardID)
	if err != nil {
		return nil, "", fmt.Errorf("卡片不存在")
	}
	expiresAt, err := shareExpiry(req.ExpiresIn)
	if err != nil {
		return nil, "", err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", err
	}
	token := fmt.Sprintf("%x", tokenBytes)
	var pwHash string
	if req.Password != "" {
		if len(req.Password) < 4 || len(req.Password) > 128 {
			return nil, "", fmt.Errorf("分享密码长度需要在 4-128 位之间")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", err
		}
		pwHash = string(h)
	}
	id := randomID("sh")
	var expiresVal interface{} = nil
	if expiresAt != nil {
		expiresVal = expiresAt.UTC().Format(time.RFC3339)
	}
	_, err = s.db.Exec(`
		INSERT INTO note_shares (id, note_id, card_id, share_token_hash, password_hash, expires_at, allow_download, created_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		id, nullIfEmpty(c.NoteID), c.ID, sha256Hex(token), nullIfEmpty(pwHash), expiresVal,
		boolToInt(req.AllowDownload), nowUTC())
	if err != nil {
		return nil, "", err
	}
	share := &PrivateShare{
		ID: id, NoteID: c.NoteID, CardID: c.ID, ShareTokenHash: sha256Hex(token),
		PasswordHash: pwHash, ExpiresAt: expiresAt, AllowDownload: req.AllowDownload,
		CreatedAt: time.Now().UTC(),
	}
	return share, token, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *PrivateStore) getShareByToken(token string) (*PrivateShare, error) {
	if token == "" {
		return nil, fmt.Errorf("分享不存在")
	}
	row := s.db.QueryRow(`
		SELECT id, COALESCE(note_id,''), card_id, share_token_hash, COALESCE(password_hash,''),
			COALESCE(expires_at,''), allow_download, created_at, COALESCE(revoked_at,'')
		FROM note_shares WHERE share_token_hash = ?`, sha256Hex(token))
	var sh PrivateShare
	var expires, revoked, created string
	var allow int
	if err := row.Scan(&sh.ID, &sh.NoteID, &sh.CardID, &sh.ShareTokenHash, &sh.PasswordHash,
		&expires, &allow, &created, &revoked); err != nil {
		return nil, err
	}
	sh.AllowDownload = allow == 1
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

func (s *PrivateStore) shareCard(share *PrivateShare) (*PrivateCardMeta, error) {
	var c PrivateCardMeta
	err := s.db.QueryRow(`
		SELECT id, COALESCE(note_id,''), template, file_path, width, height, title, created_at
		FROM note_cards WHERE id = ?`, share.CardID).
		Scan(&c.ID, &c.NoteID, &c.Template, &c.FilePath, &c.Width, &c.Height, &c.Title, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.URL = "/api/private/cards/" + c.ID + "/image"
	return &c, nil
}

func (s *PrivateStore) shareInvalid(share *PrivateShare, now time.Time) bool {
	if share.RevokedAt != nil {
		return true
	}
	if share.ExpiresAt != nil && now.After(*share.ExpiresAt) {
		return true
	}
	return false
}

func (s *PrivateStore) verifySharePassword(token, password string) bool {
	sh, err := s.getShareByToken(token)
	if err != nil || sh.PasswordHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(sh.PasswordHash), []byte(password)) == nil
}

func (s *PrivateStore) revokeShare(userID, token string) error {
	sh, err := s.getShareByToken(token)
	if err != nil {
		return err
	}
	var uid string
	if err := s.db.QueryRow(`SELECT user_id FROM note_cards WHERE id = ?`, sh.CardID).Scan(&uid); err != nil {
		return err
	}
	if uid != userID {
		return fmt.Errorf("无权操作")
	}
	_, err = s.db.Exec(`UPDATE note_shares SET revoked_at = ? WHERE id = ?`, nowUTC(), sh.ID)
	return err
}

func (s *PrivateStore) listShares(userID string) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`
		SELECT sh.id, sh.card_id, COALESCE(sh.note_id,''), sh.expires_at, sh.allow_download,
			sh.created_at, COALESCE(sh.revoked_at,''), c.title, c.template, c.width, c.height
		FROM note_shares sh JOIN note_cards c ON c.id = sh.card_id
		WHERE c.user_id = ? ORDER BY sh.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, cardID, noteID, expires, created, revoked, title, template string
		var allow int
		var w, h int
		if err := rows.Scan(&id, &cardID, &noteID, &expires, &allow, &created, &revoked, &title, &template, &w, &h); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"id":             id,
			"card_id":        cardID,
			"note_id":        noteID,
			"title":          title,
			"template":       template,
			"width":          w,
			"height":         h,
			"expires_at":     expires,
			"allow_download": allow == 1,
			"created_at":     created,
			"revoked_at":     revoked,
			"card_url":       "/api/private/cards/" + cardID + "/image",
		})
	}
	return out, rows.Err()
}

// shareCookieName 分享密码校验 Cookie 名（不携带明文 Token）
func shareCookieName(token string) string {
	return "share_ok_" + sha256Hex(token)[:16]
}

// ==================== 公开分享处理器 ====================

// sharePageHandler GET /card/{token} 公开分享页（无需登录）
func sharePageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	data, err := os.ReadFile(filepath.Join(indexPath, "share.html"))
	if err != nil {
		http.Error(w, "分享页面不存在", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Write(data)
}

// shareDataHandler GET /api/share/{token}/data 公开分享元数据
func shareDataHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	token := r.PathValue("token")
	sh, err := privateStore.getShareByToken(token)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	invalid := privateStore.shareInvalid(sh, time.Now())
	card, err := privateStore.shareCard(sh)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	writeJSON(w, http.StatusOK, "获取分享成功", map[string]interface{}{
		"token":          token,
		"card_id":        card.ID,
		"title":          card.Title,
		"template":       card.Template,
		"width":          card.Width,
		"height":         card.Height,
		"has_password":   sh.PasswordHash != "",
		"expires_at":     timePtrString(sh.ExpiresAt),
		"created_at":     sh.CreatedAt.Format(time.RFC3339),
		"revoked":        sh.RevokedAt != nil,
		"invalid":        invalid,
		"allow_download": sh.AllowDownload,
		"image_url":      "/api/share/" + token + "/image",
	})
}

func timePtrString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// shareVerifyHandler POST /api/share/{token}/verify 公开分享密码验证
func shareVerifyHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	token := r.PathValue("token")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if privateStore == nil || !privateStore.verifySharePassword(token, req.Password) {
		writeJSONError(w, http.StatusForbidden, "密码错误")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: shareCookieName(token), Value: hmacSign(token), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
		MaxAge: 2 * 60 * 60,
	})
	writeJSON(w, http.StatusOK, "验证成功", map[string]interface{}{"ok": true})
}

// shareImageHandler GET /api/share/{token}/image 公开分享卡片图片
func shareImageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	if privateStore == nil {
		http.NotFound(w, r)
		return
	}
	token := r.PathValue("token")
	sh, err := privateStore.getShareByToken(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if privateStore.shareInvalid(sh, time.Now()) {
		http.NotFound(w, r)
		return
	}
	if sh.PasswordHash != "" {
		if cookie, err := r.Cookie(shareCookieName(token)); err != nil || cookie.Value != hmacSign(token) {
			writeJSONError(w, http.StatusForbidden, "需要密码")
			return
		}
	}
	card, err := privateStore.shareCard(sh)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	abs, err := privateStore.safeFilePath(card.FilePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	servePrivateMediaFile(w, r, abs, "card.png")
}

// shareQRHandler GET /api/share/{token}/qr 分享二维码
func shareQRHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	token := r.PathValue("token")
	if privateStore == nil {
		http.NotFound(w, r)
		return
	}
	sh, err := privateStore.getShareByToken(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// 二维码只编码公开 URL，不暴露任何私人内容
	_ = sh
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	shareURL := fmt.Sprintf("%s://%s/card/%s", scheme, r.Host, token)
	png, err := qrcode.Encode(shareURL, qrcode.Medium, 320)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "二维码生成失败")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Write(png)
}

// ==================== 私有卡片/分享处理器 ====================

func privateListCardsHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	cards, err := privateStore.listCards(session.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取卡片失败")
		return
	}
	if cards == nil {
		cards = []PrivateCardMeta{}
	}
	writeJSON(w, http.StatusOK, "获取卡片成功", cards)
}

func privateCreateCardHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	var req createCardRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if req.Template == "" {
		req.Template = "simple"
	}
	if req.Width == 0 || req.Height == 0 {
		req.Width = privateStore.config.Cards.DefaultWidth
		req.Height = privateStore.config.Cards.DefaultHeight
		if req.Width == 0 {
			req.Width = 1080
		}
		if req.Height == 0 {
			req.Height = 1080
		}
	}
	card, err := privateStore.createCard(session.Username, req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "卡片生成失败，请重试")
		log.Printf("PRIVATE card.create error: %v", err)
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.card.create")
	writeJSON(w, http.StatusOK, "卡片生成成功", card)
}

func privateGetCardHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	card, err := privateStore.getCard(session.Username, r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	writeJSON(w, http.StatusOK, "获取卡片成功", card)
}

func privateDeleteCardHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	if err := privateStore.deleteCard(session.Username, r.PathValue("id")); err != nil {
		writeJSONError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.card.delete")
	writeJSON(w, http.StatusOK, "卡片已删除", nil)
}

// privateCardImageHandler GET /api/private/cards/{id}/image（双层认证）
func privateCardImageHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	abs, name, err := privateStore.cardFilePath(session.Username, r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "卡片不存在")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	servePrivateMediaFile(w, r, abs, name)
}

// privateCreateShareHandler POST /api/private/cards/{id}/share
func privateCreateShareHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	cardID := r.PathValue("id")
	var req createShareRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求数据")
		return
	}
	share, token, err := privateStore.createShare(session.Username, cardID, req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "分享失败，请重试")
		log.Printf("PRIVATE share.create error: %v", err)
		return
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	shareURL := fmt.Sprintf("%s://%s/card/%s", scheme, r.Host, token)
	privateStore.auditPrivate(r, session.Username, "private_note.card.share")
	writeJSON(w, http.StatusOK, "分享创建成功", map[string]interface{}{
		"token":          token,
		"url":            shareURL,
		"qr_url":         "/api/share/" + token + "/qr",
		"expires_at":     timePtrString(share.ExpiresAt),
		"allow_download": share.AllowDownload,
		"has_password":   share.PasswordHash != "",
	})
}

// privateCreateShareAliasHandler POST /api/private/shares（兼容：从 body 取 card_id）
func privateCreateShareAliasHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	var req struct {
		CardID string `json:"card_id"`
		createShareRequest
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.CardID == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少卡片 ID")
		return
	}
	r2 := *r
	r2.SetPathValue("id", req.CardID)
	privateCreateShareHandler(w, &r2)
}

func privateListSharesHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	shares, err := privateStore.listShares(session.Username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取分享失败")
		return
	}
	if shares == nil {
		shares = []map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, "获取分享成功", shares)
}

func privateRevokeShareHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	token := r.PathValue("token")
	if err := privateStore.revokeShare(session.Username, token); err != nil {
		writeJSONError(w, http.StatusNotFound, "分享不存在")
		return
	}
	privateStore.auditPrivate(r, session.Username, "private_note.card.revoke")
	writeJSON(w, http.StatusOK, "分享已撤销", nil)
}
