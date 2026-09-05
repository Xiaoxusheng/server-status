package main

// 私人空间手记 CRUD 与附件文件管理。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif" // 注册 GIF 解码器（image.Decode 按内容分发）
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type noteRow struct {
	id, userID, title, content, createdAt, updatedAt, locationName string
	latitude, longitude                                            *float64
}

const noteColumns = `id, user_id, title, content, created_at, updated_at, location_name, latitude, longitude`

func scanNote(sc interface{ Scan(...interface{}) error }) (*noteRow, error) {
	var n noteRow
	if err := sc.Scan(&n.id, &n.userID, &n.title, &n.content, &n.createdAt, &n.updatedAt, &n.locationName, &n.latitude, &n.longitude); err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *PrivateStore) listNotes(userID, tag, q string) ([]*PrivateNote, error) {
	notes, _, err := s.queryNotes(userID, tag, q, 0, 0)
	return notes, err
}

// listNotesPaged 分页查询手记（page 从 1 起，pageSize 已由调用方钳制上限）
func (s *PrivateStore) listNotesPaged(userID, tag, q string, page, pageSize int) ([]*PrivateNote, int, error) {
	return s.queryNotes(userID, tag, q, page, pageSize)
}

// queryNotes 手记列表查询：page/pageSize 均 <=0 时为全量模式（兼容旧调用，不分页）。
// 详情（图片/语音/视频/标签）先查 notes 再按 note_id 批量 IN 查询后内存聚合，
// 取代旧版逐条 fillNoteDetails 的 N+1 查询；返回 JSON 结构与旧版完全一致
func (s *PrivateStore) queryNotes(userID, tag, q string, page, pageSize int) ([]*PrivateNote, int, error) {
	where := ` WHERE user_id = ?`
	args := []interface{}{userID}
	if tag != "" {
		where += ` AND id IN (SELECT note_id FROM note_tags WHERE tag = ?)`
		args = append(args, tag)
	}
	if q != "" {
		where += ` AND (title LIKE ? OR content LIKE ? OR location_name LIKE ?
			OR id IN (SELECT note_id FROM note_tags WHERE tag LIKE ?))`
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}

	total := 0
	query := `SELECT ` + noteColumns + ` FROM notes` + where + ` ORDER BY created_at DESC`
	qargs := append([]interface{}{}, args...)
	if page > 0 && pageSize > 0 {
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM notes`+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		query += ` LIMIT ? OFFSET ?`
		qargs = append(qargs, pageSize, (page-1)*pageSize)
	}

	rows, err := s.db.Query(query, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	notes := []*PrivateNote{}
	for rows.Next() {
		row, err := scanNote(rows)
		if err != nil {
			return nil, 0, err
		}
		notes = append(notes, &PrivateNote{
			ID: row.id, UserID: row.userID, Title: row.title, Content: row.content,
			CreatedAt: row.createdAt, UpdatedAt: row.updatedAt, LocationName: row.locationName,
			Latitude: row.latitude, Longitude: row.longitude,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := s.fillNotesDetailsBatch(notes); err != nil {
		return nil, 0, err
	}
	return notes, total, nil
}

func (s *PrivateStore) getNote(userID, id string) (*PrivateNote, error) {
	row, err := scanNote(s.db.QueryRow(`SELECT `+noteColumns+` FROM notes WHERE id = ? AND user_id = ?`, id, userID))
	if err != nil {
		return nil, err
	}
	n := &PrivateNote{
		ID: row.id, UserID: row.userID, Title: row.title, Content: row.content,
		CreatedAt: row.createdAt, UpdatedAt: row.updatedAt, LocationName: row.locationName,
		Latitude: row.latitude, Longitude: row.longitude,
	}
	if err := s.fillNotesDetailsBatch([]*PrivateNote{n}); err != nil {
		return nil, err
	}
	return n, nil
}

// batchChunk 批量 IN 查询的分块大小（防占位符超过 SQLite 变量上限）
const batchChunk = 400

// chunkIDs 把 note_id 列表切成 ≤batchChunk 的分块
func chunkIDs(ids []string, size int) [][]string {
	var out [][]string
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[i:end])
	}
	return out
}

// placeholders 生成 n 个 "?" 占位符（逗号分隔）
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// toArgs []string 转 []interface{}（database/sql 参数）
func toArgs(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, v := range ss {
		out[i] = v
	}
	return out
}

// fillNotesDetailsBatch 批量填充手记详情：图片/语音/视频/标签各按 note_id IN 分块查询，
// 聚合挂回各手记，消除逐条查询的 N+1 开销
func (s *PrivateStore) fillNotesDetailsBatch(notes []*PrivateNote) error {
	if len(notes) == 0 {
		return nil
	}
	byID := make(map[string]*PrivateNote, len(notes))
	var ids []string
	for _, n := range notes {
		byID[n.ID] = n
		ids = append(ids, n.ID)
	}

	// 图片（含缩略图路径与宽高元数据）
	for _, chunk := range chunkIDs(ids, batchChunk) {
		rows, err := s.db.Query(`SELECT id, note_id, file_path, thumb_path, width, height, thumb_width, thumb_height, sort_order, created_at
			FROM note_images WHERE note_id IN (`+placeholders(len(chunk))+`) ORDER BY sort_order ASC, created_at ASC`, toArgs(chunk)...)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				var img PrivateImage
				if err := rows.Scan(&img.ID, &img.NoteID, &img.FilePath, &img.ThumbPath, &img.Width, &img.Height, &img.ThumbWidth, &img.ThumbHeight, &img.SortOrder, &img.CreatedAt); err != nil {
					return err
				}
				img.URL = fmt.Sprintf("/api/private/notes/%s/images/%s/file", img.NoteID, img.ID)
				img.ThumbURL = fmt.Sprintf("/api/private/notes/%s/images/%s/thumb", img.NoteID, img.ID)
				if n := byID[img.NoteID]; n != nil {
					n.Images = append(n.Images, img)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}

	// 语音
	for _, chunk := range chunkIDs(ids, batchChunk) {
		rows, err := s.db.Query(`SELECT id, note_id, file_path, duration, created_at
			FROM note_audio WHERE note_id IN (`+placeholders(len(chunk))+`) ORDER BY created_at ASC`, toArgs(chunk)...)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				var a PrivateAudio
				if err := rows.Scan(&a.ID, &a.NoteID, &a.FilePath, &a.Duration, &a.CreatedAt); err != nil {
					return err
				}
				a.URL = fmt.Sprintf("/api/private/notes/%s/audio/%s/file", a.NoteID, a.ID)
				if n := byID[a.NoteID]; n != nil {
					n.Audio = append(n.Audio, a)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}

	// 视频（含播放与海报 URL）
	for _, chunk := range chunkIDs(ids, batchChunk) {
		rows, err := s.db.Query(`SELECT id, note_id, file_path, poster_path, duration, size, created_at
			FROM note_videos WHERE note_id IN (`+placeholders(len(chunk))+`) ORDER BY created_at ASC`, toArgs(chunk)...)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				var v PrivateVideo
				if err := rows.Scan(&v.ID, &v.NoteID, &v.FilePath, &v.PosterPath, &v.Duration, &v.Size, &v.CreatedAt); err != nil {
					return err
				}
				v.URL = fmt.Sprintf("/api/private/notes/%s/video/%s/file", v.NoteID, v.ID)
				if v.PosterPath != "" {
					v.PosterURL = fmt.Sprintf("/api/private/notes/%s/video/%s/poster", v.NoteID, v.ID)
				}
				if n := byID[v.NoteID]; n != nil {
					n.Videos = append(n.Videos, v)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}

	// 标签
	for _, chunk := range chunkIDs(ids, batchChunk) {
		rows, err := s.db.Query(`SELECT note_id, tag FROM note_tags WHERE note_id IN (`+placeholders(len(chunk))+`) ORDER BY id ASC`, toArgs(chunk)...)
		if err != nil {
			return err
		}
		err = func() error {
			defer rows.Close()
			for rows.Next() {
				var noteID, tag string
				if err := rows.Scan(&noteID, &tag); err != nil {
					return err
				}
				if n := byID[noteID]; n != nil {
					n.Tags = append(n.Tags, tag)
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

type createNoteRequest struct {
	Title        string   `json:"title"`
	Content      string   `json:"content"`
	CreatedAt    string   `json:"created_at"`
	LocationName string   `json:"location_name"`
	Latitude     *float64 `json:"latitude"`
	Longitude    *float64 `json:"longitude"`
	Tags         []string `json:"tags"`
}

func (s *PrivateStore) createNote(userID string, req createNoteRequest) (*PrivateNote, error) {
	id := randomID("n")
	createdAt := req.CreatedAt
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		createdAt = t.UTC().Format(time.RFC3339)
	}
	if createdAt == "" {
		createdAt = nowUTC()
	}
	if _, err := s.db.Exec(`
		INSERT INTO notes (id, user_id, title, content, created_at, updated_at, location_name, latitude, longitude)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, req.Title, req.Content, createdAt, nowUTC(), req.LocationName, req.Latitude, req.Longitude); err != nil {
		return nil, err
	}
	if err := s.replaceTags(id, req.Tags); err != nil {
		return nil, err
	}
	return s.getNote(userID, id)
}

func (s *PrivateStore) updateNote(userID, id string, req createNoteRequest) (*PrivateNote, error) {
	var cnt int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notes WHERE id = ? AND user_id = ?`, id, userID).Scan(&cnt); err != nil || cnt == 0 {
		return nil, fmt.Errorf("手记不存在")
	}
	createdAt := req.CreatedAt
	if createdAt == "" {
		s.db.QueryRow(`SELECT created_at FROM notes WHERE id = ?`, id).Scan(&createdAt)
	} else if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		createdAt = t.UTC().Format(time.RFC3339)
	}
	if _, err := s.db.Exec(`
		UPDATE notes SET title = ?, content = ?, created_at = ?, updated_at = ?, location_name = ?, latitude = ?, longitude = ?
		WHERE id = ? AND user_id = ?`,
		req.Title, req.Content, createdAt, nowUTC(), req.LocationName, req.Latitude, req.Longitude, id, userID); err != nil {
		return nil, err
	}
	if err := s.replaceTags(id, req.Tags); err != nil {
		return nil, err
	}
	return s.getNote(userID, id)
}

func (s *PrivateStore) replaceTags(noteID string, tags []string) error {
	if _, err := s.db.Exec(`DELETE FROM note_tags WHERE note_id = ?`, noteID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if _, err := s.db.Exec(`INSERT INTO note_tags (note_id, tag) VALUES (?, ?)`, noteID, t); err != nil {
			return err
		}
	}
	return nil
}

// deleteNote 删除手记及全部附件文件（图片/语音/卡片）
func (s *PrivateStore) deleteNote(userID, id string) error {
	n, err := s.getNote(userID, id)
	if err != nil {
		return err
	}
	for _, img := range n.Images {
		if abs, err := s.safeFilePath(img.FilePath); err == nil {
			os.Remove(abs)
		}
		// 同步清理缩略图文件（缩略图回退引用原图时两者相同，跳过）
		if img.ThumbPath != "" && img.ThumbPath != img.FilePath {
			if abs, err := s.safeFilePath(img.ThumbPath); err == nil {
				os.Remove(abs)
			}
		}
	}
	for _, a := range n.Audio {
		if abs, err := s.safeFilePath(a.FilePath); err == nil {
			os.Remove(abs)
		}
	}
	for _, v := range n.Videos {
		if abs, err := s.safeFilePath(v.FilePath); err == nil {
			os.Remove(abs)
		}
		if v.PosterPath != "" {
			if abs, err := s.safeFilePath(v.PosterPath); err == nil {
				os.Remove(abs)
			}
		}
	}
	if cards, err := s.listCardsForNote(userID, id); err == nil {
		for _, c := range cards {
			if abs, err := s.safeFilePath(c.FilePath); err == nil {
				os.Remove(abs)
			}
		}
	}
	_, err = s.db.Exec(`DELETE FROM notes WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (s *PrivateStore) listTags(userID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT t.tag FROM note_tags t JOIN notes n ON n.id = t.note_id
		WHERE n.user_id = ? ORDER BY t.tag ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, rows.Err()
}

// ==================== 图片 / 语音 文件 ====================

func (s *PrivateStore) noteOwnedBy(userID, noteID string) bool {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM notes WHERE id = ? AND user_id = ?`, noteID, userID).Scan(&n)
	return err == nil && n > 0
}

func (s *PrivateStore) addImage(userID, noteID string, file multipart.File, header *multipart.FileHeader) (*PrivateImage, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return nil, fmt.Errorf("手记不存在")
	}
	ext, valid := imageExtForMIME(header.Header.Get("Content-Type"), header.Filename)
	if !valid {
		return nil, fmt.Errorf("仅支持 jpg / jpeg / png / webp / gif 图片")
	}
	if header.Size > 20*1024*1024 {
		return nil, fmt.Errorf("图片不能超过 20MB")
	}
	sniff := make([]byte, 512)
	n, _ := io.ReadFull(file, sniff)
	detected := http.DetectContentType(sniff[:n])
	if !strings.HasPrefix(detected, "image/") {
		return nil, fmt.Errorf("文件内容不是有效图片")
	}
	rel, abs, err := s.newNoteFilePath(ext)
	if err != nil {
		return nil, err
	}
	rest, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取上传内容失败: %w", err)
	}
	data := make([]byte, 0, n+len(rest))
	data = append(data, sniff[:n]...)
	data = append(data, rest...)
	if len(data) > 20*1024*1024 {
		return nil, fmt.Errorf("图片不能超过 20MB")
	}
	enc, err := encryptMediaBytes(data)
	if err != nil {
		return nil, err
	}
	dst, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(enc); err != nil {
		dst.Close()
		os.Remove(abs)
		return nil, err
	}
	if err := dst.Close(); err != nil {
		os.Remove(abs)
		return nil, err
	}

	id := randomID("img")
	var maxOrder int
	s.db.QueryRow(`SELECT COALESCE(MAX(sort_order), -1) FROM note_images WHERE note_id = ?`, noteID).Scan(&maxOrder)
	if _, err := s.db.Exec(`
		INSERT INTO note_images (id, note_id, file_path, sort_order, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, noteID, filepath.ToSlash(rel), maxOrder+1, nowUTC()); err != nil {
		os.Remove(abs)
		return nil, err
	}
	img := &PrivateImage{
		ID: id, NoteID: noteID, FilePath: filepath.ToSlash(rel), SortOrder: maxOrder + 1, CreatedAt: nowUTC(),
		URL:      fmt.Sprintf("/api/private/notes/%s/images/%s/file", noteID, id),
		ThumbURL: fmt.Sprintf("/api/private/notes/%s/images/%s/thumb", noteID, id),
	}
	// 上传时同步生成持久缩略图（480px）：失败不阻塞上传（thumb_url 仍有效，首次访问按需生成）
	if _, tw, th, w, h, terr := s.ensureImageThumb(noteID, id); terr == nil {
		img.ThumbWidth, img.ThumbHeight, img.Width, img.Height = tw, th, w, h
	}
	return img, nil
}

func (s *PrivateStore) deleteImage(userID, noteID, imageID string) error {
	if !s.noteOwnedBy(userID, noteID) {
		return fmt.Errorf("手记不存在")
	}
	var rel, thumbRel string
	if err := s.db.QueryRow(`SELECT file_path, thumb_path FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID).Scan(&rel, &thumbRel); err != nil {
		return err
	}
	if abs, err := s.safeFilePath(rel); err == nil {
		os.Remove(abs)
	}
	// 同步清理缩略图文件（缩略图回退引用原图时两者相同，跳过）
	if thumbRel != "" && thumbRel != rel {
		if abs, err := s.safeFilePath(thumbRel); err == nil {
			os.Remove(abs)
		}
	}
	_, err := s.db.Exec(`DELETE FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID)
	return err
}

func (s *PrivateStore) reorderImages(userID, noteID string, ids []string) error {
	if !s.noteOwnedBy(userID, noteID) {
		return fmt.Errorf("手记不存在")
	}
	for i, id := range ids {
		if _, err := s.db.Exec(`UPDATE note_images SET sort_order = ? WHERE id = ? AND note_id = ?`, i, id, noteID); err != nil {
			return err
		}
	}
	return nil
}

// imageFilePath 返回图片的绝对路径与展示文件名（本地读取）
func (s *PrivateStore) imageFilePath(userID, noteID, imageID string) (string, string, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return "", "", fmt.Errorf("手记不存在")
	}
	var rel string
	if err := s.db.QueryRow(`SELECT file_path FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID).Scan(&rel); err != nil {
		return "", "", err
	}
	abs, err := s.safeFilePath(rel)
	return abs, filepath.Base(abs), err
}

// ==================== 缩略图 ====================
// 缩略图规格：最长边 480px，JPEG 质量 82（PNG 源保留透明通道）。
// 说明：Go 标准库无 WebP 编码器，按"优先标准库、不引入重量级图片依赖"约束输出 JPEG，
// 480px q82 普通照片普遍 30~80KB，满足 <100KB 目标。
// 历史图片（thumb_path 为空）不在启动时批量生成：首次访问 thumb 接口时按需生成并持久化，
// 后续直接读取；并发访问通过 per-image singleflight 去重。

// thumbMaxEdge 缩略图最长边
const thumbMaxEdge = 480

// imageThumbPath 返回缩略图绝对路径与文件名（不存在时按需生成）
func (s *PrivateStore) imageThumbPath(userID, noteID, imageID string) (string, string, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return "", "", fmt.Errorf("手记不存在")
	}
	rel, _, _, _, _, err := s.ensureImageThumb(noteID, imageID)
	if err != nil {
		return "", "", err
	}
	abs, err := s.safeFilePath(rel)
	if err != nil {
		return "", "", err
	}
	return abs, filepath.Base(abs), nil
}

// lookupImageThumb 读取图片行中已持久化的缩略图路径与宽高；thumb_path 为空表示尚未生成
func (s *PrivateStore) lookupImageThumb(noteID, imageID string) (thumbRel string, tw, th, w, h int, err error) {
	err = s.db.QueryRow(`SELECT file_path, thumb_path, width, height, thumb_width, thumb_height
		FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID).
		Scan(new(string), &thumbRel, &w, &h, &tw, &th)
	return
}

// ensureImageThumb 确保缩略图已生成并返回（thumbRel, thumbW, thumbH, origW, origH, err）。
// 已存在直接返回；不存在时经 singleflight 生成（并发请求只生成一次，其余等待后重查）
func (s *PrivateStore) ensureImageThumb(noteID, imageID string) (string, int, int, int, int, error) {
	if rel, tw, th, w, h, err := s.lookupImageThumb(noteID, imageID); err == nil && rel != "" {
		return rel, tw, th, w, h, nil
	}
	key := noteID + "/" + imageID
	s.thumbMu.Lock()
	if s.thumbCalls == nil {
		s.thumbCalls = make(map[string]*thumbCall)
	}
	if c, ok := s.thumbCalls[key]; ok {
		// 已有同一图片的生成任务：等待完成后重查（任务完成后 thumb_path 必已落库）
		s.thumbMu.Unlock()
		<-c.done
	} else {
		c := &thumbCall{done: make(chan struct{})}
		s.thumbCalls[key] = c
		s.thumbMu.Unlock()
		func() {
			defer close(c.done)
			if _, _, _, _, _, err := s.generateImageThumb(noteID, imageID); err != nil {
				log.Printf("缩略图生成失败 note=%s image=%s: %v", noteID, imageID, err)
			}
		}()
		s.thumbMu.Lock()
		delete(s.thumbCalls, key)
		s.thumbMu.Unlock()
	}
	rel, tw, th, w, h, err := s.lookupImageThumb(noteID, imageID)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	if rel == "" {
		return "", 0, 0, 0, 0, fmt.Errorf("缩略图生成失败")
	}
	return rel, tw, th, w, h, nil
}

// generateImageThumb 生成并持久化缩略图：解密原图 → 解码 → 按 EXIF 方向矫正 →
// 最长边 ≤480px 面积平均缩放 → JPEG q82（PNG 源用 PNG 保留透明）→ 加密落盘 → 回写 DB。
// GIF（保持动图）与无法解码的格式（如 WebP）直接以原图作为缩略图引用，保证 thumb 接口始终可用
func (s *PrivateStore) generateImageThumb(noteID, imageID string) (string, int, int, int, int, error) {
	var origRel string
	if err := s.db.QueryRow(`SELECT file_path FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID).Scan(&origRel); err != nil {
		return "", 0, 0, 0, 0, err
	}
	// fallbackAsOriginal 无法生成缩略图时回退：缩略图直接引用原图（记录原始宽高，缩略宽高留 0）
	fallbackAsOriginal := func(w, h int) (string, int, int, int, int, error) {
		if _, err := s.db.Exec(`UPDATE note_images SET thumb_path = ?, width = ?, height = ? WHERE id = ?`,
			origRel, w, h, imageID); err != nil {
			return "", 0, 0, 0, 0, err
		}
		return origRel, 0, 0, w, h, nil
	}

	abs, err := s.safeFilePath(origRel)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	data, err := decryptMediaBytes(raw)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return fallbackAsOriginal(0, 0)
	}
	// 显示宽高按 EXIF 方向修正（浏览器渲染 <img> 时同样遵循 EXIF 方向）
	orient := exifOrientation(data)
	w, h := cfg.Width, cfg.Height
	if orient >= 5 {
		w, h = h, w
	}
	// GIF 多为动图：缩略图直接引用原图，避免抽帧丢失动画
	if format == "gif" {
		if _, err := s.db.Exec(`UPDATE note_images SET thumb_path = ?, width = ?, height = ?, thumb_width = ?, thumb_height = ? WHERE id = ?`,
			origRel, w, h, w, h, imageID); err != nil {
			return "", 0, 0, 0, 0, err
		}
		return origRel, w, h, w, h, nil
	}

	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return fallbackAsOriginal(w, h)
	}
	// 统一转 RGBA 后按 EXIF 方向矫正，再面积平均缩放（只缩不放）
	b := src.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(rgba, rgba.Bounds(), src, b.Min, draw.Src)
	rgba = orientRGBA(rgba, orient)
	sw, sh := rgba.Bounds().Dx(), rgba.Bounds().Dy()
	dw, dh := sw, sh
	if m := max(sw, sh); m > thumbMaxEdge {
		dw = max(1, sw*thumbMaxEdge/m)
		dh = max(1, sh*thumbMaxEdge/m)
	}
	thumb := resizeAreaRGBA(rgba, dw, dh)

	var out bytes.Buffer
	if format == "png" {
		err = png.Encode(&out, thumb)
	} else {
		err = jpeg.Encode(&out, thumb, &jpeg.Options{Quality: 82})
	}
	if err != nil {
		return fallbackAsOriginal(w, h)
	}
	ext := ".jpg"
	if format == "png" {
		ext = ".png"
	}
	thumbRel := strings.TrimSuffix(origRel, filepath.Ext(origRel)) + ".thumb" + ext
	tabs, err := s.safeFilePath(thumbRel)
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	enc, err := encryptMediaBytes(out.Bytes())
	if err != nil {
		return "", 0, 0, 0, 0, err
	}
	if err := os.MkdirAll(filepath.Dir(tabs), 0755); err != nil {
		return "", 0, 0, 0, 0, err
	}
	if err := os.WriteFile(tabs, enc, 0644); err != nil {
		return "", 0, 0, 0, 0, err
	}
	if _, err := s.db.Exec(`UPDATE note_images SET thumb_path = ?, width = ?, height = ?, thumb_width = ?, thumb_height = ? WHERE id = ?`,
		thumbRel, w, h, dw, dh, imageID); err != nil {
		os.Remove(tabs)
		return "", 0, 0, 0, 0, err
	}
	return thumbRel, dw, dh, w, h, nil
}

// exifOrientation 解析 JPEG EXIF 方向标签（TIFF IFD0 Orientation 0x0112）；
// 非 JPEG 或缺失时返回 1（不旋转）
func exifOrientation(data []byte) int {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return 1
	}
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			return 1
		}
		marker := data[pos+1]
		if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 {
			pos += 2
			continue
		}
		if marker == 0xDA {
			break // SOS：头部段结束
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			return 1
		}
		if marker == 0xE1 && pos+10 <= len(data) && bytes.HasPrefix(data[pos+4:pos+10], []byte("Exif\x00\x00")) {
			return parseTIFFOrientation(data[pos+10 : pos+2+segLen])
		}
		pos += 2 + segLen
	}
	return 1
}

// parseTIFFOrientation 从 TIFF 头解析 IFD0 的 Orientation 值（非法/缺失返回 1）
func parseTIFFOrientation(tiff []byte) int {
	if len(tiff) < 8 {
		return 1
	}
	var bo binary.ByteOrder = binary.LittleEndian
	switch {
	case tiff[0] == 'M' && tiff[1] == 'M':
		bo = binary.BigEndian
	case tiff[0] != 'I' || tiff[1] != 'I':
		return 1
	}
	if bo.Uint16(tiff[2:]) != 42 {
		return 1
	}
	ifd0 := int(bo.Uint32(tiff[4:]))
	if ifd0+2 > len(tiff) {
		return 1
	}
	n := int(bo.Uint16(tiff[ifd0:]))
	for i := 0; i < n; i++ {
		e := ifd0 + 2 + i*12
		if e+12 > len(tiff) {
			break
		}
		if bo.Uint16(tiff[e:]) == 0x0112 {
			if o := int(bo.Uint16(tiff[e+8:])); o >= 1 && o <= 8 {
				return o
			}
			return 1
		}
	}
	return 1
}

// orientRGBA 按 EXIF Orientation（2-8）变换像素方向，保证缩略图方向与浏览器渲染原图一致；
// 方向 5-8 输出宽高互换。方向 1 或非法值原样返回
func orientRGBA(src *image.RGBA, o int) *image.RGBA {
	if o <= 1 || o > 8 {
		return src
	}
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	dw, dh := sw, sh
	if o >= 5 {
		dw, dh = sh, sw
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			var sx, sy int
			switch o {
			case 2: // 水平翻转
				sx, sy = sw-1-x, y
			case 3: // 旋转 180°
				sx, sy = sw-1-x, sh-1-y
			case 4: // 垂直翻转
				sx, sy = x, sh-1-y
			case 5: // 转置（主对角线镜像）
				sx, sy = y, x
			case 6: // 顺时针旋转 90°
				sx, sy = y, sh-1-x
			case 7: // 反对角线镜像
				sx, sy = sw-1-y, sh-1-x
			case 8: // 逆时针旋转 90°
				sx, sy = sw-1-y, x
			}
			dst.SetRGBA(x, y, src.RGBAAt(sb.Min.X+sx, sb.Min.Y+sy))
		}
	}
	return dst
}

// resizeAreaRGBA 盒式面积平均缩放（纯标准库实现）：每个目标像素取源图对应矩形块
// 的预乘平均色，缩比明显时质量优于最近邻，速度远快于逐点双线性大核采样
func resizeAreaRGBA(src *image.RGBA, dw, dh int) *image.RGBA {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	if dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0 {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for dy := 0; dy < dh; dy++ {
		sy0 := dy * sh / dh
		sy1 := (dy + 1) * sh / dh
		if sy1 <= sy0 {
			sy1 = min(sy0+1, sh)
		}
		for dx := 0; dx < dw; dx++ {
			sx0 := dx * sw / dw
			sx1 := (dx + 1) * sw / dw
			if sx1 <= sx0 {
				sx1 = min(sx0+1, sw)
			}
			var r, g, b, a float64
			for y := sy0; y < sy1; y++ {
				rowOff := (sb.Min.Y + y - src.Rect.Min.Y) * src.Stride
				for x := sx0; x < sx1; x++ {
					off := rowOff + (sb.Min.X+x-src.Rect.Min.X)*4
					a += float64(src.Pix[off+3])
					// 预乘后累加，避免半透明边缘出现颜色渗光
					af := float64(src.Pix[off+3]) / 255
					r += float64(src.Pix[off+0]) * af
					g += float64(src.Pix[off+1]) * af
					b += float64(src.Pix[off+2]) * af
				}
			}
			n := float64((sx1 - sx0) * (sy1 - sy0))
			pa := a / n
			doff := dst.PixOffset(dx, dy)
			if pa > 0 {
				// 非预乘色 = 预乘均值 × 255 / 平均 alpha
				dst.Pix[doff+0] = uint8(math.Min(255, (r/n)*255/pa))
				dst.Pix[doff+1] = uint8(math.Min(255, (g/n)*255/pa))
				dst.Pix[doff+2] = uint8(math.Min(255, (b/n)*255/pa))
			}
			dst.Pix[doff+3] = uint8(math.Min(255, pa))
		}
	}
	return dst
}

func (s *PrivateStore) addAudio(userID, noteID string, file multipart.File, header *multipart.FileHeader, duration float64) (*PrivateAudio, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return nil, fmt.Errorf("手记不存在")
	}
	ext, valid := audioExtForMIME(header.Header.Get("Content-Type"), header.Filename)
	if !valid {
		return nil, fmt.Errorf("不支持的音频格式")
	}
	if header.Size > 30*1024*1024 {
		return nil, fmt.Errorf("语音不能超过 30MB")
	}
	rel, abs, err := s.newNoteFilePath(ext)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取上传内容失败: %w", err)
	}
	if len(data) > 30*1024*1024 {
		return nil, fmt.Errorf("语音不能超过 30MB")
	}
	enc, err := encryptMediaBytes(data)
	if err != nil {
		return nil, err
	}
	dst, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(enc); err != nil {
		dst.Close()
		os.Remove(abs)
		return nil, err
	}
	if err := dst.Close(); err != nil {
		os.Remove(abs)
		return nil, err
	}
	id := randomID("au")
	if _, err := s.db.Exec(`
		INSERT INTO note_audio (id, note_id, file_path, duration, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, noteID, filepath.ToSlash(rel), duration, nowUTC()); err != nil {
		os.Remove(abs)
		return nil, err
	}
	return &PrivateAudio{ID: id, NoteID: noteID, FilePath: filepath.ToSlash(rel), Duration: duration, CreatedAt: nowUTC()}, nil
}

func (s *PrivateStore) deleteAudio(userID, noteID, audioID string) error {
	if !s.noteOwnedBy(userID, noteID) {
		return fmt.Errorf("手记不存在")
	}
	var rel string
	if err := s.db.QueryRow(`SELECT file_path FROM note_audio WHERE id = ? AND note_id = ?`, audioID, noteID).Scan(&rel); err != nil {
		return err
	}
	if abs, err := s.safeFilePath(rel); err == nil {
		os.Remove(abs)
	}
	_, err := s.db.Exec(`DELETE FROM note_audio WHERE id = ? AND note_id = ?`, audioID, noteID)
	return err
}

// audioFilePath 返回语音的绝对路径与展示文件名（本地读取）
func (s *PrivateStore) audioFilePath(userID, noteID, audioID string) (string, string, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return "", "", fmt.Errorf("手记不存在")
	}
	var rel string
	if err := s.db.QueryRow(`SELECT file_path FROM note_audio WHERE id = ? AND note_id = ?`, audioID, noteID).Scan(&rel); err != nil {
		return "", "", err
	}
	abs, err := s.safeFilePath(rel)
	return abs, filepath.Base(abs), err
}

// ==================== 视频文件 ====================

// videoExtForMIME 校验视频扩展名与 MIME 匹配（手机拍摄常见 mp4/mov，浏览器录制 webm）
func videoExtForMIME(contentType, fileName string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(fileName))
	mime := strings.ToLower(strings.TrimSpace(contentType))
	if !strings.HasPrefix(mime, "video/") && mime != "application/octet-stream" {
		return "", false
	}
	switch ext {
	case ".mp4", ".m4v", ".webm", ".mov":
		return ext, true
	}
	return "", false
}

// addVideo 流式分块加密写入视频并保存海报（海报为客户端截取的首帧 JPEG）
func (s *PrivateStore) addVideo(userID, noteID string, file multipart.File, header *multipart.FileHeader, poster multipart.File, posterHeader *multipart.FileHeader, duration float64) (*PrivateVideo, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return nil, fmt.Errorf("手记不存在")
	}
	ext, valid := videoExtForMIME(header.Header.Get("Content-Type"), header.Filename)
	if !valid {
		return nil, fmt.Errorf("仅支持 mp4 / mov / webm 视频")
	}
	if header.Size > videoMaxSize {
		return nil, fmt.Errorf("视频不能超过 200MB")
	}
	// 视频文件：流式分块加密，不整读进内存
	rel, abs, err := s.newNoteFilePath(ext)
	if err != nil {
		return nil, err
	}
	dst, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	written, err := encryptVideoStream(file, dst, header.Size)
	if err != nil {
		dst.Close()
		os.Remove(abs)
		return nil, fmt.Errorf("视频加密写入失败: %w", err)
	}
	if err := dst.Close(); err != nil {
		os.Remove(abs)
		return nil, err
	}

	// 海报（可选）：小图整块加密存储
	posterRel := ""
	if poster != nil && posterHeader != nil && posterHeader.Size > 0 {
		if posterHeader.Size > 5*1024*1024 {
			os.Remove(abs)
			return nil, fmt.Errorf("封面图不能超过 5MB")
		}
		pext, pvalid := imageExtForMIME(posterHeader.Header.Get("Content-Type"), posterHeader.Filename)
		if !pvalid {
			os.Remove(abs)
			return nil, fmt.Errorf("封面图仅支持 jpg / png / webp")
		}
		prel, pabs, err := s.newNoteFilePath(pext)
		if err != nil {
			os.Remove(abs)
			return nil, err
		}
		pdata, err := io.ReadAll(poster)
		if err != nil || int64(len(pdata)) != posterHeader.Size {
			os.Remove(abs)
			os.Remove(pabs)
			return nil, fmt.Errorf("读取封面失败")
		}
		penc, err := encryptMediaBytes(pdata)
		if err != nil {
			os.Remove(abs)
			os.Remove(pabs)
			return nil, err
		}
		if err := os.WriteFile(pabs, penc, 0644); err != nil {
			os.Remove(abs)
			os.Remove(pabs)
			return nil, err
		}
		posterRel = filepath.ToSlash(prel)
	}

	// 服务器端兜底：前端截帧失败（如 HEVC 编码）或时长缺失时，用 ffmpeg 解密抽帧补齐
	if poster == nil || duration <= 0 {
		log.Printf("视频封面服务器兜底触发 note=%s poster_nil=%v duration=%.3f", noteID, poster == nil, duration)
		if d, jpg, e := extractVideoMetaWithFFmpeg(abs); e == nil {
			if duration <= 0 {
				duration = d
			}
			if poster == nil && len(jpg) > 0 {
				log.Printf("视频封面服务器兜底成功 note=%s ffprobe_duration=%.3f poster_bytes=%d", noteID, d, len(jpg))
				prel, pabs, perr := s.newNoteFilePath(".jpg")
				if perr == nil {
					if penc, eenc := encryptMediaBytes(jpg); eenc == nil && os.WriteFile(pabs, penc, 0644) == nil {
						posterRel = filepath.ToSlash(prel)
					} else {
						os.Remove(pabs)
					}
				}
			}
		} else {
			log.Printf("视频封面服务器兜底失败 note=%s: %v", noteID, e)
		}
	}

	id := randomID("vid")
	if _, err := s.db.Exec(`
		INSERT INTO note_videos (id, note_id, file_path, poster_path, duration, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, noteID, filepath.ToSlash(rel), posterRel, duration, written, nowUTC()); err != nil {
		os.Remove(abs)
		if posterRel != "" {
			if pabs, e := s.safeFilePath(posterRel); e == nil {
				os.Remove(pabs)
			}
		}
		return nil, err
	}
	return &PrivateVideo{
		ID: id, NoteID: noteID, FilePath: filepath.ToSlash(rel), PosterPath: posterRel,
		URL:      fmt.Sprintf("/api/private/notes/%s/video/%s/file", noteID, id),
		Duration: duration, Size: written, CreatedAt: nowUTC(),
	}, nil
}

func (s *PrivateStore) deleteVideo(userID, noteID, videoID string) error {
	if !s.noteOwnedBy(userID, noteID) {
		return fmt.Errorf("手记不存在")
	}
	var rel, posterRel string
	if err := s.db.QueryRow(`SELECT file_path, poster_path FROM note_videos WHERE id = ? AND note_id = ?`, videoID, noteID).Scan(&rel, &posterRel); err != nil {
		return err
	}
	if abs, err := s.safeFilePath(rel); err == nil {
		os.Remove(abs)
	}
	if posterRel != "" {
		if abs, err := s.safeFilePath(posterRel); err == nil {
			os.Remove(abs)
		}
	}
	_, err := s.db.Exec(`DELETE FROM note_videos WHERE id = ? AND note_id = ?`, videoID, noteID)
	return err
}

// videoFilePath 返回视频/海报的绝对路径与展示文件名（kind: file | poster）
func (s *PrivateStore) videoFilePath(userID, noteID, videoID, kind string) (string, string, error) {
	if !s.noteOwnedBy(userID, noteID) {
		return "", "", fmt.Errorf("手记不存在")
	}
	var rel, posterRel string
	if err := s.db.QueryRow(`SELECT file_path, poster_path FROM note_videos WHERE id = ? AND note_id = ?`, videoID, noteID).Scan(&rel, &posterRel); err != nil {
		return "", "", err
	}
	if kind == "poster" {
		if posterRel == "" {
			return "", "", fmt.Errorf("视频无封面")
		}
		rel = posterRel
	}
	abs, err := s.safeFilePath(rel)
	return abs, filepath.Base(abs), err
}

// extractVideoMetaWithFFmpeg 服务器端兜底：前端 canvas 截帧失败（如 HEVC/AV1 编码浏览器不支持）时，
// 将加密视频流式解密到临时文件，用 ffprobe 读取时长、ffmpeg 抽取 25% 处一帧（≤2s，避开开头黑场）作 JPEG
// ffmpeg/ffprobe 不存在或解码失败时返回 err，调用方静默降级（无封面）
func extractVideoMetaWithFFmpeg(abs string) (duration float64, poster []byte, err error) {
	// 1. 解密到临时 mp4（ffmpeg 需要 seekable 输入）
	tmp, err := os.CreateTemp("", "pv-meta-*.mp4")
	if err != nil {
		return 0, nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	jpgName := tmpName + ".jpg"
	defer os.Remove(jpgName)

	vr, err := openVideoReader(abs)
	if err != nil {
		tmp.Close()
		return 0, nil, err
	}
	_, copyErr := io.Copy(tmp, vr)
	vr.Close()
	tmp.Close()
	if copyErr != nil {
		return 0, nil, copyErr
	}

	// 2. ffprobe 读取时长（秒）
	if out, e := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", tmpName).Output(); e == nil {
		duration, _ = strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	}

	// 3. ffmpeg 抽帧：宽 720 内等比，质量 q:v=3（filter 内逗号须用 filtergraph 引号包裹，否则被当过滤器分隔符）
	pos := math.Min(math.Max(duration*0.25, 0.1), 2)
	if e := exec.Command("ffmpeg", "-ss", strconv.FormatFloat(pos, 'f', 2, 64),
		"-i", tmpName, "-frames:v", "1", "-vf", "scale='min(720,iw)':-2", "-q:v", "3", "-y", jpgName).Run(); e != nil {
		return duration, nil, nil // 时长已拿到，抽帧失败不阻塞
	}
	poster, err = os.ReadFile(jpgName)
	if err != nil || len(poster) == 0 {
		return duration, nil, nil
	}
	return duration, poster, nil
}

// ==================== 导出 ====================

func (s *PrivateStore) exportNoteMarkdown(userID, id, baseURL string) (string, error) {
	n, err := s.getNote(userID, id)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", firstLineOrTitle(n)))
	b.WriteString(fmt.Sprintf("> 时间：%s\n", n.CreatedAt))
	if n.LocationName != "" {
		b.WriteString(fmt.Sprintf("> 地点：%s\n", n.LocationName))
	}
	if len(n.Tags) > 0 {
		b.WriteString("> 标签：" + strings.Join(n.Tags, " ") + "\n")
	}
	b.WriteString("\n" + n.Content + "\n")
	for _, img := range n.Images {
		b.WriteString(fmt.Sprintf("\n![图片](%s%s)\n", baseURL, img.URL))
	}
	for _, a := range n.Audio {
		b.WriteString(fmt.Sprintf("\n[语音](%s%s)\n", baseURL, a.URL))
	}
	for _, v := range n.Videos {
		b.WriteString(fmt.Sprintf("\n[视频](%s%s)\n", baseURL, v.URL))
	}
	return b.String(), nil
}

func firstLineOrTitle(n *PrivateNote) string {
	if n.Title != "" {
		return n.Title
	}
	for _, line := range strings.Split(n.Content, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return "未命名手记"
}
