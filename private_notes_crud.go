package main

// 私人空间手记 CRUD 与附件文件管理。

import (
	"fmt"
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
	query := `SELECT ` + noteColumns + ` FROM notes WHERE user_id = ?`
	args := []interface{}{userID}
	if tag != "" {
		query += ` AND id IN (SELECT note_id FROM note_tags WHERE tag = ?)`
		args = append(args, tag)
	}
	if q != "" {
		query += ` AND (title LIKE ? OR content LIKE ? OR location_name LIKE ?
			OR id IN (SELECT note_id FROM note_tags WHERE tag LIKE ?))`
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []*PrivateNote
	for rows.Next() {
		row, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		notes = append(notes, &PrivateNote{
			ID: row.id, UserID: row.userID, Title: row.title, Content: row.content,
			CreatedAt: row.createdAt, UpdatedAt: row.updatedAt, LocationName: row.locationName,
			Latitude: row.latitude, Longitude: row.longitude,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, n := range notes {
		if err := s.fillNoteDetails(n); err != nil {
			return nil, err
		}
	}
	return notes, nil
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
	if err := s.fillNoteDetails(n); err != nil {
		return nil, err
	}
	return n, nil
}

func (s *PrivateStore) fillNoteDetails(n *PrivateNote) error {
	if err := s.fillNoteImages(n); err != nil {
		return err
	}
	if err := s.fillNoteAudio(n); err != nil {
		return err
	}
	if err := s.fillNoteVideos(n); err != nil {
		return err
	}
	return s.fillNoteTags(n)
}

func (s *PrivateStore) fillNoteImages(n *PrivateNote) error {
	rows, err := s.db.Query(`SELECT id, note_id, file_path, sort_order, created_at FROM note_images WHERE note_id = ? ORDER BY sort_order ASC, created_at ASC`, n.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var img PrivateImage
		if err := rows.Scan(&img.ID, &img.NoteID, &img.FilePath, &img.SortOrder, &img.CreatedAt); err != nil {
			return err
		}
		img.URL = fmt.Sprintf("/api/private/notes/%s/images/%s/file", n.ID, img.ID)
		n.Images = append(n.Images, img)
	}
	return rows.Err()
}

func (s *PrivateStore) fillNoteAudio(n *PrivateNote) error {
	rows, err := s.db.Query(`SELECT id, note_id, file_path, duration, created_at FROM note_audio WHERE note_id = ? ORDER BY created_at ASC`, n.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a PrivateAudio
		if err := rows.Scan(&a.ID, &a.NoteID, &a.FilePath, &a.Duration, &a.CreatedAt); err != nil {
			return err
		}
		a.URL = fmt.Sprintf("/api/private/notes/%s/audio/%s/file", n.ID, a.ID)
		n.Audio = append(n.Audio, a)
	}
	return rows.Err()
}

// fillNoteVideos 填充手记视频列表（含播放与海报 URL）
func (s *PrivateStore) fillNoteVideos(n *PrivateNote) error {
	rows, err := s.db.Query(`SELECT id, note_id, file_path, poster_path, duration, size, created_at FROM note_videos WHERE note_id = ? ORDER BY created_at ASC`, n.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v PrivateVideo
		if err := rows.Scan(&v.ID, &v.NoteID, &v.FilePath, &v.PosterPath, &v.Duration, &v.Size, &v.CreatedAt); err != nil {
			return err
		}
		v.URL = fmt.Sprintf("/api/private/notes/%s/video/%s/file", n.ID, v.ID)
		if v.PosterPath != "" {
			v.PosterURL = fmt.Sprintf("/api/private/notes/%s/video/%s/poster", n.ID, v.ID)
		}
		n.Videos = append(n.Videos, v)
	}
	return rows.Err()
}

func (s *PrivateStore) fillNoteTags(n *PrivateNote) error {
	rows, err := s.db.Query(`SELECT tag FROM note_tags WHERE note_id = ? ORDER BY id ASC`, n.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return err
		}
		n.Tags = append(n.Tags, tag)
	}
	return rows.Err()
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
	return &PrivateImage{ID: id, NoteID: noteID, FilePath: filepath.ToSlash(rel), SortOrder: maxOrder + 1, CreatedAt: nowUTC()}, nil
}

func (s *PrivateStore) deleteImage(userID, noteID, imageID string) error {
	if !s.noteOwnedBy(userID, noteID) {
		return fmt.Errorf("手记不存在")
	}
	var rel string
	if err := s.db.QueryRow(`SELECT file_path FROM note_images WHERE id = ? AND note_id = ?`, imageID, noteID).Scan(&rel); err != nil {
		return err
	}
	if abs, err := s.safeFilePath(rel); err == nil {
		os.Remove(abs)
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
