package main

// 私人空间手记 CRUD 与附件文件管理。

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
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
