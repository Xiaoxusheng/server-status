package main

// 私人空间全量备份导出：手记 Markdown + 图片/语音解密后打包为 zip 流式下载。
// 备份为自包含结构，图片/语音以 zip 内相对路径被 Markdown 引用，无需服务端即可阅读。

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// zipNameSanitizer 匹配文件名中不允许出现的字符（Windows 保留字符与控制字符）
var zipNameSanitizer = regexp.MustCompile(`[\\/:*?"<>|\x00-\x1f]`)

// sanitizeZipName 将标题清理为安全的 zip 内文件名片段（去路径符/控制符，限长防超长文件名）
func sanitizeZipName(s string, maxRunes int) string {
	s = zipNameSanitizer.ReplaceAllString(strings.TrimSpace(s), "_")
	runes := []rune(s)
	if len(runes) > maxRunes {
		runes = runes[:maxRunes]
	}
	s = strings.Trim(string(runes), " .")
	if s == "" {
		s = "未命名"
	}
	return s
}

// noteLocalDay 将 RFC3339(UTC) 时间转为本地时区的 yyyy-mm-dd，用于备份内文件按日期归档
func noteLocalDay(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("2006-01-02")
	}
	return "unknown-date"
}

// readPrivateMedia 读取相对路径媒体文件并解密为明文字节（历史明文文件原样返回）
func (s *PrivateStore) readPrivateMedia(rel string) ([]byte, error) {
	abs, err := s.safeFilePath(rel)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return decryptMediaBytes(raw)
}

// copyPrivateVideo 将分块加密视频解密后流式拷贝到 w（避免大视频整体读入内存）
func (s *PrivateStore) copyPrivateVideo(rel string, w io.Writer) error {
	abs, err := s.safeFilePath(rel)
	if err != nil {
		return err
	}
	vr, err := openVideoReader(abs)
	if err != nil {
		return err
	}
	defer vr.Close()
	_, err = io.Copy(w, vr)
	return err
}

// privateExportAllHandler GET /api/private/export/all
// 全量导出当前用户的手记备份 zip（流式写出，不落临时文件）：
//
//	notes/<日期>_<标题>_<id>.md    正文，图片/语音以相对路径引用
//	images/<noteID>/img-NN.<ext>   解密后的原图
//	audio/<noteID>/audio-NN.<ext>  解密后的原音频
//	manifest.json                  备份元信息
//
// 双层认证与手记列表一致（登录会话 + 私人空间解锁会话），仅能导出本人的手记。
func privateExportAllHandler(w http.ResponseWriter, r *http.Request) {
	recordAccess(r)
	session, _ := getSessionFromRequest(r)
	notes, err := privateStore.listNotes(session.Username, "", "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取手记失败")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	exportName := "手记备份-" + time.Now().Format("20060102-150405") + ".zip"
	// RFC 5987：中文文件名用 filename*=UTF-8'' 编码，同时提供 ASCII 回退名
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="notes-backup.zip"; filename*=UTF-8''%s`, url.PathEscape(exportName)))

	zw := zip.NewWriter(w)
	defer zw.Close()
	noteCount, imgCount, audioCount, videoCount := 0, 0, 0, 0

	for _, n := range notes {
		noteCount++
		day := noteLocalDay(n.CreatedAt)
		base := fmt.Sprintf("%s_%s_%s", day, sanitizeZipName(firstLineOrTitle(n), 40), n.ID)

		// 1. Markdown 正文：结构与单条导出一致，图片/语音/视频改为 zip 内相对路径（自包含）
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
		for i, img := range n.Images {
			b.WriteString(fmt.Sprintf("\n![图片%d](../images/%s/img-%02d%s)\n", i+1, n.ID, i+1, strings.ToLower(filepath.Ext(img.FilePath))))
		}
		for i, a := range n.Audio {
			b.WriteString(fmt.Sprintf("\n[语音%d](../audio/%s/audio-%02d%s)\n", i+1, n.ID, i+1, strings.ToLower(filepath.Ext(a.FilePath))))
		}
		for i, v := range n.Videos {
			b.WriteString(fmt.Sprintf("\n[视频%d](../videos/%s/video-%02d%s)\n", i+1, n.ID, i+1, strings.ToLower(filepath.Ext(v.FilePath))))
		}
		if f, err := zw.Create("notes/" + base + ".md"); err == nil {
			_, _ = f.Write([]byte(b.String()))
		}

		// 2. 图片：解密后按原格式写入；单个文件失败仅记录日志并跳过，不中断整体导出
		for i, img := range n.Images {
			data, err := privateStore.readPrivateMedia(img.FilePath)
			if err != nil {
				log.Printf("备份导出：图片读取失败 note=%s img=%s: %v", n.ID, img.ID, err)
				continue
			}
			if f, err := zw.Create(fmt.Sprintf("images/%s/img-%02d%s", n.ID, i+1, strings.ToLower(filepath.Ext(img.FilePath)))); err == nil {
				_, _ = f.Write(data)
				imgCount++
			}
		}

		// 3. 语音：同图片处理
		for i, a := range n.Audio {
			data, err := privateStore.readPrivateMedia(a.FilePath)
			if err != nil {
				log.Printf("备份导出：语音读取失败 note=%s audio=%s: %v", n.ID, a.ID, err)
				continue
			}
			if f, err := zw.Create(fmt.Sprintf("audio/%s/audio-%02d%s", n.ID, i+1, strings.ToLower(filepath.Ext(a.FilePath)))); err == nil {
				_, _ = f.Write(data)
				audioCount++
			}
		}

		// 4. 视频：分块格式流式解密拷入；封面随后写入
		for i, v := range n.Videos {
			if f, err := zw.Create(fmt.Sprintf("videos/%s/video-%02d%s", n.ID, i+1, strings.ToLower(filepath.Ext(v.FilePath)))); err == nil {
				if err := privateStore.copyPrivateVideo(v.FilePath, f); err != nil {
					log.Printf("备份导出：视频读取失败 note=%s video=%s: %v", n.ID, v.ID, err)
				} else {
					videoCount++
				}
			}
			if v.PosterPath == "" {
				continue
			}
			if data, err := privateStore.readPrivateMedia(v.PosterPath); err != nil {
				log.Printf("备份导出：视频封面读取失败 note=%s video=%s: %v", n.ID, v.ID, err)
			} else if f, err := zw.Create(fmt.Sprintf("videos/%s/poster-%02d%s", n.ID, i+1, strings.ToLower(filepath.Ext(v.PosterPath)))); err == nil {
				_, _ = f.Write(data)
			}
		}
	}

	// 5. manifest.json 备份元信息
	if f, err := zw.Create("manifest.json"); err == nil {
		meta, _ := json.MarshalIndent(map[string]interface{}{
			"exported_at": time.Now().Format(time.RFC3339),
			"user":        session.Username,
			"notes":       noteCount,
			"images":      imgCount,
			"audio":       audioCount,
			"videos":      videoCount,
			"version":     1,
		}, "", "  ")
		_, _ = f.Write(meta)
	}

	privateStore.auditPrivate(r, session.Username, "private_note.export_all")
}
