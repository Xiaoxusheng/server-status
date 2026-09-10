package main

// 私人手记媒体云同步（OpenList/WebDAV → 移动云盘）。
// 设计铁律（docs/private-notes-cloud-impl-spec.md）：
//   1. 本地副本永不删除——云端只是副本，任何云端故障只影响带宽优化，不影响功能；
//   2. 读取链路失败必须在同请求内回退服务器解密路径（private_api.go privateImageCloudHandler）；
//   3. 视频本体（PVVIDEO1）不参与云同步与重加密；
//   4. CloudSync.Enabled=false 时所有入口直接短路，行为与未引入本特性完全一致。
//
// 直链链路：浏览器 → GET /api/private/notes/{id}/images/{iid}/cloud → 服务器调 OpenList
// /api/fs/get 拿 raw_url（移动云盘 CDN）→ 302 → 浏览器拉到 PVMEDIA2 密文 → WebCrypto 本地解密。
// OpenList 仅由服务器本机调用，无需公网暴露。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// davHTTPClient WebDAV 客户端：20MB 原图上行可能较慢，超时放宽到 90s
var davHTTPClient = &http.Client{Timeout: 90 * time.Second}

// openlistHTTPClient OpenList fs/get 仅本机调用，10s 足够
var openlistHTTPClient = &http.Client{Timeout: 10 * time.Second}

// cloudRetryBackoff 云端上传失败重试退避序列（5 次后放弃，等对账兜底）；
// 包级变量便于测试缩短等待
var cloudRetryBackoff = []time.Duration{2 * time.Second, 8 * time.Second, 32 * time.Second, 2 * time.Minute, 8 * time.Minute}

// cloudTask 一次云端操作（del=false 上传 / del=true 删除），以 rel（本地相对路径）为去重键
type cloudTask struct {
	rel string
	del bool
}

// cloudStatus 云同步队列计数（mutex 保护，供 /api/private/cloud/status 快照）
type cloudStatus struct {
	mu        sync.Mutex
	pending   int64
	uploaded  int64
	deleted   int64
	failed    int64
	lastErr   string
	lastErrAt time.Time
}

// inc 原子累加某计数（field: pending/uploaded/deleted/failed）
func (c *cloudStatus) inc(field string, delta int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch field {
	case "pending":
		c.pending += delta
	case "uploaded":
		c.uploaded += delta
	case "deleted":
		c.deleted += delta
	case "failed":
		c.failed += delta
	}
}

// recordErr 记录最近一次云同步错误（只存消息，绝不含密钥/raw_url 全文）
func (c *cloudStatus) recordErr(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = msg
	c.lastErrAt = time.Now()
}

// snapshot 状态快照（handler 输出用）
func (c *cloudStatus) snapshot() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"pending":    c.pending,
		"uploaded":   c.uploaded,
		"deleted":    c.deleted,
		"failed":     c.failed,
		"last_error": c.lastErr,
		"last_err_at": func() string {
			if c.lastErrAt.IsZero() {
				return ""
			}
			return c.lastErrAt.Format(time.RFC3339)
		}(),
	}
}

// reencryptStatus PVMEDIA1 → PVMEDIA2 重加密迁移进度
type reencryptStatus struct {
	running  bool
	scanned  int64
	migrated int64
	skipped  int64
	errors   int64
}

// snapshot 迁移进度快照
func (r *reencryptStatus) snapshot() map[string]interface{} {
	return map[string]interface{}{
		"running":  r.running,
		"scanned":  r.scanned,
		"migrated": r.migrated,
		"skipped":  r.skipped,
		"errors":   r.errors,
	}
}

// startCloudSync 云同步启用时启动单 worker 上传队列与周期对账（NewPrivateStore 末尾调用）。
// 单 worker 串行：移动云盘对高频并发 API 敏感，绝不并发上传
func (s *PrivateStore) startCloudSync() {
	if !s.config.CloudSync.Enabled {
		return
	}
	s.cloudQueue = make(chan cloudTask, 512)
	s.cloudInflight = make(map[string]bool)
	go s.cloudWorker()
	// 启动 2 分钟后首次对账（等待启动高峰过去），此后每 24h 一次；
	// 两者均带 recover，绝不让对账异常拖垮 store
	time.AfterFunc(2*time.Minute, func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("⚠️ 手记云同步对账 panic（已恢复）: %v", p)
			}
		}()
		s.reconcileCloud()
	})
	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("⚠️ 手记云同步对账循环 panic（已恢复）: %v", p)
			}
		}()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			s.reconcileCloud()
		}
	}()
	log.Printf("☁️ 手记媒体云同步已启用 remote=%s", s.config.CloudSync.RemoteDir)
}

// cloudWorker 单 worker：逐任务串行执行，任务异常 recover 防止拖死整个 store
func (s *PrivateStore) cloudWorker() {
	for task := range s.cloudQueue {
		s.runCloudTask(task)
	}
}

// runCloudTask 执行单个云任务（上传带重试退避；删除尽力而为一次），完成后清理 in-flight 标记
func (s *PrivateStore) runCloudTask(task cloudTask) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("⚠️ 手记云任务 panic（已恢复） rel=%s: %v", task.rel, p)
		}
		s.cloudStat.inc("pending", -1)
		s.cloudInflightMu.Lock()
		delete(s.cloudInflight, task.rel)
		s.cloudInflightMu.Unlock()
	}()
	if task.del {
		if err := s.davDelete(task.rel); err != nil {
			s.cloudStat.inc("failed", 1)
			s.cloudStat.recordErr("删除失败: " + err.Error())
			log.Printf("☁️ 手记云删除失败 %s: %v", task.rel, err)
			return
		}
		s.cloudStat.inc("deleted", 1)
		return
	}
	var lastErr error
	for i, back := range append([]time.Duration{0}, cloudRetryBackoff...) {
		if back > 0 {
			time.Sleep(back)
		}
		if err := s.davPut(task.rel); err == nil {
			s.cloudStat.inc("uploaded", 1)
			return
		} else {
			lastErr = err
			log.Printf("☁️ 手记云上传失败(第 %d/%d 次) %s: %v", i+1, len(cloudRetryBackoff)+1, task.rel, err)
		}
	}
	s.cloudStat.inc("failed", 1)
	s.cloudStat.recordErr("上传失败: " + lastErr.Error())
	log.Printf("⚠️ 手记云上传最终失败 %s: %v（等待对账兜底重传）", task.rel, lastErr)
}

// enqueueCloudUpload 原图入上传队列；未启用/队列满直接短路，绝不阻塞上传主流程
func (s *PrivateStore) enqueueCloudUpload(rel string) { s.enqueueCloudTask(rel, false) }

// enqueueCloudDelete 云端副本删除入队（尽力而为；未上传过云端会得到 404=成功）
func (s *PrivateStore) enqueueCloudDelete(rel string) { s.enqueueCloudTask(rel, true) }

// enqueueCloudTask 入队核心：in-flight 去重（同 rel 在队/执行中时丢弃新任务）+ 非阻塞投递
func (s *PrivateStore) enqueueCloudTask(rel string, del bool) {
	if !s.config.CloudSync.Enabled || s.cloudQueue == nil || rel == "" {
		return
	}
	s.cloudInflightMu.Lock()
	if s.cloudInflight[rel] {
		s.cloudInflightMu.Unlock()
		return
	}
	s.cloudInflight[rel] = true
	s.cloudInflightMu.Unlock()
	select {
	case s.cloudQueue <- cloudTask{rel: rel, del: del}:
		s.cloudStat.inc("pending", 1)
	default:
		// 队列满：放弃并释放预占（上传失败由对账兜底）
		s.cloudInflightMu.Lock()
		delete(s.cloudInflight, rel)
		s.cloudInflightMu.Unlock()
		s.cloudStat.recordErr("云同步队列已满，本次任务被丢弃")
		log.Printf("⚠️ 手记云同步队列已满，丢弃任务 rel=%s", rel)
	}
}

// reconcileCloud 对账：对全部手记原图逐个 HEAD 云端，缺失的重新入队（缩略图/语音/海报不在云上）。
// HEAD 网络错误时跳过该文件（避免网络抖动引发入队风暴），下轮对账再补
func (s *PrivateStore) reconcileCloud() {
	if !s.config.CloudSync.Enabled {
		return
	}
	rows, err := s.db.Query(`SELECT file_path FROM note_images`)
	if err != nil {
		log.Printf("⚠️ 手记云对账查询失败: %v", err)
		return
	}
	rels := make([]string, 0, 256)
	for rows.Next() {
		var rel string
		if rows.Scan(&rel) == nil && rel != "" {
			rels = append(rels, rel)
		}
	}
	rows.Close()
	missing := 0
	for _, rel := range rels {
		exists, err := s.davExists(rel)
		if err != nil {
			log.Printf("☁️ 手记云对账 HEAD 失败（跳过） %s: %v", rel, err)
			continue
		}
		if !exists {
			s.enqueueCloudUpload(rel)
			missing++
		}
	}
	if missing > 0 {
		log.Printf("☁️ 手记云对账完成：共 %d 张原图，缺失 %d 张已重新入队", len(rels), missing)
	}
}

// ==================== WebDAV 极简客户端（仅标准库） ====================

// percentEncodeSegments 对远程路径逐段做 URL 编码（云端目录名含中文/空格），空段跳过，结果以 / 开头
func percentEncodeSegments(p string) string {
	out := make([]string, 0, 8)
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			continue
		}
		out = append(out, url.PathEscape(seg))
	}
	return "/" + strings.Join(out, "/")
}

// davDo WebDAV 请求基础封装：Basic Auth + 期望状态码校验（非期望状态关闭 body 后报错）。
// relPath 相对 RemoteDir（可为空表示 RemoteDir 本身），完整路径 = RemoteDir + "/" + relPath
func davDo(cfg CloudSyncConfig, method, relPath string, body []byte, expect map[int]bool) (*http.Response, error) {
	return davRequest(cfg, method, cfg.RemoteDir+"/"+relPath, body, expect)
}

// davRequest WebDAV 请求底层封装：fullPath 为含 RemoteDir 的完整云端路径
func davRequest(cfg CloudSyncConfig, method, fullPath string, body []byte, expect map[int]bool) (*http.Response, error) {
	u := strings.TrimRight(cfg.DAVURL, "/") + percentEncodeSegments(fullPath)
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if cfg.DAVUser != "" || cfg.DAVPass != "" {
		req.SetBasicAuth(cfg.DAVUser, cfg.DAVPass)
	}
	resp, err := davHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if !expect[resp.StatusCode] {
		resp.Body.Close()
		return nil, fmt.Errorf("WebDAV %s %s 返回 %d", method, fullPath, resp.StatusCode)
	}
	return resp, nil
}

// davMkdirAll 对完整云端路径（含 RemoteDir）逐段 MKCOL 建目录，从首个段开始逐级创建
// （与 deploy/pv-backup.sh 行为一致）；405/301 视为已存在
func davMkdirAll(cfg CloudSyncConfig, fullPath string) error {
	cur := ""
	for _, seg := range strings.Split(fullPath, "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		resp, err := davRequest(cfg, "MKCOL", cur, nil, map[int]bool{201: true, 405: true, 301: true})
		if err != nil {
			return err
		}
		resp.Body.Close()
	}
	return nil
}

// davPut 读取本地原图并 PUT 到云端（目录逐级创建）
func (s *PrivateStore) davPut(rel string) error {
	cfg := s.config.CloudSync
	abs, err := s.safeFilePath(rel)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	relDir := rel[:strings.LastIndex(rel, "/")+1]
	if err := davMkdirAll(cfg, cfg.RemoteDir+"/"+relDir); err != nil {
		return fmt.Errorf("建目录失败: %w", err)
	}
	resp, err := davDo(cfg, "PUT", rel, data, map[int]bool{200: true, 201: true, 204: true})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// davPutWithRetry 带指数退避重试的上传：最多 1+5 次（退避 2s/8s/32s/2m/8m），全部失败返回最后一次错误
func (s *PrivateStore) davPutWithRetry(rel string) error {
	var lastErr error
	for i, back := range append([]time.Duration{0}, cloudRetryBackoff...) {
		if back > 0 {
			time.Sleep(back)
		}
		if err := s.davPut(rel); err == nil {
			return nil
		} else {
			lastErr = err
			log.Printf("☁️ 手记云上传失败(第 %d/%d 次) %s: %v", i+1, len(cloudRetryBackoff)+1, rel, err)
		}
	}
	return lastErr
}

// davDelete 删除云端副本；404 视为成功（云端本没有）
func (s *PrivateStore) davDelete(rel string) error {
	resp, err := davDo(s.config.CloudSync, "DELETE", rel, nil, map[int]bool{200: true, 204: true, 404: true})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// davExists HEAD 探测云端副本是否存在；非 200/404 的状态按错误处理（对账跳过）
func (s *PrivateStore) davExists(rel string) (bool, error) {
	resp, err := davDo(s.config.CloudSync, "HEAD", rel, nil, map[int]bool{200: true, 404: true})
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ==================== OpenList 直链客户端 ====================

// openlistRawURL 调 OpenList POST /api/fs/get 换取网盘 CDN 直链（raw_url 有时效）。
// fs/get 的 path 是 JSON 字段，不做 URL 编码；link_mode 仅实现 server_get。
// 响应只截断记日志，raw_url 全文绝不落日志
func openlistRawURL(cfg CloudSyncConfig, relPath string) (string, error) {
	if !strings.EqualFold(cfg.LinkMode, "server_get") {
		return "", fmt.Errorf("不支持的直链模式: %s", cfg.LinkMode)
	}
	body, _ := json.Marshal(map[string]string{"path": strings.TrimRight(cfg.RemoteDir, "/") + "/" + relPath})
	req, err := http.NewRequest("POST", strings.TrimRight(cfg.OpenlistAPI, "/")+"/api/fs/get", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", cfg.OpenlistToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := openlistHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var out struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			RawURL string `json:"raw_url"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("fs/get 响应解析失败: %w", err)
	}
	if out.Code != 200 || out.Data.RawURL == "" {
		return "", fmt.Errorf("fs/get 失败 code=%d msg=%s resp=%.200s", out.Code, out.Message, string(raw))
	}
	return out.Data.RawURL, nil
}

// ==================== PVMEDIA1 → PVMEDIA2 重加密迁移 ====================

// startMediaReencrypt 触发后台重加密迁移（幂等：已在运行返回 false，不自动执行，仅管理接口触发）。
// 迁移范围：手记原图 / 语音 / 视频海报 / 卡片 PNG；视频本体（PVVIDEO1）绝不触碰。
// 迁移成功的原图（云同步启用时）重新入队覆盖云端旧密文
func (s *PrivateStore) startMediaReencrypt() bool {
	s.reencMu.Lock()
	defer s.reencMu.Unlock()
	if s.reenc.running {
		return false
	}
	s.reenc = reencryptStatus{running: true}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Printf("⚠️ 手记媒体重加密 panic（已恢复）: %v", p)
				s.reencMu.Lock()
				s.reenc.running = false
				s.reenc.errors++
				s.reencMu.Unlock()
			}
		}()
		s.runMediaReencrypt()
	}()
	return true
}

// reencryptCandidates 枚举全部待迁移文件（均带属主）：
// 图片 / 语音按 note 关联取 user_id；视频只取海报（poster_path，不含 file_path）；卡片自带 user_id
func (s *PrivateStore) reencryptCandidates() [][2]string {
	var out [][2]string
	queries := []string{
		`SELECT ni.file_path, n.user_id FROM note_images ni JOIN notes n ON n.id = ni.note_id`,
		`SELECT na.file_path, n.user_id FROM note_audio na JOIN notes n ON n.id = na.note_id`,
		`SELECT nv.poster_path, n.user_id FROM note_videos nv JOIN notes n ON n.id = nv.note_id WHERE nv.poster_path != ''`,
		`SELECT file_path, user_id FROM note_cards`,
	}
	for _, q := range queries {
		rows, err := s.db.Query(q)
		if err != nil {
			log.Printf("⚠️ 重加密迁移枚举查询失败: %v", err)
			continue
		}
		for rows.Next() {
			var rel, user string
			if rows.Scan(&rel, &user) == nil && rel != "" && user != "" {
				out = append(out, [2]string{rel, user})
			}
		}
		rows.Close()
	}
	return out
}

// runMediaReencrypt 执行迁移：PVMEDIA1 → 解密 → per-user 重加密 → 临时文件 + 原子替换；
// 纯明文直接 per-user 加密；已是 PVMEDIA2 或其他加密格式计 skipped（幂等，可重复执行）
func (s *PrivateStore) runMediaReencrypt() {
	start := time.Now()
	candidates := s.reencryptCandidates()
	s.reencMu.Lock()
	s.reenc.scanned = int64(len(candidates))
	s.reencMu.Unlock()
	for _, c := range candidates {
		rel, owner := c[0], c[1]
		abs, err := s.safeFilePath(rel)
		if err != nil {
			s.bumpReencErr()
			continue
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			s.bumpReencErr()
			continue
		}
		// 已是 PVMEDIA2 或其他加密格式（如 PVVIDEO1 误入列表）：跳过不动
		if bytes.HasPrefix(raw, mediaCryptMagic2) || (isMediaEncrypted(raw) && !bytes.HasPrefix(raw, mediaCryptMagic)) {
			s.bumpReencSkip()
			continue
		}
		plain, err := s.decryptMediaBytes(raw)
		if err != nil {
			log.Printf("⚠️ 重加密解密失败 %s: %v", rel, err)
			s.bumpReencErr()
			continue
		}
		enc, err := s.encryptMediaBytesFor(owner, plain)
		if err != nil {
			log.Printf("⚠️ 重加密加密失败 %s: %v", rel, err)
			s.bumpReencErr()
			continue
		}
		// 同目录临时文件 + Rename 原子替换，中断不留半个损坏文件
		tmp := abs + ".reenc.tmp"
		if err := os.WriteFile(tmp, enc, 0644); err != nil {
			s.bumpReencErr()
			continue
		}
		if err := os.Rename(tmp, abs); err != nil {
			os.Remove(tmp)
			s.bumpReencErr()
			continue
		}
		s.bumpReencMigrated()
		// 云同步启用时重新入队覆盖云端旧密文（旧密文仍可解但失去直链价值）
		if bytes.HasPrefix(raw, mediaCryptMagic) {
			s.enqueueCloudUpload(rel)
		}
	}
	s.reencMu.Lock()
	s.reenc.running = false
	s.reencMu.Unlock()
	log.Printf("🔐 手记媒体重加密迁移完成：扫描 %d，迁移 %d，跳过 %d，失败 %d，耗时 %s",
		s.reenc.scanned, s.reenc.migrated, s.reenc.skipped, s.reenc.errors, time.Since(start).Round(time.Millisecond))
}

// bumpReenc 系列更新迁移计数（短临界区）
func (s *PrivateStore) bumpReencSkip() {
	s.reencMu.Lock()
	s.reenc.skipped++
	s.reencMu.Unlock()
}
func (s *PrivateStore) bumpReencMigrated() {
	s.reencMu.Lock()
	s.reenc.migrated++
	s.reencMu.Unlock()
}
func (s *PrivateStore) bumpReencErr() {
	s.reencMu.Lock()
	s.reenc.errors++
	s.reencMu.Unlock()
}

// cloudSyncSnapshot 云同步与重加密状态快照（/api/private/cloud/status 输出）
func (s *PrivateStore) cloudSyncSnapshot() map[string]interface{} {
	s.reencMu.Lock()
	re := s.reenc.snapshot()
	s.reencMu.Unlock()
	return map[string]interface{}{
		"enabled":   s.config.CloudSync.Enabled,
		"queue":     s.cloudStat.snapshot(),
		"reencrypt": re,
	}
}
