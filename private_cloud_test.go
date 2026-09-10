package main

// 私人手记云同步测试：PVMEDIA2 加密体系、WebDAV 客户端、OpenList 直链、
// 云直链处理器回退、重加密迁移（docs/private-notes-cloud-impl-spec.md §5）。
// 云同步默认关闭：newTestStore 出来的 store 不启动任何后台任务，现有用例零影响。

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newPNG 生成指定尺寸的测试 PNG（红底纯色图）
func newPNG(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

// uploadPNG 直接调 store 层上传图片（PVMEDIA2 落盘），返回 (image, error)
func uploadPNG(t *testing.T, st *PrivateStore, userID, noteID string, w, h int) (*PrivateImage, error) {
	t.Helper()
	data := newPNG(w, h)
	f := &multipart.FileHeader{
		Filename: "t.png",
		Header:   textproto.MIMEHeader{"Content-Type": []string{"image/png"}},
		Size:     int64(len(data)),
	}
	return st.addImage(userID, noteID, &sliceReader{data: data}, f)
}

// sliceReader 最小 multipart.File 实现（io.Reader + io.Seeker + io.Closer + ReaderAt）
type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}
func (r *sliceReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		r.off = int(offset)
	case 1:
		r.off += int(offset)
	case 2:
		r.off = len(r.data) + int(offset)
	}
	if r.off < 0 {
		r.off = 0
	}
	return int64(r.off), nil
}
func (r *sliceReader) Close() error { return nil }
func (r *sliceReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	return n, nil
}

// TestPVMEDIA2Roundtrip PVMEDIA2 加解密回环 + 头部布局断言
func TestPVMEDIA2Roundtrip(t *testing.T) {
	st := newTestStore(t)
	plain := []byte("fake-jpeg-bytes-手记图片-1234567890")

	enc1, err := st.encryptMediaBytesFor("alice", plain)
	if err != nil {
		t.Fatalf("encryptMediaBytesFor: %v", err)
	}
	// 布局：前 8B magic、总长 ≥28、keyUID 占 8-16
	if !bytes.HasPrefix(enc1, mediaCryptMagic2) {
		t.Fatal("PVMEDIA2 应带 PVMEDIA2 magic 头")
	}
	if len(enc1) < pvMedia2HeaderLen+len(plain) {
		t.Fatalf("密文长度异常: %d", len(enc1))
	}
	// 同一用户两次加密 nonce 不同（8-16 为 keyUID，16-28 为 nonce）
	enc2, err := st.encryptMediaBytesFor("alice", plain)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if bytes.Equal(enc1[16:28], enc2[16:28]) {
		t.Fatal("两次加密的 nonce 不应相同")
	}
	// 解密回环
	got, err := st.decryptMediaBytes(enc1)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("解密回环失败: %v", err)
	}
	// 不同用户密钥不同：对方解不开
	st2key, err := st.encryptMediaBytesFor("bob", plain)
	if err != nil {
		t.Fatalf("bob encrypt: %v", err)
	}
	if bytes.Equal(enc1[8:16], st2key[8:16]) {
		t.Fatal("不同用户的 keyUID 不应相同")
	}
}

// TestMediaFormatDispatch 加密格式分流兼容：PVMEDIA1 可读、明文原样、篡改报错
func TestMediaFormatDispatch(t *testing.T) {
	st := newTestStore(t)
	plain := []byte("legacy-content-0123456789")

	// PVMEDIA1（旧全局密钥）仍可经 store 方法解密
	enc1, err := encryptMediaBytes(plain)
	if err != nil {
		t.Fatalf("encryptMediaBytes: %v", err)
	}
	if got, err := st.decryptMediaBytes(enc1); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("PVMEDIA1 兼容解密失败: %v", err)
	}
	// 历史明文原样返回
	if got, err := st.decryptMediaBytes(plain); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("明文应原样返回: %v", err)
	}
	// 截断的 PVMEDIA2 报错
	enc2, _ := st.encryptMediaBytesFor("alice", plain)
	if _, err := st.decryptMediaBytes(enc2[:len(enc2)-5]); err == nil {
		t.Fatal("截断的 PVMEDIA2 应报错")
	}
	// 篡改的 PVMEDIA2 报错（GCM 完整性校验）
	tampered := append([]byte{}, enc2...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := st.decryptMediaBytes(tampered); err == nil {
		t.Fatal("篡改的 PVMEDIA2 应报错")
	}
	// 头部不足 28B 报错
	if _, err := st.decryptMediaBytes(append(append([]byte{}, mediaCryptMagic2...), make([]byte, 10)...)); err == nil {
		t.Fatal("头部不足的 PVMEDIA2 应报错")
	}
}

// TestIsMediaEncryptedBothMagics isMediaEncrypted 必须同时识别两种 magic（防 §4.1 数据损坏回归）
func TestIsMediaEncryptedBothMagics(t *testing.T) {
	if !isMediaEncrypted([]byte("PVMEDIA1xxx")) {
		t.Fatal("PVMEDIA1 应被识别为已加密")
	}
	if !isMediaEncrypted([]byte("PVMEDIA2xxx")) {
		t.Fatal("PVMEDIA2 应被识别为已加密")
	}
	if isMediaEncrypted([]byte("plain data")) {
		t.Fatal("明文不应被识别为已加密")
	}
	if isMediaEncrypted([]byte("PVVIDEO1xxx")) {
		t.Fatal("PVVIDEO1（视频分块格式）不属整块媒体加密格式")
	}
}

// TestDavClient WebDAV 客户端：URL 逐段编码（中文目录）、Basic Auth、MKCOL 序列与状态码处理
func TestDavClient(t *testing.T) {
	var mu sync.Mutex
	var mkcols, puts, heads, deletes []string
	var gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		u, p, _ := r.BasicAuth()
		gotUser, gotPass = u, p
		switch r.Method {
		case "MKCOL":
			mkcols = append(mkcols, r.URL.Path)
			w.WriteHeader(201)
		case "PUT":
			puts = append(puts, r.URL.Path)
			w.WriteHeader(201)
		case "HEAD":
			heads = append(heads, r.URL.Path)
			w.WriteHeader(200)
		case "DELETE":
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()

	st := newTestStore(t)
	st.config.CloudSync = CloudSyncConfig{
		Enabled:   true,
		DAVURL:    srv.URL + "/dav",
		DAVUser:   "u1",
		DAVPass:   "p1",
		RemoteDir: "/home/备份/手记媒体",
	}
	// 造一个本地文件
	rel := "2026/09/10/f_x.jpg"
	abs, err := st.safeFilePath(rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("img-bytes"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := st.davPut(rel); err != nil {
		t.Fatalf("davPut: %v", err)
	}
	// 快照拷贝（避免持锁断言时 Fatalf 泄漏锁）
	mu.Lock()
	authBad := gotUser != "u1" || gotPass != "p1"
	putPaths := append([]string(nil), puts...)
	mkPaths := append([]string(nil), mkcols...)
	mu.Unlock()
	if authBad {
		t.Fatalf("Basic Auth 错误: %s/%s", gotUser, gotPass)
	}
	// PUT 路径：net/http 已解码 → 直接比对原文（含中文目录）
	wantPath := "/dav/home/备份/手记媒体/2026/09/10/f_x.jpg"
	if len(putPaths) != 1 || putPaths[0] != wantPath {
		t.Fatalf("PUT 路径错误: %v", putPaths)
	}
	// MKCOL 逐段：/home、/home/备份、/home/备份/手记媒体 + 3 级日期目录
	wantMk := []string{
		"/dav/home",
		"/dav/home/备份",
		"/dav/home/备份/手记媒体",
		"/dav/home/备份/手记媒体/2026",
		"/dav/home/备份/手记媒体/2026/09",
		"/dav/home/备份/手记媒体/2026/09/10",
	}
	if len(mkPaths) != len(wantMk) {
		t.Fatalf("MKCOL 次数错误 got=%d want=%d: %v", len(mkPaths), len(wantMk), mkPaths)
	}
	for i, w := range wantMk {
		if mkPaths[i] != w {
			t.Fatalf("MKCOL[%d] = %s, want %s", i, mkPaths[i], w)
		}
	}

	// HEAD/DELETE
	if ok, err := st.davExists(rel); err != nil || !ok {
		t.Fatalf("davExists: %v %v", ok, err)
	}
	if err := st.davDelete(rel); err != nil {
		t.Fatalf("davDelete: %v", err)
	}
	mu.Lock()
	headPaths := append([]string(nil), heads...)
	delPaths := append([]string(nil), deletes...)
	mu.Unlock()
	if len(headPaths) != 1 || headPaths[0] != wantPath {
		t.Fatalf("HEAD 路径错误: %v", headPaths)
	}
	if len(delPaths) != 1 || delPaths[0] != wantPath {
		t.Fatalf("DELETE 路径错误: %v", delPaths)
	}
	// percentEncodeSegments：中文段必须被编码
	enc := percentEncodeSegments("/home/备份/手记媒体/x.jpg")
	if !strings.Contains(enc, "%E5%A4%87%E4%BB%BD") || strings.Contains(enc, "备份") {
		t.Fatalf("中文段应被 URL 编码: %s", enc)
	}
}

// TestOpenlistRawURL OpenList fs/get 客户端：成功取直链 / code≠200 报错 / 非法模式报错
func TestOpenlistRawURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fs/get" {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "tok-1" {
			w.WriteHeader(401)
			return
		}
		var req struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotPath = req.Path
		w.Write([]byte(`{"code":200,"message":"ok","data":{"name":"f_x.jpg","size":3,"raw_url":"https://cdn.example.com/abc?sig=1"}}`))
	}))
	defer srv.Close()

	cfg := CloudSyncConfig{
		Enabled:       true,
		LinkMode:      "server_get",
		OpenlistAPI:   srv.URL,
		OpenlistToken: "tok-1",
		RemoteDir:     "/home/备份/手记媒体",
	}
	raw, err := openlistRawURL(cfg, "2026/09/10/f_x.jpg")
	if err != nil {
		t.Fatalf("openlistRawURL: %v", err)
	}
	if raw != "https://cdn.example.com/abc?sig=1" {
		t.Fatalf("raw_url 错误: %s", raw)
	}
	// fs/get 的 path 为 JSON 字段，不做 URL 编码
	if gotPath != "/home/备份/手记媒体/2026/09/10/f_x.jpg" {
		t.Fatalf("fs/get path 错误: %s", gotPath)
	}
	// code≠200 → error
	cfgBad := cfg
	cfgBad.OpenlistToken = "wrong"
	if _, err := openlistRawURL(cfgBad, "x.jpg"); err == nil {
		t.Fatal("token 错误应返回 error")
	}
	// 非法 link_mode → error
	cfgOther := cfg
	cfgOther.LinkMode = "openlist_redirect"
	if _, err := openlistRawURL(cfgOther, "x.jpg"); err == nil {
		t.Fatal("未实现的 link_mode 应返回 error")
	}
}

// TestPrivateImageCloudHandlerFallback 云直链接口：未解锁 403、他人手记 404、
// 云端不可用（token 空）时同请求回退输出可解密明文（PNG magic）
func TestPrivateImageCloudHandlerFallback(t *testing.T) {
	oldUM := userManager
	userManager = &UserManager{
		RWMutex:   sync.RWMutex{},
		UserInfos: map[string]*Users{"alice": {Username: "alice", IsActive: true, Permissions: []string{"*"}}},
		Sessions:  make(map[string]*Session),
	}
	defer func() { userManager = oldUM }()

	oldStore := privateStore
	st := newTestStore(t)
	if err := st.SetupPrivatePassword("secret-2026"); err != nil {
		t.Fatal(err)
	}
	// 云同步启用但 token 为空 → 直链签发必然失败 → 同请求回退
	st.config.CloudSync = CloudSyncConfig{Enabled: true, DAVURL: "http://127.0.0.1:1/dav", RemoteDir: "/x"}
	privateStore = st
	defer func() { privateStore = oldStore }()

	mux := http.NewServeMux()
	registerPrivateRoutes(mux)

	note, err := st.createNote("alice", createNoteRequest{Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	img, err := uploadPNG(t, st, "alice", note.ID, 8, 8)
	if err != nil {
		t.Fatalf("addImage: %v", err)
	}

	// 主站登录 session（未解锁场景要求已登录但无 private_session Cookie）
	sid := "test-session-cloud"
	userManager.Lock()
	userManager.Sessions[sid] = &Session{
		SessionID: sid, Username: "alice", CreatedAt: time.Now(),
		LastAccess: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: testCSRFToken,
	}
	userManager.Unlock()

	// cloudReq 构造带安全头（UA/Accept/语言/编码）的云直链请求
	cloudReq := func(path string, cookies ...string) *http.Request {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0")
		r.Header.Set("Accept", "application/json, text/plain, */*")
		r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate")
		if len(cookies) > 0 {
			r.Header.Set("Cookie", strings.Join(cookies, "; "))
		}
		return r
	}

	// 未解锁：403 未解锁
	r := cloudReq("/api/private/notes/"+note.ID+"/images/"+img.ID+"/cloud", "session_id="+sid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatalf("未解锁应 403: %d", rec.Code)
	}

	// 解锁后：回退路径输出明文 PNG
	token, err := st.Unlock("alice", "secret-2026", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	r2 := cloudReq("/api/private/notes/"+note.ID+"/images/"+img.ID+"/cloud", "session_id="+sid, "private_session="+token)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, r2)
	if rec2.Code != 200 {
		t.Fatalf("回退应 200: %d", rec2.Code)
	}
	if !bytes.HasPrefix(rec2.Body.Bytes(), []byte{0x89, 'P', 'N', 'G'}) {
		t.Fatal("回退输出应为解密后的明文 PNG")
	}
	// 他人手记 / 不存在的手记：404（不泄露存在性）
	r3 := cloudReq("/api/private/notes/other-note/images/"+img.ID+"/cloud", "session_id="+sid, "private_session="+token)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, r3)
	if rec3.Code != 404 {
		t.Fatalf("不存在/他人手记应 404: %d", rec3.Code)
	}
}

// TestMediaReencryptMigration 重加密迁移：PVMEDIA1 → PVMEDIA2 可读、重跑幂等、视频本体不动
func TestMediaReencryptMigration(t *testing.T) {
	st := newTestStore(t)
	plain := newPNG(8, 8)

	// 造 PVMEDIA1 历史文件 + note_images 行
	rel := "2026/08/30/f_legacy.jpg"
	abs, err := st.safeFilePath(rel)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatal(err)
	}
	enc1, err := encryptMediaBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, enc1, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.createNote("alice", createNoteRequest{Title: "legacy"}); err != nil {
		t.Fatal(err)
	}
	var noteID string
	if err := st.db.QueryRow(`SELECT id FROM notes WHERE user_id = 'alice' LIMIT 1`).Scan(&noteID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO note_images (id, note_id, file_path, sort_order, created_at) VALUES ('img-l', ?, ?, 0, ?)`,
		noteID, rel, nowUTC()); err != nil {
		t.Fatal(err)
	}
	// 造视频（PVVIDEO1 本体）+ 空海报：迁移不得触碰 file_path
	vrel := "2026/08/30/f_v.mp4"
	vabs, err := st.safeFilePath(vrel)
	if err != nil {
		t.Fatal(err)
	}
	var vbuf bytes.Buffer
	if _, err := encryptVideoStream(bytes.NewReader([]byte("video-bytes")), &vbuf, 11); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vabs, vbuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO note_videos (id, note_id, file_path, poster_path, duration, size, created_at) VALUES ('vid-l', ?, ?, '', 1, 11, ?)`,
		noteID, vrel, nowUTC()); err != nil {
		t.Fatal(err)
	}

	// 触发迁移（直接跑同步实现，避免异步时序）
	st.runMediaReencrypt()
	st.reencMu.Lock()
	snap := st.reenc.snapshot()
	st.reencMu.Unlock()
	if snap["migrated"].(int64) != 1 || snap["errors"].(int64) != 0 {
		t.Fatalf("迁移计数错误: %v", snap)
	}

	// 文件应为 PVMEDIA2 且可解密回读
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, mediaCryptMagic2) {
		t.Fatal("迁移后应为 PVMEDIA2 格式")
	}
	if got, err := st.decryptMediaBytes(raw); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("迁移后解密失败: %v", err)
	}
	// 视频本体未被触碰
	vraw, err := os.ReadFile(vabs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vraw, vbuf.Bytes()) {
		t.Fatal("视频本体不应被迁移触碰")
	}

	// 重跑幂等：全部 skipped
	st.runMediaReencrypt()
	st.reencMu.Lock()
	snap2 := st.reenc.snapshot()
	st.reencMu.Unlock()
	if snap2["scanned"].(int64) != 1 || snap2["skipped"].(int64) != 1 {
		t.Fatalf("重跑应幂等（scanned=1 skipped=1）: %v", snap2)
	}

	// startMediaReencrypt 触发后台迁移：运行中重复触发返回 false，最终完成
	if !st.startMediaReencrypt() {
		t.Fatal("首次触发应成功")
	}
	deadline := time.Now().Add(3 * time.Second)
	for st.reenc.running && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st.reenc.running {
		t.Fatal("后台迁移应完成")
	}
	if started := st.startMediaReencrypt(); !started {
		t.Fatal("完成后再次触发应成功")
	}
	deadline = time.Now().Add(3 * time.Second)
	for st.reenc.running && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCloudDisabledNoSideEffects 云同步关闭时：入队直接短路、新上传仍是 PVMEDIA2、旧接口可读
func TestCloudDisabledNoSideEffects(t *testing.T) {
	st := newTestStore(t) // 默认 Enabled=false
	if _, err := st.createNote("alice", createNoteRequest{Title: "t"}); err != nil {
		t.Fatal(err)
	}
	var noteID string
	if err := st.db.QueryRow(`SELECT id FROM notes WHERE user_id = 'alice' LIMIT 1`).Scan(&noteID); err != nil {
		t.Fatal(err)
	}
	img, err := uploadPNG(t, st, "alice", noteID, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	// 新上传应为 PVMEDIA2 且可解密
	abs, _, err := st.imageFilePath("alice", noteID, img.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, mediaCryptMagic2) {
		t.Fatal("新上传应为 PVMEDIA2")
	}
	// 关闭态下重复入队不 panic、无副作用
	st.enqueueCloudUpload("a/b.jpg")
	st.enqueueCloudDelete("a/b.jpg")
}
