package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *PrivateStore {
	t.Helper()
	st, err := NewPrivateStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewPrivateStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestVideoChunkedCryptoRoundTrip 验证视频分块加密格式：整读一致 + 随机 Seek 读取与原文对齐
func TestVideoChunkedCryptoRoundTrip(t *testing.T) {
	// 2.5 个块：覆盖整块与不足块的末块
	plain := make([]byte, videoChunkSize*2+videoChunkSize/2)
	for i := range plain {
		plain[i] = byte(i % 251)
	}
	encBuf := &bytes.Buffer{}
	if _, err := encryptVideoStream(bytes.NewReader(plain), encBuf, int64(len(plain))); err != nil {
		t.Fatalf("encryptVideoStream: %v", err)
	}

	// 落盘后用读取器整读，必须与原文一致
	enc := encBuf.Bytes()
	vr, err := openVideoReaderFile(t, enc)
	if err != nil {
		t.Fatalf("openVideoReader: %v", err)
	}
	defer vr.Close()
	got := &bytes.Buffer{}
	if _, err := io.Copy(got, vr); err != nil {
		t.Fatalf("full read: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plain) {
		t.Fatalf("整读结果与原文不一致")
	}

	// 随机 Seek：模拟 Range 请求的多段读取
	cs := int64(videoChunkSize)
	offsets := []int64{0, 17, cs - 5, cs, cs + 123, int64(len(plain)) - 7}
	for _, off := range offsets {
		if _, err := vr.Seek(off, io.SeekStart); err != nil {
			t.Fatalf("Seek(%d): %v", off, err)
		}
		want := plain[off:]
		gotChunk := make([]byte, len(want))
		n, err := io.ReadFull(vr, gotChunk)
		if err != nil {
			t.Fatalf("read at %d: %v", off, err)
		}
		if n != len(want) || !bytes.Equal(gotChunk, want) {
			t.Fatalf("偏移 %d 处读取内容不一致", off)
		}
	}

	// SeekEnd：明文总长
	if n, _ := vr.Seek(0, io.SeekEnd); n != int64(len(plain)) {
		t.Fatalf("SeekEnd = %d, want %d", n, len(plain))
	}
}

// openVideoReaderFile 将加密字节写入临时文件后打开读取器（openVideoReader 以文件为输入）
func openVideoReaderFile(t *testing.T, enc []byte) (*videoReader, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v.bin")
	if err := os.WriteFile(p, enc, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return openVideoReader(p)
}

// TestVideoFFmpegMetaFallback 验证服务器端兜底：加密视频 → ffmpeg 抽帧 + ffprobe 时长（本机/服务器需有 ffmpeg，缺失则跳过）
func TestVideoFFmpegMetaFallback(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg 不可用，跳过")
	}
	if _, err := exec.LookPath("ffprobe"); err != nil {
		t.Skip("ffprobe 不可用，跳过")
	}
	// 用 ffmpeg 生成 2 秒测试视频（testsrc 彩条）
	src := filepath.Join(t.TempDir(), "src.mp4")
	if err := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=2:size=1280x720:rate=30",
		"-pix_fmt", "yuv420p", "-y", src).Run(); err != nil {
		t.Fatalf("生成测试视频失败: %v", err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}

	// 加密为 PVVIDEO1 格式
	enc := &bytes.Buffer{}
	if _, err := encryptVideoStream(bytes.NewReader(raw), enc, int64(len(raw))); err != nil {
		t.Fatalf("encryptVideoStream: %v", err)
	}
	encFile := filepath.Join(t.TempDir(), "enc.bin")
	if err := os.WriteFile(encFile, enc.Bytes(), 0644); err != nil {
		t.Fatalf("write enc: %v", err)
	}

	duration, poster, err := extractVideoMetaWithFFmpeg(encFile)
	if err != nil {
		t.Fatalf("extractVideoMetaWithFFmpeg: %v", err)
	}
	if duration < 1.5 || duration > 2.5 {
		t.Fatalf("时长异常: %v", duration)
	}
	if len(poster) == 0 {
		t.Fatalf("未抽取到封面")
	}
	// 封面应为有效 JPEG（FFD8 开头）
	if len(poster) < 3 || poster[0] != 0xFF || poster[1] != 0xD8 {
		t.Fatalf("封面不是有效 JPEG")
	}
}

func TestPrivatePasswordAndUnlock(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetupPrivatePassword("my-secret"); err != nil {
		t.Fatalf("SetupPrivatePassword: %v", err)
	}
	// 重复设置应失败
	if err := st.SetupPrivatePassword("other"); err == nil {
		t.Fatal("重复设置密码应失败")
	}
	// 错误密码
	if _, err := st.Unlock("admin", "wrong", "127.0.0.1"); err == nil {
		t.Fatal("错误密码应解锁失败")
	}
	// 正确密码
	token, err := st.Unlock("admin", "my-secret", "127.0.0.1")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if token == "" {
		t.Fatal("token 不应为空")
	}
	if ps, ok := st.ValidateSession("admin", token); !ok || ps.UserID != "admin" {
		t.Fatal("session 应有效")
	}
	if _, ok := st.ValidateSession("other", token); ok {
		t.Fatal("其他用户不应通过验证")
	}
	st.Lock("admin", token)
	if _, ok := st.ValidateSession("admin", token); ok {
		t.Fatal("锁定后 session 应失效")
	}
}

func TestPrivateUnlockLockout(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetupPrivatePassword("secret123"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := st.Unlock("admin", "bad", "10.0.0.1"); err == nil {
			t.Fatalf("第 %d 次错误密码应失败", i+1)
		}
	}
	if _, err := st.Unlock("admin", "secret123", "10.0.0.1"); err != privateErrLocked {
		t.Fatalf("锁定期间应返回 privateErrLocked, got %v", err)
	}
	// 其他 IP 不受影响
	if _, err := st.Unlock("admin", "secret123", "10.0.0.2"); err != nil {
		t.Fatalf("其他 IP 不应被锁定: %v", err)
	}
}

func TestPrivateSessionExpiry(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetupPrivatePassword("secret123"); err != nil {
		t.Fatal(err)
	}
	token, err := st.Unlock("admin", "secret123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 31 分钟无操作
	old := time.Now().UTC().Add(-31 * time.Minute).Format(time.RFC3339)
	if _, err := st.db.Exec(`UPDATE private_note_sessions SET last_access_at = ?`, old); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.ValidateSession("admin", token); ok {
		t.Fatal("无操作超过 30 分钟应自动锁定")
	}
}

func TestPrivateNotesCRUD(t *testing.T) {
	st := newTestStore(t)
	lat := 35.6812
	lng := 139.7671
	note, err := st.createNote("alice", createNoteRequest{
		Title: "东京出差", Content: "今天去东京站办事。", LocationName: "东京站",
		Latitude: &lat, Longitude: &lng, Tags: []string{"生活", "东京"},
	})
	if err != nil {
		t.Fatalf("createNote: %v", err)
	}
	if len(note.Tags) != 2 || note.LocationName != "东京站" {
		t.Fatalf("标签/位置未保存: %+v", note)
	}
	got, err := st.getNote("alice", note.ID)
	if err != nil || got.Title != "东京出差" {
		t.Fatalf("getNote: %v %+v", err, got)
	}
	// 其他用户不可见
	if _, err := st.getNote("bob", note.ID); err == nil {
		t.Fatal("其他用户不应读取到该手记")
	}
	// 更新
	upd, err := st.updateNote("alice", note.ID, createNoteRequest{
		Title: "东京出差（已改）", Content: "更新内容", Tags: []string{"工作"},
	})
	if err != nil {
		t.Fatalf("updateNote: %v", err)
	}
	if upd.Title != "东京出差（已改）" || len(upd.Tags) != 1 || upd.Tags[0] != "工作" {
		t.Fatalf("更新失败: %+v", upd)
	}
	// 搜索
	results, err := st.listNotes("alice", "", "东京")
	if err != nil || len(results) != 1 {
		t.Fatalf("搜索失败: %v %d", err, len(results))
	}
	// 标签过滤
	tagged, err := st.listNotes("alice", "工作", "")
	if err != nil || len(tagged) != 1 {
		t.Fatalf("标签过滤失败: %v %d", err, len(tagged))
	}
	// 导出
	md, err := st.exportNoteMarkdown("alice", note.ID, "https://example.com")
	if err != nil || !strings.Contains(md, "东京出差（已改）") {
		t.Fatalf("导出失败: %v", err)
	}
	// 删除
	if err := st.deleteNote("alice", note.ID); err != nil {
		t.Fatalf("deleteNote: %v", err)
	}
	if _, err := st.getNote("alice", note.ID); err == nil {
		t.Fatal("删除后不应再存在")
	}
}

func TestPrivatePathSafety(t *testing.T) {
	st := newTestStore(t)
	for _, p := range []string{"../evil.txt", "../../etc/passwd", "a/../../b", "..\\..\\win.ini"} {
		if _, err := st.safeFilePath(p); err == nil {
			t.Fatalf("路径穿越应被拒绝: %s", p)
		}
	}
	abs, err := st.safeFilePath("2026/08/17/abc.jpg")
	if err != nil {
		t.Fatalf("合法路径被拒绝: %v", err)
	}
	base, _ := filepath.Abs(st.storageDir)
	if !strings.HasPrefix(abs, base) {
		t.Fatalf("路径越界: %s", abs)
	}
}

// TestImageThumbGeneration 验证缩略图链路：上传即生成持久缩略图（最长边 480，不放大小图）、
// 加密落盘且可解密回读、宽高元数据正确、列表携带 thumb_url、越权拒绝、删除图片同步清理缩略图
func TestImageThumbGeneration(t *testing.T) {
	st := newTestStore(t)
	note, err := st.createNote("alice", createNoteRequest{Title: "图片手记"})
	if err != nil {
		t.Fatalf("createNote: %v", err)
	}

	upload := func(w, h int) *PrivateImage {
		t.Helper()
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			t.Fatal(err)
		}
		tmp := filepath.Join(t.TempDir(), "upload.png")
		if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(tmp)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		hdr := &multipart.FileHeader{
			Filename: "test.png",
			Header:   textproto.MIMEHeader{"Content-Type": []string{"image/png"}},
			Size:     int64(buf.Len()),
		}
		uploaded, err := st.addImage("alice", note.ID, f, hdr)
		if err != nil {
			t.Fatalf("addImage(%dx%d): %v", w, h, err)
		}
		return uploaded
	}

	// 小图（20x40）：最长边 ≤480 不放大，缩略宽高保持原值
	small := upload(20, 40)
	if small.ThumbURL == "" || small.URL == "" {
		t.Fatal("上传后应同时返回 url 与 thumb_url")
	}
	if small.Width != 20 || small.Height != 40 || small.ThumbWidth != 20 || small.ThumbHeight != 40 {
		t.Fatalf("小图宽高应保持原值: %dx%d thumb %dx%d", small.Width, small.Height, small.ThumbWidth, small.ThumbHeight)
	}

	// 大图（1000x500）：缩略图最长边应为 480 → 480x240
	big := upload(1000, 500)
	if big.ThumbWidth != 480 || big.ThumbHeight != 240 {
		t.Fatalf("缩略图尺寸应为 480x240: %dx%d", big.ThumbWidth, big.ThumbHeight)
	}

	// 缩略图文件加密落盘且可解密回读为有效 PNG
	abs, name, err := st.imageThumbPath("alice", note.ID, big.ID)
	if err != nil {
		t.Fatalf("imageThumbPath: %v", err)
	}
	if !strings.HasSuffix(name, ".thumb.png") {
		t.Fatalf("缩略图文件名异常: %s", name)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !isMediaEncrypted(raw) {
		t.Fatal("缩略图应与原图一样加密存储")
	}
	data, err := decryptMediaBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || format != "png" {
		t.Fatalf("缩略图应为有效 PNG: %v %v", format, err)
	}
	if cfg.Width != 480 || cfg.Height != 240 {
		t.Fatalf("缩略图实际尺寸 %dx%d", cfg.Width, cfg.Height)
	}

	// 列表接口应携带 thumb_url 与宽高
	notes, err := st.listNotes("alice", "", "")
	if err != nil || len(notes) != 1 {
		t.Fatalf("listNotes: %v %d", err, len(notes))
	}
	if len(notes[0].Images) != 2 {
		t.Fatalf("应有 2 张图片: %d", len(notes[0].Images))
	}
	for _, im := range notes[0].Images {
		if im.ThumbURL == "" || im.URL == "" {
			t.Fatal("列表图片应同时返回 url 与 thumb_url")
		}
	}

	// 越权：其他用户不可读取缩略图
	if _, _, err := st.imageThumbPath("bob", note.ID, big.ID); err == nil {
		t.Fatal("其他用户不应读取缩略图")
	}

	// 删除图片应同步清理缩略图文件
	if err := st.deleteImage("alice", note.ID, big.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Fatal("删除图片后缩略图文件应被清理")
	}
}

// TestImageThumbLazyBackfill 验证历史图片兼容：DB 中 thumb_path 为空的旧图片
// 首次访问 thumb 接口时按需生成并回写，后续直接复用
func TestImageThumbLazyBackfill(t *testing.T) {
	st := newTestStore(t)
	note, err := st.createNote("alice", createNoteRequest{Title: "历史图片"})
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 960, 480))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "old.png")
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hdr := &multipart.FileHeader{
		Filename: "old.png",
		Header:   textproto.MIMEHeader{"Content-Type": []string{"image/png"}},
		Size:     int64(buf.Len()),
	}
	uploaded, err := st.addImage("alice", note.ID, f, hdr)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟历史数据：清空缩略图列
	if _, err := st.db.Exec(`UPDATE note_images SET thumb_path = '', width = 0, height = 0, thumb_width = 0, thumb_height = 0 WHERE id = ?`, uploaded.ID); err != nil {
		t.Fatal(err)
	}
	// 首次访问：按需生成
	rel, tw, th, w, h, err := st.ensureImageThumb(note.ID, uploaded.ID)
	if err != nil {
		t.Fatalf("ensureImageThumb: %v", err)
	}
	if rel == "" || tw != 480 || th != 240 || w != 960 || h != 480 {
		t.Fatalf("历史图片按需生成结果异常: rel=%s %dx%d %dx%d", rel, tw, th, w, h)
	}
	// 并发访问：singleflight 去重不报错，结果一致
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, _, _, _, _, e := st.ensureImageThumb(note.ID, uploaded.ID)
			if e != nil || r == "" {
				errs[i] = e
			}
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatalf("并发 ensureImageThumb: %v", e)
		}
	}
}

// TestNotesPagination 验证手记分页查询：total/页大小/倒序页序正确，全量模式保持旧结构
func TestNotesPagination(t *testing.T) {
	st := newTestStore(t)
	for i := 0; i < 25; i++ {
		// created_at 秒级精度，逐条错开保证排序稳定
		createdAt := time.Now().UTC().Add(-time.Duration(25-i) * time.Hour).Format(time.RFC3339)
		if _, err := st.createNote("alice", createNoteRequest{Title: strconv.Itoa(i), CreatedAt: createdAt}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.createNote("bob", createNoteRequest{Title: "bob 的手记"}); err != nil {
		t.Fatal(err)
	}
	page1, total, err := st.listNotesPaged("alice", "", "", 1, 20)
	if err != nil || total != 25 || len(page1) != 20 {
		t.Fatalf("page1: total=%d len=%d err=%v", total, len(page1), err)
	}
	page2, total2, err := st.listNotesPaged("alice", "", "", 2, 20)
	if err != nil || total2 != 25 || len(page2) != 5 {
		t.Fatalf("page2: total=%d len=%d err=%v", total2, len(page2), err)
	}
	if page1[0].CreatedAt <= page2[0].CreatedAt {
		t.Fatalf("应按 created_at 倒序: %s vs %s", page1[0].CreatedAt, page2[0].CreatedAt)
	}
	// 全量模式（不带 page 参数）与分页模式数据一致
	all, err := st.listNotes("alice", "", "")
	if err != nil || len(all) != 25 {
		t.Fatalf("全量模式应返回 25 条: %v %d", err, len(all))
	}
}

func TestImageExtValidation(t *testing.T) {
	cases := []struct {
		mime, name string
		want       bool
	}{
		{"image/jpeg", "a.jpg", true},
		{"image/jpeg", "a.png", false},
		{"image/png", "a.png", true},
		{"image/webp", "a.webp", true},
		{"image/gif", "a.gif", true},
		{"text/html", "a.jpg", false},
		{"image/jpeg", "a.php.jpg", true}, // 扩展名合法且 MIME 匹配
		{"image/jpeg", "a.svg", false},
	}
	for _, c := range cases {
		if _, ok := imageExtForMIME(c.mime, c.name); ok != c.want {
			t.Fatalf("imageExtForMIME(%s,%s) = %v, want %v", c.mime, c.name, ok, c.want)
		}
	}
}

func TestCardCreateAndShare(t *testing.T) {
	st := newTestStore(t)
	// 生成 1x1 PNG
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	card, err := st.createCard("alice", createCardRequest{
		Template: "simple", Width: 1080, Height: 1080,
		Title: "测试卡片", Image: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if err != nil {
		t.Fatalf("createCard: %v", err)
	}
	if card.ID == "" {
		t.Fatal("卡片 ID 为空")
	}
	// 非法尺寸
	if _, err := st.createCard("alice", createCardRequest{Template: "simple", Width: 123, Height: 456, Image: base64.StdEncoding.EncodeToString(buf.Bytes())}); err == nil {
		t.Fatal("非法尺寸应被拒绝")
	}
	// 非 PNG
	if _, err := st.createCard("alice", createCardRequest{Template: "simple", Width: 1080, Height: 1080, Image: base64.StdEncoding.EncodeToString([]byte("not png"))}); err == nil {
		t.Fatal("非 PNG 应被拒绝")
	}
	// 创建分享
	share, token, err := st.createShare("alice", card.ID, createShareRequest{
		ExpiresIn: "1h", Password: "share123", AllowDownload: true,
	})
	if err != nil {
		t.Fatalf("createShare: %v", err)
	}
	if share.ShareTokenHash != sha256Hex(token) {
		t.Fatal("Token Hash 不一致")
	}
	gotShare, err := st.getShareByToken(token)
	if err != nil {
		t.Fatalf("getShareByToken: %v", err)
	}
	if gotShare.PasswordHash == "" {
		t.Fatalf("PasswordHash 为空 (len=%d)", len(gotShare.PasswordHash))
	}
	if !st.verifySharePassword(token, "share123") {
		t.Fatalf("分享密码应验证通过, hash=%q", gotShare.PasswordHash)
	}
	if st.verifySharePassword(token, "wrong") {
		t.Fatal("错误分享密码不应通过")
	}
	got, err := st.getShareByToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if st.shareInvalid(got, time.Now()) {
		t.Fatal("有效期内不应失效")
	}
	// 过期
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := st.db.Exec(`UPDATE note_shares SET expires_at = ?`, past); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.getShareByToken(token)
	if !st.shareInvalid(got2, time.Now()) {
		t.Fatal("过期分享应失效")
	}
	// 撤销
	st.db.Exec(`UPDATE note_shares SET expires_at = NULL`)
	if err := st.revokeShare("alice", token); err != nil {
		t.Fatalf("revokeShare: %v", err)
	}
	got3, _ := st.getShareByToken(token)
	if !st.shareInvalid(got3, time.Now()) {
		t.Fatal("撤销后分享应失效")
	}
	if err := st.revokeShare("bob", token); err == nil {
		t.Fatal("非卡片所有者不应能撤销")
	}
	// 删除卡片后分享级联删除
	card2, _ := st.createCard("alice", createCardRequest{
		Template: "dark", Width: 1080, Height: 1350, Image: base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	_, token2, _ := st.createShare("alice", card2.ID, createShareRequest{ExpiresIn: "permanent"})
	if err := st.deleteCard("alice", card2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.getShareByToken(token2); err == nil {
		t.Fatal("删除卡片后分享应被级联删除")
	}
}

func TestDecodeBase64Image(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	var buf bytes.Buffer
	png.Encode(&buf, img)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	if _, err := decodeBase64Image("data:image/png;base64," + b64); err != nil {
		t.Fatalf("合法 PNG 应通过: %v", err)
	}
	if _, err := decodeBase64Image(base64.StdEncoding.EncodeToString([]byte("hello"))); err == nil {
		t.Fatal("非 PNG 应被拒绝")
	}
}

func TestShareExpiryParse(t *testing.T) {
	if e, err := shareExpiry("10m"); err != nil || e == nil {
		t.Fatalf("10m 应解析成功: %v %v", e, err)
	}
	if e, err := shareExpiry("permanent"); err != nil || e != nil {
		t.Fatalf("permanent 应为空过期: %v %v", e, err)
	}
	if _, err := shareExpiry("xyz"); err == nil {
		t.Fatal("非法有效期应报错")
	}
}

func TestMediaEncryptionRoundtrip(t *testing.T) {
	st := newTestStore(t)
	plain := []byte("fake-png-bytes-用于测试-1234567890")

	// 加密后带 magic 头，解密回环一致
	enc, err := encryptMediaBytes(plain)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if !isMediaEncrypted(enc) {
		t.Fatal("加密内容应带 magic 头")
	}
	if got, err := decryptMediaBytes(enc); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("解密回环失败: %v", err)
	}

	// 历史明文兼容：不带 magic 头的内容原样返回
	if got, err := decryptMediaBytes(plain); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("历史明文应原样返回: %v", err)
	}

	// 启动迁移：明文文件原位加密、可解密回读、重复迁移幂等
	abs := filepath.Join(st.storageDir, "2026", "08", "30", "legacy.png")
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, plain, 0644); err != nil {
		t.Fatal(err)
	}
	if n, err := st.migratePlainMedia(); err != nil || n != 1 {
		t.Fatalf("迁移应处理 1 个文件: n=%d err=%v", n, err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	if !isMediaEncrypted(raw) {
		t.Fatal("迁移后文件应为加密格式")
	}
	if n, err := st.migratePlainMedia(); err != nil || n != 0 {
		t.Fatalf("重复迁移应幂等: n=%d err=%v", n, err)
	}
	if got, err := decryptMediaBytes(raw); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("迁移后解密回环失败: %v", err)
	}
}

// TestAudioShareCardLifecycle 语音二维码令牌随卡片删除而失效：
// 绑定令牌在所属卡片删除后必须失效；未绑定令牌在手记无剩余卡片时一并失效
func TestAudioShareCardLifecycle(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339)
	// 手记 + 语音（createAudioShare 的前置条件）
	noteID := "note-as-life"
	if _, err := st.db.Exec(`INSERT INTO notes (id, user_id, title, created_at, updated_at) VALUES (?, 'alice', '语音手记', ?, ?)`,
		noteID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO note_audio (id, note_id, file_path, duration, created_at) VALUES ('aud-1', ?, 'audio/a.webm', 3, ?)`,
		noteID, now); err != nil {
		t.Fatal(err)
	}
	// 生成 1x1 PNG（卡片图片入参）
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	pngB64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
	newCard := func() *PrivateCardMeta {
		t.Helper()
		c, err := st.createCard("alice", createCardRequest{
			NoteID: noteID, Template: "simple", Width: 1080, Height: 1080, Image: pngB64,
		})
		if err != nil {
			t.Fatalf("createCard: %v", err)
		}
		return c
	}
	shareAlive := func(token string) bool {
		t.Helper()
		_, err := st.getAudioShareByToken(token)
		return err == nil
	}

	// 场景 1：两次打开弹窗各产生一个令牌 → 各绑定到一张卡片 → 删一张卡只失效自己的令牌
	tok1, err := st.createAudioShare("alice", noteID)
	if err != nil {
		t.Fatalf("createAudioShare: %v", err)
	}
	tok2, err := st.createAudioShare("alice", noteID)
	if err != nil {
		t.Fatalf("createAudioShare: %v", err)
	}
	card1 := newCard() // 绑定 tok2（最新未绑定令牌）
	card2 := newCard() // 绑定 tok1
	if err := st.deleteCard("alice", card1.ID); err != nil {
		t.Fatalf("deleteCard: %v", err)
	}
	if shareAlive(tok2) {
		t.Fatal("卡片删除后其绑定的语音分享令牌应失效")
	}
	if !shareAlive(tok1) {
		t.Fatal("未删除卡片（card2）的令牌不应被误删")
	}

	// 场景 2：删除最后一张卡片后，未绑定令牌（历史数据/未保存卡片）一并失效
	tok3, err := st.createAudioShare("alice", noteID)
	if err != nil {
		t.Fatalf("createAudioShare: %v", err)
	}
	if !shareAlive(tok3) {
		t.Fatal("新令牌应有效")
	}
	if err := st.deleteCard("alice", card2.ID); err != nil {
		t.Fatalf("deleteCard: %v", err)
	}
	if shareAlive(tok1) || shareAlive(tok3) {
		t.Fatal("手记无剩余卡片后，剩余令牌应全部失效")
	}

	// 场景 3：无语音的手记不能创建语音分享（回归确认）
	if _, err := st.db.Exec(`DELETE FROM note_audio WHERE id = 'aud-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.createAudioShare("alice", noteID); err == nil {
		t.Fatal("无语音手记不应创建语音分享")
	}
}
