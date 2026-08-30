package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
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
