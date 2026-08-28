//go:build !windows

package main

// Web Shell PTY 与 WebSocket 端到端集成测试（仅在有真实 PTY 的 Linux/Unix 运行）。
// 覆盖：echo/pwd/uname、Ctrl+C 中断前台进程、resize 同步、exit 退出、
// 进程树清理、WebSocket 认证-建连-交互-断开清理、无 Token/坏 Token/重放/非法 Origin/未登录拒绝。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// ptyHarness 一个可直接读写的手工 PTY shell 测试夹具
type ptyHarness struct {
	ptmx *os.File
	cmd  *exec.Cmd
	buf  bytes.Buffer
}

// openTestPTY 启动一个真实 PTY 的交互 shell
func openTestPTY(t *testing.T) *ptyHarness {
	t.Helper()
	shell := resolveShell()
	if shell == "" {
		t.Skip("no shell available")
	}
	cmd := exec.Command(shell)
	cmd.Env = buildShellEnv()
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cmd.Dir = home
	}
	p, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start(%s) 失败: %v", shell, err)
	}
	return &ptyHarness{ptmx: p, cmd: cmd}
}

// send 向 PTY 输入一行并回车
func (h *ptyHarness) send(line string) {
	_, _ = h.ptmx.WriteString(line + "\r")
}

// waitFor 轮询读取 PTY 输出直到包含 substring 或超时
func (h *ptyHarness) waitFor(t *testing.T, substring string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = h.ptmx.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 4096)
		n, err := h.ptmx.Read(buf)
		if n > 0 {
			h.buf.Write(buf[:n])
		}
		if strings.Contains(h.buf.String(), substring) {
			return
		}
		if err != nil && n == 0 {
			// 读超时（非 EOF）继续轮询
		}
	}
	t.Fatalf("等待 %q 超时，已读输出: %q", substring, h.buf.String())
}

func (h *ptyHarness) close() {
	if h.ptmx != nil {
		_ = h.ptmx.Close()
	}
	_ = h.cmd.Wait()
}

// PTY 基本交互：echo / pwd / uname -s / exit
func TestPTYBasicEchoPwdUnameExit(t *testing.T) {
	h := openTestPTY(t)
	defer h.close()

	h.send("echo shell_hello_marker")
	h.waitFor(t, "shell_hello_marker", 5*time.Second)

	h.send("pwd")
	home, _ := os.UserHomeDir()
	if home != "" {
		h.waitFor(t, home, 5*time.Second)
	}

	h.send("uname -s")
	if runtime.GOOS == "linux" {
		h.waitFor(t, "Linux", 5*time.Second)
	}

	// exit 正常退出
	h.send("exit")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = h.ptmx.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1024)
		_, err := h.ptmx.Read(buf)
		if err != nil {
			return // EOF → 正常退出
		}
	}
	t.Fatalf("exit 后 PTY 未结束")
}

// Ctrl+C 必须真的中断前台运行的进程（sleep 500）
func TestPTYCtrlCInterruptsProcess(t *testing.T) {
	h := openTestPTY(t)
	defer h.close()

	h.send("sleep 500")
	h.waitFor(t, "sleep 500", 5*time.Second)
	// 发送 Ctrl+C
	_, _ = h.ptmx.WriteString("\x03")
	// 若前台被中断，shell 回到提示符，后续命令会立即执行
	h.send("echo after_interrupt_ok")
	h.waitFor(t, "after_interrupt_ok", 5*time.Second)
}

// resize 同步 rows/cols
func TestPTYResize(t *testing.T) {
	h := openTestPTY(t)
	defer h.close()

	if err := pty.Setsize(h.ptmx, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatalf("Setsize 失败: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	rows, cols, err := pty.Getsize(h.ptmx)
	if err != nil {
		t.Fatalf("Getsize 失败: %v", err)
	}
	if rows != 40 || cols != 120 {
		t.Fatalf("resize 未同步: got rows=%d cols=%d want 40x120", rows, cols)
	}
}

// killProcessTree 需终止 shell 及其后台子进程（避免孤儿）
func TestPTYKillProcessTree(t *testing.T) {
	h := openTestPTY(t)
	h.send("sh -c 'while :; do :; done' & echo bg_started")
	h.waitFor(t, "bg_started", 5*time.Second)

	killProcessTree(h.cmd)
	done := make(chan struct{})
	go func() { _ = h.cmd.Wait(); close(done) }()
	select {
	case <-done:
		// 进程已回收
	case <-time.After(5 * time.Second):
		h.close()
		t.Fatalf("killProcessTree 未能在 5s 内回收 shell 进程")
	}
	h.close()
}

// ---------- WebSocket 端到端 ----------

// e2eServer 构造一个真实 HTTP 服务器与 admin 会话
func e2eServer(t *testing.T, password string) (*httptest.Server, *Session) {
	mux, sess := setupShellTest(t, "admin", password)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, sess
}

// e2eAuth REST 调用 /api/shell/auth 获取一次性 Token
func e2eAuth(t *testing.T, srv *httptest.Server, sess *Session, password string) string {
	body := `{"password":"` + password + `"}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/shell/auth", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.Header.Set("Cookie", "session_id="+sess.SessionID+"; csrf_token="+sess.CSRFToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("e2e auth 请求失败: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("e2e auth 应 200, got %d: %v", resp.StatusCode, m)
	}
	data, _ := m["data"].(map[string]interface{})
	tok, _ := data["shell_token"].(string)
	if tok == "" {
		t.Fatalf("未返回 shell_token")
	}
	return tok
}

// wsURL 转换 http:// → ws://
func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/shell"
}

// dialShell 带完整保护头建立 WebSocket 连接
func dialShell(srv *httptest.Server, sess *Session, origin, cookie string) (*websocket.Conn, *http.Response, error) {
	hdr := http.Header{}
	hdr.Set("Origin", origin)
	hdr.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120")
	if cookie != "" {
		hdr.Set("Cookie", cookie)
	}
	return websocket.DefaultDialer.Dial(wsURL(srv), hdr)
}

// wsReadBinUntil 读取 WS，累积二进制输出直到包含目标或超时
func wsReadBinUntil(t *testing.T, conn *websocket.Conn, want string) []byte {
	t.Helper()
	var out []byte
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.BinaryMessage {
			out = append(out, data...)
		}
		if bytes.Contains(out, []byte(want)) {
			return out
		}
	}
	return out
}

// 完整流程：认证 → 一次性 Token → WS(auth 首帧) → 建 PTY → 交互 → 断开 → PTY 清理
func TestShellWSFullLifecycleAndCleanup(t *testing.T) {
	srv, sess := e2eServer(t, testShellPassword)
	tok := e2eAuth(t, srv, sess, testShellPassword)

	conn, resp, err := dialShell(srv, sess, "http://127.0.0.1:9000", "session_id="+sess.SessionID)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial 失败 status=%d err=%v", resp.StatusCode, err)
		}
		t.Fatalf("dial 失败: %v", err)
	}
	defer conn.Close()

	_ = conn.WriteJSON(map[string]interface{}{"type": "auth", "token": tok, "rows": 24, "cols": 100})

	// 等待 PTY 输出（提示符）
	var out []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !bytes.Contains(out, []byte("$")) && !bytes.Contains(out, []byte("#")) {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		mt, d, rerr := conn.ReadMessage()
		if rerr != nil {
			break
		}
		if mt == websocket.BinaryMessage {
			out = append(out, d...)
		}
	}
	if len(out) == 0 {
		t.Fatalf("建连后未收到 PTY 输出")
	}

	// 应存在 1 个 shell 会话
	shellHubState.RLock()
	n := len(shellHubState.shells)
	shellHubState.RUnlock()
	if n != 1 {
		t.Fatalf("应存在 1 个 shell 会话, got %d", n)
	}

	// 执行命令
	_ = conn.WriteJSON(map[string]interface{}{"type": "input", "data": "echo E2E_MARKER_XYZ\n"})
	got := wsReadBinUntil(t, conn, "E2E_MARKER_XYZ")
	if !bytes.Contains(got, []byte("E2E_MARKER_XYZ")) {
		t.Fatalf("未收到命令回显输出")
	}

	// 客户端正常断开 → 服务端必须清理 PTY/会话
	_ = conn.Close()

	waitRemovedAt := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitRemovedAt) {
		shellHubState.RLock()
		cur := len(shellHubState.shells)
		shellHubState.RUnlock()
		if cur == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("断开后会话未清理（仍有 %d 个）", len(shellHubState.shells))
}

// 未登录（无 Cookie）→ 握手失败
func TestShellWSNoSessionRejected(t *testing.T) {
	srv, _ := e2eServer(t, testShellPassword)
	conn, _, err := dialShell(srv, nil, "http://127.0.0.1:9000", "")
	if err == nil {
		conn.Close()
		t.Fatalf("未登录应拒绝握手")
	}
}

// 非法 Origin → 拒绝
func TestShellWSBadOriginRejected(t *testing.T) {
	srv, sess := e2eServer(t, testShellPassword)
	conn, _, err := dialShell(srv, sess, "http://evil.example.com", "session_id="+sess.SessionID)
	if err == nil {
		conn.Close()
		t.Fatalf("非法 Origin 应拒绝")
	}
}

// 无 auth 首帧 → 拒绝且不建 PTY
func TestShellWSNoAuthFrameRejected(t *testing.T) {
	srv, sess := e2eServer(t, testShellPassword)
	conn, _, err := dialShell(srv, sess, "http://127.0.0.1:9000", "session_id="+sess.SessionID)
	if err != nil {
		t.Fatalf("dial 应成功: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteJSON(map[string]interface{}{"type": "nothing", "data": "x"})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, _ := conn.ReadMessage()
	if mt == websocket.BinaryMessage {
		t.Fatalf("不应创建 PTY")
	}
	if !strings.Contains(string(data), "error") {
		t.Fatalf("应返回错误帧")
	}
}

// 错误 Token → 拒绝且不建 PTY
func TestShellWSBadTokenRejected(t *testing.T) {
	srv, sess := e2eServer(t, testShellPassword)
	conn, _, err := dialShell(srv, sess, "http://127.0.0.1:9000", "session_id="+sess.SessionID)
	if err != nil {
		t.Fatalf("dial 应成功: %v", err)
	}
	defer conn.Close()
	_ = conn.WriteJSON(map[string]interface{}{"type": "auth", "token": "not-a-valid-token"})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, data, _ := conn.ReadMessage()
	if mt == websocket.BinaryMessage {
		t.Fatalf("错误 Token 不应创建 PTY")
	}
	if !strings.Contains(string(data), "error") {
		t.Fatalf("应返回错误帧")
	}
}

// 一次性 Token 重放 → 拒绝并不新增认证/PTY
func TestShellWSTokenReplayRejected(t *testing.T) {
	srv, sess := e2eServer(t, testShellPassword)
	tok := e2eAuth(t, srv, sess, testShellPassword)

	// 第一次成功消费
	conn, _, err := dialShell(srv, sess, "http://127.0.0.1:9000", "session_id="+sess.SessionID)
	if err != nil {
		t.Fatalf("第一次连接应成功: %v", err)
	}
	_ = conn.WriteJSON(map[string]interface{}{"type": "auth", "token": tok})
	wsReadBinUntil(t, conn, "") // 至少读到首帧输出
	_ = conn.Close()
	time.Sleep(300 * time.Millisecond)

	// 重放同一 Token
	conn2, resp2, err2 := dialShell(srv, sess, "http://127.0.0.1:9000", "session_id="+sess.SessionID)
	if err2 != nil {
		if resp2 != nil {
			// 握手即被拒
			return
		}
		t.Fatalf("重放 dial 异常: %v", err2)
	}
	defer conn2.Close()
	before := len(shellHubState.shells)
	_ = conn2.WriteJSON(map[string]interface{}{"type": "auth", "token": tok})
	_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, d2, _ := conn2.ReadMessage()
	if mt == websocket.BinaryMessage {
		t.Fatalf("重放 Token 不应创建 PTY")
	}
	if !strings.Contains(string(d2), "error") {
		t.Fatalf("重放应返回错误帧, got %s", string(d2))
	}
	if len(shellHubState.shells) != before {
		t.Fatalf("重放不应新增会话")
	}
}
