//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"time"
)

// killProcessTree 终止 PTY 会话进程及其子进程。
// pty.Start 以 Setsid 启动，cmd.Process.Pid 即进程组 ID；对负值发送信号可终止整个进程组，避免遗留孤儿进程。
// 先 SIGHUP 让交互式 shell 优雅退出，随后 SIGKILL 兜底，最后 Wait 回收。
func killProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGHUP)
	time.Sleep(50 * time.Millisecond)
	_ = syscall.Kill(pgid, syscall.SIGKILL)
}
