//go:build windows

package main

import (
	"os/exec"
)

// killProcessTree 在 Windows 上仅终止主进程（负 PID 进程组信号在 Windows 无意义）。
// Web Shell 实际运行于 Linux 部署环境，此实现仅保证 Windows 下可编译。
func killProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
