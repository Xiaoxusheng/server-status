# shell.html —— 宿主机命令行终端 设计规格（待实现）

> 状态：已评审待实现。功能为 server-status 运行所在 Linux 服务器的**通用交互终端**，非 Docker、非 SSH。

## 设计决策
1. 执行目标：本机服务器，Go 进程直接 spawn 交互 shell。
2. 运行身份：以 server-status 进程自身的用户身份运行（非 root，隔离性更好）。
3. 权限：复用 `docker:manage`（未来需要更细粒度可新增独立 `shell` 权限）。
4. 审计：记「会话 + 每条命令」，「绝不」记录回显输出。
5. 终端：`xterm.js`（CDN）。
6. 会话模型：单会话单页，含重连/断开。

## 页面布局（对齐 ip-panel 整页）
- topbar：首页 / 服务端口 / 进程 + 深浅色 + 退出（复用现有样式）。
- 标题区：`Linux 命令行终端` + 连接状态徽标（连接中 / 已退出 / 已断开）+ 危险提示条 `仅管理员 · 命令以服务器用户身份执行 · 操作风险自负`。
- 主体：xterm.js 全宽终端 + 工具条（重连 / 断开 / 清屏 / 放大 / 缩小 / 全屏）。
- 移动端：自适应、横屏优先、顶栏 responsive。

## 后端（go + WebSocket，复用现有鉴权/CSRF/审计基建）
- 端点：`GET /api/shell`（WS 升级）。
- 鉴权链：会话校验 → RBAC `docker:manage` → Origin 校验 → WS 升级。
- 执行：`exec.Command("/bin/sh", "-i")` + PTY（github.com/creack/pty），stderr 合并，stdin/stdout 与 WS 三方管道互转。
- 消息帧 JSON：`in: input/resize/ping`，`out: output(base64)/exit/pong/error`；输入按字节透传；输出 read 后 base64 送 WS。
- 加固：
  - 空闲超时（10min）自动断开；全局并发上限（每用户 ≤2）；关闭页面即 `SIGHUP` 回收子进程防僵尸；
  - 命令审计：仅记录「用户敲的命令文本」到审计库，回显输出「绝不」落日志/审计；
  - WS 校验 session + Origin；单一固定 shell 入口，不在 URL/日志/错误暴露命令内容。

## 验收
- 仅 admin 可开终端；非授权被拒且无执行痕迹；关闭页面进程被回收、无僵尸；并发受限；命令有审计、回显零泄漏。