# server-status

基于 Go 的轻量级服务器监控与运维面板：实时状态监控、Web 终端、文件管理、RBAC 权限，外加一个完全隐藏的私人数字空间。单二进制部署，自带 HTTPS，前端模板随版本分发、更新无需重启。

## 功能特性

- 🖥️ **实时监控**：CPU / 内存 / 磁盘 / 网络 / 负载，WebSocket 每秒推送，多网卡切换
- 👥 **在线用户 & 访问统计**：每日 / 每周访问量、唯一访客、IP 明细、自动封禁与白名单
- ⚙️ **进程 & 服务中心**：进程列表 / TOP10 / 结束进程；systemd 服务创建启停、监听端口识别、防火墙端口管理、Docker 容器管理
- 🖥️ **Web Shell**：真正的 Linux PTY 交互终端（xterm.js + WebSocket），独立密码二次认证 + 一次性 Token
- 📁 **文件管理**：浏览 / 上传 / 新建目录 / 删除，移动端卡片视图，TS 直录流播放
- 🎥 **媒体服务**：随机图片 / 视频、EPUB 电子书在线阅读
- 🔑 **授权下载**：下载令牌签发 / 撤销，配额与有效期控制，支持粘贴链接自动解析
- 🚀 **Trojan-Go 监控**：状态 / 在线用户 / 实时流量，用户增删改、限速与 IP 限额，用户档案跨重启持久化（可选功能，见 [TROJAN.md](TROJAN.md)）
- 🔒 **隐藏私人空间**：普通界面完全无入口；手记 + 图片 + 定位 + 语音 + 卡片生成与加密分享（见下文）
- 🛡️ **RBAC 权限**：用户 / 角色 / 权限三级管理，接口级细粒度控制
- 🔐 **安全加固**：bcrypt、HMAC 签名、AES-GCM 落盘加密、CSRF、登录防爆破、TLS 1.2+、路径穿越防护
- 📱 **响应式 + 暗黑模式**：桌面 / 移动端自适应

---

## 快速开始

### 方式一：一键部署脚本（推荐）

在 Linux 服务器上（systemd 发行版），把项目目录上传后在根目录执行：

```bash
# 交互式部署：自动生成密钥、自签证书、安装 systemd 服务并启动
sudo bash deploy.sh

# 或指定域名（正式证书，需 80 端口可用 + 域名已解析）
sudo bash deploy.sh -d example.com --letsencrypt

# Docker Compose 部署
sudo bash deploy.sh --docker
```

脚本幂等：重复执行不会覆盖已生成的密钥 / 证书 / 配置，可直接用于升级。完成后按提示访问 `https://你的服务器:9000`，**默认账号 `admin / admin123`，首次登录后立即改密**。

> 本地有 Go 环境时脚本会现场编译；否则先在本机交叉编译并上传：
> ```bash
> CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o server-status-linux .
> ```

### 方式二：Docker Compose 手动部署

```bash
cp .env.example .env
# 编辑 .env，用 openssl rand -hex 32 生成三个密钥填入
mkdir -p tls   # 放入 cert.pem / key.pem（或用 openssl 自签，见下文证书一节）
docker compose up -d --build
```

### 方式三：systemd 手动部署

```bash
# 1. 构建（本地或服务器上）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o server-status-linux .

# 2. 安装到数据目录（默认 /opt/server-status，可自行替换）
sudo mkdir -p /opt/server-status/templates
sudo cp server-status-linux /opt/server-status/server-status && sudo chmod +x /opt/server-status/server-status
sudo cp -r templates/. /opt/server-status/templates/
sudo cp config.json private_notes.json /opt/server-status/

# 3. 配置：复制 .env.example 到 /etc/server-status/server-status.env，填入密钥与域名（见「配置说明」）
# 4. 证书：放到 /opt/server-status/tls/cert.pem 与 key.pem（见「TLS 证书」）
# 5. 安装服务单元并启动
sudo cp server-status.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now server-status
```

**首次启动后**：

1. 浏览器访问 `https://主机:9000`，用 `admin / admin123` 登录并立即改密。
2. （可选）按需创建 RBAC 角色与普通用户，管理页 `/rbac.html`。
3. （可选）首次启动前在配置文件中设置 `PRIVATE_NOTES_PASSWORD` 初始化私人空间密码。

---

## 配置说明

所有配置通过**环境变量**注入，编译产物不再绑定任何域名 / 路径 / 端口。Docker 模式写在 `.env`，systemd 模式写在 `/etc/server-status/server-status.env`（root 属主、0600 权限，服务单元已自动挂载）。完整模板见 [.env.example](.env.example)。

### 必填：三个密钥

| 环境变量 | 保护什么 | 不设置的后果 |
|---|---|---|
| `SERVER_STATUS_SIGNING_KEY` | HMAC 签名：会话 Cookie、分享密码 Cookie、私人空间入口 | 每次启动随机生成，**重启后所有已签发 Cookie 全部失效** |
| `SERVER_STATUS_ENCRYPT_KEY` | AES-GCM 落盘加密：用户 / 角色 / 令牌数据、Shell 密码文件、私人空间媒体文件（图片 / 语音 / 卡片，首次启动自动迁移加密） | 回退内置默认值，等于**数据可被任何拿到源码的人解密** |
| `SERVER_STATUS_DOWNLOAD_TOKEN_SECRET` | 下载令牌签名 | 同上 |

```bash
# 三个密钥各自独立生成、互不复用；生成后保持不变——
# 更换 ENCRYPT_KEY 会导致已加密数据无法解密；更换另外两个等效于全员登出
openssl rand -hex 32
```

### 可选：站点与路径

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_STATUS_DOMAIN` | `localhost` | 对外域名（不带协议和端口）。跨域白名单、Cookie Domain、证书探测都用它；生产务必设置 |
| `SERVER_STATUS_LISTEN_ADDR` | `:9000` | HTTPS 监听地址 |
| `SERVER_STATUS_HOME` | `/opt/server-status` | **数据根目录**：运行数据、日志、模板、TLS 证书默认都在它下面 |
| `SERVER_STATUS_TEMPLATES_DIR` | `<数据根目录>/templates` | 前端模板目录（Docker 中固定为镜像内 `/app/templates`） |
| `SERVER_STATUS_TLS_CERT` / `_KEY` | `<数据根目录>/tls/cert.pem`、`key.pem` | TLS 证书与私钥路径 |
| `SERVER_STATUS_MEDIA_DIR` | `<数据根目录>/media` | 媒体文件目录（图片 / 视频 / EPUB） |
| `SERVER_STATUS_STATIC_BASE_URL` | 空 | 随机媒体外链基地址。**留空时自动回退为同源 `/api/media` 接口（会话鉴权），无需额外静态服务器**；如你有独立公开静态服务，填 `https://域名:端口/static/` |
| `SERVER_STATUS_EXTRA_ORIGINS` | 空 | 额外跨域白名单 Origin，逗号分隔（反向代理地址、静态服务地址等） |

### 可选：功能开关

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `PRIVATE_NOTES_PASSWORD` | 无 | 私人空间密码初始化，**仅首次启动且未初始化时生效**，生效后从配置中删除该行 |
| `SHELL_PASSWORD_HASH` | 无 | Web Shell 二次认证密码的 bcrypt 哈希（`htpasswd -bnBC 10 "" '密码' \| tr -d ':\n'`）；设置后页面改密接口自动禁用 |
| `SERVER_STATUS_TROJAN_ENABLED` 等 | 读数据目录 `config.json` | Trojan-Go 监控覆盖项，见 [TROJAN.md](TROJAN.md) |
| `MAX_SHELLS_PER_USER` / `MAX_SHELLS_GLOBAL` / `SHELL_IDLE_TIMEOUT` / `SHELL_MAX_LIFETIME` / `SHELL_TOKEN_TTL` | 3 / 10 / 30m / 12h / 60s | Web Shell 并发与生命周期调优 |

### 目录结构（自动创建）

以默认数据根目录 `/opt/server-status` 为例：

```
/opt/server-status/
├── server-status          # 二进制
├── templates/             # 前端模板（随版本更新，服务端直接读磁盘、改完即生效）
├── tls/                   # cert.pem / key.pem
├── media/                 # 媒体文件（.jpg .png .jpeg .mp4 .webm 与 EPUB）
├── log/                   # 运行日志
├── config.json            # Trojan-Go 监控配置（可选功能）
├── private_notes.json     # 私人空间功能配置
├── users.json / rbac.json / download_tokens.json / server_data.json   # 运行数据（AES-GCM 加密落盘，0600）
└── private_notes.db       # 私人空间 SQLite 数据库
```

### TLS 证书

程序自带 HTTPS（TLS 1.2+），证书默认放在 `<数据根目录>/tls/` 下，文件名固定 `cert.pem` / `key.pem`：

- **自签（内网 / 测试）**：`deploy.sh` 自动生成 10 年期自签证书；也可手动：
  ```bash
  sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout /opt/server-status/tls/key.pem -out /opt/server-status/tls/cert.pem \
    -subj "/CN=你的域名" -addext "subjectAltName=DNS:你的域名,DNS:localhost,IP:127.0.0.1"
  ```
- **正式证书（生产推荐）**：`sudo bash deploy.sh -d 你的域名 --letsencrypt`，或手动 certbot 后把 `fullchain.pem` / `privkey.pem` 复制为上面的 `cert.pem` / `key.pem`。
- 自签或域名不匹配的证书在手机浏览器上会导致部分 Web API 被禁用（如 GPS 定位要求安全上下文）。
- 防火墙 / 反向代理放行 9000 端口即可。

### 从旧版本升级（编译期常量 → 环境变量）

v0.x 版本把证书路径、域名、端口、目录写死在源码常量里；新版本全部改为环境变量读取，**老数据无需搬家**：在配置文件中把各路径指向原位置即可。旧值可在旧版本源码 `main.go` 顶部常量区查到（`tlsCertFile` / `tlsKeyFile` / `mediaDir` / 各数据文件路径等），对照填入：

```ini
SERVER_STATUS_HOME=<旧数据目录>
SERVER_STATUS_MEDIA_DIR=<旧媒体目录>
SERVER_STATUS_TLS_CERT=<旧证书文件路径>
SERVER_STATUS_TLS_KEY=<旧私钥文件路径>
SERVER_STATUS_DOMAIN=<你的域名>
SERVER_STATUS_STATIC_BASE_URL=<旧媒体外链基地址，如有独立静态服务器>
SERVER_STATUS_EXTRA_ORIGINS=<旧额外跨域来源，逗号分隔>
```

写入 `/etc/server-status/server-status.env` 后重启服务即可。确认运行正常后，建议把数据迁到默认布局（`/opt/server-status`），之后配置只需保留三个密钥与 `SERVER_STATUS_DOMAIN`。

---

## 隐藏私人空间

普通界面完全不可见（无入口、无提示）：**桌面端 `Ctrl + Shift + Alt + N`** 打开密码验证；**移动端连续快速点击 Logo 5 次**。

- 双层认证：普通登录 + 独立私人密码（仅存 bcrypt，不落任何前端存储）；30 分钟无操作自动锁定，密码错 5 次锁 60 秒
- 功能：时间线手记（Markdown / 图片 / 定位 / 语音 / 标签）、全局搜索、卡片生成器（5 种模板 × 多种尺寸，Canvas 真渲染 PNG）、分享链接 + 二维码 + 访问密码 + 有效期
- 安全：图片 / 语音 / 卡片以 AES-GCM 加密落盘（历史明文文件启动时自动迁移），存于私有目录，静态文件服务不暴露；分享 Token 只存哈希；审计日志不记录任何正文与密码
- 启用：默认开启，首次进入设置密码即可（或用 `PRIVATE_NOTES_PASSWORD` 在首次启动时初始化）
- 细节配置见数据目录下 `private_notes.json`

## Web Shell（Web 终端）

真正的 Linux PTY 交互终端（`top` / `vim` / `htop` 等全支持）。**每次新建 Shell 都要输入独立 Shell 密码二次认证**（即使已登录、有 `system:exec` 权限）：密码 bcrypt 校验 → 颁发 60 秒一次性 Token → WebSocket 首帧认证后才建 PTY。并发限制（每用户 3 / 全局 10）、空闲 30 分钟 / 最长 12 小时自动回收，环境变量剥离敏感项，审计不记录终端输入输出。

- Shell 密码初始化：登录后调用 `POST /api/shell/setup-password`，或配置 `SHELL_PASSWORD_HASH`
- 改密后自动撤销全部旧认证与运行中的本人 Shell

## API 概览

所有 `/api/` 接口需登录会话（HttpOnly + Secure + SameSite Cookie）；写操作额外要求 `X-CSRF-Token` 请求头（来自登录会话绑定的 `csrf_token` Cookie，Double-Submit 模式）。

| 分组 | 代表接口 | 权限 |
|---|---|---|
| 实时监控 | `GET /ws?iface=`（WebSocket）、`GET /access-stats` | `system:view` |
| Web Shell | `POST /api/shell/auth`、`GET /ws/shell`、`GET /api/shell/sessions` | `system:exec` |
| 命令白名单 | `POST /exec?command=`（`uptime` / `df` / `free` / `who` / `uname` / `ls`） | `system:exec` |
| 进程 | `GET /api/processes`、`POST /api/processes/kill` | `system:process` |
| 文件 | `GET /api/files`、`POST /api/files/upload`、`DELETE /api/files` | `files:manage` |
| 媒体 | `GET /random-media`、`GET /epubs`、`GET /api/media?path=` | `files:view` / `files:manage` |
| 下载令牌 | `POST /generate-download-token`、`GET /download?token_id=&token=&file=` | `token:issue` / `token:manage` |
| IP 管理 | `GET /api/ip/blocked`、`POST /api/ip/block`、`POST /api/ip/whitelist` | `ip:manage` |
| RBAC | `GET/POST/PUT/DELETE /api/rbac/roles`、`/api/rbac/users` | `role:manage` / `user:manage` |

上传禁止可执行 / 脚本 / 网页类扩展名；下载令牌在校验时同时校验所属账号仍具备 `files:download` 权限，权限收回令牌立即失效。

### 默认角色与权限

- `admin`：全部权限（`*`）
- `operator`：`system:view`、`system:exec`、`files:view`、`files:download`、`token:manage`、`user:view`
- `user`：`system:view`、`files:view`、`files:download`、`token:manage`

| 权限 | 说明 | 权限 | 说明 |
|---|---|---|---|
| `system:view` | 查看状态与统计 | `files:manage` | 浏览 / 上传 / 删除文件 |
| `system:exec` | 命令白名单 + Web Shell | `token:manage` | 管理自己名下的令牌 |
| `system:process` | 查看 / 结束进程 | `token:issue` | 为指定用户签发令牌 |
| `ip:manage` | IP 封禁 / 白名单 | `user:view` / `user:manage` | 用户查看 / 管理 |
| `files:view` | 查看媒体内容 | `role:manage` | 角色与权限管理 |

## 安全特性

- 登录 bcrypt 哈希 + 失败锁定（防爆破）；会话 HttpOnly + Secure + SameSite，服务端管理
- CSRF Double-Submit 强制校验；WebSocket / CORS Origin 精确白名单（防前缀绕过）
- 敏感数据 AES-GCM 加密落盘（0600）：用户 / 角色 / 令牌数据、Shell 密码文件、私人空间媒体文件（图片 / 语音 / 卡片）；浏览器不持有任何服务端 Secret
- 命令执行白名单 + 固定参数；路径穿越防护；上传类型黑名单
- 反爬：UA 白名单、行为分析、IP 自动封禁（不信任可伪造的 `X-Forwarded-For`）
- TLS 1.2+、HSTS、X-Frame-Options、nosniff；模板目录中 `.bak/.json/.key/.pem` 等禁止访问

## 压力测试

内置零依赖压测工具（纯标准库），只打只读 GET 接口：

```bash
# 认证场景（推荐）：每个 worker 登录一次后压测，不受反爬频控
STRESS_PASSWORD='你的密码' go run ./stress -target https://127.0.0.1:9000 \
  -scenario auth -username admin -c 100 -d 30s -ramp 5s

# 未认证场景：单 IP 5 分钟内超过 100 次请求会触发自动封禁 1 小时，切勿高强度使用
go run ./stress -target https://127.0.0.1:9000 -scenario public -c 50 -d 30s
```

健康判据：**p99 < 500ms 且错误率 < 1%**，可按并发阶梯逐档定位最大健康并发。

## 本地开发

```bash
go mod download
SERVER_STATUS_HOME=./data go run main.go   # 数据/日志/证书都写进 ./data（首次启动会因缺证书退出，按上节自签一份放入 ./data/tls/）
go test ./...
```

## 依赖库

- [gorilla/websocket](https://github.com/gorilla/websocket) - WebSocket
- [shirou/gopsutil](https://github.com/shirou/gopsutil) - 系统监控
- [golang.org/x/crypto](https://golang.org/x/crypto) - bcrypt
- [creack/pty](https://github.com/creack/pty) - 伪终端（Web Shell）

## 许可证

MIT，详见 [LICENSE](LICENSE)。

## 效果图

<table border="1" cellpadding="1" cellspacing="1">
    <tbody>
        <tr>
            <td><img src="img/01-dashboard.png" alt="实时监控仪表盘" width="1920" /></td>
            <td><img src="img/13-dashboard-dark.png" alt="暗黑模式" width="1920" /></td>
        </tr>
        <tr>
            <td><img src="img/02-process.png" alt="进程监控" width="1920" /></td>
            <td><img src="img/09-ebooks.png" alt="电子书阅读" width="1920" /></td>
        </tr>
        <tr>
            <td><img src="img/11-download.png" alt="安全下载令牌" width="1920" /></td>
            <td><img src="img/15-private-gate.png" alt="私人空间密码门" width="1920" /></td>
        </tr>
        <tr>
            <td colspan="2"><img src="img/16-mobile.png" alt="移动端布局" width="390" /></td>
        </tr>
    </tbody>
</table>

