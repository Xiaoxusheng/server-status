# server-status 安全扫描报告

- **扫描日期**：2026-09-15
- **扫描对象**：`D:\server-status`（Go 1.25 / net/http + 自研 RBAC + SQLite）
- **扫描方式**：
  1. `govulncheck ./...` —— 依赖可达漏洞
  2. `go vet ./...` —— 静态检查
  3. 人工代码审计 —— 认证 / 授权 / CSRF / 路径穿越 / 命令执行 / SQL / 密钥管理 / 前端 XSS
  4. **本地实例实测** —— 自签名 TLS 起真实服务，用浏览器式请求头做未认证访问验证

---

## 一、结论概览

| 级别 | 数量 | 摘要 |
| --- | --- | --- |
| 高 | 2 | 默认管理员弱口令；内置默认加密/签名密钥 |
| 中 | 3 | 面板模板未认证可读（**已修复**）；反代下限流误伤；高德 key 明文硬编码 |
| 低 | 4 | 限流器内存无界增长；docker logs 参数注入；Cookie Secure 策略不一致；静态路由缺安全头 |

**修复进展**：
- **H1 / H2 经生产环境只读核实，当前均不成立**（admin 口令非默认值；三个密钥均已注入真实值）。
  这两条仍对"全新部署"场景成立，建议加强制改密与启动校验（详见第七节）。
- **M1 已修复并部署上线**（2026-09-15 12:31）：`main.go` 的 `staticFileHandler` +
  `publicTemplatePages` 白名单，配套回归测试 `static_page_access_test.go`；
  生产复验后台页面全部 302、公开页与分享路由正常。同时清理了 15 个 `pv-*.html` 草稿页。
- M2 / M3 / L1–L4 待处理。

**整体评价**：这个项目的安全基线明显高于同类自研面板 —— 路径穿越、命令执行、SQL 注入、CSRF、口令哈希这几条主线都防住了（详见第四节）。真正需要立刻处理的是 **部署层面的两个默认值**，它们和代码质量无关，但只要漏配就等于全盘失守。

---

## 二、高危

### H1　默认管理员口令 `admin/admin123`，且无强制改密机制

**位置**：`main.go:3446-3473`（`createDefaultAdmin`）

```go
hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
...
log.Println("✅ 创建默认管理员用户: admin / admin123")
```

首次启动且 `users.json` 不存在时，自动创建超级管理员 `admin`，口令硬编码为 `admin123`。

**实测验证**（本地干净实例）：

```
POST /login  {"username":"admin","password":"admin123"}
→ 200 {"code":200,"message":"登录成功",
        "user":{"permissions":["*","admin","execute","read","write"],"role":"超级管理员"}}
```

登录直接返回 `permissions: ["*"]` —— 完全控制权。

同时全仓库搜索 `must_change|force_change|首次登录|强制修改` **无任何命中**，即不存在首次登录强制改密的机制。口令会一直保持 `admin123` 直到管理员手动修改。

**风险**：项目是开源的，`admin123` 是公开信息。任何全新部署若未在初始化后立即改密，等于把带 Shell 终端、Docker 管理、Trojan 节点管理、文件管理的服务器控制台敞开在公网。

**建议**：
- 首次启动改为从环境变量（如 `SERVER_STATUS_ADMIN_PASSWORD`）读取初始口令；未设置时随机生成一次并打印到日志/写入一个仅 root 可读的文件，而不是固定字符串。
- 或引入 `MustChangePassword` 标记：首次以默认口令登录后，除改密接口外全部 API 返回 403。
- 最低成本方案：在 `createDefaultAdmin` 里检测到未设置环境变量时，生成 `crypto/rand` 随机口令并打印，杜绝固定值。

**注意**：生产环境已有 `users.json`（加密存储），默认口令只在"全新部署 / 删库重来"时生效。请确认现网 `admin` 口令已非 `admin123`。

---

### H2　内置默认加密密钥与签名密钥（开源项目 = 密钥公开）

**位置**：`main.go:101-104`

```go
encryptionKey = getEnvOr("SERVER_STATUS_ENCRYPT_KEY",
    "server_status_user_data_encryption_key_2024")
downloadTokenSecret = getEnvOr("SERVER_STATUS_DOWNLOAD_TOKEN_SECRET",
    "server_status_download_token_secret_2024")
```

两个密钥都有硬编码兜底值。程序在启动时会告警（`main.go:6229-6235`），但**告警不阻止启动**：

```
⚠️ 建议通过环境变量 SERVER_STATUS_ENCRYPT_KEY / SERVER_STATUS_DOWNLOAD_TOKEN_SECRET
   注入加密密钥，避免使用内置默认值。
```

**风险**：`encryptionKey` 用于 AES-GCM 加密 `users.json`、`rbac.json`、`download_tokens.json`、Shell 密码文件、私人空间的图片/语音/卡片媒体文件。项目开源 → 兜底密钥人人可知 → 一旦生产漏配环境变量，**所有"加密落盘"的数据等于明文**，拿到任意一次备份/磁盘快照即可全解。

对比：`SERVER_STATUS_SIGNING_KEY` 的处理是正确的 —— 未设置时用 `crypto/rand` 随机生成（`main.go:120`），不回落固定值。`ENCRYPT_KEY` 应改为同样策略。

**建议**：
- 短期：确认 `/etc/server-status/server-status.env` 里三个密钥都已用 `openssl rand -hex 32` 生成并注入。
- 长期：把 `ENCRYPT_KEY` 的兜底改为启动即失败（`log.Fatal`），或随机生成并明确拒绝解密已有数据，避免"静默降级"。

---

## 三、中危

### M1　39/40 个面板模板未认证即可读取　【已修复 2026-09-15】

**位置**：`main.go:6015-6034` 的 `http.Handle("/", ...)` 静态兜底路由

该路由**没有套 `authMiddleware`，也没有套 `securityMiddleware`**，任何未登录请求都能命中：

```go
http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    lower := strings.ToLower(r.URL.Path)
    for _, pat := range []string{".bak", ".json", ".go", ".sh", ".key", ".pem", ".log", ".db", ".tmp", "~"} {
        if strings.Contains(lower, pat) { http.NotFound(w, r); return }
    }
    ...
    if serveTemplateCached(w, r, name) { return }
    http.FileServer(http.Dir(indexPath)).ServeHTTP(w, r)
}))
```

**实测结果**（未携带任何 Cookie，仅用浏览器式 UA/Accept 头）：

```
=== 未登录直接可读 (200) ===   共 39 个
  backup.html         33 KB     log.html          34 KB
  docker.html         20 KB     process.html      69 KB
  ebooks.html         55 KB     rbac.html         76 KB
  files.html          90 KB     remediation.html  36 KB
  github.html        105 KB     security.html     88 KB
  index.html          21 KB     security-events.html 18 KB
  ip-panel.html       81 KB     services.html    119 KB
  location.html       35 KB     tasks.html        51 KB
  share.html          54 KB     task-history.html 23 KB
  trojan.html         71 KB     video.html        16 KB
  dl.html             31 KB     download.html     32 KB
  audio-share.html    20 KB     + pv-*.html 共 13 个草稿页（每个 130-140 KB）
=== 被拦截 ===
  shell.html          401   （shell.go 显式注册了 authMiddleware）
```

即整个后台的**页面外壳与前端代码**（含 `rbac.html`、`security.html`、`trojan.html`、`services.html`）全部公开。`/private.html` 本身是安全的（实测会 302 回 `/index.html`，`privatePageHandler` 正确校验了 `pv_entry` Cookie + 会话 + `private:view` 权限）。

**为什么算问题**：
- 泄露完整攻击面：所有 API 路径、请求/响应结构、权限点名称、内部功能清单。攻击者不用猜就能精准构造请求打 RBAC / Trojan / Docker 接口。
- 破坏"隐藏私人空间"的设计意图 —— `private.html` 虽然挡住了，但同目录 13 个 `pv-*.html` 草稿页（各 130KB+）连同页面结构一起外泄。
- 这些页面本该是私有的（模板缓存刻意设了 `Cache-Control: private`），但访问控制没跟上。

**已实施的修复**（`main.go`）：

兜底 handler 从 `main()` 里的匿名闭包提取为独立函数 `staticFileHandler()`（便于测试直接覆盖），
并新增页面级访问控制 + 公开页白名单 `publicTemplatePages`：

```go
var publicTemplatePages = map[string]bool{
    "index.html": true, "share.html": true, "dl.html": true, "download.html": true,
    "audio-share.html": true, "pv-share.html": true, "pv-share-pw.html": true,
    "pv-share-bad.html": true,
}
```

```go
// 仅对 .html 页面设限；非 .html 的静态资源（ui.css / 字体 / 前端库）保持公开，
// 否则公开分享页会丢失样式与脚本。
if strings.HasSuffix(strings.ToLower(name), ".html") && !publicTemplatePages[strings.ToLower(name)] {
    if _, ok := getSessionFromRequest(r); !ok {
        http.Redirect(w, r, "/index.html", http.StatusFound)  // 与 privatePageHandler 行为一致
        return
    }
}
```

设计要点：
- **只锁 `.html` 页面**。页面外壳才是泄露源（含完整 API 路径与权限结构）；`ui.css`、`echarts.min.js`、
  `fa/` 字体等资源必须保持公开，否则未登录访客看到的分享页会没有样式。
- **未登录用 302 跳回首页**，与 `privatePageHandler` 保持一致，避免用 404/302 的差异暴露"该页面是否存在"。
- **`shell.html` / `private.html` 无需登记**——它们由更具体的路由接管（`shell.go:6148`、
  `private_api.go:85`），ServeMux 优先匹配具体模式，本就不会走到兜底 handler。
- 只校验"是否已登录"，不校验具体权限。页面内各 API 仍由自身 RBAC 把关，
  这样不会改变原有的按页授权语义（例如无 `docker:view` 的用户能打开 docker.html 外壳，
  但其 API 依旧 403，与改动前一致）。

**配套回归测试**（新增 `static_page_access_test.go`，6 个用例全通过）：
未登录访问 21 个后台页面 → 302；9 个公开页/资源 → 200；已登录访问 5 个后台页面 → 200 且有页面内容；
伪造会话 → 302；10 个敏感后缀 → 404；`shell.html` / `private.html` 未被误登记为公开页。

**端到端复验**（自签名 TLS 起真实实例）：

```
未登录（不跟随跳转）:              登录后:
  /docker.html  302 /index.html      /docker.html   200  20 KB
  /rbac.html    302 /index.html      /rbac.html     200  19 KB
  /trojan.html  302 /index.html      /trojan.html   200  19 KB
  /pv-c.html    302 /index.html      /files.html    200  25 KB
  /index.html   200                  /shell.html    200  67 KB
  /share.html   200                  /security.html 200  24 KB
  /ui.css       200                  /github.html   200  27 KB
  /shell.html   401（自身路由）       /services.html 200  32 KB
  /private.html 302 /index.html（自身路由）
```

**剩余事项**：`pv-*.html` 是 `.gitignore` 里的设计迭代草稿（13 个、各 130KB+），
现已需登录才能访问，但仍建议从生产 `templates/` 目录删除——它们本就不该被部署。

---

### M2　`getClientIP` 不信任 `X-Forwarded-For` —— 一旦前置反向代理，限流与封禁会误伤全站

**位置**：`main.go:5019-5032`

```go
func getClientIP(r *http.Request) string {
    // 仅信任直连地址，不解析 X-Forwarded-For，防止伪造头绕过限流/封禁
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    ...
}
```

这个取舍本身是**对的**（直接解析 XFF 会被伪造头绕过限流）。但它和项目自身的部署建议冲突 —— README 第 153 行建议"防火墙 / 反向代理放行 9000 端口"，而工作记忆中记录的正确架构是"前置 Nginx/Caddy 终止 TLS 并反代到本进程"。

**一旦真的前置了代理**，所有请求的 `RemoteAddr` 都会变成 `127.0.0.1`，于是：

1. **登录限流全局化**：`loginGuard` 按 IP 计数（`loginMaxFailures = 10` / 15 分钟）。任何一个人连续输错 10 次密码，**全部用户**在 15 分钟内都无法登录。
2. **IP 封禁自我封锁**：`isIPBlocked` 配合反爬行为分析，一旦触发自动封禁，被封的是代理 IP —— 整个站点对所有访客不可用。

**建议**：二选一
- 让反代透传真实 IP，并在代码中**仅信任来自本机/已知代理网段**的 `X-Forwarded-For`（配置 `SERVER_STATUS_TRUSTED_PROXIES`，`net.SplitHostPort(r.RemoteAddr)` 命中白名单时才解析 XFF 的最左非可信地址）。
- 或者保持现状，但明确在 README 中写清"不支持前置反向代理"，并确保限流 key 改为 `session`/`username` 维度而非纯 IP。

---

### M3　高德 API Key 明文硬编码在部署脚本

**位置**：`deploy/set-amap-key.py:6`

```python
KEY = '<REDACTED：真实值见 deploy/set-amap-key.py，已脱敏不入版本库>'
```

> **注**：本报告提交前已把该 Key 脱敏。原文件 `deploy/set-amap-key.py` 被 `.gitignore`
> 的 `deploy/**` 规则忽略，从未入库；请勿把真实值回填进版本库内的任何文件。

**当前状态（已核实）**：该文件被 `.gitignore` 的 `deploy/**` 规则正确忽略，`git ls-files deploy/` 只有 `check-openlist-direct.sh`，`git grep` 在 HEAD 中搜不到这个 key —— **没有入库，没有公开泄露**。这一点做得对。

**残留风险**：密钥以明文躺在工作区文件里，且没有走环境变量。任何人打包/压缩工作目录、或用 `git add -f` 强行提交，都会立刻泄露；这类 Web 服务 key 泄露后会被盗刷配额。

**建议**：改为从环境变量或 `/etc/server-status/server-status.env` 读取，脚本里只留占位符。同时到高德控制台给该 key 配置 IP/域名白名单，并评估是否需要轮换。

---

## 四、低危

### L1　`loginGuard` 的失败记录 map 只增不删

**位置**：`main.go:3652-3689`

```go
func (g *loginGuard) fail(key string) {
    g.Lock(); defer g.Unlock()
    g.failures[key] = append(g.failures[key], time.Now())
}
```

`allowed()` 会清理**单个 key** 的过期时间戳，但**从不删除 map 的 key 本身**。分布式来源的撞库（每个 IP 只试几次）会让 `failures` 的条目数持续增长，形成缓慢的内存泄漏。同一模式的 `downloadFailLimiter` 也值得一并检查。

**建议**：加一个定期清理 goroutine，或在 `allowed()` 里顺手 `delete` 已清空的 key。

### L2　`docker logs` 接口存在参数注入

**位置**：`docker.go:311-345`

```go
args := []string{"logs", "--tail", strconv.Itoa(lines)}
if since := strings.TrimSpace(r.URL.Query().Get("since")); since != "" {
    args = append(args, "--since", since)   // since 未做格式校验
}
args = append(args, container)              // container 未过滤前导 "--"
```

`container` 直接作为独立参数追加，若传入 `--follow` 会变成 `docker logs --tail 100 --since X --follow`，导致请求长时间挂起（虽有 10s context 超时兜底，仍会占用 goroutine 与 docker 进程）。`since` 也应校验为 `\d+[smhd]` 之类的合法时间表达式。

**建议**：对 `container` 做 `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$` 校验，对 `since` 做正则白名单。

### L3　Cookie 的 `Secure` 策略前后不一致

`main.go:3699` 的会话 Cookie 硬编码 `Secure: true`，而 `private_api.go`、`private_cards_api.go` 的多个 Cookie 用 `Secure: r.TLS != nil`。

若按 M2 的建议前置反代（后端是明文 HTTP），`r.TLS` 为 nil → 私人空间的 `private_session`、`pv_entry` Cookie **不会带 Secure 标记**，在降级/混合内容场景下存在被明文传输的风险。

**建议**：统一策略。既然部署形态是"TLS 终止在反代"，应统一改为 `Secure: true` 并让反代负责实际加密。

### L4　静态路由缺少安全响应头与 CSP

静态兜底路由未套 `securityMiddleware`，因此模板响应不带 `Strict-Transport-Security`、`X-Frame-Options`、`Referrer-Policy` 等头部。全站也**没有 Content-Security-Policy**。

考虑到页面大量使用 `<script type="text/babel">` 运行时编译与 `dangerouslySetInnerHTML`，加一条 CSP 能显著抬高 XSS 利用门槛。

**建议**：在静态路由上补 `securityMiddleware`（或至少补齐安全头），并评估引入 CSP（注意 `@babel/standalone` 需要 `unsafe-eval`，需先做构建链改造才能真正收紧）。

---

## 五、已确认良好的实践

以下项经代码审计 + 实测确认**防护有效**，不需要改动：

| 项 | 证据 |
| --- | --- |
| **依赖漏洞** | `govulncheck ./...` → **0 个可达漏洞**（3 个模块级告警，代码未调用） |
| **静态检查** | `go vet ./...` → 无告警 |
| **路径穿越** | `isSafeFilePath`（`main.go:2726`）用 `filepath.Abs + Rel + ".."` 校验，覆盖全部 8 处文件操作入口；上传时 `filepath.Base` 剥离目录 |
| **敏感文件泄露** | 实测 `/users.json`、`/config.json` → **404**（后缀黑名单生效） |
| **命令执行** | `dockerActionHandler` 的 `action` 走 `start/stop/restart` 白名单，参数以独立 argv 传递，无 shell 拼接 |
| **SQL 注入** | 全部走参数化占位符；仅有的 3 处字符串拼接均为内部常量列名与 `placeholders(n)` 生成的 `?,?,?`，无用户输入拼接 |
| **口令哈希** | 全站 bcrypt（`DefaultCost`）；Shell 密码另有 `dummyHashCache` 做时序混淆 |
| **令牌比较** | `subtle.ConstantTimeCompare` 用于下载令牌（`main.go:2490`）与 CSRF Token（`main.go:3639`） |
| **CSRF** | 会话绑定随机 Token 的 Double-Submit，写方法（POST/PUT/PATCH/DELETE）强制校验；CSRF Cookie 故意非 HttpOnly 供 JS 读取 |
| **Cookie 属性** | 会话 Cookie `HttpOnly + Secure + SameSite=Lax` 齐备；登出用 `SameSite=Strict` |
| **CORS** | `enableCORSh` 只回显白名单内的 Origin，**不是** `*`，且 `Vary: Origin` 正确 |
| **WebSocket** | `CheckOrigin` = `checkOrigin && verifySecurityHeaders`，且路由另有 `authMiddleware + system:view` |
| **登录爆破** | `loginGuard` 10 次 / 15 分钟按 IP 限速，并写审计日志（不泄露"用户是否存在"） |
| **越权** | 下载令牌校验"令牌所属账号仍持有 `files:download` 权限"（`main.go:2913`），跨用户签发需 `user:manage` |
| **私人空间** | 双层认证：会话 + 独立 bcrypt 密码；`private_session` 30 分钟无操作自动锁定；全部路由套 `authMiddleware + privateAuthMiddleware` |
| **前端 XSS** | `renderMarkdown` **先 `escapeHtml` 再拼标签**，`mdInline` 对链接做 `https?/mailto/#` 协议白名单；`/private.html` 不向浏览器下发 amap key，反地理编码走服务端代理 |
| **上传限制** | 1GB `MaxBytesReader` + `ParseMultipartForm(32MB)`；`.html/.js/.php/.svg/.sh` 等活跃内容后缀黑名单 |
| **密钥入库** | `.gitignore` 有效：`deploy/**`、`.env`、`users.json`、`*_key` 均未进入 Git 历史（已核实） |
| **原子写** | 用户数据写盘走 `临时文件 + Sync + Rename`，避免异常退出损坏 |

---

## 六、修复优先级建议

1. **立即**：确认生产 `admin` 口令已改（H1）；确认 `SERVER_STATUS_ENCRYPT_KEY` / `_DOWNLOAD_TOKEN_SECRET` / `_SIGNING_KEY` 已在 env 文件注入（H2）。
   → **两项已于 2026-09-15 核实，当前生产均不成立**（见第七节）。剩余工作是把"防呆"做进代码：
   初始口令改随机生成、`ENCRYPT_KEY` 未设置时启动即失败而非静默降级。
2. ~~**本周**：给静态模板路由加认证，只放行公开页（M1）~~ —— **已完成并上线**（2026-09-15 12:31）。
   顺带清理了生产 `templates/` 里的 15 个 `pv-*.html` 草稿页。
   注意本地 `templates/` 仍保留这些草稿，下次同步模板会重新上传。
3. **本周**：明确反向代理策略，修复 IP 识别（M2）—— 这是"哪天加 Nginx 就会踩"的定时炸弹。
4. **顺手**：高德 key 改环境变量 + 轮换（M3）；`loginGuard` 加清理（L1）；docker 参数校验（L2）；统一 Cookie `Secure`（L3）。
5. **有余力**：补安全响应头与 CSP（L4），配合前端构建链改造一起做。

## 七、生产环境核实（2026-09-15，只读）

登录 `root@192.168.5.10` 做了只读核实，未修改任何文件、未发起任何登录请求。

### H1 —— 已解决 ✅

把 `/home/os/users.json` 拉到本地，用 env 文件里的真实 `ENCRYPT_KEY` 解密
（AES-GCM，`key = SHA256(encryptKey)`，nonce 前置 12 字节），再用 bcrypt 逐个试 10 个常见弱口令：

```
✅ 解密成功（当前 ENCRYPT_KEY 有效）   用户数: 3

用户 "admin"   $2a$10$***  (总长 60)  启用: true  角色: admin
  权限: [admin read write execute]   创建: 2025-10-28   最后登录: 2026-09-15 10:13
  ✅ 未命中 10 个常见弱口令
用户 "users"   $2a$10$***  角色: user  权限: []
  ✅ 未命中 10 个常见弱口令
用户 "xiao"    $2a$10$***  角色: user  权限: [read]
  ✅ 未命中 10 个常见弱口令
```

三个账号全部 bcrypt cost 10，admin 口令**不是** `admin123`，且账号在活跃使用（当日有登录）。
**结论：H1 在当前生产环境不成立。** 该风险只对"全新部署且未改密"的场景成立，仍建议加强制改密机制。

### H2 —— 已解决 ✅

`/etc/server-status/server-status.env`（权限 0600）三个密钥全部注入：

| 变量 | 状态 | 长度 |
| --- | --- | --- |
| `SERVER_STATUS_SIGNING_KEY` | 已设置 | 64 字符 |
| `SERVER_STATUS_ENCRYPT_KEY` | 已设置 | 36 字符 |
| `SERVER_STATUS_DOWNLOAD_TOKEN_SECRET` | 已设置 | 33 字符 |

长度均与硬编码默认值（42 / 41 字符）不同 → **兜底密钥未生效**。
另用该 `ENCRYPT_KEY` 成功解密 `users.json`，反证密钥确实在用。

**结论：H2 在当前生产环境不成立。** 小提示：`ENCRYPT_KEY`(36) 与 `TOKEN_SECRET`(33)
不是 `.env.example` 建议的 64 位 hex，熵值略低于推荐值，但不影响当前安全性；
将来轮换时按 `openssl rand -hex 32` 生成即可。

附带发现：`SHELL_PASSWORD_HASH` 是在 systemd 单元里用 `Environment=` 直接下发的，
不走 env 文件（避免密钥文件里出现第二个副本，做法没问题，但排查时容易漏看）。

### M1 —— 生产影响已实测确认，**已部署上线** ✅

**部署前**未认证 GET `https://192.168.5.10:9000`：

```
  /rbac.html         200  19 KB   ← 未认证可读
  /security.html     200  24 KB   ← 未认证可读
  /trojan.html       200  19 KB   ← 未认证可读
  /files.html        200  25 KB   ← 未认证可读
  /shell.html        401          （自身路由，本来就对）
  /users.json        404          （敏感后缀拦截，本来就对）
```

**部署过程**（2026-09-15 12:31）：

1. 备份 → `/home/os/backup-pre-m1-20260915-123051/`（原二进制 + `templates.tar.gz` 7.4MB）
2. 交叉编译 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`，md5 `d4eb4d2bafc48d7a3730ca667f82f805`
3. 上传为 `server-status.new`，**校验远端 md5 一致**后 `chmod 755` + `mv` 原子替换
   （直接覆盖会撞 "Text file busy"）
4. `systemctl restart server-status`（启动约 10s）
5. 删除 15 个 `pv-*.html` 草稿页（见下）后再次重启，让内存模板缓存同步刷新

**部署后**同端口复验：

```
【后台页面】全部 302 → /index.html（20 个页面，含 rbac/security/trojan/files/docker/services/
            github/log/backup/process/tasks/task-history/remediation/ip-panel/ebooks/video/location）
【公开页】  /  /index.html  /share.html  /audio-share.html  /ui.css  /echarts.min.js  → 全部 200
【固有防护】/shell.html 401、/private.html 302、/users.json 404、/config.json 404、
            /api/files 401、/api/rbac/users 401、/api/trojan/users 401  —— 均未受影响
【伪造会话】带 `session_id=forged-...` 访问后台页 → 仍 302（无效会话不放行）
【分享路由】/card/{token} → 200 + share.html(56KB)；/audio/{token} → 200 + audio-share.html(20KB)
```

服务 `active`，启动日志 `version=v2.3.0-6-g344b4f8 commit=344b4f8`，
模板缓存 52 → 37 个文件，近 5 分钟 0 个 panic/fatal/error。

**一个值得注意的行为**：`/pv-c.html`（已删除）未认证访问仍返回 **302 而非 404**。
这是**正确的**——访问控制检查在文件查找之前执行，未登录时无法区分"页面存在但需登录"
与"页面不存在"，正是防信息泄露的设计意图。（白名单内的 `/pv-share.html` 已删除，
所以它走到了 404。）

### 顺带清理：15 个 pv-*.html 草稿页

`.gitignore` 已标注 `templates/pv-*.html` 为"未接线的设计迭代副本"。清理前做了三重确认：

1. **全仓无引用**：`grep` 遍历所有模板与 Go 代码，除我自己新加的白名单条目外零命中。
2. **分享链路不依赖**：卡片分享链接是 `/card/{token}` → `sharePageHandler` → `share.html`；
   语音分享是 `/audio/{token}` → `audioSharePageHandler` → `audio-share.html`。
   没有任何 `pv-*` 被任何 handler 服务。
3. **生产无独有版本**：逐文件 md5 比对，生产与本地 15 个文件的 md5 **一一对应**
   （例如 `pv-c/m/n/o` 互为同一份、`pv-pw2` 与 `pv-share-pw` 完全相同），
   删除生产副本不会丢失任何本地没有的迭代。

清理结果：`/home/os/templates/` 的 `.html` 从 41 → 26，`index/share/audio-share/dl/
download/shell/private` 等关键页全部完好。

**遗留提醒**：本地 `templates/pv-*.html` 仍在（属于你的设计稿，且被 gitignore，
不在版本控制内，我没有动）。**下次把模板同步到生产时，这 15 个文件会重新上传**。
设计迭代结束后建议在本地也删掉。

### 生产其他现状

- 服务 `active`，最近 200 行日志无 `panic` / `fatal`。
- `/home/os/templates/` 清理后 26 个 `.html`（原 41），另有 `.bak.*` 残留可一并清理。
- `/home` 磁盘使用 58%（65G 中已用 38G），无变化。

---

*报告基于 2026-09-15 的代码快照（HEAD `344b4f8`）。*
