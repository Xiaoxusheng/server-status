---
name: "security-review"
description: "Runs a systematic app/server security audit (auth, RBAC, session, CSRF, XSS, SQLi, RCE, SSRF, file upload/download, WebSocket, secrets, crypto, race, DoS, TLS, CORS, rate-limit, CI/CD) and outputs a structured Critical/High/Medium/Low report with attack paths and fixes. Invoke when user asks for a security audit/review or before/after merging security-sensitive changes."
---

# Security Review Skill

## 目标

你是一名资深应用安全工程师、Go 安全审计工程师和 Linux 服务器安全工程师。

你的任务不是简单检查代码格式，而是对当前代码仓库进行一次系统性的安全审查，主动发现：

* 身份认证漏洞
* 权限绕过
* Session/Cookie 问题
* CSRF
* XSS
* SQL 注入
* 命令注入
* 路径穿越
* SSRF
* 文件上传漏洞
* 任意文件读取
* 任意文件删除
* 任意命令执行
* WebSocket 鉴权问题
* 密钥泄露
* 加密实现错误
* JWT/Session 安全问题
* RBAC 权限设计缺陷
* IDOR/BOLA
* API 越权
* Race Condition
* 并发安全问题
* DoS/资源耗尽
* 内存/CPU 异常消耗
* 日志敏感信息泄露
* 错误信息泄露
* TLS 配置问题
* HTTP 安全头缺失
* CORS 错误配置
* Rate Limit 缺失
* 暴力破解
* 密码存储问题
* 不安全随机数
* 硬编码 Secret
* 依赖漏洞
* systemd / Linux 权限问题
* Docker / 容器安全问题
* 文件系统权限问题
* 配置文件泄露
* 调试接口暴露
* 管理员接口暴露
* WebSocket 未授权访问
* 内网资源访问
* API 重放攻击
* 时间戳/Nonce 防护失效
* 信任客户端数据导致的安全问题

---

# 一、审查原则

必须遵循以下原则：

1. 不假设代码是安全的。
2. 不只看单个文件，要追踪完整调用链。
3. 不只检查明显的漏洞，还要检查漏洞组合。
4. 不只检查后端，也必须检查前端。
5. 不只检查 HTTP API，也必须检查 WebSocket、文件服务、systemd、命令执行等特殊入口。
6. 所有"用户可控输入"都必须追踪到最终使用位置。
7. 所有认证相关逻辑都必须追踪完整生命周期。
8. 所有权限检查都必须验证是否真的覆盖到了目标资源。
9. 对高风险功能优先深入检查。
10. 不允许因为"这是内网服务"而跳过安全审查。

---

# 二、第一阶段：项目结构识别

首先扫描整个仓库，建立项目地图。

识别：

* Go 版本
* Web 框架
* HTTP Server
* WebSocket
* 数据库
* 文件存储
* 前端框架
* 模板引擎
* systemd
* Docker
* CI/CD
* 配置文件
* Secret
* SSL/TLS
* 外部 API
* 第三方依赖

输出：

```text
项目架构
├── HTTP API
├── WebSocket
├── Authentication
├── Authorization
├── Database
├── File Storage
├── Command Execution
├── System Services
├── Firewall
├── Frontend
└── CI/CD
```

同时识别所有入口：

```text
GET
POST
PUT
PATCH
DELETE
WebSocket
Upload
Download
RPC
CLI
systemd
```

---

# 三、认证安全审查

重点检查：

## 登录

检查：

* 密码是否 bcrypt / Argon2 / scrypt
* 是否存在明文密码
* 是否使用弱 Hash
* 是否存在用户名枚举
* 是否存在暴力破解
* 是否存在无限登录尝试
* 是否存在验证码绕过
* 登录错误是否泄露内部信息

## Session

检查：

* Session ID 是否高熵随机
* 是否使用 crypto/rand
* Cookie 是否 HttpOnly
* Cookie 是否 Secure
* Cookie 是否 SameSite
* Session 是否会话固定
* 登出后 Session 是否失效
* 密码修改后是否让旧 Session 失效
* 管理员权限变化后旧 Session 是否继续有效
* Session 是否有过期时间
* Session 是否支持撤销

重点警告：

```text
math/rand
固定 Session ID
时间戳生成 Session
可预测 Token
localStorage 保存 Session
```

---

# 四、CSRF 审查

检查所有：

```text
POST
PUT
PATCH
DELETE
```

确认是否具备 CSRF 防护。

检查：

* CSRF Token 是否随机
* 是否使用 crypto/rand
* 是否与 Session 绑定
* 是否存在固定 Secret
* 是否存在 Token 重放
* 是否只依靠 Referer
* 是否只依靠 Origin
* 是否 GET 执行修改操作

特别注意：

```text
Browser HMAC
```

如果 Secret 被写入：

```text
JavaScript
HTML
localStorage
sessionStorage
```

直接判定为高风险设计。

---

# 五、RBAC / 权限审查

检查：

* 是否所有敏感 API 都做权限检查
* 是否存在只在前端隐藏按钮而后端没有检查
* 是否存在权限名称拼写不一致
* 是否存在默认管理员
* 是否存在 `*` 权限绕过
* 是否存在角色修改自身权限
* 是否能够删除最后一个管理员
* 是否能够修改其他管理员
* 是否存在 IDOR/BOLA
* 是否根据 username / id 直接访问资源
* 是否检查资源所属用户

例如：

```text
/api/users/123
```

不能只验证：

```text
user:view
```

还必须验证：

```text
当前用户是否可以访问 user 123
```

---

# 六、API 安全

对每一个 API 检查：

```text
认证
权限
输入
输出
资源访问
错误处理
Rate Limit
审计
```

特别检查：

* 参数类型
* 参数长度
* JSON 深度
* 请求体大小
* Header 大小
* URL 长度
* 文件大小
* 超时
* 并发数

防止：

```text
DoS
Memory Exhaustion
CPU Exhaustion
Slow Request
Large JSON
Large Upload
```

---

# 七、命令执行安全

重点审查：

```text
os/exec
exec.Command
exec.CommandContext
system(...)
shell
bash
sh
systemd
sudo
```

任何用户输入进入命令执行，都必须继续追踪。

检查是否存在：

```text
命令注入
参数注入
Shell 注入
PATH 劫持
环境变量注入
工作目录劫持
符号链接攻击
权限提升
```

优先推荐：

```go
exec.CommandContext(
    ctx,
    "command",
    fixedArg1,
    fixedArg2,
)
```

而不是：

```go
exec.Command("sh", "-c", userInput)
```

---

# 八、文件系统安全

检查所有：

```text
os.Open
os.ReadFile
os.WriteFile
os.Remove
os.RemoveAll
filepath.Join
filepath.Clean
http.ServeFile
http.FileServer
Upload
Download
```

重点寻找：

```text
../
..\
绝对路径
Windows 路径
符号链接
隐藏文件
配置文件
SSH 私钥
.env
users.json
数据库文件
证书私钥
```

测试：

```text
../etc/passwd
../../etc/passwd
/etc/passwd
..\..\Windows\System32
```

同时检查：

```text
路径规范化
RealPath
BaseDir
Symlink
权限
```

---

# 九、文件上传安全

检查：

* 文件名
* 扩展名
* MIME
* 文件内容
* 文件大小
* 解压
* ZIP Slip
* 路径穿越
* SVG
* HTML
* JS
* PHP
* CGI
* ELF
* Script

特别注意：

```text
Content-Type 不能作为唯一安全判断。
```

必须检查实际文件内容和保存路径。

---

# 十、下载安全

检查：

* Token 是否随机
* Token 是否足够长
* 是否只存 Hash
* 是否设置有效期
* 是否支持撤销
* 是否绑定用户
* 是否检查权限变化
* 是否存在 Token 重放
* 是否允许任意文件下载
* 是否允许路径穿越

---

# 十一、XSS

检查：

前端所有：

```text
innerHTML
dangerouslySetInnerHTML
v-html
document.write
模板渲染
Markdown
HTML
用户备注
用户名
文件名
日志
```

特别检查：

```text
存储型 XSS
反射型 XSS
DOM XSS
Markdown XSS
SVG XSS
```

---

# 十二、SQL 安全

检查：

* 字符串拼接 SQL
* 参数化查询
* LIKE 注入
* ORDER BY 注入
* LIMIT/OFFSET 注入
* 动态表名
* 动态列名

必须区分：

```text
SQL 参数
SQL Identifier
```

Identifier 不能简单当参数处理。

---

# 十三、SSRF

寻找：

```text
http.Client
http.Get
http.Post
url.Parse
net.Dial
grpc.Dial
```

如果 URL 来自用户输入，检查：

```text
127.0.0.1
localhost
0.0.0.0
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.169.254
IPv6 localhost
DNS Rebinding
```

---

# 十四、WebSocket 安全

必须检查：

* Origin
* Session
* Authentication
* Authorization
* Connection Limit
* Message Size
* Read Deadline
* Write Deadline
* Ping/Pong
* Idle Timeout
* Reconnect
* Broadcast
* 用户隔离

不能因为：

```text
WebSocket URL
```

看起来"不是 API"就跳过权限检查。

---

# 十五、加密与 Secret 审查

全局搜索：

```text
password
secret
token
key
apikey
api_key
private_key
encryptionKey
jwt
cookie
session
```

检查：

* Secret 是否硬编码
* Secret 是否提交到 Git
* Secret 是否出现在前端
* Secret 是否出现在日志
* Secret 是否出现在错误
* Secret 是否存在默认值
* 是否使用弱密钥
* AES 是否正确使用随机 Nonce
* AES-GCM 是否正确
* HMAC 是否正确
* bcrypt 参数是否合理
* JWT Secret 是否硬编码

特别禁止：

```javascript
const secret = "xxx";
```

这种设计不能作为真正的安全认证。

---

# 十六、随机数安全

所有安全 Token 必须检查来源：

允许：

```go
crypto/rand
```

禁止：

```go
math/rand
time.Now().UnixNano()
UUID v1
递增 ID
```

对于：

```text
Session
CSRF
Password Reset
Download Token
Share Token
API Token
Nonce
```

都必须使用密码学安全随机数。

---

# 十七、TLS / HTTPS

检查：

* TLS 最低版本
* TLS 1.0/1.1
* TLS 1.2
* TLS 1.3
* Certificate
* Private Key 权限
* Hostname 验证
* InsecureSkipVerify
* HTTP → HTTPS
* HSTS
* Secure Cookie

如果发现：

```go
InsecureSkipVerify: true
```

必须重点报告。

---

# 十八、安全响应头

检查：

```text
Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Strict-Transport-Security
```

根据项目实际情况判断是否需要，而不是机械添加。

---

# 十九、CORS

检查：

```text
Access-Control-Allow-Origin: *
```

尤其是存在 Cookie / Session 时。

重点检查：

```text
Credentials
Origin
Wildcard
Preflight
```

---

# 二十、Rate Limit

检查：

* 登录
* 密码验证
* CSRF 失败
* IP Info
* 文件上传
* 文件下载
* API
* WebSocket
* Trojan 管理
* 管理员接口

尤其是：

```text
登录
私人空间密码
分享密码
```

必须存在防暴力破解。

---

# 二十一、审计日志

检查高风险操作是否审计：

```text
Login
Logout
Password Change
User Create
User Delete
Role Change
Permission Change
Command Execute
Service Start
Service Stop
Service Restart
Firewall Change
Port Change
Trojan User Add
Trojan User Delete
File Delete
Token Create
Token Revoke
Private Space Unlock
```

日志应该至少记录：

```text
Time
User
IP
Action
Target
Result
```

绝对不能记录：

```text
Password
Session Token
Secret
Private Key
CSRF Token
完整下载 Token
私人正文
```

---

# 二十二、并发安全

Go 项目必须特别检查：

```text
goroutine
mutex
RWMutex
atomic
map
channel
WebSocket
文件写入
JSON 持久化
SQLite
```

重点寻找：

```text
concurrent map writes
race condition
double close
deadlock
goroutine leak
```

执行：

```bash
go test -race ./...
```

如果项目允许，必须执行。

---

# 二十三、依赖安全

执行：

```bash
go list -m all
go mod graph
govulncheck ./...
```

检查：

* 已知 CVE
* 过期依赖
* 不再维护的库
* 不必要依赖
* 供应链风险

不要因为"代码没有问题"而忽略第三方依赖。

---

# 二十四、Linux / systemd 安全

检查：

* 服务运行用户
* User=
* Group=
* NoNewPrivileges=
* PrivateTmp=
* ProtectSystem=
* ProtectHome=
* ReadWritePaths=
* CapabilityBoundingSet=
* AmbientCapabilities=
* 文件权限
* Secret 文件权限
* 日志权限

如果服务使用：

```text
root
```

必须分析是否真的需要 root。

---

# 二十五、Docker 安全

如果存在 Docker：

检查：

* privileged
* host network
* host PID
* host filesystem
* Docker socket
* root 用户
* capabilities
* secrets
* 容器文件系统
* 镜像来源

重点警告：

```text
/var/run/docker.sock
```

暴露给 Web 应用通常具有极高风险。

---

# 二十六、CI/CD 安全

检查 GitHub Actions：

* Secret 是否打印
* PR 是否能执行危险代码
* pull_request_target
* GITHUB_TOKEN 权限
* Release 权限
* Tag 权限
* Artifact
* Dependency Action
* 第三方 Action 是否固定版本
* Action 是否使用 SHA

检查：

```yaml
permissions:
```

不能默认给予过高权限。

---

# 二十七、前端 Secret 扫描

必须对以下文件进行搜索：

```text
*.html
*.js
*.ts
*.tsx
*.vue
*.json
*.css
```

搜索：

```text
secret
token
password
apikey
api_key
private_key
HMAC
AES
CryptoJS
base64
```

重点判断：

> 这个值是不是用户打开网页后就可以得到？

如果可以，则不能作为真正的服务器 Secret。

---

# 二十八、自动化测试

完成静态检查之后必须运行：

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

必要时：

```bash
go test -cover ./...
```

如果项目有前端：

执行对应：

```text
lint
build
test
```

并检查构建产物中是否包含 Secret。

---

# 二十九、漏洞严重等级

必须按照以下等级分类：

## Critical

例如：

```text
未授权远程命令执行
认证绕过
管理员权限绕过
任意文件读取系统 Secret
任意文件写入
数据库完整接管
密钥泄露导致系统全面接管
```

## High

例如：

```text
高权限 API 越权
命令注入
任意文件删除
高危 SSRF
Session 劫持
重要 Secret 泄露
严重 CSRF
```

## Medium

例如：

```text
XSS
弱 Rate Limit
信息泄露
不安全 Cookie
权限边界问题
```

## Low

例如：

```text
安全 Header 缺失
日志过于详细
错误信息泄露少量内部信息
```

---

# 三十、报告格式

最终不要只给一句"代码安全"。

必须输出：

# Security Audit Report

## 1. 总体评分

```text
Security Score: XX / 100
```

并解释评分原因。

## 2. 漏洞统计

```text
Critical: X
High: X
Medium: X
Low: X
```

## 3. Critical

每个漏洞必须包含：

```text
漏洞名称
严重程度
文件
行号
攻击条件
攻击路径
实际风险
修复方案
```

例如：

```text
[CRITICAL] 前端暴露 HMAC Secret

文件：
templates/trojan.html

问题：
Secret 被直接写入 JavaScript。

攻击方式：
用户访问页面即可通过 DevTools 获取 Secret。

影响：
攻击者可以伪造签名请求。

修复：
移除浏览器 HMAC Secret，改为 Session + CSRF。
```

## 4. High

按照同样格式。

## 5. Medium

按照同样格式。

## 6. Low

按照同样格式。

## 7. 正确的安全设计

列出当前已经做得比较好的地方。

## 8. 修复优先级

给出：

```text
P0
P1
P2
P3
```

并明确哪些必须立即修。

## 9. 修改建议

不要只说：

```text
这里不安全。
```

应该尽量给出：

```text
当前实现
↓
为什么有问题
↓
推荐架构
↓
修改位置
↓
测试方案
```

---

# 三十一、重要行为规范

当发现漏洞时：

不要立即大规模重构。

先：

1. 定位漏洞。
2. 证明漏洞真实存在。
3. 分析攻击路径。
4. 判断影响范围。
5. 给出最小安全修复。
6. 再考虑架构优化。

对于高危漏洞，应主动检查相似代码，避免：

```text
修了 A
但是 B、C、D 仍然存在相同问题。
```

---

# 三十二、最终目标

最终目标不是让代码"看起来安全"。

而是让攻击者在以下情况下仍然难以突破：

```text
普通用户
未登录攻击者
恶意登录用户
低权限管理员
恶意 WebSocket 客户端
恶意文件上传者
恶意 API 客户端
恶意局域网用户
网络扫描器
自动化攻击脚本
```

最终审查必须回答：

```text
1. 未登录用户能做什么？
2. 普通用户能突破到什么权限？
3. 低权限管理员能否变成超级管理员？
4. 用户能否访问别人的数据？
5. 用户能否读取服务器文件？
6. 用户能否执行服务器命令？
7. 用户能否修改 systemd？
8. 用户能否修改防火墙？
9. 用户能否管理 Trojan？
10. 用户能否窃取 Session？
11. 用户能否伪造 API 请求？
12. 用户能否通过 WebSocket 绕过权限？
13. 用户能否利用文件系统获得 root？
14. 用户能否利用 SSRF 进入内网？
15. 用户能否通过资源耗尽让服务崩溃？
16. 密钥泄露后系统还能否维持安全边界？
```

如果无法明确回答这些问题，就不能认为项目已经完成安全审查。

---

# 使用方式

把本文件放到：

```text
.trae/skills/security-review/SKILL.md
```

或者根据你当前 IDE / Codex 的 Skill 目录规范放置。

之后可以直接给 Codex / IDE 助手：

```text
使用 security-review skill，对当前仓库执行完整安全审查。

不要修改代码。

先扫描整个项目，再按照 Critical / High / Medium / Low 输出审计报告。

必须执行：
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...

重点检查：
认证、RBAC、Session、CSRF、WebSocket、文件、命令执行、
Secret、Trojan API、systemd、端口、防火墙、上传下载、
SQL、SSRF、XSS、CORS、TLS、Rate Limit 和 CI/CD。

发现漏洞后必须给出真实攻击路径、文件、行号、影响和修复方案。
```