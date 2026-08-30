# Trojan-Go 监控与管理（server-status 集成）

本模块把 Trojan-Go v0.10.6 的 gRPC API（`127.0.0.1:10000`）接入现有 server-status 面板：

```
浏览器 ──HTTPS/WS──▶ server-status ──gRPC──▶ 127.0.0.1:10000 ──▶ Trojan-Go
```

浏览器不会直接访问 Trojan-Go gRPC 端口；所有状态拉取、用户增删改都经过 server-status 的
认证（登录会话 + RBAC `trojan:manage` 权限 + HMAC 签名头）。

## 1. 配置文件（完整内容）

`config.json`（放在 `/opt/server-status/config.json`，与 `private_notes.json` 同级）：

```json
{
  "trojan": {
    "enabled": true,
    "api_addr": "127.0.0.1:10000",
    "api_timeout": 5,
    "refresh_interval": 2
  }
}
```

说明：

- `enabled`：是否启用 Trojan-Go 模块（false 时页面显示 Offline，不影响其他监控）。
- `api_addr`：Trojan-Go gRPC 地址，默认仅本机回环 `127.0.0.1:10000`。
- `api_timeout`：单次 gRPC 调用超时（秒）。
- `refresh_interval`：状态刷新间隔（秒），建议 1~2 秒。

环境变量可覆盖配置文件（便于临时调试）：
`SERVER_STATUS_TROJAN_ENABLED`、`SERVER_STATUS_TROJAN_API_ADDR`、
`SERVER_STATUS_TROJAN_API_TIMEOUT`、`SERVER_STATUS_TROJAN_REFRESH_INTERVAL`。

## 2. Trojan-Go config.json 需要增加的内容

你的 Trojan-Go 配置已包含（确认 `api_addr`/`api_port` 只监听回环）：

```json
{
  "api": {
    "enabled": true,
    "api_addr": "127.0.0.1",
    "api_port": 10000
  }
}
```

安全要求：**绝不能改成 `0.0.0.0:10000`**，gRPC 管理接口只允许本机访问。
数据服务端口保持 `8388`。

## 3. 如何启动 Trojan-Go

```bash
cd /opt/server-status/trojan   # 实际 trojan-go 目录
./trojan-go -config config.json > trojan.log 2>&1 &
# 或使用 systemd：
# systemctl start trojan-go
```

启动后验证 gRPC 端口：

```bash
ss -tlnp | grep 10000   # 应看到 127.0.0.1:10000 处于 LISTEN
```

## 4. 如何启动 server-status

```bash
cd /opt/server-status
go build -o server-status -ldflags "-w -s" .
sudo systemctl restart server-status
```

查看日志确认 Trojan 客户端已连接：

```bash
journalctl -u server-status -n 50 --no-pager | grep -i trojan
```

正常会看到：

```
Trojan-Go 客户端已启用，API: 127.0.0.1:10000，刷新间隔: 2s
```

## 5. systemd 配置（/etc/systemd/system/server-status.service）

仓库根目录已附带示例 `server-status.service`，安装方式：

```bash
sudo cp /opt/server-status/server-status.service /etc/systemd/system/server-status.service
sudo systemctl daemon-reload
sudo systemctl enable --now server-status
```

文件内容：

```ini
[Unit]
Description=Server Status Monitor Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/server-status
ExecStart=/opt/server-status/server-status
LimitNOFILE=65535
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```

## 6. 如何测试 gRPC

本地跑内存集成测试（无需真实 Trojan-Go，模拟 v0.10.6 服务端语义）：

```bash
go test -run TestTrojanClientIntegration -v
```

真实环境直接执行：

```bash
go test -v ./...
```

也可以临时把 `config.json` 的 `api_addr` 指向测试地址，观察
`journalctl -u server-status | grep Trojan` 的输出。

## 7. 如何测试 Web API

所有接口都要求登录 session + `trojan:manage` 权限；写操作（POST/PUT/DELETE）还需 CSRF
校验（Double-Submit：请求头 `X-CSRF-Token` 必须等于登录会话绑定的 `csrf_token` Cookie）。
> 不再使用浏览器端 HMAC 签名头（X-Timestamp/X-Nonce/X-Signature 已被移除，服务端不再校验）。

带 Cookie 的 curl 示例（先登录拿到 `session_id` 与 `csrf_token`）：

```bash
# 1. 登录（同时下发 HttpOnly 的 session_id 与 JS 可读的 csrf_token Cookie）
curl -k -c /tmp/ss.jar -X POST https://192.168.1.10:9000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"你的密码"}'

# 2. 从 Cookie 中取 CSRF Token（Double-Submit：头 = Cookie）
CSRF=$(grep csrf_token /tmp/ss.jar | awk '{print $7}')

# 3. 状态（GET，无需 CSRF）
curl -k -b /tmp/ss.jar "https://192.168.1.10:9000/api/trojan/status"

# 4. 用户列表（GET，无需 CSRF）
curl -k -b /tmp/ss.jar "https://192.168.1.10:9000/api/trojan/users"

# 5. 添加用户（POST，需 CSRF 头；限速单位 B/s：10 MB/s = 10485760）
curl -k -b /tmp/ss.jar -X POST "https://192.168.1.10:9000/api/trojan/users" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"password":"MyPass123","upload_limit":10485760,"download_limit":52428800,"ip_limit":5}'

# 6. 修改用户（PUT，需 CSRF 头；用列表里返回的 hash）
curl -k -b /tmp/ss.jar -X PUT "https://192.168.1.10:9000/api/trojan/users" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"hash":"<用户hash>","upload_limit":10485760,"download_limit":104857600,"ip_limit":8}'

# 7. 删除用户（DELETE，需 CSRF 头）
curl -k -b /tmp/ss.jar -X DELETE "https://192.168.1.10:9000/api/trojan/users" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"hash":"<用户hash>"}'
```

注意：上面示例便于说明流程，实际操作建议直接使用面板 UI（前端会自动携带 CSRF Token）。

未登录访问任一接口会返回 `401`；无 `trojan:manage` 权限返回 `403`；写请求缺/错 CSRF 返回 `403`。

## 8. 浏览器访问地址

```text
https://192.168.1.10:9000/
```

登录后 Dashboard 底部会出现 **Trojan-Go** 模块：

首页只显示一张 **Trojan-Go 概览卡片**（与 IP 流量模块同级）：

- `● Running / ● Offline` 状态、在线用户、在线 IP、下载/上传速度、Trojan API 状态；
- 整张卡片可点击，或点“查看详情”，进入 `/trojan` 专属详情页。

`/trojan` 详情页（需登录且具备 `trojan:manage` 权限）：

- 顶部：与 server-status 其他页面一致的顶栏（Server Status / Trojan-Go），页面标题 + “监控与管理”副标题，
  右侧 `● Running/Offline`、`Trojan API ● Connected/Disconnected`、刷新、返回；
- 统计区：6 个紧凑指标卡（在线用户、在线 IP、当前下载/上传速度、总下载/上传流量），桌面 6 列 / 平板 3 列 / 移动 2-1 列；
- Trojan-Go Traffic 实时曲线（最近 60 秒，最多 60 个点，断开时显示 API Offline）；
- 客户端列表：Card + Table（用户、状态 Badge、在线 IP、当前下载/上传、下载/上传限制、总下载/总上传、详情/编辑/删除）；
- 详情：右侧 Drawer（Descriptions + Statistic + Tag，含实时速度区）；
- 用户管理：Modal + Form 添加/编辑（Password 仅添加时，限速支持 KB/s/MB/s/GB/s 单位并自动转 B/s），删除用 Modal.confirm 二次确认；
- 在线判定：`IpCurrent > 0` 为主，Trojan-Go 未统计 IP（ip_limit=0）时以实时速度兜底，避免“有流量却显示离线”。

## 9. 如何验证实时速度

1. 打开 `https://192.168.1.10:9000/` 并登录；
2. 用 Trojan 客户端（如 v2rayN/Trojan-Qt5）连接 `8388` 端口开始下载；
3. 观察 Trojan-Go 卡片“下载速度”和 Traffic 曲线上升；
4. 上传同理。数据每 1~2 秒刷新一次（来自 gRPC `ListUsers` 的 `SpeedCurrent`）。

## 10. 如何验证添加用户

1. 点击“添加用户”；
2. 填写 Password、上传/下载限速（MB/s）、IP 限制；
3. 点“创建”，成功后列表出现新用户（Hash 为密码的 SHA-224）；
4. 用该密码连接 `8388` 即可使用。

## 11. 如何验证删除用户

1. 用户行点击“删除”；
2. 弹窗确认“确定删除该 Trojan 用户？”；
3. 点“删除”，列表刷新后该用户消失；再用原密码连接会失败。

## 12. 如何验证限速

1. 添加用户时把下载限速设为 `10`（MB/s）；
2. 客户端下载大文件；
3. 面板“下载速度”应稳定在约 `10 MB/s`（Trojan-Go 返回的 `SpeedLimit` 也会显示该值）；
4. 通过“编辑”把限速改为 `50`，客户端速度应随之上升。

## 13. 如何验证 Trojan-Go API 断开后的表现

```bash
sudo systemctl stop trojan-go
```

- 面板 Trojan-Go 卡片变为 `● Offline`，Trojan API 显示 `● Disconnected`；
- Traffic 图标题变为 `API Offline`，不再追加数据点；
- 用户表提示“API Offline，无法获取用户列表”；
- CPU/内存/磁盘/网络等其他监控完全不受影响；
- 日志每 30 秒记录一次 `Trojan-Go API offline`，不会刷屏。

恢复：

```bash
sudo systemctl start trojan-go
```

日志输出 `Trojan-Go API connection restored`，面板自动恢复 `● Running`。

## 14. 数据与安全说明

- gRPC 连接在进程启动时创建并复用，不每秒新建连接；
- 状态通过现有 WebSocket（每秒推送）透传 `trojan` 字段，不新增第二套 WebSocket；
- 用户列表由后端定时缓存，前端最多保留 60 个流量采样点；
- Trojan-Go v0.10.6 的 `SetUsers/Modify` **不支持修改密码**，编辑弹窗不提供密码字段；
- `Add` 使用密码 SHA-224 作为用户 Hash，与 Trojan-Go 服务端计算规则一致；
- API 地址默认仅 `127.0.0.1`，请勿暴露到公网。

## 14.5 连接配置（Trojan URI / 二维码 / Clash / sing-box）

每个用户行有 `连接` 按钮，点击后弹出连接 Modal（需登录 + `trojan:manage` 权限 + HMAC secureFetch）：

- 展示服务器 `example.com:8388`、TLS、SNI、WebSocket Path/Host、UDP、家庭局域网 `192.168.1.0/24`；
- 密码默认隐藏，点 `显示` 才显示明文，`复制密码` 复制到剪贴板；
- `复制 URI` / `复制 Clash` / `复制 sing-box` / `下载 Clash` / `下载 sing-box` / `显示二维码` / `下载二维码`；
- 连接模式默认 `互联网 + 家庭局域网`（生成 `IP-CIDR,<网段>,<proxy>` + `MATCH` 规则），可切换 `仅互联网`；
- 连接弹窗内可直接修改家庭局域网网段（默认预填 `config.json` 的 `trojan.connection.lan_cidr`，如 `192.168.1.0/24`），Clash 规则、连接测试路由检查均使用弹窗内自定义网段；
- `测试连接`：检测 Trojan-Go gRPC API、服务状态、`8388` 端口监听（IPv4/IPv6 回环）、到家庭局域网的路由。

### 连接 API（均受认证与 RBAC 保护）

```
GET  /api/trojan/users/{hash}/connection             # 完整连接信息（密码/URI/Clash/sing-box）
POST /api/trojan/users/{hash}/credential             # 补录/更新密码凭据（历史用户缺凭据时使用）
GET  /api/trojan/users/{hash}/connection/test        # 连接测试结果
GET  /api/trojan/users/{hash}/clash/download?lan=1   # 下载 Clash（?lan=true 附加家庭局域网分流规则）
GET  /api/trojan/users/{hash}/singbox/download       # 下载 sing-box
```

### 凭据存储

- 创建用户时，`server-status` 在 `trojan_credentials.json`（与 `private_notes.json` 同目录，权限 `0600`）保存 `hash → 明文密码` 的安全映射；
- 密码**绝不**进入普通用户列表、Dashboard WebSocket、日志、URL 参数或 HTML 源码；仅在上述受保护连接 API 中返回；
- 删除用户同步删除对应凭据；编辑限速会把新的限速/IP 限制同步进档案；
- **重启自动恢复**：Trojan-Go v0.10.6 的用户表存于内存，进程重启即清空。面板在检测到
  Trojan-Go 连接恢复（离线→在线转换，含面板冷启动）时，会按本地档案自动补发缺失的用户
  （含限速/IP 限额），并把服务端已有但未记录的用户（含手动在 trojan-go 侧创建的）写入档案，
  使其同样获得重启恢复能力。恢复动作只补缺失、不改动服务端已存在用户；
- 若凭据丢失，连接接口返回 `404 该用户缺少连接凭据`，连接弹窗会引导补录该用户创建时设置的密码（`POST /api/trojan/users/{hash}/credential`，校验密码 hash 与用户匹配，仅保存到凭据文件、不调用 Trojan-Go），无需删除重建、不丢流量数据；

### 连接测试的路由提示

连接测试对家庭局域网执行真实路由检测（本地网卡是否位于该网段、Linux `/proc/net/route` 是否有覆盖路由）。
若服务器没有到 `192.168.1.0/24` 的路由，页面会明确提示
`当前服务器没有发现到家庭局域网 192.168.1.0/24 的可用路由`，不会伪造成功。

## 15. Trojan-Go v0.10.6 已知问题与已应用的补丁

**现象**：客户端明明在走流量（trojan-go 日志持续输出 `tunneling to ... closed sent/recv`），
但 gRPC API（`ListUsers`/`GetUsers`）返回的用户流量、速度、在线 IP 全部为 0。

**原因**：v0.10.6 在启用 WebSocket 时，同一进程内会创建**两个 trojan 服务实例**
（TLS 直连路径 + WebSocket 路径），每个实例在各自 context 上创建独立的 `memory` 统计认证器；
gRPC API 只绑定到其中一个实例，而客户端流量走另一个实例，所以 API 看到的是空统计。

**修复**：给 trojan-go v0.10.6 打补丁 `docs/trojan-go-shared-auth.patch`，
把 `statistic.NewAuthenticator` 的缓存键从 `context` 改为**后端名称**，
让两个实例共享同一个统计认证器。已在 `192.168.1.10` 上重新编译并部署：

```bash
cp -r /root/go/pkg/mod/github.com/p4gefau1t/trojan-go@v0.10.6 /opt/trojan-go/src/trojan-go-src
chmod -R u+w /opt/trojan-go/src/trojan-go-src
cd /opt/trojan-go/src/trojan-go-src
patch -p1 < /opt/trojan-go/src/trojan-go-shared-auth.patch   # 或直接替换 statistic/statistics.go
CGO_ENABLED=0 go build -tags "server custom api" -trimpath -ldflags="-s -w" \
  -o /opt/trojan-go/trojan-go.new .
mv /opt/trojan-go/trojan-go /opt/trojan-go/trojan-go.bak.20260825
mv /opt/trojan-go/trojan-go.new /opt/trojan-go/trojan-go
systemctl restart trojan-go
```

注意：

- 必须用 `-tags "server custom api"`（或官方 `-tags full`）编译，否则 `-config` 参数或
  gRPC API 组件不会被打进二进制；
- 原二进制已备份为 `/opt/trojan-go/trojan-go.bak.20260825`；
- 在线 IP 计数依赖 `ip_limit > 0`：v0.10.6 内存认证器在 IP 限制为 0（不限）时**不记录 IP**，
  因此 `ip_current` 恒为 0。需要在面板“编辑用户”里给用户设置 IP 限制（当前已设为 20），
  在线 IP 才会显示；该限制仅保存在 trojan-go 运行内存中，trojan-go 重启后会恢复为 0，
  届时在面板里重新设置即可（配置文件的 password 列表不支持每用户 IP 限制）。
