# 私人手记图片「云盘直链 + 客户端解密」实施规格书

> 本文档是**自包含的实施规格**，写给执行改造的编码 agent。执行前不需要其他上下文；
> 所有文件路径、行号、函数名、数据格式均已核实（行号基于 2026-09-10 的代码状态，
> 执行时以函数名/内容定位为准，行号可能漂移）。
> 背景与方案论证见 `docs/private-notes-webdav-report.md`（可选阅读）。

---

## 0. 目标与总体架构

**目标**：手记图片的字节流量不再消耗服务器出向带宽——浏览器 302 直连移动云盘（经 OpenList）拿**密文**，用 WebCrypto 在浏览器本地解密渲染。

**链路**：

```
上传：浏览器 → 服务器加密落盘(PVMEDIA2, 每用户密钥) → 异步队列 PUT 到 OpenList(WebDAV) → 移动云盘
读取：浏览器 fetch /cloud 接口 → 服务器校验权限后 302 到移动云盘 CDN(raw_url)
      → 浏览器拿到密文 → WebCrypto 解密 → blob URL 渲染
回退：上述任一环节失败 → 自动回退现有服务器解密路径（本地副本永远保留），功能零劣化
```

**铁律（实现时不得违反）**：

1. 本地副本**永远不删**（本期不做省磁盘模式），云端只是副本 → 任何云端故障只影响带宽优化，不影响功能。
2. 所有新读取链路必须有**同请求内**的服务器解密回退，绝不因云端问题让图片打不开。
3. 视频本体（PVVIDEO1 分块格式）、缩略图、分享页**本期一律不动**（见 §2 格式表）。
4. 云同步默认关闭（配置开关），关闭时全部行为与现状 100% 一致，现有测试不得受影响。

---

## 1. 必须先理解的现状（已核实的代码事实）

### 1.1 媒体加密格式（private_store.go:221-311）

| 格式 | magic | 布局 | 密钥 | 用途 |
|---|---|---|---|---|
| PVMEDIA1（现状） | `"PVMEDIA1"`(8B) | `magic(8) ‖ nonce(12) ‖ GCM密文‖tag(16)` | 全局 | 图片/语音/视频海报/卡片 PNG |
| PVVIDEO1（**不动**） | `"PVVIDEO1"`(8B) | 头 36B：`magic(8)‖baseNonce(12)‖chunkSize(4BE)‖totalChunks(4BE)‖plainSize(8BE)` + 1MiB 分块，**每块 AAD=36B 头**，块 nonce=base 高4B+块序号8B(BE)，每块密文前 4B 明文长度 | 全局 | 视频本体（`videoReader` 随机读） |

- 全局密钥：`sha256(ASCII(encryptionKey))`，`encryptionKey = getEnvOr("SERVER_STATUS_ENCRYPT_KEY", "server_status_user_data_encryption_key_2024")`（main.go:104）。
- `encryptData`（main.go:3265）：`gcm.Seal(nonce, nonce, data, nil)` → 输出即 `nonce(12)‖ciphertext‖tag(16)`，**无 AAD**，Go GCM 默认 tag 16B 追加在尾部。`decryptData`（main.go:3287）对称。
- `encryptMediaBytes`（private_store.go:229）= `"PVMEDIA1" ‖ encryptData(plain)`；`decryptMediaBytes`（:245）剥 magic 后解密。
- `mediaGCM`（:291）构建全局 AES-GCM，视频加解密共用（**勿改签名/行为**）。
- `isMediaEncrypted`（:240）目前只查 PVMEDIA1 前缀 —— **这是本次改造的头号坑，见 §4.1**。

### 1.2 认证栈（所有 /api/private 路由统一）

```go
authMiddleware(securityMiddleware(privateAuthMiddleware(handler)))
```
- `authMiddleware`（main.go:3896）：主站登录（Cookie session / Bearer；写方法要 CSRF）。
- `privateAuthMiddleware`（private_api.go:266-298）：校验 `private_session` Cookie（Path=/api/private，滑动续期，会话在 `private_note_sessions` 表），未解锁 → 403 `"未解锁"`（前端 `api()` 收到后广播 `pv-locked` 事件）。
- 新路由必须用同样的三层包裹。

### 1.3 数据库（private_notes.db，建表在 private_store.go migrate() :620-709）

- 手记用户 = 主站登录用户名（`notes.user_id` 直接存用户名，无独立用户表）。
- 媒体表：`note_images(id, note_id, file_path, thumb_path, width, height, thumb_width, thumb_height, sort_order, created_at)`、`note_audio`、`note_videos(file_path=视频, poster_path=海报)`、`note_cards(user_id, file_path)`。
- `private_media_keys` 表**不存在，需新增**（§3.2）。
- 配置文件 `private_notes.json`（结构 `PrivateNotesJSON` :39-81，加载 `loadPrivateNotesJSON` :597）：**全仓库没有写回逻辑**，新增配置段后由用户手改文件+重启，不要实现配置写回。

### 1.4 图片上传/读取现有流程

- `addImage`（private_notes_crud.go:415-483）：校验→读全量→`encryptMediaBytes`(:446)→`os.OpenFile(O_EXCL)` 落盘→INSERT `note_images`→同步生成缩略图(:479)。返回的 `PrivateImage` 含 `json:"id"`/`"note_id"`/`"url"`/`"thumb_url"`（private_store.go:108-121）。
- `generateImageThumb`（:607-703）：读原图→解密(:629)→EXIF 矫正→480px→`encryptMediaBytes`(:687)→落盘 `.thumb.jpg`→回写 DB。
- 读取：`/api/private/notes/{id}/images/{image_id}/file|thumb`（private_api.go:104-105）→ `imageFilePath`/`imageThumbPath`（含 `noteOwnedBy` 归属校验）→ `servePrivateMediaFile`（private_store.go:253-270：`os.ReadFile`→`decryptMediaBytes`→`http.ServeContent`，immutable 缓存+ETag）。
- `servePrivateMediaFile` 的 9 个调用点：原图、缩略图、语音、视频海报（private_api.go:514/537/589/667）、卡片私有图（private_cards_api.go）、卡片分享图（private_cards_api.go:540）、语音分享（private_audio_share.go:250）。**分享页调用者无登录会话**——这是选择"密钥随文件走"（keyUID）设计的原因，见 §3.1。

### 1.5 前端（templates/private.html，6246 行，React18+antd5+Babel 内联于 `<script type="text/babel">` 2283-6244）

- `baseUrl`=origin（:2292）；统一 `api()` 封装（:2308-2335，`credentials:'include'`，写方法加 `X-CSRF-Token`，403"未解锁"→`pv-locked` 事件，401→`pv-relogin`）。
- 图片渲染点：
  - 列表缩略图 `LazyImg`（:3485-3522，IntersectionObserver 懒加载）+ NoteCard 网格（:3661）——**用 thumb_url，本期不改**。
  - 全屏查看器 `NoteImageViewer`（:3530-3605）：原图 `imgs[cur].url`（:3533），缩略图占位（:3590），原图 `<img>`（:3594），相邻预加载直接 `el.src = n.url`（:3543-3548）——**本期改造主战场**。
  - 编辑器预览条（:4342）本地 blob 优先——**不改**。
  - 卡片 canvas 绘制取原图：`loadImg`（:2622-2649，fetch→blob→createImageBitmap）、`drawImageCover`（:2673-2710）、`selImgs` 初始为 `note.images.map(i=>i.url)`（:4617-4621）、选择网格（:4867-4895）——**本期改造**。
- 解锁/锁定：`PasswordGate`（:5749-5786）POST `/api/private/unlock`；`pv-locked` 监听（:5929-5941）；`pv-unlocked` 广播（:5943-5954）；启动时 `/api/private/session` 判定（:5959-5965）。**敏感态只放内存**（先例：`amapKey` :2294），无 localStorage。
- 卡片/语音分享页（share.html / audio-share.html）独立、无登录态——**本期不改，继续服务器解密**。

---

## 2. 方案设计（定案，不要另起炉灶）

### 2.1 PVMEDIA2：每用户密钥 + 密钥标识随文件走

新格式（在 PVMEDIA1 基础上加 8B 密钥标识）：

```
"PVMEDIA2"(8B) ‖ keyUID(8B) ‖ nonce(12B) ‖ GCM密文‖tag(16B)
keyUID = sha256(perUserKey)[:8]
perUserKey = 32B crypto/rand，首次使用时生成，AES-GCM(全局密钥) 加密后存 DB
```

**为什么用 keyUID 而不是给解密函数传 userID**：解密发生在 `servePrivateMediaFile`（无用户上下文）与分享页（调用者不是属主）。keyUID 让解密自包含——读文件头拿到 keyUID → 内存缓存/DB 查 `private_media_keys.key_uid` → 得密钥。属主是谁根本不需要知道。这是本设计的核心决策，**不要改成传 userID 的方案**（会牵扯 9 个调用点 + 分享页查属主，还得给每处传用户）。

- keyUID 是密钥哈希前 8 字节，仅作查找标识，泄露无风险（preimage 抗性）。
- 新图片/语音/视频海报/卡片 PNG → PVMEDIA2；历史文件保持 PVMEDIA1 继续可读；由迁移任务（§3.6）逐步转 PVMEDIA2。
- 视频本体继续 PVVIDEO1 + 全局密钥（`mediaGCM` 一字不动），视频继续服务器解密播放。

### 2.2 云同步（新文件 private_cloud.go）

- 配置段 `cloud_sync`（结构见 §3.1），默认 `enabled:false`。
- 远端布局：`{remote_dir}/{rel}`，rel = 本地相对路径（如 `2026/09/10/f_ab12.jpg`）。目录段逐段百分号编码（云端目录名含中文）。
- 上传队列：单 worker 串行（避免触发移动云盘限流）+ 指数退避重试 + 去重；**只上传手记原图**（缩略图可再生成且体积小、语音/海报本期不直链，不上传）。
- 对账：启动 2 分钟后 + 每 24h，对 `note_images.file_path` 逐个 HEAD 云端，缺失的重新入队。
- 直链获取（`link_mode:"server_get"`，本期唯一实现）：服务器内部调 OpenList `POST /api/fs/get`（`Authorization: <token>` 头，body `{"path": "<remote_dir>/<rel>"}`），响应 `data.raw_url` 即移动云盘 CDN 直链 → 我方接口 302 过去。**OpenList 无需公网暴露**（fs/get 由服务器本机调用）。`openlist_redirect` 模式本期只留配置位不实现。
- 直链两大风险（已被验收脚本覆盖，代码必须保证失败即回退）：
  1. **CORS**：fetch 跟随 302 后读取跨域 CDN 响应体，要求 CDN 返回 `Access-Control-Allow-Origin`；若没有 → fetch 抛错 → 前端回退。**不阻塞开发，实测后才知道**。
  2. **IP 绑定**：raw_url 可能绑定"调用 fs/get 的 IP"（=服务器），浏览器拉取 403 → 前端回退。

### 2.3 带宽路径生效的前提（用户侧 Phase 0，脚本 §6）

用户在服务器跑 `deploy/check-openlist-direct.sh` 验证：fs/get 返回直链、CDN 带 CORS 头、浏览器 IP 能直拉。任一不满足 → 线上自动全走回退（无带宽收益但无损害），代码不需要改。

---

## 3. 逐文件改动清单

### 3.1 private_store.go —— 配置与加密体系

1. **配置结构**（:36-81 区域）：新增

```go
// CloudSyncConfig 手记媒体云同步配置（OpenList/WebDAV → 网盘）
type CloudSyncConfig struct {
    Enabled       bool   `json:"enabled"`
    DAVURL        string `json:"dav_url"`        // 如 http://127.0.0.1:5244/dav
    DAVUser       string `json:"dav_user"`
    DAVPass       string `json:"dav_pass"`
    RemoteDir     string `json:"remote_dir"`     // 如 /home/备份/手记媒体
    OpenlistAPI   string `json:"openlist_api"`   // 如 http://127.0.0.1:5244
    OpenlistToken string `json:"openlist_token"`
    LinkMode      string `json:"link_mode"`      // 仅实现 server_get
}
```
   挂到 `PrivateNotesJSON.CloudSync`；`defaultPrivateNotesJSON()` 给默认值（Enabled:false、DAVURL `http://127.0.0.1:5244/dav`、RemoteDir `/home/备份/手记媒体`、OpenlistAPI `http://127.0.0.1:5244`、LinkMode `server_get`）。`loadPrivateNotesJSON` 无需改（缺段即零值=关闭）。

2. **密钥表**（migrate() schema 数组追加）：

```sql
CREATE TABLE IF NOT EXISTS private_media_keys (
    user_id TEXT PRIMARY KEY, key_uid TEXT NOT NULL UNIQUE,
    key_enc TEXT NOT NULL, created_at TEXT NOT NULL)
```

3. **加密体系改造**（§1.1 所在区域）：
   - `var mediaCryptMagic2 = []byte("PVMEDIA2")`；PVMEDIA2 头长 = 8+8+12 = 28B。
   - **修复 `isMediaEncrypted`**：`return bytes.HasPrefix(raw, mediaCryptMagic) || bytes.HasPrefix(raw, mediaCryptMagic2)`。
   - `PrivateStore` 增加字段：`mediaKeysMu sync.Mutex`、`mediaKeys map[string]cipher.AEAD`（keyUID hex → AEAD 缓存）。
   - 新增方法：
     - `userMediaKey(userID string) ([]byte, error)`：查 `private_media_keys` → `decryptData(hex解码)` 得 32B；无则 `crypto/rand` 生成 32B → keyUID → `hex.EncodeToString(encryptData(key))` INSERT（冲突重查）→ 回填 AEAD 缓存。
     - `userAEADByUID(uid []byte) (cipher.AEAD, error)`：内存缓存命中即返回；未命中 `SELECT key_enc FROM private_media_keys WHERE key_uid = ?` → 解出 key → `mediaGCMWith(key)`（把 mediaGCM 重构为 `mediaGCMWith(key []byte)` + `mediaGCM()` 调 `mediaGCMWith(sha256(encryptionKey))`，视频路径行为不变）→ 缓存。
     - `encryptMediaBytesFor(userID string, plain []byte) ([]byte, error)`：`key := userMediaKey(userID)` → `PVMEDIA2 ‖ sha256(key)[:8] ‖ gcm.Seal(nonce, nonce, plain, nil)`。
     - **把 `decryptMediaBytes` 从包函数改为 store 方法** `func (s *PrivateStore) decryptMediaBytes(raw []byte) ([]byte, error)`：PVMEDIA2 前缀 → 头长校验（≥28B）→ `userAEADByUID(raw[8:16])` → `gcm.Open(nil, raw[16:28], raw[28:], nil)`；PVMEDIA1 前缀 → 全局 `decryptData`；其余 → 原样返回（历史明文兼容，语义不变）。
   - `servePrivateMediaFile`（:253）内的 `decryptMediaBytes(raw)` 改为 `privateStore.decryptMediaBytes(raw)`（该函数只在全局 store 就绪后被调用；调用点均已有 nil 检查）。签名**不变**。
   - 包内其余 `decryptMediaBytes` 调用（`generateImageThumb`、`readPrivateMedia`、`migratePlainMedia`）改为 `s.decryptMediaBytes`。
   - `migratePlainMedia`（:511-536）逻辑不动（明文→PVMEDIA1 全局加密），但因 `isMediaEncrypted` 已修复，PVMEDIA2 文件会被正确跳过。

### 3.2 private_notes_crud.go —— 写入切 per-user 密钥 + 入队

| 位置 | 改动 |
|---|---|
| `addImage` :446 | `encryptMediaBytes(data)` → `s.encryptMediaBytesFor(userID, data)`；DB INSERT 成功后（:472 后）`s.enqueueCloudUpload(filepath.ToSlash(rel))` |
| `generateImageThumb` :629/:687 | 解密 `s.decryptMediaBytes(raw)`（方法化自然获得）；加密改 per-user：加 helper `noteOwner(noteID) (string, error)`（`SELECT user_id FROM notes WHERE id=?`），:687 → `s.encryptMediaBytesFor(owner, out.Bytes())` |
| `addAudio` :880 | → `s.encryptMediaBytesFor(userID, data)` |
| `addVideo` :1006 与 :1031（海报） | → `s.encryptMediaBytesFor(userID, pdata)` / `(userID, jpg)`；**:972 `encryptVideoStream` 不动** |
| `deleteImage` :485-504 | 本地删除逻辑不动；DB 删除成功后 `s.enqueueCloudDelete(filepath.ToSlash(rel))`（尽力而为，失败只记日志） |
| 缩略图上传 | **不入云队列** |

### 3.3 private_cards_api.go —— 卡片 PNG

- `createCard` :73 → `s.encryptMediaBytesFor(userID, raw)`（userID 形参已有）。
- 卡片私有图/分享图处理器**零改动**（解密走 keyUID 自解析）。

### 3.4 private_export.go —— 导出

- `readPrivateMedia`（:47）内 `decryptMediaBytes` → `s.decryptMediaBytes`。签名不变（导出只导本人，但 PVMEDIA2 文件自解析，无需属主）。

### 3.5 新文件 private_cloud.go —— 云同步全部后端逻辑

包含（同包 main）：

1. **WebDAV 极简客户端**（仅 net/http + 标准 lib，**不引第三方依赖**）：
   - `davDo(cfg, method, relPath string, body []byte, expect map[int]bool) error`：URL = `cfg.DAVURL + percentEncodeSegments(cfg.RemoteDir + "/" + relPath)`，Basic Auth，`http.Client{Timeout: 90s}`（20MB 图片上行可能慢）。
   - `davPut`：先逐段 MKCOL（405/301 视为已存在），PUT 期望 200/201/204。
   - `davDelete`：期望 200/204/404（404=云端本没有，算成功）。
   - `davExists`：HEAD，200=true、404=false。
   - 路径编码注意：`RemoteDir` 以 `/` 开头；逐段 `url.PathEscape` 后重新用 `/` 拼接；空段跳过。
2. **OpenList 直链客户端**：
   - `openlistRawURL(cfg, relPath) (string, error)`：`POST cfg.OpenlistAPI + "/api/fs/get"`，头 `Authorization: <cfg.OpenlistToken>`、`Content-Type: application/json`，body `{"path": "<remoteDir>/<rel>"}`（**此接口的 path 不做 URL 编码**，是 JSON 字段）；`http.Client{Timeout: 10s}`；响应 `{code:200, data:{raw_url, sign, name, size}}`；code≠200 或 raw_url 空 → error。响应体做 200 行截断日志。
   - `link_mode != "server_get"` 时直接返回 error（本期未实现）。
3. **队列**（PrivateStore 增加字段，或 private_cloud.go 内以 store 扩展）：
   - `cloudQueue chan cloudTask`（容量 512，`cloudTask{rel string; del bool}`）；
   - `NewPrivateStore` 末尾：`if st.config.CloudSync.Enabled { go st.cloudWorker() }`；worker 内 `recover()` 防崩，逐任务执行：`del ? davDelete : davPutWithRetry`。重试策略：最多 5 次，退避 2s/8s/32s/2m/8m；最终失败计数并记 lastErr。任务用 `rel` 去重（in-flight map + sync.Mutex；同 rel 任务在队/执行中时丢弃新任务——上传失败后由对账兜底）。
   - `enqueueCloudUpload(rel)` / `enqueueCloudDelete(rel)`：`cfg.CloudSync.Enabled` 为 false 直接 return；channel 满则丢弃并计数（不阻塞上传主流程）。
   - 状态：`cloudStatus{pending, uploaded, deleted, failed int64; lastErr string; lastErrAt time.Time; mu sync.Mutex}`。
   - **对账** `reconcileCloud()`：查 `SELECT file_path FROM note_images`（全用户）→ 逐个 `davExists` → 缺失入队。`NewPrivateStore` 里 `if Enabled { time.AfterFunc(2*time.Minute, ...); time.Ticker 24h }`，两个都带 recover。
4. **重加密迁移任务**（PVMEDIA1 → PVMEDIA2，幂等）：
   - `startMediaReencrypt() (started bool)`：`sync.Mutex` 防并发；后台 goroutine 执行：
     - 枚举（4 条查询，均带属主）：
       `SELECT ni.file_path, n.user_id FROM note_images ni JOIN notes n ON n.id=ni.note_id`；
       `note_audio` 同理；`SELECT nv.poster_path, n.user_id FROM note_videos nv JOIN notes n ... WHERE nv.poster_path != ''`（**不含 file_path，视频不动**）；`SELECT file_path, user_id FROM note_cards`。
     - 逐文件：`os.ReadFile` → 已是 PVMEDIA2 或已加密且非 PVMEDIA1 → 计 skipped；PVMEDIA1 → `decryptMediaBytes` → `encryptMediaBytesFor` → 同目录临时文件 + `os.Rename` 原子替换；纯明文 → 直接 per-user 加密。
     - 进度计数 `reencryptStatus{running bool; scanned, migrated, skipped, errors int64}`。
   - **不自动执行**，仅由管理接口触发（§3.6）。
5. **审计**：密钥下发、直链签发、重加密触发走 `s.auditPrivate(r, username, "private_cloud.xxx")`（日志绝不含密钥本体/raw_url 全文）。

### 3.6 private_api.go —— 新路由（4 条，全部三层包裹）

```go
mux.HandleFunc("GET /api/private/media/key",      authMiddleware(securityMiddleware(privateAuthMiddleware(privateMediaKeyHandler))))
mux.HandleFunc("GET /api/private/notes/{id}/images/{image_id}/cloud", authMiddleware(securityMiddleware(privateAuthMiddleware(privateImageCloudHandler))))
mux.HandleFunc("GET /api/private/cloud/status",   authMiddleware(securityMiddleware(privateAuthMiddleware(privateCloudStatusHandler))))
mux.HandleFunc("POST /api/private/media/reencrypt", authMiddleware(securityMiddleware(privateAuthMiddleware(privateMediaReencryptHandler))))
```

- `privateMediaKeyHandler`（GET）：`hex.EncodeToString(key)` → `writeJSON(w, 200, "ok", map[string]string{"key": hex})`；审计 `private_cloud.media_key`。**只在解锁会话内可达**（三层中间件保证）。
- `privateImageCloudHandler`（GET）：
  1. `rel, err := privateStore.imageRelPath(username, r.PathValue("id"), r.PathValue("image_id"))`（新增小方法：`noteOwnedBy` + `SELECT file_path FROM note_images WHERE id=? AND note_id=?`；任何错误 → 404 "图片不存在"）。
  2. `if cfg.CloudSync.Enabled && token != ""`：`rawURL, err := openlistRawURL(...)`；成功 → `w.Header().Set("Cache-Control", "no-store")`（raw_url 有时效，绝不能被缓存）→ 审计 → `http.Redirect(w, r, rawURL, http.StatusFound)`。
  3. 失败/未启用 → **同请求回退**：`abs, name, err := privateStore.imageFilePath(username, noteID, imageID)` → 与 `privateImageFileHandler` 相同的 `Content-Disposition/Cache-Control/ETag` 头 → `servePrivateMediaFile`。
- `privateCloudStatusHandler`（GET）：`{queue: {...}, reencrypt: {...}}` 快照 JSON。
- `privateMediaReencryptHandler`（POST）：调 `startMediaReencrypt()`，返回 `{started}`；审计。

### 3.7 templates/private.html —— 前端解密渲染

全部改动在现有 babel script 内（2283-6244）：

1. **密钥与 blob 缓存**（放 `amapKey` :2294 附近）：

```js
let pvMediaKey = null;            // CryptoKey，内存缓存
let pvMediaKeyPromise = null;     // 并发去重
const pvBlobCache = new Map();    // imageID -> Promise<blobURL>

function pvHexToBytes(h) { /* 64 hex -> Uint8Array(32) */ }

function ensurePvMediaKey() {
  if (pvMediaKey) return Promise.resolve(pvMediaKey);
  if (!pvMediaKeyPromise) pvMediaKeyPromise = api('/api/private/media/key')
    .then(d => crypto.subtle.importKey('raw', pvHexToBytes(d.data.key), 'AES-GCM', false, ['decrypt']))
    .then(k => { pvMediaKey = k; return k; })
    .catch(e => { pvMediaKeyPromise = null; throw e; });
  return pvMediaKeyPromise;
}

function pvDecryptMedia(buf /* Uint8Array */) {
  const M = [0x50,0x56,0x4D,0x45,0x44,0x49,0x41,0x32]; // "PVMEDIA2"
  for (let i = 0; i < 8; i++) if (buf[i] !== M[i]) throw new Error('not-pvmedia2');
  const iv = buf.slice(16, 28);          // magic(8)+keyUID(8) 之后是 nonce(12)
  return crypto.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, pvMediaKey, buf.slice(28));
}

function pvMime(b) { // 解密后按魔数定 MIME：FFD8 jpeg / 89 50 4E 47 png / GIF87a,89a gif / RIFF..WEBP webp / 其余 application/octet-stream
}

function pvCleanupMedia() {
  pvMediaKey = null; pvMediaKeyPromise = null;
  pvBlobCache.forEach(p => p.then(u => URL.revokeObjectURL(u)).catch(() => {}));
  pvBlobCache.clear();
}
```

2. **核心取图函数**：

   **缓存上限（必做）**：blob 是常驻内存的，移动端连续浏览大图会累积数百 MB。`pvBlobCache` 超过 **30 条**时淘汰最早写入的条目并 `revokeObjectURL`（FIFO 即可，不必真 LRU）；淘汰后再次查看该图会重新走直链（有浏览器 HTTP 缓存兜底，代价小）。

```js
function fetchDecryptedImage(noteID, imageID, fallbackURL) {
  if (pvBlobCache.has(imageID)) return pvBlobCache.get(imageID);
  const p = (async () => {
    try {
      const key = await ensurePvMediaKey();
      const r = await fetch(baseUrl + `/api/private/notes/${noteID}/images/${imageID}/cloud`,
        { credentials: 'include', redirect: 'follow' });   // 302 自动跟到 CDN
      if (!r.ok) throw new Error('cloud ' + r.status);
      const buf = new Uint8Array(await r.arrayBuffer());   // CORS 不通过会在这里抛错
      const plain = await pvDecryptMedia.call(null, ensureKeyThen(buf, key)); // 伪码：先 pvMediaKey=key 再解密
      return URL.createObjectURL(new Blob([plain], { type: pvMime(plain) }));
    } catch (e) {
      const r2 = await fetch(baseUrl + fallbackURL, { credentials: 'include' });  // 服务器解密回退
      if (!r2.ok) throw new Error('fallback ' + r2.status);
      return URL.createObjectURL(await r2.blob());
    }
  })();
  pvBlobCache.set(imageID, p);
  p.catch(() => pvBlobCache.delete(imageID));
  return p;
}
```
   （实现时把 `pvDecryptMedia` 写成接收 key 参数的形态，去掉伪码。）

3. **接入 NoteImageViewer**（:3530-3605）：
   - `const src = imgs[cur].url`（:3533）改为 state：`const [src, setSrc] = useState(null)` + `useEffect([cur])` 调 `fetchDecryptedImage(img.note_id, img.id, img.url)` → setSrc；切换/关闭时无需 revoke（缓存统一管理）。
   - 相邻预加载（:3543-3548）`el.src = n.url` 改为 `fetchDecryptedImage(n.note_id, n.id, n.url).then(u => { el.src = u; })`（失败静默）。
   - 图片对象已有 `id`/`note_id`（后端 JSON 字段，§1.4）。

4. **接入 loadImg**（:2622-2649，卡片 canvas 用）：加可选参数 `loadImg(url, ref)`，`ref = {noteID, imageID}` 时先 `fetchDecryptedImage(ref.noteID, ref.imageID, url)` 拿 blob URL 再走现有解码流程；无 ref 走原逻辑（兼容）。调用点 `selImgs`（:4617-4621）改为保留完整 `{url, id}`，`drawImageCover`/选择网格（:4867-4895）把 `noteID` 透传（noteID 从当前编辑的 note 取）。

5. **锁定清理**：`pv-locked` 监听（:5929-5941）与 `setPhase('locked')`（:6179）处调用 `pvCleanupMedia()`；`pv-unlocked` 监听（:5943-5954）与启动已解锁分支（:5959-5965）里 `ensurePvMediaKey().catch(() => {})` 预热。密钥绝不写 sessionStorage/localStorage。

### 3.8 deploy/check-openlist-direct.sh —— 新建验证脚本

```bash
#!/bin/bash
# 用法: ./check-openlist-direct.sh <OpenList地址> <API Token> <云盘内某文件完整路径>
# 例:   ./check-openlist-direct.sh http://127.0.0.1:5244 xxxxxxx "/home/备份/手记媒体/2026/09/10/f_x.jpg"
set -euo pipefail
BASE="$1"; TOKEN="$2"; PATH_="$3"
echo "== 1) fs/get 获取直链 =="
RESP=$(curl -s -X POST "$BASE/api/fs/get" -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d "{\"path\":\"$PATH_\"}")
echo "$RESP" | head -c 400; echo
RAW=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"].get("raw_url",""))' 2>/dev/null || true)
[ -n "$RAW" ] || { echo "❌ 未取到 raw_url（token 错误 / 路径错误 / 驱动仅代理模式）"; exit 1; }
echo "== 2) 直链可达性（服务器视角） =="; curl -sI "$RAW" | head -5
echo "== 3) CORS 检查（决定浏览器能否 fetch 跨域密文，最关键） =="
curl -sI -H "Origin: https://example.com" "$RAW" | grep -i "access-control-allow-origin" \
  && echo "✅ CDN 带 CORS 头，直链方案可用" || echo "⚠️ 无 CORS 头：浏览器 fetch 会失败并自动回退服务器（带宽不省但功能无损）"
echo "== 4) 把 RAW_URL 换到你本地浏览器/curl 再测一次，检查是否绑定服务器 IP =="
echo "RAW_URL=$RAW"
```
（jq 不保证有，用 python3 兜底，与 deploy/pv-backup.sh 的风格一致。）

---

## 4. 已识别的坑（按严重度排序，实现时逐条对照）

1. **[致命] `isMediaEncrypted` 只认 PVMEDIA1 前缀**：不改的话 `migratePlainMedia` 会把 PVMEDIA2 文件当明文再用全局密钥加密一层 → 数据永久损坏。见 §3.1 第 3 点，必须最先改。
2. **[致命] 视频路径**：`mediaGCM`/`encryptVideoStream`/`videoReader`/`openVideoReader` 一律不动。视频本体仍是全局密钥 PVVIDEO1；`note_videos.file_path` 绝不能进重加密任务（只处理 poster_path）。
3. **[高危] 302 响应缓存**：raw_url 是短时效签名 URL，`/cloud` 接口必须 `Cache-Control: no-store`，否则浏览器缓存 302 后直链过期。
4. **[高危] CORS/回退链**：fetch→302→CDN 读体失败（CORS/403/超时）必须 catch 后走服务器回退，且回退失败也要抛出可感知错误（前端显示加载失败，而不是无限等待）。
5. **[中] 队列不得阻塞上传**：入队非阻塞，channel 满丢弃+计数；worker panic 必须 recover，否则拖死整个 store。
6. **[中] WebDAV 路径编码**：中文目录逐段 `url.PathEscape`；MKCOL 逐级建且 405 视为成功（与 deploy/pv-backup.sh 行为一致）。
7. **[中] 单 worker 串行**：移动云盘对高频并发 API 敏感，绝不并发上传。
8. **[低] 测试隔离**：现有测试通过 `privateStore = st` 全局替换（private_http_test.go:36）；云同步默认关、`enqueue*` 在 disabled 时直接 return，现有用例零影响。
9. **[低] `decryptMediaBytes` 方法化**后，private_notes_test.go:624 等直接调包函数的测试要改为 `st.decryptMediaBytes(...)`。
10. **[低] keyUID 冲突重试**：32B 随机 key 的 sha256 前 8B 冲突概率忽略不计，但 INSERT 时 key_uid UNIQUE 冲突应重查而非崩溃。

---

## 5. 测试要求（新增 private_cloud_test.go，并跑全量回归）

1. PVMEDIA2 roundtrip：`encryptMediaBytesFor` → `decryptMediaBytes` 还原；magic/keyUID 布局断言（长度 ≥28、前 8B magic、两文件 nonce 不同）。
2. 分流兼容：PVMEDIA1（旧 `encryptMediaBytes`）文件仍可 `s.decryptMediaBytes`；明文原样返回；截断/篡改 PVMEDIA2 报错。
3. `isMediaEncrypted` 对两种 magic 与明文的判定（防坑 §4.1 回归）。
4. WebDAV 客户端：httptest 断言 PUT/HEAD/DELETE 的 URL 编码（含中文段）、Basic Auth、MKCOL 序列、状态码处理。
5. `openlistRawURL`：httptest 返回 {code:200,data:{raw_url}}；code≠200/网络错误 → error。
6. `privateImageCloudHandler`：未解锁 403；他人手记 404；云端失败（token 空）→ 同请求回退输出可解密图片（比对 PNG magic）。
7. 重加密迁移：造 PVMEDIA1 文件+DB 行 → 迁移 → 变 PVMEDIA2 且可解密、原图可读；重跑幂等（skipped）；视频 file_path 不被触碰。
8. `go build ./... && go test ./...` 全量通过（Windows 开发机，Git Bash）。

---

## 6. 交付物与验收清单

| # | 交付物 | 验收方式 |
|---|---|---|
| 1 | private_store.go / private_notes_crud.go / private_cards_api.go / private_export.go 改造 | go build + 全量测试通过；旧 PVMEDIA1 文件可读 |
| 2 | private_cloud.go（客户端/队列/对账/迁移） | 单测覆盖 §5.4-5.7 |
| 3 | 4 条新路由 | 手动 curl：未解锁 403、解锁后 /media/key 返回 64 位 hex |
| 4 | private.html 前端 | 解锁后打开全屏图片查看器，Network 面板中原图请求指向 /cloud 且 302 到外部域；断网 OpenList 后图片仍能打开（回退生效）；锁定→解锁后图片恢复 |
| 5 | deploy/check-openlist-direct.sh | 用户在服务器执行，输出 CORS 判定 |
| 6 | 文档：private_notes.json 的 cloud_sync 配置样例 + 使用说明（追加到 docs/private-notes-webdav-report.md） | 用户照做可启用 |

**上线步骤（写给用户，代码完成后附到文档）**：① 手改 private_notes.json 加 `cloud_sync` 段（enabled=true、dav 账号密码、openlist_token）→ 重启；② 管理页/接口触发重加密迁移；③ 跑 check-openlist-direct.sh 确认 CORS；④ 观察几天后可在移动端验证直链流量（DevTools Network 无图片字节经服务器域名）。

**本期明确不做**：卡片查看器/语音播放/视频的直链化、`delete_local_after_upload`（省磁盘）、配置写回 UI、OpenList 状态监控页。文档中注明为二期。
