# 提交规范与版本发布指南

> 本文档是仓库的约定，与既有提交历史和 [.github/workflows/go-ci-cd.yml](../.github/workflows/go-ci-cd.yml)
> 的实际行为一致。新提交、打 tag、发版请遵循。

## 一、Git 提交规范

### 1. 格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

- subject 必填，body / footer 按需；subject 与 body 之间空一行。
- 单行提交（`git commit -m "<type>: <subject>"`）仅限琐碎改动；有价值上下文的一律写 body。

### 2. type 类型

| type | 含义 | 对版本的影响 |
|---|---|---|
| `feat` | 新功能（页面 / 接口 / 模块 / 现有能力的扩展） | 升 MINOR |
| `fix` | bug 修复 | 升 PATCH |
| `ux` | 纯前端交互 / 视觉体验改版（本项目约定，等于界面向的 feat） | 按体量升 MINOR 或 PATCH |
| `perf` | 性能优化，不改变行为 | 升 PATCH |
| `refactor` | 重构，不改变行为 | 不单独发版 |
| `docs` | 文档 | 不发版 |
| `test` | 测试补充 | 不发版 |
| `chore` | 构建、脚本、依赖等杂项 | 视内容升 PATCH |
| `build` / `ci` | 构建系统 / CI 配置 | 不发版 |

> CI 的 Release Notes 按 `feat` / `fix` / 其他 三组自动归类（按前缀匹配，
> 带 scope 的提交同样识别），所以 type 一定不能写错或自造。

### 3. scope（可选）

模块名小写：`private`（私人空间）、`backup`、`cards`、`shell`、`trojan`、`files`、
`rbac`、`security`、`deploy`、`ui` 等。影响多个模块时省略 scope。

### 4. subject

- 中文，≤ 50 字，结尾不加句号；
- 说清"做了什么"；需要交代动机 / 关键点时用"——"引出（仓库历史风格），例如：

```
feat(backup): 云备份只读展示页——执行计划/上传记录/原始日志 + 备份计划修改
ux: 公开分享页 /card/{token} 重设计——拍立得式卡片布局+信息层级、沉浸式大图预览
```

### 5. body

- 写**为什么**这么做、关键实现决策、取舍；不要复述 diff 能看出来的"做了什么"；
- 涉及数据结构变更的，写清旧库如何迁移（如 `ALTER TABLE` 自动补列）；
- 破坏性变更必须在 footer 加 `BREAKING CHANGE: <说明 + 迁移方法>`。

### 6. 原子性

- 一个 commit 只做一件事；无关文件不搭车；
- 一次工作产出多个逻辑改动时，拆成多个提交（同文件内可用 `git apply --cached` 按 hunk 拆分）；
- 提交前跑 `go test ./...`（CI 同样会跑，本地先绿再推）。

## 二、版本号：语义化版本（SemVer）

格式 `vMAJOR.MINOR.PATCH`（当前基线 `v2.1.0`）。版本号**不需要改源码**——
`main.go` 里 `version = "dev"` 只是兜底，CI 打包时用 `-ldflags "-X main.version=<tag名>"` 注入。

### 升 MAJOR（x +1.0.0）：不兼容，升级需要人工干预

- 配置 / 密钥语义变更：如更换 `SERVER_STATUS_ENCRYPT_KEY` 导致旧数据无法解密；
- API / 路由删除或行为不兼容；数据存储结构无法自动迁移；
- 部署方式变更（systemd 单元、Docker、目录结构变化，需手工迁移）；
- 安全默认值收紧导致旧客户端无法连接（如 TLS 最低版本）。

### 升 MINOR（y +1.0）：向后兼容的新功能

- 新页面 / 新模块 / 新接口（如云备份页、EXIF 自动回填）；
- 现有接口新增可选字段、新增权限点、新增通知渠道等。

### 升 PATCH（z +1.0）：修问题，不添能力

- bug 修复、性能优化、UI 细节微调、依赖安全升级、文档。

**速查**：用户"能多做事"→ MINOR；"原来不对、现在对了"→ PATCH；"升级会坏、要动手迁移"→ MAJOR。

## 三、什么时候打 tag

原则：**tag 是发布事件，不是开发里程碑**。只有"准备部署到真实环境的版本"才打 tag，
开发中间态一律不打。

- 打在 master 上，用附注 tag，注明版本要点：

  ```bash
  git tag -a v2.2.0 -m "v2.2.0: 云备份页；语音二维码令牌生命周期；EXIF 自动回填"
  git push origin master && git push origin v2.2.0
  ```

- 推送 `v*` tag 自动触发 CI：测试 → 多平台交叉编译 → 创建 GitHub Release
  （发布说明按 feat / fix / 其他 分组自动生成，范围 = 上一个 tag 到当前 tag 的全部提交）；
- 版本号在打 tag **前**按第二节规则决定，tag 推送后不可更改（错了就删掉重打，且需说明）；
- 预发布可用 `v2.3.0-rc.1`，同样会触发 CI，发布后在 GitHub 上手动标记 pre-release。

### hotfix 流程

- master 即生产分支（单人仓库常态）：直接修复 → PATCH +1 → 打 tag；
- 若 master 已领先线上版本较多：从线上 tag 拉 `hotfix/xxx` 分支修复 → PATCH +1 →
  打 tag → 合回 master。

## 四、发版 checklist

1. [ ] `go test ./...` 全绿；动了前端模板的，浏览器里把对应页面过一遍；
2. [ ] 提交历史整理完毕，每个 commit 符合第一节规范（发版说明由 commit 主题生成）；
3. [ ] 按第二节规则决定版本号；
4. [ ] push master，确认 CI 测试通过；
5. [ ] 打附注 tag 并推送（命令见第三节）；
6. [ ] 等 CI 跑完 build + release 两个 job，检查 Release 页产物（多平台二进制 + sha256）与说明；
7. [ ] 部署：`sudo bash deploy.sh`（幂等，可直接用于升级）或替换二进制后
       `systemctl restart server-status`；
8. [ ] 线上验证：登录后确认版本号（启动日志 `version=...`）、关键页面可用、备份页有记录。
