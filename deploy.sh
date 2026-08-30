#!/usr/bin/env bash
# ============================================================
# server-status 一键部署脚本
#
# 用法（在 Linux 服务器上，项目根目录执行）：
#   sudo bash deploy.sh                          # 交互式，systemd 部署 + 自签证书
#   sudo bash deploy.sh -d example.com           # 指定域名 + 自签证书
#   sudo bash deploy.sh -d example.com --letsencrypt   # 用 certbot 签发正式证书
#   sudo bash deploy.sh --docker                 # Docker Compose 部署
#
# 脚本做完全部事情：生成随机密钥 → 安装二进制与模板 → 准备证书 →
# 写配置文件 → 安装/重启 systemd 服务 → 健康检查。
# 幂等：重复执行不会覆盖已存在的密钥 / 证书 / 配置，可放心用于升级。
# ============================================================
set -euo pipefail

# ---------------- 默认配置 ----------------
DOMAIN="localhost"          # 对外域名（-d 覆盖）
PORT="9000"                 # HTTPS 监听端口（-p 覆盖）
DATA_DIR="/opt/server-status"  # 数据根目录（--data-dir 覆盖）
MODE="systemd"              # systemd | docker
USE_LETSENCRYPT="no"
PRIVATE_PASSWORD=""         # 私人空间初始化密码（可选，仅首次启动生效）
STATIC_BASE_URL=""          # 独立静态服务器地址（可选）
EXTRA_ORIGINS=""            # 额外跨域白名单（可选）
CUSTOM_BINARY=""            # 指定预编译二进制路径（可选）
ENV_FILE="/etc/server-status/server-status.env"
SERVICE_NAME="server-status.service"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}警告:${NC} $*"; }
die()   { echo -e "${RED}错误:${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------- 参数解析 ----------------
usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)        DOMAIN="$2"; shift 2 ;;
    -p|--port)          PORT="$2"; shift 2 ;;
    --data-dir)         DATA_DIR="$2"; shift 2 ;;
    --media-dir)        MEDIA_DIR="$2"; shift 2 ;;
    --letsencrypt)      USE_LETSENCRYPT="yes"; shift ;;
    --docker)           MODE="docker"; shift ;;
    --static-base)      STATIC_BASE_URL="$2"; shift 2 ;;
    --extra-origins)    EXTRA_ORIGINS="$2"; shift 2 ;;
    --binary)           CUSTOM_BINARY="$2"; shift 2 ;;
    --private-password) PRIVATE_PASSWORD="$2"; shift 2 ;;
    -h|--help)          usage ;;
    *)                  die "未知参数: $1（--help 查看用法）" ;;
  esac
done
MEDIA_DIR="${MEDIA_DIR:-${DATA_DIR}/media}"

# ---------------- 通用前置检查 ----------------
[[ $EUID -eq 0 ]] || die "请用 root 运行（sudo bash deploy.sh）"
command -v openssl >/dev/null || die "缺少 openssl，请先安装"

# 生成一段 64 位十六进制随机密钥
gen_key() { openssl rand -hex 32; }

# 写 TLS 证书（已存在则跳过，绝不覆盖）
ensure_tls() {  # $1=证书目录 $2=域名
  local tls_dir="$1" domain="$2"
  mkdir -p "$tls_dir"
  if [[ -s "$tls_dir/cert.pem" && -s "$tls_dir/key.pem" ]]; then
    info "TLS 证书已存在，跳过（${tls_dir}）"
    return
  fi
  info "生成 10 年期自签证书（CN=${domain}）..."
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$tls_dir/key.pem" -out "$tls_dir/cert.pem" \
    -subj "/CN=${domain}" \
    -addext "subjectAltName=DNS:${domain},DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
  chmod 600 "$tls_dir/key.pem"
}

# 打印部署摘要
print_summary() {  # $1=模式
  local mode="$1" url
  url="https://${DOMAIN}:${PORT}"
  echo ""
  echo -e "${CYAN}======================== 部署完成 ========================${NC}"
  echo -e "  访问地址    : ${GREEN}${url}${NC}  （浏览器打开后用默认账号登录）"
  echo -e "  默认管理员  : admin / admin123  ${RED}首次登录后请立刻修改密码！${NC}"
  echo -e "  隐藏私人空间: 桌面端 Ctrl+Shift+Alt+N；移动端连点 Logo 5 次（首次进入需设置私人密码）"
  if [[ "$mode" == "systemd" ]]; then
    echo -e "  数据目录    : ${DATA_DIR}（模板/数据/日志/媒体/证书）"
    echo -e "  配置文件    : ${ENV_FILE}（密钥等，root:0600）"
    echo -e "  服务管理    : systemctl status/restart ${SERVICE_NAME}"
    echo -e "  查看日志    : journalctl -u ${SERVICE_NAME} -f"
    echo -e "  更新版本    : 替换 ${DATA_DIR}/server-status 后 systemctl restart ${SERVICE_NAME}"
    echo -e "                （或使用 restart-server.sh，先编译成功再重启，失败不影响运行中的服务）"
  else
    echo -e "  数据卷      : server-status-data（运行数据/日志/媒体）"
    echo -e "  证书目录    : ./tls/（cert.pem / key.pem）"
    echo -e "  配置文件    : ./.env（密钥等，已加入 .gitignore）"
    echo -e "  服务管理    : docker compose logs -f / restart / down"
  fi
  echo -e "  配置说明    : 全部环境变量见 README「配置说明」或 .env.example"
  echo -e "${CYAN}==========================================================${NC}"
}

# 健康检查：等待 HTTPS 端口就绪（最多 30 秒）
wait_healthy() {  # $1=域名 $2=端口
  local host="$1" port="$2" i code
  info "等待服务就绪（https://127.0.0.1:${port}/）..."
  for i in $(seq 1 30); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${port}/" || true)"
    if [[ "$code" != "000" && -n "$code" ]]; then
      info "服务已就绪（HTTP ${code}）"
      return 0
    fi
    sleep 1
  done
  warn "30 秒内未探测到 HTTPS 响应，请查看日志排查"
  return 1
}

# ---------------- Docker 模式 ----------------
deploy_docker() {
  command -v docker >/dev/null || die "未安装 docker"
  docker compose version >/dev/null 2>&1 || die "未安装 docker compose 插件"

  # 1. .env：已存在则保留（密钥不能轮换），否则从模板生成并填入随机密钥
  if [[ -f .env ]]; then
    info ".env 已存在，跳过（密钥保持不变）"
  else
    [[ -f .env.example ]] || die "缺少 .env.example"
    info "生成 .env（随机密钥）..."
    sed -e "s|^SERVER_STATUS_SIGNING_KEY=.*|SERVER_STATUS_SIGNING_KEY=$(gen_key)|" \
        -e "s|^SERVER_STATUS_ENCRYPT_KEY=.*|SERVER_STATUS_ENCRYPT_KEY=$(gen_key)|" \
        -e "s|^SERVER_STATUS_DOWNLOAD_TOKEN_SECRET=.*|SERVER_STATUS_DOWNLOAD_TOKEN_SECRET=$(gen_key)|" \
        -e "s|^#SERVER_STATUS_DOMAIN=.*|SERVER_STATUS_DOMAIN=${DOMAIN}|" \
        .env.example > .env
    chmod 600 .env
  fi

  # 2. 证书
  ensure_tls "$SCRIPT_DIR/tls" "$DOMAIN"

  # 3. 启动
  info "构建并启动容器（首次构建需下载依赖，可能需要几分钟）..."
  docker compose up -d --build

  wait_healthy "$DOMAIN" "$PORT" || docker compose logs --tail 50
  print_summary "docker"
}

# ---------------- systemd 模式 ----------------
deploy_systemd() {
  command -v systemctl >/dev/null || die "未检测到 systemd（本脚本仅支持 systemd 发行版）"

  # 1. 准备二进制：优先用指定的 → 项目内预编译产物 → 现场编译
  local bin_src=""
  if [[ -n "$CUSTOM_BINARY" ]]; then
    [[ -f "$CUSTOM_BINARY" ]] || die "指定的二进制不存在: $CUSTOM_BINARY"
    bin_src="$CUSTOM_BINARY"
  elif [[ -f "$SCRIPT_DIR/server-status-linux" ]]; then
    bin_src="$SCRIPT_DIR/server-status-linux"
  elif command -v go >/dev/null; then
    info "未找到预编译产物 server-status-linux，现场编译（约 1-2 分钟）..."
    ( cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w" -o server-status-linux . ) \
      || die "编译失败，请检查 Go 环境（或先在本地交叉编译：CGO_ENABLED=0 GOOS=linux go build -o server-status-linux .）"
    bin_src="$SCRIPT_DIR/server-status-linux"
  else
    die "没有可用的二进制：项目中无 server-status-linux，且未安装 Go。
请先在本机构建后上传，再用 --binary 指定路径：
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags=\"-s -w\" -o server-status-linux ."
  fi

  # 2. 数据目录：二进制 / 模板 / 默认配置（已有的不覆盖）
  info "安装程序到 ${DATA_DIR} ..."
  mkdir -p "$DATA_DIR/templates" "$MEDIA_DIR" "$DATA_DIR/log" "$DATA_DIR/tls"
  # 先传 .new 再原子 mv，避免覆盖正在运行的二进制报 Text file busy
  cp -f "$bin_src" "${DATA_DIR}/server-status.new"
  chmod 755 "${DATA_DIR}/server-status.new"
  mv -f "${DATA_DIR}/server-status.new" "${DATA_DIR}/server-status"
  cp -rf "$SCRIPT_DIR/templates/." "$DATA_DIR/templates/"
  [[ -f "$DATA_DIR/config.json" ]] || cp -f "$SCRIPT_DIR/config.json" "$DATA_DIR/config.json"
  [[ -f "$DATA_DIR/private_notes.json" ]] || cp -f "$SCRIPT_DIR/private_notes.json" "$DATA_DIR/private_notes.json"

  # 3. 配置文件（已存在则保留 —— 密钥绝不能轮换）
  if [[ -f "$ENV_FILE" ]]; then
    info "配置文件已存在，跳过（${ENV_FILE}）"
  else
    info "生成配置文件 ${ENV_FILE}（随机密钥）..."
    mkdir -p "$(dirname "$ENV_FILE")"
    {
      echo "SERVER_STATUS_SIGNING_KEY=$(gen_key)"
      echo "SERVER_STATUS_ENCRYPT_KEY=$(gen_key)"
      echo "SERVER_STATUS_DOWNLOAD_TOKEN_SECRET=$(gen_key)"
      echo "SERVER_STATUS_DOMAIN=${DOMAIN}"
      echo "SERVER_STATUS_LISTEN_ADDR=:${PORT}"
      echo "SERVER_STATUS_HOME=${DATA_DIR}"
      echo "SERVER_STATUS_MEDIA_DIR=${MEDIA_DIR}"
      if [[ -n "$STATIC_BASE_URL" ]]; then echo "SERVER_STATUS_STATIC_BASE_URL=${STATIC_BASE_URL}"; fi
      if [[ -n "$EXTRA_ORIGINS" ]];   then echo "SERVER_STATUS_EXTRA_ORIGINS=${EXTRA_ORIGINS}"; fi
      if [[ -n "$PRIVATE_PASSWORD" ]]; then
        echo "PRIVATE_NOTES_PASSWORD=${PRIVATE_PASSWORD}"
        echo "# 提示：PRIVATE_NOTES_PASSWORD 仅首次启动生效，私人密码初始化后可删除此行"
      fi
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  fi

  # 4. TLS 证书
  if [[ "$USE_LETSENCRYPT" == "yes" ]]; then
    [[ "$DOMAIN" != "localhost" ]] || die "--letsencrypt 需要先用 -d 指定真实域名"
    command -v certbot >/dev/null || die "未安装 certbot（apt install certbot / yum install certbot）"
    info "通过 certbot 签发证书（需 80 端口可用）..."
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos \
      --register-unsafely-without-email || die "certbot 签发失败，请确认域名解析与本机 80 端口可达"
    cp -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$DATA_DIR/tls/cert.pem"
    cp -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"  "$DATA_DIR/tls/key.pem"
    chmod 600 "$DATA_DIR/tls/key.pem"
    warn "证书续期后需同步到 ${DATA_DIR}/tls/ 并重启服务，可在 crontab 加："
    echo "    0 3 * * * cp -f /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${DATA_DIR}/tls/cert.pem && cp -f /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${DATA_DIR}/tls/key.pem && systemctl restart ${SERVICE_NAME}"
  else
    ensure_tls "$DATA_DIR/tls" "$DOMAIN"
  fi

  # 5. systemd 服务单元
  info "安装 systemd 服务 ..."
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=Server Status Monitor Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${DATA_DIR}
ExecStart=${DATA_DIR}/server-status
EnvironmentFile=-${ENV_FILE}
LimitNOFILE=65535
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null

  # 6. 启动 / 重启
  info "(重)启动服务 ..."
  systemctl restart "$SERVICE_NAME"
  sleep 2
  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl status "$SERVICE_NAME" --no-pager || true
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
    die "服务启动失败，请根据上方日志排查"
  fi

  if wait_healthy "$DOMAIN" "$PORT"; then
    # 启动后检查密钥告警（⚠️ 表示 env 未生效）
    if journalctl -u "$SERVICE_NAME" -n 30 --no-pager | grep -q "⚠️"; then
      warn "启动日志中存在密钥相关告警，请确认 ${ENV_FILE} 已正确写入并重启服务"
    fi
  fi
  print_summary "systemd"
}

# ---------------- 私人空间密码（交互式可选） ----------------
if [[ -z "$PRIVATE_PASSWORD" && "$MODE" == "systemd" && -t 0 ]]; then
  read -r -p "可选：设置私人空间初始化密码（直接回车跳过，之后可在应用内设置）: " PRIVATE_PASSWORD || true
fi

# ---------------- 执行 ----------------
if [[ "$MODE" == "docker" ]]; then
  cd "$SCRIPT_DIR"
  deploy_docker
else
  deploy_systemd
fi
