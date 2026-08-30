#!/bin/bash
# ============================================================
# server-status 手动安装 systemd 服务的辅助脚本
# （如果你只是想要一键部署，请直接用根目录的 deploy.sh）
#
# 前提：二进制与 templates/ 已就位于应用目录（下方 WORK_DIR）
# ============================================================

# ================= 配置区域 =================
# 应用目录（= 数据根目录，与 SERVER_STATUS_HOME 保持一致）
WORK_DIR="/opt/server-status"
# 可执行文件的完整路径
EXEC_PATH="/opt/server-status/server-status"
# 环境变量文件（密钥、域名等；不存在时服务仍可启动，但强烈建议创建）
ENV_FILE="/etc/server-status/server-status.env"
# 服务名称
SERVICE_NAME="server-status.service"
# ===========================================

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ ! -f "$EXEC_PATH" ]; then
    echo -e "${RED}错误: 找不到可执行文件 $EXEC_PATH${NC}"
    echo "请先构建并放置二进制（CGO_ENABLED=0 GOOS=linux go build -o $EXEC_PATH .），或直接使用 deploy.sh"
    exit 1
fi

echo -e "${GREEN}===> 1. 写入 systemd 服务文件...${NC}"

cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=Server Status Monitor Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$WORK_DIR
ExecStart=$EXEC_PATH
EnvironmentFile=-$ENV_FILE
LimitNOFILE=65535
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}===> 2. 重新加载 systemd...${NC}"
systemctl daemon-reload

echo -e "${GREEN}===> 3. 设置开机自启...${NC}"
systemctl enable $SERVICE_NAME

echo -e "${GREEN}===> 4. (重)启动服务...${NC}"
systemctl restart $SERVICE_NAME

echo -e "${GREEN}===> 5. 检查服务状态...${NC}"
sleep 2

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}✅ 安装成功！服务已启动并设置开机自启。${NC}"
    echo "常用命令："
    echo "  查看状态: systemctl status $SERVICE_NAME"
    echo "  查看日志: journalctl -u $SERVICE_NAME -f"
    echo "  停止服务: systemctl stop $SERVICE_NAME"
    echo "  重启服务: systemctl restart $SERVICE_NAME"
else
    echo -e "${RED}❌ 服务启动失败，请检查以下日志：${NC}"
    systemctl status $SERVICE_NAME --no-pager
    journalctl -u $SERVICE_NAME -n 20 --no-pager
    exit 1
fi
