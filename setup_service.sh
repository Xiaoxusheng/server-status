#!/bin/bash

# ================= 配置区域 =================
# 程序所在的目录
WORK_DIR="/home/os"
# 可执行文件的完整路径
EXEC_PATH="/home/os/server-status"
# 服务名称
SERVICE_NAME="server-status.service"
# ===========================================

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 检查可执行文件是否存在
if [ ! -f "$EXEC_PATH" ]; then
    echo -e "${RED}错误: 找不到可执行文件 $EXEC_PATH${NC}"
    echo "请先运行 'go build -o server-status main.go' 进行编译"
    exit 1
fi

echo -e "${GREEN}===> 1. 正在生成 Systemd 服务文件...${NC}"

# 写入服务文件
# 注意：这里默认使用 root 用户运行，确保有权限绑定端口和读写文件
sudo cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=Server Status Monitor Service
Documentation=https://wustwu.cn
After=network.target network-online.target
Wants=network-online.target

[Service]
# 启动类型
Type=simple

# 运行用户 (建议使用 root 以免出现权限问题，或者修改为你当前的用户)
User=root
Group=root

# 工作目录 (非常重要，确保程序能找到 templates, static 等相对路径资源)
WorkingDirectory=$WORK_DIR

# 启动命令
ExecStart=$EXEC_PATH

# 资源限制 (可选)
LimitNOFILE=65535

# 自动重启配置
Restart=always
RestartSec=5s
StartLimitInterval=0

# 环境配置 (如果需要)
# Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}===> 2. 重新加载 Systemd 守护进程...${NC}"
sudo systemctl daemon-reload

echo -e "${GREEN}===> 3. 启用开机自启...${NC}"
# 这步是关键：创建软链接到 /etc/systemd/system/multi-user.target.wants/
sudo systemctl enable $SERVICE_NAME

echo -e "${GREEN}===> 4. (重)启动服务...${NC}"
sudo systemctl restart $SERVICE_NAME

echo -e "${GREEN}===> 5. 检查服务状态...${NC}"
sleep 2

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}✅ 设置成功！服务已启动并设置为开机自启。${NC}"
    echo "常用命令："
    echo "  查看状态: systemctl status $SERVICE_NAME"
    echo "  查看日志: journalctl -u $SERVICE_NAME -f"
    echo "  停止服务: systemctl stop $SERVICE_NAME"
    echo "  重启服务: systemctl restart $SERVICE_NAME"
else
    echo -e "${RED}❌ 服务启动失败，请检查以下日志：${NC}"
    systemctl status $SERVICE_NAME --no-pager
    journalctl -u $SERVICE_NAME -n 20 --no-pager
fi