#!/bin/bash

# 配置
APP_NAME="server-status"
SERVICE_NAME="server-status.service"
SRC_DIR="/home/os"  # main.go 所在目录

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. 先进入目录
cd $SRC_DIR

# 2. 【第一步】先编译 (Compile First)
# 这样做的好处是：如果代码写错了导致编译失败，旧服务还在运行，不会导致网站挂掉。
echo -e "${GREEN}===> 1. 开始编译新版本...${NC}"
if go build -o "$APP_NAME" -ldflags "-w -s"; then
    echo -e "${GREEN}编译成功！${NC}"
else
    echo -e "${RED}编译失败！脚本终止，服务未受影响。${NC}"
    exit 1
fi

# 3. 【最后一步】重启 Systemd 服务 (Restart Last)
# systemctl restart 会自动完成 "停止旧进程 -> 启动新进程" 的操作
echo -e "${GREEN}===> 2. 重启服务 (Systemd)...${NC}"
sudo systemctl restart $SERVICE_NAME

# 4. 检查启动状态
echo -e "${GREEN}===> 3. 检查服务状态...${NC}"
sleep 2

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}服务重启成功!${NC}"
    # 显示最新的几行日志，确认服务正常跑起来了
    echo "--- 最新日志 (journalctl) ---"
    journalctl -u $SERVICE_NAME -n 10 --no-pager
else
    echo -e "${RED}服务启动失败! 请检查报错:${NC}"
    systemctl status $SERVICE_NAME --no-pager
    exit 1
fi