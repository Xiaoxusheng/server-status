#!/bin/bash

APP_NAME="server-status"
APP_DIR="/opt/${APP_NAME}"
BIN_PATH="/usr/local/bin/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

# 确保脚本以 root 权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 权限运行此脚本"
    exit 1
fi

echo "1. 创建应用目录：${APP_DIR}"
mkdir -p ${APP_DIR}

echo "2. 复制 Go 源码到 ${APP_DIR}"
cp -r ./* ${APP_DIR}/

echo "3. 编译 Go 程序"
cd ${APP_DIR}
go mod tidy
go build -o ${BIN_PATH}  -flags "-s -w"

if [ ! -f "${BIN_PATH}" ]; then
    echo "编译失败，请检查 Go 环境"
    exit 1
fi

echo "4. 创建 systemd 服务文件：${SERVICE_FILE}"
cat > ${SERVICE_FILE} <<EOF
[Unit]
Description=Server Status Monitoring
After=network.target

[Service]
ExecStart="/root/os"
Restart=always
User=root
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOF

echo "5. 重新加载 systemd"
systemctl daemon-reload

echo "6. 启动服务"
systemctl start ${APP_NAME}

echo "7. 设置开机自启"
systemctl enable ${APP_NAME}

echo "✅ 部署完成，状态查看：systemctl status ${APP_NAME}"
