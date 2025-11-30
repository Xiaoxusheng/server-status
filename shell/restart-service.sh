#!/bin/bash

# 简单版本，不依赖 lsof
PORT=9000
APP_NAME="server-status"

echo "停止服务..."
# 使用 netstat 查找并杀死进程
netstat -tlnp 2>/dev/null | grep ":${PORT} " | awk '{print $7}' | cut -d'/' -f1 | xargs -r kill -9

# 如果 netstat 不可用，尝试使用 ss
if ! command -v netstat &> /dev/null; then
    ss -tlnp 2>/dev/null | grep ":${PORT} " | awk '{print $6}' | cut -d':' -f2 | cut -d',' -f1 | xargs -r kill -9
fi

sleep 2

echo "重新编译..."
go build -o "$APP_NAME" -ldflags "-w -s"

echo "启动服务..."
 ./"$APP_NAME" > app.log 2>&1 &

echo "等待服务启动..."
sleep 5

# 检查端口是否被监听
if netstat -tln 2>/dev/null | grep ":${PORT} " > /dev/null || ss -tln 2>/dev/null | grep ":${PORT} " > /dev/null; then
    echo "服务启动成功!"
    echo "日志文件: app.log"
else
    echo "服务启动失败! 查看日志: app.log"
    tail -20 app.log
    exit 1
fi

