# syntax=docker/dockerfile:1

########################
# 构建阶段：编译 Go 二进制
########################
FROM golang:1.25-alpine AS builder

# 国内网络可用 GOPROXY 加速依赖下载（默认已指向 goproxy.cn，海外构建可传参覆盖）
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src

# 先复制依赖清单，利用 Docker 层缓存加速后续构建
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并编译
# modernc.org/sqlite 为纯 Go 实现，可关闭 CGO；-s -w 去除符号表减小体积
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server-status .

########################
# 运行阶段：最小化运行时镜像
########################
FROM alpine:3.20

# 安装运行时依赖：
# - docker-cli: 容器管理页通过 docker CLI 操作宿主 Docker（需自行挂载 /var/run/docker.sock）
# - bash:       Web Shell 页面优先使用 /bin/bash
# - procps:     进程页依赖完整版 ps（busybox ps 不支持 --sort 等参数）
# - ca-certificates / tzdata: HTTPS 根证书与时区数据
RUN apk add --no-cache ca-certificates tzdata bash docker-cli procps

# /data 为唯一数据卷挂载点（运行数据 / 日志 / 媒体 / TLS 证书 / config.json 都在其中）
RUN mkdir -p /data/log /data/media /data/tls /app

# 复制编译产物；模板烧入镜像（不随数据卷丢失），通过 SERVER_STATUS_TEMPLATES_DIR 指向
COPY --from=builder /out/server-status /app/server-status
COPY templates/ /app/templates/

# 默认功能配置（named volume 首次创建时会把镜像内 /data 内容播种进去，之后以卷内为准）
COPY config.json /data/config.json
COPY private_notes.json /data/private_notes.json

# 容器内固定数据根目录；密钥/域名等敏感配置由 compose 从 .env 注入
ENV SERVER_STATUS_HOME=/data \
    SERVER_STATUS_TEMPLATES_DIR=/app/templates \
    SERVER_STATUS_TLS_CERT=/data/tls/cert.pem \
    SERVER_STATUS_TLS_KEY=/data/tls/key.pem

WORKDIR /data

EXPOSE 9000

# 健康检查：忽略自签证书访问 HTTPS 首页
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD wget --no-check-certificate -q -O /dev/null https://127.0.0.1:9000/ || exit 1

ENTRYPOINT ["/app/server-status"]
