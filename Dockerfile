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
# modernc.org/sqlite 为纯 Go 实现，可关闭 CGO；-s -w 与 build.sh 保持一致（去除符号表减小体积）
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server-status .

########################
# 运行阶段：最小化运行时镜像
########################
FROM alpine:3.20

# 安装运行时依赖：
# - docker-cli: 容器管理页通过 docker CLI 操作宿主 Docker（需挂载 /var/run/docker.sock）
# - bash:       Web Shell 页面优先使用 /bin/bash
# - procps:     进程页依赖完整版 ps（busybox ps 不支持 --sort 等参数）
# - ca-certificates / tzdata: HTTPS 根证书与时区数据
RUN apk add --no-cache ca-certificates tzdata bash docker-cli procps

# 按二进制硬编码路径创建目录（/opt/server-status 数据与模板、/etc/server-status/tls 证书、/opt/server-status/media 媒体）
RUN mkdir -p /opt/server-status/templates /opt/server-status/log /etc/server-status/tls /opt/server-status/media /app

# 复制编译产物与默认模板/配置（若挂载宿主机目录，宿主内容将覆盖镜像内文件）
COPY --from=builder /out/server-status /app/server-status
COPY templates/ /opt/server-status/templates/
COPY config.json /opt/server-status/config.json

WORKDIR /opt/server-status

EXPOSE 9000

# 健康检查：忽略自签证书访问 HTTPS 首页
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD wget --no-check-certificate -q -O /dev/null https://127.0.0.1:9000/ || exit 1

ENTRYPOINT ["/app/server-status"]
