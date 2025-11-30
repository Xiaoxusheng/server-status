#!/bin/bash

# 跨平台构建脚本
# 使用方法: ./build.sh [平台列表]

# 设置颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 项目配置
PROJECT_NAME="myapp"
VERSION="1.0.0"
BUILD_DIR="dist"
MAIN_FILE="main.go"  # 如果是Go项目

# 支持的平台列表
SUPPORTED_PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
)

# 显示帮助信息
show_help() {
    echo "使用方法: $0 [选项]"
    echo "选项:"
    echo "  -a, --all          构建所有支持的平台"
    echo "  -p, --platform     指定平台 (例如: linux/amd64)"
    echo "  -l, --list         列出所有支持的平台"
    echo "  -c, --clean        清理构建目录"
    echo "  -h, --help         显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --all                    # 构建所有平台"
    echo "  $0 --platform linux/amd64   # 构建特定平台"
    echo "  $0 --list                   # 列出支持的平台"
}

# 列出所有支持的平台
list_platforms() {
    echo "支持的平台:"
    for platform in "${SUPPORTED_PLATFORMS[@]}"; do
        echo "  $platform"
    done
}

# 清理构建目录
clean_build() {
    echo -e "${YELLOW}清理构建目录...${NC}"
    rm -rf "$BUILD_DIR"
    echo -e "${GREEN}清理完成!${NC}"
}

# 构建函数
build_platform() {
    local platform=$1
    local os="${platform%/*}"
    local arch="${platform#*/}"
    local output_name="$PROJECT_NAME"

    # Windows平台添加.exe后缀
    if [ "$os" = "windows" ]; then
        output_name="$output_name.exe"
    fi

    local output_path="$BUILD_DIR/${os}_${arch}/$output_name"

    echo -e "${YELLOW}构建 $platform -> $output_path${NC}"

    # 创建输出目录
    mkdir -p "$(dirname "$output_path")"

    # 根据不同语言选择构建方式
    if [ -f "$MAIN_FILE" ]; then
        # Go项目构建
        if command -v go &> /dev/null; then
            CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -ldflags="-s -w" -o "$output_path" "$MAIN_FILE"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ $platform 构建成功${NC}"

                # 复制配置文件等（如果有）
                copy_resources "$(dirname "$output_path")"
            else
                echo -e "${RED}✗ $platform 构建失败${NC}"
                return 1
            fi
        else
            echo -e "${RED}错误: 未找到Go编译器${NC}"
            return 1
        fi
    elif [ -f "package.json" ]; then
        # Node.js项目 - 使用pkg打包
        if command -v pkg &> /dev/null; then
            pkg . --target "$platform" --output "$output_path"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ $platform 构建成功${NC}"
            else
                echo -e "${RED}✗ $platform 构建失败${NC}"
                return 1
            fi
        else
            echo -e "${RED}错误: 未安装pkg, 请运行: npm install -g pkg${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法确定项目类型${NC}"
        echo "请确保存在 main.go (Go) 或 package.json (Node.js) 文件"
        return 1
    fi

    return 0
}

# 复制资源文件
copy_resources() {
    local target_dir=$1

    # 复制配置文件示例
    if [ -f "config.example.yaml" ]; then
        cp "config.example.yaml" "$target_dir/"
    fi

    # 复制README等文档
    if [ -f "README.md" ]; then
        cp "README.md" "$target_dir/"
    fi
}

# 创建压缩包
create_archive() {
    echo -e "${YELLOW}创建压缩包...${NC}"

    cd "$BUILD_DIR" || exit 1

    for dir in */; do
        if [ -d "$dir" ]; then
            local dir_name="${dir%/}"
            echo "压缩: $dir_name"
            if command -v tar &> /dev/null; then
                tar -czf "${dir_name}_v${VERSION}.tar.gz" "$dir_name"
            fi
            if command -v zip &> /dev/null && [ "$(echo "$dir_name" | grep windows)" ]; then
                zip -qr "${dir_name}_v${VERSION}.zip" "$dir_name"
            fi
        fi
    done

    cd - > /dev/null || exit 1
    echo -e "${GREEN}压缩包创建完成!${NC}"
}

# 主函数
main() {
    # 检查参数
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all)
                BUILD_ALL=true
                shift
                ;;
            -p|--platform)
                TARGET_PLATFORM="$2"
                shift 2
                ;;
            -l|--list)
                list_platforms
                exit 0
                ;;
            -c|--clean)
                clean_build
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}未知参数: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # 创建构建目录
    mkdir -p "$BUILD_DIR"

    # 执行构建
    if [ "$BUILD_ALL" = true ]; then
        echo -e "${GREEN}开始构建所有平台...${NC}"
        success_count=0
        total_count=0

        for platform in "${SUPPORTED_PLATFORMS[@]}"; do
            ((total_count++))
            if build_platform "$platform"; then
                ((success_count++))
            fi
        done

        echo -e "${GREEN}构建完成: $success_count/$total_count 个平台构建成功${NC}"

    elif [ -n "$TARGET_PLATFORM" ]; then
        # 检查平台是否支持
        found=false
        for platform in "${SUPPORTED_PLATFORMS[@]}"; do
            if [ "$platform" = "$TARGET_PLATFORM" ]; then
                found=true
                break
            fi
        done

        if [ "$found" = true ]; then
            build_platform "$TARGET_PLATFORM"
        else
            echo -e "${RED}不支持的平台: $TARGET_PLATFORM${NC}"
            list_platforms
            exit 1
        fi
    fi

    # 创建压缩包
    if [ -d "$BUILD_DIR" ] && [ "$(ls -A "$BUILD_DIR")" ]; then
        create_archive
    fi
}

# 运行主函数
main "$@"