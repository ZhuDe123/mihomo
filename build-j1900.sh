#!/bin/bash
set -e

# =============================================================================
# mihomo 内核构建脚本 - 适配 Intel J1900 处理器
# J1900: x86_64 架构，支持 SSE3/SSE4.1 指令集 (GOAMD64=v2)
# =============================================================================

RED='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${RED}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_output"
CACHE_DIR="${HOME}/.cache/mihomo-build"

VERSION=$(git describe --tags --always 2>/dev/null || echo "unknown")
VERSION="${VERSION#v}"
VERSION="${VERSION//\//-}"
BUILDTIME=$(date)

# 初始化
init() {
    log_info "初始化构建环境..."
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${CACHE_DIR}/gomod"
    
    if ! command -v go &> /dev/null; then
        echo "错误：未找到 Go"
        exit 1
    fi
    go version
}

# 更新 CA 证书
update_ca() {
    log_info "更新 CA 证书..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq ca-certificates
        sudo update-ca-certificates
        cp -f /etc/ssl/certs/ca-certificates.crt "${SCRIPT_DIR}/component/ca/ca-certificates.crt" 2>/dev/null || true
    fi
}

# 构建核心
build_core() {
    log_info "开始构建 mihomo 核心 (GOAMD64=v2)..."
    
    export GOOS="linux"
    export GOARCH="amd64"
    export GOAMD64="v2"
    export CGO_ENABLED="0"
    export GOTOOLCHAIN="local"
    export GOMODCACHE="${CACHE_DIR}/gomod"
    
    local ldflags="-extldflags --static -X 'github.com/metacubex/mihomo/constant.Version=${VERSION}' -X 'github.com/metacubex/mihomo/constant.BuildTime=${BUILDTIME}' -w -s -buildid="
    
    log_info "GOOS=${GOOS}, GOARCH=${GOARCH}, GOAMD64=${GOAMD64}, VERSION=${VERSION}"
    
    go build -v \
        -tags "with_gvisor" \
        -trimpath \
        -ldflags "${ldflags}" \
        -o "${BUILD_DIR}/mihomo"
    
    cd "${BUILD_DIR}"
    gzip -c mihomo > "mihomo-linux-amd64-v2-${VERSION}.gz"
    
    log_info "构建完成!"
    ls -lh "${BUILD_DIR}/"
}

# 打包 DEB
package_deb() {
    log_info "打包 DEB..."
    if command -v fpm &> /dev/null; then
        cp "${SCRIPT_DIR}/.github/release/.fpm_systemd" "${SCRIPT_DIR}/.fpm" 2>/dev/null || true
        fpm -t deb -v "${VERSION}" -p "${BUILD_DIR}/mihomo-linux-amd64-v2-${VERSION}.deb" \
            --architecture amd64 "${BUILD_DIR}/mihomo=/usr/bin/mihomo"
        log_info "DEB 打包完成"
    else
        log_warn "fpm 未安装，跳过 DEB 打包 (sudo gem install fpm)"
    fi
}

# 清理缓存
clean_cache() {
    log_info "清理缓存..."
    rm -rf "${CACHE_DIR}"
}

show_help() {
    cat << EOF
mihomo 构建脚本 - Intel J1900 (GOAMD64=v2)

用法: $0 [选项]

选项:
    -b, --build     构建核心 (默认)
    -d, --deb       构建 + 打包 DEB
    -c, --clean     清理缓存
    -h, --help      显示帮助

EOF
}

main() {
    local action="build"
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--build) action="build"; shift ;;
            -d|--deb) action="deb"; shift ;;
            -c|--clean) action="clean"; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log_warn "未知选项：$1"; show_help; exit 1 ;;
        esac
    done
    
    case ${action} in
        build) init; update_ca; build_core ;;
        deb) init; update_ca; build_core; package_deb ;;
        clean) clean_cache ;;
    esac
}

main "$@"
