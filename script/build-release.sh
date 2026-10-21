#!/bin/sh

#========================================================
#   Santaizi Agent (Rust) 发布产物构建
#   用法: script/build-release.sh <x86_64-musl|aarch64-musl>
#   镜像可用 SANTAIZI_BUILD_IMAGE 覆盖（仅供实验）。
#========================================================

set -eu

TARGET="${1:-}"
case "$TARGET" in
    x86_64-musl)
        TRIPLE="x86_64-unknown-linux-musl"
        ;;
    aarch64-musl)
        TRIPLE="aarch64-unknown-linux-musl"
        ;;
    *)
        echo "用法: $0 <x86_64-musl|aarch64-musl>" >&2
        exit 1
        ;;
esac

# messense/rust-musl-cross 是 Ubuntu + musl 交叉工具链：构建进程跑在 glibc 上
# （bindgen 能 dlopen libclang），产物是静态 musl。
IMAGE="${SANTAIZI_BUILD_IMAGE:-messense/rust-musl-cross:${TARGET}}"
# build.rs 走 tonic-prost-build 要 protoc，镜像里没有，从官方 release 取。
PROTOC_VERSION="${SANTAIZI_PROTOC_VERSION:-25.1}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker 不可用：发布产物必须在固定容器里构建，不能直接在开发机上编。" >&2
    exit 1
fi

# 为什么是静态 musl，而不是直接编 gnu：GitHub runner 的 ubuntu-latest 自带
# glibc 2.39，在它上面 cargo build 出来的二进制会要求 GLIBC_2.38
# （__isoc23_strtoull，glibc 2.38 起 strtoull 的 C23 重定向）和 GLIBC_2.39
# （pidfd_spawnp / pidfd_getpid，Rust std 的弱符号，链接时按构建机 glibc 记录
# 版本需求）。Debian 11/12、Ubuntu 20.04/22.04 的 loader 直接报
# "version `GLIBC_2.38' not found" 拒绝启动，systemd 里只看到
# status=1/FAILURE（Go 探针静态链接所以没这个毛病）。
# 静态 musl 不带 glibc，任何 Linux 都能跑，也不必在安装脚本里查 glibc 版本。

docker run --rm \
    -v "$PWD:/w" -w /w \
    -e CARGO_TARGET_DIR=/w/target \
    -e TRIPLE="$TRIPLE" \
    -e PROTOC_VERSION="$PROTOC_VERSION" \
    "$IMAGE" sh -euc '
# 镜像里的 stable 是镜像发布时点的 rustc（可能落后于 Cargo.lock 里
# wreq 等包声明的 rust-version），卸掉重装拿当前 stable；musl 目标也要补。
rustup toolchain uninstall stable >/dev/null 2>&1 || true
rustup toolchain install stable --profile minimal >/dev/null
rustup default stable >/dev/null
rustup target add "${CARGO_BUILD_TARGET}" >/dev/null

# btls-sys 用 bindgen 生成 FFI：clang 默认会找到宿主 glibc 的 /usr/include，
# 同架构时碰巧能过，交叉到 aarch64 时 glibc 的 stdint.h 会去找
# bits/libc-header-start.h 而 sysroot 里没有，直接 fatal error。显式把 musl
# 的 include 顶到最前面，绑定才按目标 libc 生成。
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/local/musl/${TRIPLE}/include"

if ! command -v protoc >/dev/null 2>&1; then
    # GitHub release 偶发 SSL 断流，重试几次；只取 bin/protoc：本仓 proto 不
    # import google.protobuf，用不到 include/。
    curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors -o /tmp/protoc.zip \
        "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    unzip -qo /tmp/protoc.zip -d /usr/local "bin/protoc"
    rm -f /tmp/protoc.zip
fi
# 镜像的 CARGO_BUILD_TARGET 已指向对应 musl 目标。
cargo build --release --locked

# 自检：产物必须静态、且不带任何 glibc 版本需求。gnu 产物会把构建机 glibc 的
# 版本需求写进 ELF，旧系统 loader 直接拒启——systemd 里只看到 status=1/FAILURE，
# 应用一行日志都没有（v1.0.6 就是这样）。每次构建都挡一道，别靠人记得。
# file 对 x86_64 输出 static-pie linked、aarch64 输出 statically linked，
# 两种都是全静态（无 INTERP、无 NEEDED），所以只匹配 static。
bin="target/${CARGO_BUILD_TARGET}/release/santaizi-agent-rs"
file "$bin" | grep -q "static" || {
    echo "产物不是静态链接：$(file "$bin")" >&2
    exit 1
}
if objdump -T "$bin" | grep -q GLIBC; then
    echo "产物仍带 glibc 版本需求：" >&2
    objdump -T "$bin" | grep GLIBC | head -3 >&2
    exit 1
fi
'
