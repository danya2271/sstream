#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUTPUT_DIR="${OUTPUT_DIR:-builddir-linux}"
STATIC_OPENSSL="${STATIC_OPENSSL:-1}"
OPENSSL_STATIC_PREFIX="${OPENSSL_STATIC_PREFIX:-}"

die() {
    echo "error: $*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for tool in git meson ninja pkg-config; do
    have_cmd "$tool" || die "missing required tool: $tool"
done

deps_ready() {
    [ -f subprojects/picoquic/CMakeLists.txt ] &&
        [ -f subprojects/picoquic/picotls/CMakeLists.txt ] &&
        [ -f subprojects/picoquic/picotls/deps/picotest/picotest.c ] &&
        [ -f extern/SPCDNS/src/dns.h ] &&
        [ -f extern/lua-resty-base-encoding/base32.c ] &&
        [ -f extern/quick_arg_parser/quick_arg_parser.hpp ]
}

echo "=== Checking subprojects ==="
if ! deps_ready; then
    git submodule update --init --recursive
    if [ -d subprojects/picoquic/picotls ] && [ ! -f subprojects/picoquic/picotls/deps/picotest/picotest.c ]; then
        git -C subprojects/picoquic/picotls submodule update --init --recursive
    fi
fi

[ -f subprojects/picoquic/CMakeLists.txt ] || die "subprojects/picoquic is missing or incomplete"
[ -f subprojects/picoquic/picotls/CMakeLists.txt ] || die "subprojects/picoquic/picotls is missing or incomplete"
[ -f subprojects/picoquic/picotls/deps/picotest/picotest.c ] || die "subprojects/picoquic/picotls/deps/picotest is missing or incomplete"
[ -f extern/SPCDNS/src/dns.h ] || die "extern/SPCDNS is missing or incomplete"
[ -f extern/lua-resty-base-encoding/base32.c ] || die "extern/lua-resty-base-encoding is missing or incomplete"
[ -f extern/quick_arg_parser/quick_arg_parser.hpp ] || die "extern/quick_arg_parser is missing or incomplete"

find_static_openssl_prefix() {
    local prefix libdir

    if [ -n "$OPENSSL_STATIC_PREFIX" ]; then
        for libdir in "$OPENSSL_STATIC_PREFIX/lib" "$OPENSSL_STATIC_PREFIX/lib64"; do
            if [ -f "$libdir/libssl.a" ] && [ -f "$libdir/libcrypto.a" ]; then
                printf '%s\n' "$OPENSSL_STATIC_PREFIX"
                return 0
            fi
        done
        return 1
    fi

    libdir=$(pkg-config --variable=libdir openssl 2>/dev/null || true)
    prefix=$(pkg-config --variable=prefix openssl 2>/dev/null || true)
    if [ -n "$libdir" ] && [ -f "$libdir/libssl.a" ] && [ -f "$libdir/libcrypto.a" ]; then
        printf '%s\n' "$prefix"
        return 0
    fi

    for prefix in /usr /usr/local; do
        for libdir in "$prefix/lib" "$prefix/lib64"; do
            if [ -f "$libdir/libssl.a" ] && [ -f "$libdir/libcrypto.a" ]; then
                printf '%s\n' "$prefix"
                return 0
            fi
        done
    done

    return 1
}

common_c_args="-ffunction-sections -fdata-sections"
common_link_args="-Wl,--gc-sections -Wl,-O1"

if have_cmd ccache && [ -z "${CCACHE_DIR:-}" ] && [ "${CCACHE_DISABLE:-0}" != "1" ]; then
    mkdir -p "$OUTPUT_DIR/.ccache"
    CCACHE_DIR=$(cd "$OUTPUT_DIR/.ccache" && pwd)
    export CCACHE_DIR
fi

meson_args=(
    "$OUTPUT_DIR"
    --buildtype=release
    --default-library=static
    --prefer-static
    -Db_lto=true
    -Dstrip=true
    -Dbuild_loglib=false
    -Dwerror=false
    -Dwarning_level=0
    -Dc_args="$common_c_args"
    -Dcpp_args="$common_c_args"
)

if [ "$STATIC_OPENSSL" = "1" ]; then
    openssl_prefix=$(find_static_openssl_prefix) || die "static OpenSSL libraries were not found. Install the OpenSSL static development package or set OPENSSL_STATIC_PREFIX=/path/to/openssl. To build with dynamic OpenSSL, run STATIC_OPENSSL=0 $0"

    echo "=== Static OpenSSL prefix: $openssl_prefix ==="
    pkg_config_path=""
    for pkgdir in "$openssl_prefix/lib/pkgconfig" "$openssl_prefix/lib64/pkgconfig"; do
        if [ -d "$pkgdir" ]; then
            pkg_config_path="$pkgdir${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            break
        fi
    done
    if [ -n "$pkg_config_path" ]; then
        openssl_static_libs=$(PKG_CONFIG_PATH="$pkg_config_path" pkg-config --static --libs openssl 2>/dev/null || printf '%s' '-lssl -lcrypto -ldl -pthread')
    else
        openssl_static_libs=$(pkg-config --static --libs openssl 2>/dev/null || printf '%s' '-lssl -lcrypto -ldl -pthread')
    fi
    full_static_link_args="-static $common_link_args $openssl_static_libs"
    meson_args+=(
        -Dstatic_openssl=true
        -Dopenssl_root_dir="$openssl_prefix"
        -Dc_link_args="$full_static_link_args"
        -Dcpp_link_args="$full_static_link_args"
    )
else
    echo "=== STATIC_OPENSSL=0: building project libraries static, OpenSSL may remain dynamic ==="
    meson_args+=(
        -Dstatic_openssl=false
        -Dc_link_args="$common_link_args"
        -Dcpp_link_args="$common_link_args"
    )
fi

echo "=== Meson setup: $OUTPUT_DIR ==="
if [ -d "$OUTPUT_DIR/meson-info" ]; then
    meson setup --wipe "${meson_args[@]}"
else
    meson setup "${meson_args[@]}"
fi

echo "=== Compiling ==="
ninja -C "$OUTPUT_DIR" slipstream-client slipstream-server

if [ "$STATIC_OPENSSL" = "1" ] && ldd "$OUTPUT_DIR/slipstream-server" >/dev/null 2>&1; then
    die "slipstream-server is still dynamically linked"
fi

echo "=== Build complete ==="
ls -lh "$OUTPUT_DIR/slipstream-client" "$OUTPUT_DIR/slipstream-server"
