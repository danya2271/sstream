#!/bin/bash
# Build script for Android arm64-v8a executable (PIE)
set -e

ROOT_DIR="$PWD"
NDK_ROOT="${1:-}"
API_LEVEL="${2:-26}"
MESON_BUILD_DIR="${3:-builddir-android}"

if [ -z "$NDK_ROOT" ]; then
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        NDK_ROOT=$(ls -d $HOME/Library/Android/sdk/ndk/* | sort -V | tail -1)
    elif [ -d "/opt/android-ndk" ]; then
        NDK_ROOT="/opt/android-ndk"
    else
        echo "ERROR: NDK not found. Pass it as the first argument."
        exit 1
    fi
fi

echo "=== Building slipstream for Android arm64-v8a (PIE) ==="

SYSROOT_DIR="$ROOT_DIR/android-sysroot"
mkdir -p "$SYSROOT_DIR"

# --- 1. COMPILE OPENSSL FOR ANDROID ---
OPENSSL_VER="3.1.5"
OPENSSL_DIR="$SYSROOT_DIR/openssl"

SSL_LIB_DIR="$OPENSSL_DIR/lib"
if [ -d "$OPENSSL_DIR/lib64" ]; then
    SSL_LIB_DIR="$OPENSSL_DIR/lib64"
fi

if [ ! -f "$SSL_LIB_DIR/libcrypto.a" ]; then
    echo "=== Building OpenSSL $OPENSSL_VER for Android ==="
    mkdir -p "$SYSROOT_DIR/tmp"
    cd "$SYSROOT_DIR/tmp"
    
    if [ ! -d "openssl-$OPENSSL_VER" ]; then
        curl -LO https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz
        tar xzf openssl-${OPENSSL_VER}.tar.gz
    fi
    
    cd openssl-${OPENSSL_VER}
    
    export ANDROID_NDK_ROOT="$NDK_ROOT"
    export PATH="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
    
    ./Configure android-arm64 no-shared no-tests --prefix="$OPENSSL_DIR"
    make -j$(nproc) --quiet
    make install_sw --quiet
    cd "$ROOT_DIR"
    echo "=== OpenSSL Build Complete ==="
    
    SSL_LIB_DIR="$OPENSSL_DIR/lib"
    if [ -d "$OPENSSL_DIR/lib64" ]; then
        SSL_LIB_DIR="$OPENSSL_DIR/lib64"
    fi
else
    echo "=== OpenSSL already built. Skipping. ==="
fi

# --- 2. OVERWRITE BROKEN CMAKE SCRIPT ---
if [ -f "meson.build" ]; then
    meson subprojects download || true
fi

PTLS_FIND_FILE="$ROOT_DIR/subprojects/picoquic/cmake/FindPTLS.cmake"
if [ -f "$PTLS_FIND_FILE" ]; then
    cat > "$PTLS_FIND_FILE" << EOF
set(PTLS_FOUND TRUE)
set(PTLS_INCLUDE_DIRS "")
set(PTLS_LIBRARIES picotls-core picotls-openssl picotls-minicrypto)
EOF
fi

# --- 3. CREATE PKG-CONFIG SANDBOX ---
PKG_WRAPPER="$SYSROOT_DIR/pkg-config-wrapper"
cat > "$PKG_WRAPPER" << EOF
#!/bin/sh
export PKG_CONFIG_DIR=""
export PKG_CONFIG_LIBDIR="${SSL_LIB_DIR}/pkgconfig"
exec pkg-config "\$@"
EOF
chmod +x "$PKG_WRAPPER"

# --- 4. CREATE CMAKE TOOLCHAIN WRAPPER ---
WRAPPER_FILE="$SYSROOT_DIR/android-toolchain-wrapper.cmake"
cat > "$WRAPPER_FILE" << EOF
set(ANDROID_ABI "arm64-v8a" CACHE STRING "Android ABI" FORCE)
set(ANDROID_PLATFORM "android-${API_LEVEL}" CACHE STRING "Android API Level" FORCE)

include("${NDK_ROOT}/build/cmake/android.toolchain.cmake")

set(OPENSSL_ROOT_DIR "${OPENSSL_DIR}" CACHE PATH "OpenSSL Root" FORCE)
set(OPENSSL_USE_STATIC_LIBS TRUE CACHE BOOL "Use static OpenSSL" FORCE)
set(OPENSSL_INCLUDE_DIR "${OPENSSL_DIR}/include" CACHE PATH "OpenSSL Include" FORCE)
set(OPENSSL_CRYPTO_LIBRARY "${SSL_LIB_DIR}/libcrypto.a" CACHE FILEPATH "libcrypto" FORCE)
set(OPENSSL_SSL_LIBRARY "${SSL_LIB_DIR}/libssl.a" CACHE FILEPATH "libssl" FORCE)
set(OPENSSL_FOUND TRUE CACHE BOOL "OpenSSL Found" FORCE)

set(PKG_CONFIG_EXECUTABLE "${PKG_WRAPPER}" CACHE FILEPATH "pkg-config wrapper" FORCE)
EOF

# --- 5. CREATE COMPILER WRAPPERS (THE FIX) ---
# These scripts physically force `-w` (no warnings) at the very end of the command line
CLANG="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${API_LEVEL}-clang"
CLANGPP="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${API_LEVEL}-clang++"
LLVM_AR="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
LLVM_STRIP="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"

C_WRAPPER="$SYSROOT_DIR/clang-wrapper.sh"
cat > "$C_WRAPPER" << EOF
#!/bin/sh
# This wrapper forcefully injects the include paths that Meson/CMake lose.
# The paths are evaluated at compile time, after meson setup has run and created them.
exec "${CLANG}" \\
    -I"${ROOT_DIR}/${MESON_BUILD_DIR}/subprojects/picoquic/__CMake_build/_deps/picotls-src/include" \\
    -I"${OPENSSL_DIR}/include" \\
    "\$@" \\
    -w -Wno-error
EOF
chmod +x "$C_WRAPPER"

CXX_WRAPPER="$SYSROOT_DIR/clangpp-wrapper.sh"
cat > "$CXX_WRAPPER" << EOF
#!/bin/sh
exec "${CLANGPP}" \\
    -I"${ROOT_DIR}/${MESON_BUILD_DIR}/subprojects/picoquic/__CMake_build/_deps/picotls-src/include" \\
    -I"${OPENSSL_DIR}/include" \\
    "\$@" \\
    -w -Wno-error
EOF
chmod +x "$CXX_WRAPPER"

# --- 6. SETUP MESON CROSS FILE ---
CROSS_FILE="$SYSROOT_DIR/android-arm64-cross.txt"
cat > "$CROSS_FILE" << EOF
[binaries]
# Point Meson/CMake to our wrapper scripts instead of the direct compiler!
c = '${C_WRAPPER}'
cpp = '${CXX_WRAPPER}'
ar = '${LLVM_AR}'
strip = '${LLVM_STRIP}'
ninja = 'ninja'
pkg-config = '${PKG_WRAPPER}'
pkgconfig = '${PKG_WRAPPER}'

[properties]
android_api_level = ${API_LEVEL}
cmake_toolchain_file = '${WRAPPER_FILE}'

[built-in options]
# Option 1: Aggressive speed optimization (may slightly increase size)
c_args = ['-Oz', '-flto', '-march=armv8-a+crypto']
cpp_args = ['-Oz', '-flto', '-march=armv8-a+crypto']

# Linker flags to strip symbols and garbage collect unused code sections
c_link_args = ['-flto', '-Wl,-s', '-Wl,--gc-sections']
cpp_link_args = ['-flto', '-Wl,-s', '-Wl,--gc-sections']

# Enable Position Independent Executable (required for Android)
b_pie = true

# Enable Link-Time Optimization
b_lto = true

[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
EOF

# --- 7. BUILD SLIPSTREAM ---
export CMAKE_MAKE_PROGRAM=$(command -v ninja)
cd "$ROOT_DIR"

rm -rf "$MESON_BUILD_DIR"

meson setup "$MESON_BUILD_DIR" \
    --cross-file="$CROSS_FILE" \
    -Dbuildtype=release \
    -Dbuild_loglib=false

echo "Compiling..."
ninja -C "$MESON_BUILD_DIR"

$LLVM_STRIP "$MESON_BUILD_DIR/slipstream-client"

echo "=== Build complete! ==="
ls -lh "$MESON_BUILD_DIR/slipstream-client"