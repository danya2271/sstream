#!/bin/bash
set -e

# 1. Move to the folder where the script is, then go up to project root
cd "$(dirname "$0")"
cd ..

# Save the absolute path to the project root
PROJ_ROOT=$(pwd)
OUTPUT_DIR="builddir-linux"

echo "=== 1. Checking Subprojects ==="
# Ensure picoquic submodule is actually there
git submodule update --init --recursive

# Ensure picotls is downloaded
if [ ! -d "subprojects/picotls" ]; then
    echo "Cloning picotls..."
    git clone https://github.com/h2o/picotls.git subprojects/picotls
fi

echo "=== 2. Cleaning old build ==="
rm -rf "$OUTPUT_DIR"

echo "=== 3. Setting Compiler Paths ==="
# These variables tell GCC/Clang where to find headers and libraries
# regardless of what Meson says.
export C_INCLUDE_PATH="$PROJ_ROOT/subprojects/picotls/include:$C_INCLUDE_PATH"
export CPATH="$PROJ_ROOT/subprojects/picotls/include:$CPATH"

echo "=== 4. Meson Setup ==="
# We also pass the include path directly into the meson config
meson setup "$OUTPUT_DIR" \
    --buildtype=release \
    -Db_lto=true \
    -Dstrip=true \
    -Ddefault_library=static \
    -Dbuild_loglib=false \
    -Dwerror=false \
    -Dwarning_level=0 \
    -Dc_args="-I$PROJ_ROOT/subprojects/picotls/include -ffunction-sections -fdata-sections" \
    -Dc_link_args="-Wl,--gc-sections -lcrypto -lssl -ldl"

echo "=== 5. Compiling ==="

ninja -C "$OUTPUT_DIR" subprojects/picoquic/libpicoquic_core.a || true

# Clear ccache to ensure we don't use old failed headers
ccache -c
ninja -C "$OUTPUT_DIR"

echo "=== Finalizing Linkage (Manual Hack for Correct Paths) ==="
PICO_DIR="builddir-linux/subprojects/picoquic"

# Собираем сервер
g++ -o builddir-linux/slipstream-server \
    builddir-linux/slipstream-server.p/*.o \
    $PICO_DIR/libpicoquic_core.a \
    $PICO_DIR/libpicotls_openssl.a \
    $PICO_DIR/libpicotls_core.a \
    $PICO_DIR/libpicotls_fusion.a \
    $PICO_DIR/libpicotls_minicrypto.a \
    -lcrypto -lssl -lpthread -ldl -flto -Os -s

# Собираем клиент
g++ -o builddir-linux/slipstream-client \
    builddir-linux/slipstream-client.p/*.o \
    $PICO_DIR/libpicoquic_core.a \
    $PICO_DIR/libpicotls_openssl.a \
    $PICO_DIR/libpicotls_core.a \
    $PICO_DIR/libpicotls_fusion.a \
    $PICO_DIR/libpicotls_minicrypto.a \
    -lcrypto -lssl -lpthread -ldl -flto -Os -s

echo "Success! Server size: $(du -h builddir-linux/slipstream-server | cut -f1)"

echo "=== Build complete! ==="
