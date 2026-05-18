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
    -Ddefault_library=static \
    -Dbuild_loglib=false \
    -Dwerror=false \
    -Dwarning_level=0 \
    -Dc_args="-I$PROJ_ROOT/subprojects/picotls/include" \
    .

echo "=== 5. Compiling ==="
# Clear ccache to ensure we don't use old failed headers
ccache -c
ninja -C "$OUTPUT_DIR"

echo "=== Build complete! ==="
