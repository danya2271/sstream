#!/bin/bash
set -e

# 1. Move to the project root
cd "$(dirname "$0")/.."

OUTPUT_DIR="${1:-builddir-linux}"

# 2. Clean up failed attempts
echo "=== Cleaning environment ==="
rm -rf "$OUTPUT_DIR"
# Some versions of this project store picotls inside picoquic;
# ensure submodules are actually there.
git submodule update --init --recursive

# Inside scripts/build-linux-static.sh, before 'meson setup'
if [ ! -d "subprojects/picotls" ]; then
    echo "picotls missing, cloning..."
    git clone https://github.com/h2o/picotls.git subprojects/picotls
fi

echo "=== Building slipstream for Linux x86-64 (static) ==="

# 3. Setup with explicit dependency handling
# -Dpicotls:default_library=static ensures the sub-dependency is also static
meson setup "$OUTPUT_DIR" \
    --prefix=/usr/local \
    --buildtype=release \
    -Ddefault_library=static \
    -Dbuild_loglib=false \
    -Dwerror=false \
    -Dwarning_level=0 \
    .

# 4. Compile
echo "=== Compiling ==="
ninja -C "$OUTPUT_DIR"

echo "=== Build complete! ==="
