#!/bin/bash
# Build script for Linux x86-64 static binary
# Usage: ./scripts/build-linux-static.sh [output_dir]

set -e

# Default output directory
OUTPUT_DIR="${1:-builddir-linux}"

echo "=== Building slipstream for Linux x86-64 (static) ==="
echo "Output directory: $OUTPUT_DIR"

# Create build directory
mkdir -p "$OUTPUT_DIR"

# Build with meson
meson setup "$OUTPUT_DIR" \
    --prefix=/usr/local \
    --buildtype=release \
    -Ddefault_library=static \
    -Dbuild_loglib=false \
    ..

# Compile
echo "Compiling..."
ninja -C "$OUTPUT_DIR"

echo ""
echo "=== Build complete! ==="
echo "Binaries located at:"
echo "  $OUTPUT_DIR/slipstream-client"
echo "  $OUTPUT_DIR/slipstream-server"
echo ""
echo "To install system-wide:"
echo "  sudo ninja install -C $OUTPUT_DIR"
echo ""
echo "Or copy to custom location:"
echo "  cp $OUTPUT_DIR/slipstream-* /usr/local/bin/"