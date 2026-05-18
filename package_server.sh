#!/bin/bash
set -e

# 1. Run the existing build script
echo "Building static binaries..."
./scripts/build-linux-static.sh

# 2. Prepare staging area
BUILD_DIR="./builddir-linux"
STAGING_DIR="./dist_sstream"
rm -rf $STAGING_DIR
mkdir -p $STAGING_DIR

# 3. Copy only what's needed for the server
echo "Packaging server..."
cp "$BUILD_DIR/slipstream-server" "$STAGING_DIR/"
cp "./scripts/install_sstream.sh" "$STAGING_DIR/"

# 4. Create the tarball
PACKAGE_NAME="sstream-server.tar.gz"
tar -czvf $PACKAGE_NAME -C $STAGING_DIR .

echo "------------------------------------------------"
echo "DONE! Package created: $PACKAGE_NAME"
echo "To install on a server, run:"
echo "./install_sstream.sh $PACKAGE_NAME"
echo "------------------------------------------------"
