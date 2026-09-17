#!/bin/sh
set -e

VERSION="1.0.0"
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
if [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi

PKG_NAME="minish_${VERSION}_${ARCH}"
BUILD_DIR="build_deb"

echo "[*] Building minish binary..."
if gcc -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o minish 2>/dev/null; then
    echo "[+] Compiled static binary."
else
    echo "[!] Static build failed, building optimized dynamic binary..."
    gcc -Wall -Wextra -std=c99 -pedantic -Os shell.c -o minish
fi
strip --strip-all minish 2>/dev/null || true
BUILD_DIR="$(mktemp -d /tmp/build_deb.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "[*] Assembling package layout (DEP17 UsrMerge compliant)..."
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/DEBIAN"

# Install binary to /usr/bin/minish (standard for modern Debian/Ubuntu UsrMerge)
cp minish "$BUILD_DIR/usr/bin/minish"
chmod 755 "$BUILD_DIR/usr/bin/minish"
# Package layout: binary only (zero unnecessary files, zero doc footprint for ENOSPC resilience)

# Copy package control scripts and update architecture dynamically
sed "s/Architecture: .*/Architecture: ${ARCH}/" packaging/deb/DEBIAN/control > "$BUILD_DIR/DEBIAN/control"
chmod 644 "$BUILD_DIR/DEBIAN/control"
cp packaging/deb/DEBIAN/postinst "$BUILD_DIR/DEBIAN/"
cp packaging/deb/DEBIAN/prerm "$BUILD_DIR/DEBIAN/"
chmod 755 "$BUILD_DIR/DEBIAN/postinst" "$BUILD_DIR/DEBIAN/prerm"
chmod 755 "$BUILD_DIR/DEBIAN"

echo "[*] Generating Debian package..."
dpkg-deb --build --root-owner-group "$BUILD_DIR" "${PKG_NAME}.deb"

echo "[+] Successfully created ${PKG_NAME}.deb"
echo "    Size: $(ls -lh ${PKG_NAME}.deb | awk '{print $5}')"
echo "    Install with: sudo dpkg -i ${PKG_NAME}.deb"
