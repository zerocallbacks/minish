#!/bin/sh
set -e

VERSION="1.0.0"
ARCH="$(uname -m 2>/dev/null || echo amd64)"
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi

PKG_NAME="minish-${VERSION}-freebsd-${ARCH}"
STAGE_DIR="$(mktemp -d /tmp/minish_freebsd.XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT

echo "[*] Assembling FreeBSD package layout for ${ARCH}..."
mkdir -p "$STAGE_DIR/usr/local/bin"
mkdir -p "$STAGE_DIR/meta"

# Copy binary
if [ -f "minish" ]; then
    cp minish "$STAGE_DIR/usr/local/bin/minish"
    chmod 755 "$STAGE_DIR/usr/local/bin/minish"
fi

# Create +MANIFEST for FreeBSD pkg package manager
cat << EOF > "$STAGE_DIR/+MANIFEST"
name: minish
version: "${VERSION}"
origin: sysutils/minish
comment: Ultra-compact POSIX emergency micro-shell and recovery utility
desc: Standalone POSIX micro-shell and live disaster recovery utility designed for mission-critical recovery, offline forensics, and threat hunting on FreeBSD and Linux.
maintainer: info@zerocallbacks.com
www: https://github.com/zerocallbacks/minish
prefix: /usr/local
categories: [sysutils, shells]
licenselogic: single
licenses: [GPLv3]
files: {
  /usr/local/bin/minish: ""
}
scripts: {
  post-install: "if [ -f /etc/shells ] && ! grep -q '/usr/local/bin/minish' /etc/shells; then echo '/usr/local/bin/minish' >> /etc/shells; fi",
  post-deinstall: "if [ -f /etc/shells ]; then grep -v '/usr/local/bin/minish' /etc/shells > /etc/shells.tmp && mv /etc/shells.tmp /etc/shells; fi"
}
EOF

# Create standalone offline install script for FreeBSD systems
cat << 'EOF' > "$STAGE_DIR/install.sh"
#!/bin/sh
set -e
PREFIX="${PREFIX:-/usr/local}"
echo "[*] Installing minish to ${PREFIX}/bin/minish..."
install -d "${PREFIX}/bin"
install -m 0755 bin/minish "${PREFIX}/bin/minish"
if [ -f /etc/shells ] && ! grep -q "${PREFIX}/bin/minish" /etc/shells; then
    echo "${PREFIX}/bin/minish" >> /etc/shells
    echo "[+] Registered ${PREFIX}/bin/minish in /etc/shells"
fi
echo "[+] Successfully installed minish for FreeBSD."
EOF
chmod 755 "$STAGE_DIR/install.sh"

# Assemble archive layout
mkdir -p "$STAGE_DIR/archive/bin"
cp "$STAGE_DIR/usr/local/bin/minish" "$STAGE_DIR/archive/bin/"
cp "$STAGE_DIR/install.sh" "$STAGE_DIR/archive/"
cp "$STAGE_DIR/+MANIFEST" "$STAGE_DIR/archive/"

# Create FreeBSD tarball package
echo "[*] Creating FreeBSD distribution archive (${PKG_NAME}.tar.gz)..."
tar -czf "${PKG_NAME}.tar.gz" -C "$STAGE_DIR/archive" .

# If pkg command is available (running on native FreeBSD), create native .pkg
if command -v pkg >/dev/null 2>&1; then
    echo "[*] Creating native FreeBSD .pkg package..."
    pkg create -m "$STAGE_DIR" -r "$STAGE_DIR" -o .
fi

echo "[+] Successfully generated FreeBSD distribution package:"
echo "    Archive: ${PKG_NAME}.tar.gz ($(ls -lh "${PKG_NAME}.tar.gz" | awk '{print $5}'))"
echo "    Installation on FreeBSD:"
echo "      tar -xzf ${PKG_NAME}.tar.gz"
echo "      sudo ./install.sh"
echo "    Or compile natively on FreeBSD with Clang:"
echo "      cc -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o minish"
