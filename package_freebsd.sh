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
mkdir -p "$STAGE_DIR/archive/bin"
mkdir -p "$STAGE_DIR/archive/src"
mkdir -p "$STAGE_DIR/meta"

# Determine how to obtain genuine native FreeBSD ELF binary
FREEBSD_BIN=""

if [ "$(uname -s 2>/dev/null)" = "FreeBSD" ]; then
    echo "[*] Detected native FreeBSD host. Compiling natively..."
    cc -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o "$STAGE_DIR/minish_freebsd" -lutil -lm
    strip -s "$STAGE_DIR/minish_freebsd"
    FREEBSD_BIN="$STAGE_DIR/minish_freebsd"
elif [ -d "/opt/freebsd14/usr/include" ] && command -v clang >/dev/null 2>&1; then
    echo "[*] Cross-compiling native FreeBSD 14 ELF static binary with clang + lld..."
    clang --target=x86_64-unknown-freebsd14.4 --sysroot=/opt/freebsd14 -fuse-ld=lld \
        -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o "$STAGE_DIR/minish_freebsd" -lutil -lm
    strip -s "$STAGE_DIR/minish_freebsd"
    FREEBSD_BIN="$STAGE_DIR/minish_freebsd"
elif [ -f "minish_freebsd" ]; then
    echo "[*] Using existing pre-built minish_freebsd..."
    FREEBSD_BIN="minish_freebsd"
fi

if [ -n "$FREEBSD_BIN" ] && [ -f "$FREEBSD_BIN" ]; then
    cp "$FREEBSD_BIN" "$STAGE_DIR/usr/local/bin/minish"
    cp "$FREEBSD_BIN" "$STAGE_DIR/archive/bin/minish"
    chmod 755 "$STAGE_DIR/usr/local/bin/minish"
    chmod 755 "$STAGE_DIR/archive/bin/minish"
    echo "[+] Bundled native FreeBSD ELF binary (size: $(ls -lh "$FREEBSD_BIN" | awk '{print $5}'))."
else
    echo "[!] Warning: Native FreeBSD binary could not be generated. Bundling fallback..."
    if [ -f "minish" ]; then
        cp minish "$STAGE_DIR/usr/local/bin/minish"
        cp minish "$STAGE_DIR/archive/bin/minish"
    fi
fi

# Bundle shell.c source for standalone zero-dependency compiling on pfSense / FreeBSD hosts
if [ -f "shell.c" ]; then
    cp shell.c "$STAGE_DIR/archive/src/shell.c"
    echo "[+] Bundled shell.c in archive for offline native compilation fallback."
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

# Create standalone offline install script for FreeBSD systems (pfSense, TrueNAS, vanilla FreeBSD)
cat << 'EOF' > "$STAGE_DIR/archive/install.sh"
#!/bin/sh
set -e
PREFIX="${PREFIX:-/usr/local}"

echo "=== minish v1.0.0 FreeBSD / pfSense Installer ==="

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$DIR/bin/minish"
C_SRC="$DIR/src/shell.c"
FINAL_BIN="$PREFIX/bin/minish"

mkdir -p "$PREFIX/bin"

EXEC_OK=0

# Step 1: Test pre-compiled binary
if [ -f "$BIN_SRC" ]; then
    chmod +x "$BIN_SRC" 2>/dev/null || true
    echo "[*] Testing bundled binary compatibility..."
    if "$BIN_SRC" --no-disguise -c "exit 0" >/dev/null 2>&1; then
        EXEC_OK=1
        echo "[+] Bundled FreeBSD binary validated successfully."
    else
        echo "[!] Bundled binary returned execution error."
        # Step 2: Attempt brandelf if available
        if command -v brandelf >/dev/null 2>&1; then
            echo "[*] Attempting brandelf -t FreeBSD..."
            brandelf -t FreeBSD "$BIN_SRC" >/dev/null 2>&1 || true
            if "$BIN_SRC" --no-disguise -c "exit 0" >/dev/null 2>&1; then
                EXEC_OK=1
                echo "[+] brandelf successfully adjusted ELF header."
            fi
        fi
    fi
fi

# Step 3: If still not executable and source is present, compile natively on host
if [ "$EXEC_OK" -ne 1 ] && [ -f "$C_SRC" ]; then
    CC_CMD=""
    if command -v cc >/dev/null 2>&1; then CC_CMD="cc";
    elif command -v clang >/dev/null 2>&1; then CC_CMD="clang";
    elif command -v gcc >/dev/null 2>&1; then CC_CMD="gcc"; fi

    if [ -n "$CC_CMD" ]; then
        echo "[*] Compiling minish natively with host compiler ($CC_CMD)..."
        if $CC_CMD -Wall -Wextra -std=c99 -pedantic -Os -static "$C_SRC" -o "$BIN_SRC" -lutil -lm; then
            strip -s "$BIN_SRC" 2>/dev/null || true
            if "$BIN_SRC" --no-disguise -c "exit 0" >/dev/null 2>&1; then
                EXEC_OK=1
                echo "[+] Native host compilation succeeded."
            fi
        fi
    fi
fi

if [ "$EXEC_OK" -ne 1 ]; then
    echo ""
    echo "[ERROR] Could not execute or compile minish on this system."
    echo "        Diagnostic hints:"
    echo "        1. Check architecture: uname -m (expected x86_64 / amd64)"
    echo "        2. If running inside pfSense or hardened jail, verify execution permissions."
    echo "        3. Install clang/gcc via 'pkg install clang' to compile directly."
    exit 1
fi

echo "[*] Installing minish binary to $FINAL_BIN..."
install -m 0755 "$BIN_SRC" "$FINAL_BIN"

# Final verification of installed binary in destination
if ! "$FINAL_BIN" --no-disguise -c "exit 0" >/dev/null 2>&1; then
    echo "[ERROR] Installed binary at $FINAL_BIN failed execution test!"
    exit 1
fi

if [ -f /etc/shells ] && ! grep -q "$FINAL_BIN" /etc/shells; then
    echo "$FINAL_BIN" >> /etc/shells
    echo "[+] Registered $FINAL_BIN in /etc/shells"
fi

echo ""
echo "[+] SUCCESS: minish installed and verified at $FINAL_BIN"
echo "    Version: $("$FINAL_BIN" --no-disguise -v 2>&1 | head -n 1)"
echo "    Default Stealth: Active (disguises as -bash in process table)"
echo "    To run with default disguise:  $FINAL_BIN"
echo "    To run with custom disguise:   $FINAL_BIN -a \"[kworker/u2:0]\""
echo "    To run without disguise:       $FINAL_BIN --no-disguise"
EOF
chmod 755 "$STAGE_DIR/archive/install.sh"
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
echo "    Contents:"
tar -ztvf "${PKG_NAME}.tar.gz"
