#!/bin/sh
set -e

VERSION="1.0.0"
NAME="minish"
RPM_TOPDIR="$(mktemp -d /tmp/rpmbuild.XXXXXX)"
trap 'rm -rf "$RPM_TOPDIR"' EXIT

echo "[*] Setting up RPM build tree..."
mkdir -p "$RPM_TOPDIR/SOURCES" "$RPM_TOPDIR/SPECS" "$RPM_TOPDIR/BUILD" "$RPM_TOPDIR/RPMS" "$RPM_TOPDIR/SRPMS"

# Prepare source tarball in temporary ext4 directory
TAR_DIR="${NAME}-${VERSION}"
TMP_TAR_ROOT="$(mktemp -d /tmp/tar_root.XXXXXX)"
mkdir -p "$TMP_TAR_ROOT/$TAR_DIR"
cp shell.c Makefile "$TMP_TAR_ROOT/$TAR_DIR/"
tar -czf "$RPM_TOPDIR/SOURCES/${TAR_DIR}.tar.gz" -C "$TMP_TAR_ROOT" "$TAR_DIR"
rm -rf "$TMP_TAR_ROOT"

cp packaging/rpm/minish.spec "$RPM_TOPDIR/SPECS/"

echo "[*] Building RPM package..."
rpmbuild --define "_topdir $RPM_TOPDIR" --nodeps -ba "$RPM_TOPDIR/SPECS/minish.spec"

cp "$RPM_TOPDIR"/RPMS/*/*.rpm ./
echo "[+] Successfully built RPM packages in current directory."
echo "    Files: $(ls -lh *.rpm 2>/dev/null | awk '{print $9, "(" $5 ")"}')"
echo "    Install with: sudo rpm -ivh minish-${VERSION}-1.*.rpm"
