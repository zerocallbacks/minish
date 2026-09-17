Name:           minish
Version:        1.0.0
Release:        1%{?dist}
Summary:        Minimalist POSIX rescue and emergency administration shell

License:        GPL-3.0-or-later
URL:            https://localhost/minish
Source0:        %{name}-%{version}.tar.gz

%global debug_package %{nil}

BuildRequires:  gcc
Provides:       /bin/minish
Provides:       %{_bindir}/minish

%description
minish is a lightweight, low-dependency shell designed as a fail-safe
backup shell for system administration, container debugging, and disaster
recovery. Operates with zero history disk persistence, minimal memory
footprint, and built-in core utilities. Fully compatible with Ubuntu and
RHEL/Rocky/AlmaLinux/CentOS.

%prep
%setup -q

%build
if gcc -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o minish 2>/dev/null; then
    echo "[+] Compiled static binary"
else
    echo "[!] Static build unavailable, compiling optimized dynamic binary"
    gcc -Wall -Wextra -std=c99 -pedantic -Os shell.c -o minish
fi
strip --strip-all minish 2>/dev/null || true

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
install -m 0755 minish %{buildroot}%{_bindir}/minish

%post
if [ -f /etc/shells ]; then
    for sh_path in /bin/minish %{_bindir}/minish; do
        if ! grep -q "^${sh_path}$" /etc/shells; then
            echo "${sh_path}" >> /etc/shells
        fi
    done
fi

%postun
if [ "$1" -eq 0 ] && [ -f /etc/shells ]; then
    grep -v "minish$" /etc/shells > /etc/shells.tmp || true
    mv /etc/shells.tmp /etc/shells
fi

%files
%{_bindir}/minish

%changelog
* Wed Sep 16 2026 System Administrator <admin@localhost> - 1.0.0-1
- Hardened emergency rescue shell release with UsrMerge compliance and zero history tracking.
