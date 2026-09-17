# Minimalist POSIX Micro-Shell & Rescue Utility (`minish`)

A standalone, ultra-compact, POSIX-compliant emergency shell designed for system administration, micro-containers, embedded systems, and disaster recovery environments on **Ubuntu/Debian** and **RHEL/Rocky/AlmaLinux/CentOS**.

> 📖 **Comprehensive Manual & Playbooks**: For in-depth architectural specifications and incident response runbooks (100% full disk recovery, ghost file hunting, inode exhaustion, and broken dynamic linkers), see the [Operational & Disaster Recovery Manual](MANUAL.txt).

## Design Philosophy

- **Zero History / Zero Noise**: Does not read, write, or track command history files (`.bash_history`, `.minish_history`, etc.). Leaves zero disk footprint or interactive noise, making it fully functional even when filesystems are 100% full, read-only, or degraded.
- **Fail-Safe & Low Dependency**: Compiles into a single self-contained binary (~35 KB stripped dynamic, or static binary with zero external runtime dependencies).
- **Embedded Core & File Surgery Utilities**: Native implementations of `cd` (with `cd -`), `pwd`, `ls` (with `-a`, `-l`), `cat`, `cp`, `mv`, `rm` (with `-rf`), `touch`, `mkdir` (with `-p`), `chmod` (octal & `+x/-x`), `chown`, `umask`, `sync`, `echo` (with `-n`, `-e`), `export`, `unset`, `sleep`, `kill`, `true`, `false`, `which`, and `test` / `[` so complete recovery is possible even if `/usr/bin` is broken or unmounted.
- **Process Renaming**: In-place process renaming via `setproctitle <name>` (or C API `set_process_name()`) updates both kernel comm (`/proc/self/comm`, `top`) and argv memory block (`/proc/self/cmdline`, `ps -ef`), ideal for background rescue tasks.
- **Disaster Recovery & Kernel Control**: Direct kernel filesystem remounts (`remount rw /`), memory caches sync (`sync`), chroot jail execution (`chroot`), direct reboot/poweroff (`reboot`, `poweroff`), and Magic SysRq invocation (`sysrq s`, `sysrq u`, `sysrq b`).
- **Nonstandard Triage Diagnostics**:
  - `memfile`: In-memory virtual RAM storage table (survives on disk-less or read-only systems).
  - `probeblk`: Sniffs filesystem superblocks and magic identifiers (`ext4`, `xfs`, `btrfs`, `swap`).
  - `hexview`: Hexadecimal and ASCII binary inspector for files and raw disk partitions.
  - `falloc`: Instant multi-megabyte sparse file allocation for emergency swapfiles or test images.
  - `sockstat`: Zero-dependency socket triage parsing `/proc/net/tcp` and `/proc/net/udp`.
  - `killtree`: Recursive process hierarchy destroyer terminating hung process groups.
  - `procpeek`: Live process state inspector displaying memory RSS, PPID, and open file descriptors.
  - `httpget` & `dnslookup`: Standalone socket-level HTTP client and DNS resolver without `curl` or `wget`.
  - `randhex`: Hardware-backed random hex token generator from `/dev/urandom`.
  - `watch`: Self-contained interval execution loop with screen clearing.
- **Full-Disk & Out-of-Space Rescue (`ENOSPC`)**:
  - `df`: Native `statvfs()` inspection displaying storage blocks **and** inode exhaustion metrics with critical warning alerts.
  - `truncate`: In-place zero-allocation file shrink dropping runaway logs to 0 bytes without deleting files or breaking active daemon file descriptors.
  - `ghostfind`: Traverses `/proc/*/fd/` to uncover open unlinked files holding trapped disk space, with `-t` to immediately truncate and reclaim trapped gigabytes.
  - `findlarge`: High-speed recursive scanner locating files exceeding size thresholds (e.g. `findlarge /var 100`).
  - `tmpfs`: Directly mounts an in-memory `tmpfs` RAM disk (e.g. `tmpfs /tmp 64`) to unblock crashing host tools when the rootfs is 100% full.
- **Container & Init Hygiene**: Acts as an optimal container PID 1 or subreaper (`PR_SET_CHILD_SUBREAPER`), supporting `exec`, script sourcing (`.`), and POSIX errexit mode (`set -e`, `set +e`).
- **Full Shell Composability**: Multi-stage pipelines (`|`), full redirections (`<`, `>`, `>>`, `2>`, `2>>`, `2>&1`, `&>`, `>&2`), background execution (`&`), and left-associative conditional chaining (`&&`, `||`, `;`).
- **Quote-Aware Variable Expansion**: Interpolates `$VAR`, `${VAR}`, `$?`, `$$`, `$#`, and positional parameters (`$0`..`$9`) inside double quotes and unquoted words while preserving literal text inside single quotes.

---

## Complete Built-in Reference

| Category | Command | Description |
| :--- | :--- | :--- |
| **Full-Disk Recovery (`ENOSPC`)** | `df [path]` | Inspect storage blocks and inode table exhaustion side-by-side |
| | `truncate <f> [sz]` | In-place zero-allocation shrink (drops files to 0B without unlinking) |
| | `ghostfind [-t]` | Find open unlinked deleted files trapping disk space; `-t` truncates them |
| | `findlarge [p] [MB]`| Recursively find files exceeding size threshold (default 50MB) |
| | `inodescan [p] [N]` | Inode hoarder scanner pinpointing directories containing excess files |
| | `zerolog [path]` | Fast batch log truncator shrinking all *.log files in-place to 0 bytes |
| | `findempty [p] [-d]`| Discovers and optionally purges 0-byte orphan files wasting inode slots |
| | `dusage [p] [depth]`| Fast recursive directory space usage breakdown (built-in ncdu/du) |
| | `findinode <ino> [p]`| Reverse inode-to-path resolver finding files by physical inode number |
| | `findgrowth [p] [s]` | Real-time file growth rate monitor detecting actively expanding files |
| | `fdsize [pid]` | Storage-centric open file descriptor profiler across processes |
| | `topwriters [sec]` | Process storage write throughput monitor sampling `/proc/*/io` |
| | `ramscratch [MB]` | One-touch volatile in-memory workspace (`/dev/shm/.scratch`) |
| | `ramclone <f> [dest]`| Zero-disk file stager cloning files into RAM when `cp` fails with `ENOSPC` |
| | `tmpfs <dir> [MB]` | Mount emergency RAM tmpfs to unblock `/tmp` on full disks |
| | `memrun` / `memexec <n\|->`| Execute binary directly from RAM via `memfd_create` (zero disk & bypasses `noexec`) |
| | `memfile <op> [n]` | In-memory storage (`save`, `cat`, `list`, `rm`) in RAM |
| | `dropcaches [1\|2\|3]`| Flush dirty pagecache, dentries, and inode slabs from RAM |
| **Shell & State** | `cd [dir\|-]` | Change directory (supports `~` and `cd -` toggle) |
| | `export [V=VAL]` | Set and export environment variable |
| | `unset [VAR]` | Remove environment variable |
| | `set [-e\|+e] [-x\|+x]` | Toggle errexit (abort on error) or trace execution |
| | `.` / `source <file>` | Source and execute script inside current context |
| | `exec <cmd...>` | Replace current process with new command |
| | `chroot <dir> [cmd]` | Change root directory for jail or container recovery |
| | `setproctitle <name>` | In-place process rename (`/proc/self/comm` & `cmdline`); aliases: `procrename`, `renameproc` |
| | `exit [code]` | Exit shell with specified code |
| | `help` | Interactive command listing |
| **File Surgery & Maintenance** | `cat [file...]` | Concatenate and print file contents |
| | `cp <src> <dst>` | Copy file preserving permission mode |
| | `mv <src> <dst>` | Atomic move or rename |
| | `rm [-r] [-f] <f>` | Remove file or directory (protects dirs without `-r`) |
| | `chmod <mode> <f>` | Modify permissions (octal `0755` or symbolic `+x`, `-x`) |
| | `chown <u[:g]> <f>` | Change file UID and GID |
| | `umask [mode]` | Inspect or configure creation mask |
| | `touch <file...>` | Update timestamps or create empty file |
| | `mkdir [-p] <dir>` | Create directory hierarchy |
| | `ls [-a] [-l] [path]` | List files with sizes, permissions, and dates |
| | `pwd` | Print working directory |
| | `echo [-n] [-e] [s]`| Output text with escape sequence decoding (`\n`, `\t`) |
| | `sleep <sec>` | Suspend execution for specified integer seconds |
| | `kill [-sig] <pid>`| Send termination or POSIX signal to processes |
| | `true` / `false` | Return exit code 0 (success) or 1 (failure) |
| | `which <cmd...>` | Locate executable binary in current `$PATH` |
| | `test` / `[ expr ]`| Evaluate conditional expression and file tests (`-f`, `-d`, `-z`, `-n`, `-eq`) |
| | `sync` | Flush filesystem page caches (`sync()`) |
| | `remount <rw\|ro> [p]`| Emergency remount of filesystem read-write or read-only |
| **Text & Stream Surgery** | `vim` / `vi [file]` | Zero-dependency modal in-memory text editor (normal/insert/ex modes) |
| | `grep [-i] [-v] [-n]` | Fast substring search and stream filter |
| | `head [-n N] [f...]` | Output first N lines (default 10) |
| | `tail [-n N] [f...]` | Output last N lines using circular memory buffer |
| | `wc [-l\|-w\|-c] [f...]`| Count lines, words, and/or bytes |
| | `cut -d <d> -f <col>` | Delimited column and field extractor |
| | `sort [file...]` | In-memory line sorting |
| | `uniq [-c] [file...]` | Consecutive duplicate line filter and counter |
| | `tr [-d] <s1> [s2]` | Single-byte character translation or deletion |
| | `diff <f1> <f2>` | Lightweight line-by-line file comparison |
| **Process & Anti-Rootkit** | `ps` / `proclist` | Native process table (PID, PPID, RSS, Comm) |
| | `mapspeek <pid>` | Audit memory maps; flags anonymous executable `rwx` pages |
| | `fdpeek <pid>` | Audit open file descriptors and deleted handles |
| | `stackpeek <pid>` | Dump kernel backtrace for D-state hung processes |
| | `wchanpeek <pid>` | Display kernel wait-channel sleep symbol |
| | `oomadj [pid] [score]`| Inspect or adjust OOM score (-1000 to +1000) |
| **Security, Capabilities & LSM** | `cappeek [pid]` | Decode POSIX capability bitmasks (Eff, Prm, Inh) |
| | `nspeek [pid]` | Inspect and compare namespace inode IDs |
| | `chattr <+i\|-i> <f>` | Toggle ext2/3/4 immutable bit (`FS_IOC_SETFLAGS`) |
| | `lockdown <dir>` | Recursively mark all directory files immutable (+i) |
| | `lsmaudit` | Audit active LSMs (SELinux, AppArmor, Smack) |
| | `taintpeek` | Decode Linux kernel tainted status bitmask |
| | `id` / `whoami` | Display UID, GID, and supplemental groups |
| | `entropy <file\|->` | Calculate Shannon entropy to spot ransomware/blobs |
| **Storage & Block Recovery** | `dd if=.. of=..` | Raw block carver and imager for MBR/GPT/devices |
| | `fiemap <file>` | Map physical disk LBA sectors and extents |
| | `losetup [-d dev] [f]`| Direct loop device attachment/detachment ioctl |
| | `pivot_root <new> <old>`| Direct syscall for initramfs PID 1 boot handoff |
| | `swapon` / `swapoff` | Activate or deactivate emergency swap space |
| | `diskstat` | Storage I/O throughput and in-flight request stats |
| | `blkdiscard <dev>` | Send `BLKDISCARD` ioctl to trim SSDs or VM disks |
| | `probeblk <dev>` | Sniff filesystem magic (ext4, xfs, btrfs, swap) |
| | `falloc <MB> <path>` | Instant preallocation of files via `posix_fallocate` |
| **Network & Air-Gap Triage** | `tcpping <host> <port>` | Non-blocking TCP connect liveness test (no ICMP) |
| | `pcapdump <if> <N> [o]`| Zero-dependency raw packet sniffer (`AF_PACKET` -> `.pcap`) |
| | `ipaddr [if] [ip/mask]`| Direct ioctl network interface IP configurator |
| | `dnsquery <host> [ip]` | Direct UDP DNS query bypassing `/etc/resolv.conf` |
| | `sockhunt <port>` | Pinpoint PID, comm, and binary holding a port |
| | `killbyport <port>` | Terminate process listening on target port |
| | `netif` | Interface traffic and packet counters from `/proc` |
| | `arppeek` | Local LAN ARP neighbor table from `/proc` |
| | `routepeek` | Kernel IPv4 routing table from `/proc` |
| | `portscan <h> <s> <e>` | Fast TCP port scanner |
| | `sockstat` | Inspect active TCP/UDP sockets from `/proc/net` |
| | `httpget <url> [dest]` | Fetch files or payloads over raw HTTP socket |
| | `dnslookup <host>` | Resolve hostnames to IPv4/IPv6 addresses |
| **Forensic & Anti-Tamper** | `sha256 <file\|->` | Standalone FIPS 180-4 cryptographic hash generator |
| | `nc [-l] <h\|p> [p]` | Micro-Netcat client & listener for raw TCP streaming |
| | `elfpeek <binary>` | Zero-execution dynamic library & ELF header inspector |
| | `envpeek [pid]` | Sniff process environment & secrets from `/proc` |
| | `modpeek` | Direct `/proc/modules` kernel driver & rootkit auditor |
| | `base64 [-e\|-d] [f]` | Bit-shift RFC 4648 Base64 transceiver |
| | `replace <f> <s> <r>` | Atomic in-place string configuration patcher |
| | `mknod <p> <c\|b> M m` | Direct `mknod()` device node reconstruction syscall |
| | `mount [-t t] [-o o]` | Syscall filesystem & bind mounter |
| | `umount [-f] <target>` | Direct kernel filesystem unmount syscall (`umount2`) |
| | `memdump <pid> [out]` | Live process memory extractor from `/proc/<pid>/mem` |
| | `finfo` / `statpeek <f>`| Nanosecond inode, permission, and anti-timestomp auditor |
| | `strings [file] [len]` | Zero-dependency ASCII string & C2 artifact extractor |
| | `wipe <file> [passes]` | Secure multi-pass file overwriter & unlinker |
| **Hardware & Firmware** | `dmipeek` / `smbios` | Motherboard, BIOS, and hypervisor identification |
| | `cpuid` / `cpuinfo` | CPU microcode, cores, and hardware vulnerability status |
| | `pcipeek` | Inspect PCI hardware bus controllers without `lspci` |
| | `usbpeek` | USB device hardware sniffer (rogue USB detectors) |
| | `sysinfo` / `free` | Uptime, system load averages, and RAM/swap usage |
| | `dmesg` | Read kernel ring buffer via `klogctl` |
| | `uname [-a\|-r\|-m]` | Display kernel and architecture information |
| **Scripting, Crypto & Control** | `read [-r] [VAR]` | Prompt for interactive input into shell variable |
| | `calc <n1> <op> <n2>` | 64-bit integer arithmetic (`+`, `-`, `*`, `/`, `%`, `&`, `\|`, `^`) |
| | `clear` | Reset terminal screen via ANSI escape code |
| | `timestomp <f> <time>` | Set nanosecond timestamps via `utimensat` |
| | `uptime` | Display system uptime and load averages |
| | `symlink <tgt> <link>` | Create symbolic link without `/bin/ln` |
| | `readlink [-f] <link>` | Read symbolic link target |
| | `time <command...>` | Measure command duration (real/user/sys) |
| | `md5 <file\|->` | Standalone RFC 1321 MD5 cryptographic hasher |
| | `crc32 <file\|->` | Fast IEEE 802.3 32-bit checksum |
| | `xor <file\|-> <key>` | Bitwise XOR stream encoder/decoder |
| | `hexview <file> [off]` | Canonical hex + ASCII inspection of files and raw disks |
| | `killtree <pid> [-sig]`| Recursively terminate process and descendant children |
| | `procpeek [pid]` | Process memory RSS and open file descriptors |
| | `randhex [bytes]` | Generate cryptographic random hex tokens |
| | `watch <sec> <cmd>` | Periodic command repeater with screen refresh |
| | `reboot` / `poweroff` | Trigger direct kernel reboot or system halt |
| | `sysrq <key>` | Write to `/proc/sysrq-trigger` (`s`, `u`, `b`, `f`, `t`) |
| **In-Memory Defense & Threat Hunting** | `deletedgrab <p> <f>` | Extract deleted/open files, logs, and binaries from `/proc/*/fd/` into RAM |
| | `sigshield [on\|off]`| Anti-kill recovery armor (masks `SIGTERM`/`SIGHUP`/`SIGINT`, sets OOM -1000) |
| | `b64exec <name> [a]` | Air-gapped in-memory terminal loader; pastes & executes Base64 in RAM |
| | `ramoverlay <dir> [MB]`| Copy-on-write RAM overlayfs over full/ro directories to allow tool writes |
| | `exehunt` | Detect unlinked malware, volatile RAM binaries, and disguised process names |
| | `memscript <intp> [a]`| Execute scripts (Python/Bash/Perl) directly out of RAM (zero disk writes) |
| | `memunshare [-m\|-p\|-n]`| Run defense tools in private PID & mount namespaces to evade detection |
| | `memgrep <pid> <str>` | Sniff C2 domains, keys, and credentials directly from process virtual memory |
| | `ptracehunt` | Detect live process injection and ptrace tracing across running daemons |
| | `promischunt` | Detect network promiscuous mode and stealth raw packet sockets (BpfDoor) |
| | `persistpeek` | Audit crontabs, systemd drop-ins, and shell profiles for backdoor triggers |

---

## Top Disaster Recovery Recipes

### 1. Recover from 100% Full Disk (`ENOSPC`) Outages
When disk space hits 0 bytes and files cannot be written or edited:
```bash
# Inspect storage blocks and inode exhaustion side-by-side:
minish$ df /

# Scan for files larger than 100 MB:
minish$ findlarge /var 100

# Collapse runaway log files to 0 bytes without unlinking or breaking daemons:
minish$ truncate /var/log/syslog 0

# Find and truncate unlinked "ghost files" held open by running processes:
minish$ ghostfind -t
```

### 2. Execute Recovery Binaries on Full or `noexec` Disks
When `/tmp` is mounted `noexec` or disk is 100% full, execute recovery tools directly from RAM:
```bash
# Stream binary from network directly into RAM and execute via memfd_create:
minish$ httpget http://192.168.1.50/vendor_tool | memrun - --repair-all

# Or stage scripts in RAM virtual storage without touching disk:
minish$ echo "nameserver 8.8.8.8" | memfile save resolv.conf
minish$ memfile cat resolv.conf
```

### 3. Emergency Bare-Metal Initramfs & Chroot Rescue
Recover a non-bootable host from an emergency shell without external tools:
```bash
# Sniff partition superblock:
minish$ probeblk /dev/sda2

# Mount physical rootfs and bind pseudo-filesystems:
minish$ mkdir -p /mnt/sysroot
minish$ mount /dev/sda2 /mnt/sysroot
minish$ mount -t proc proc /mnt/sysroot/proc
minish$ mount -t sysfs sysfs /mnt/sysroot/sys
minish$ mount -o bind /dev /mnt/sysroot/dev

# Fix corrupt /etc/fstab in-place without sed:
minish$ replace /mnt/sysroot/etc/fstab UUID=bad-id UUID=good-id

# Chroot into restored environment:
minish$ chroot /mnt/sysroot /bin/bash
```

### 4. Live Threat Hunting & Process Forensics
Investigate compromised systems without stomping on disk timestamps (RFC 3227):
```bash
# Audit active network sockets without netstat/ss:
minish$ sockstat

# Inspect process memory segments and spot anonymous executable pages (rwxp):
minish$ mapspeek 1337

# Stream process RAM dump off-box over raw TCP without touching disk:
minish$ memdump 1337 - | nc 10.0.0.50 9000

# Audit kernel modules to detect hidden rootkits:
minish$ modpeek
```

### 5. Instant Directory Lockdown Against Ransomware
Halt rogue encryption or deletion scripts instantly:
```bash
# Recursively apply immutable (+i) flag to all files in directory:
minish$ lockdown /var/www

# Calculate Shannon entropy to verify if files were encrypted (entropy > 7.50):
minish$ entropy /var/www/index.html
```

### 6. Live In-Memory Adversary Hunting & Portless Sniffer Neutralization
Detect advanced rootkits, BpfDoor-style raw socket sniffers, and injected processes:
```bash
# Detect hidden malware running from deleted binaries or volatile RAM:
minish$ exehunt

# Check for live process injection or ptrace hooks across system daemons:
minish$ ptracehunt

# Detect hidden portless packet sniffers (AF_PACKET / BpfDoor):
minish$ promischunt

# Extract deleted malware binary directly out of kernel memory into RAM:
minish$ deletedgrab 3412 exe malware_sample

# Sniff C2 IP/domain or encryption keys directly from live process virtual memory:
minish$ memgrep 3412 "http"
```

### 7. Inode Hoarder Pinpointing & Emergency Batch Log Truncation
Recover from 100% full inode tables (`df -i`) and runaway debug logs:
```bash
# Pinpoint directories hoarding thousands of tiny session or spool files:
minish$ inodescan /var 1000

# Batch-truncate all *.log files in /var/log in-place without restarting daemons:
minish$ zerolog /var/log

# Purge 0-byte orphan files wasting inode metadata slots:
minish$ findempty /tmp/sessions -d
```

---

## Packaging & Installation

### Option 1: Ubuntu / Debian (`.deb`)

Build and install a native Debian package:
```bash
# Build the package:
make deb
# or run directly:
./package_deb.sh

# Install:
sudo dpkg -i minish_1.0.0_amd64.deb
```
* Installs binary to `/usr/bin/minish` (compliant with modern Debian/Ubuntu DEP17 UsrMerge standard).
* Automatically registers both `/bin/minish` and `/usr/bin/minish` in `/etc/shells` upon installation and deregisters upon removal (`sudo dpkg -r minish`).

---

### Option 2: RHEL / Rocky / AlmaLinux / CentOS (`.rpm`)

Build and install an RPM package using `rpmbuild`:
```bash
# Build the package:
make rpm
# or run directly:
./package_rpm.sh

# Install:
sudo rpm -ivh minish-1.0.0-1.*.rpm
```
* Installs binary to `/usr/bin/minish` conforming to Fedora/RHEL packaging guidelines.
* Automatically provides `/bin/minish` via system UsrMerge symlink without packaging collisions.
* Manages `/etc/shells` integration cleanly via `%post` and `%postun` hooks.

---

### Option 3: Direct Build & System Install

If building directly on target without a package manager:
```bash
# Build and install:
sudo make install

# To run verification suite:
make test

# To cleanly remove:
sudo make uninstall
```

---

## Command Line Usage

```bash
# Interactive mode:
./minish

# Execute a command string:
./minish -c "sysinfo; sockstat"

# Execute a script with arguments:
./minish test_suite.sh

# View help and version:
./minish --help
./minish --version
```

---

## Verification & Self-Test

Run the automated verification suite:
```bash
./minish test_suite.sh
# or:
make test
```
Verifies variable expansion, file surgery (`cp`, `mv`, `chmod`, `umask`, `sync`), RAM storage (`memfile`), disk analysis (`falloc`, `hexview`), random token generation (`randhex`), networking introspection (`sockstat`), process introspection (`procpeek`), and context sourcing (`.`).

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 (GPL-3.0). See LICENSE file for details.
