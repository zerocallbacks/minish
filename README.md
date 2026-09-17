# Minimalist POSIX Micro-Shell & Rescue Utility (`minish`)

A standalone, ultra-compact, POSIX-compliant emergency shell designed for system administration, micro-containers, embedded systems, and disaster recovery environments on **Ubuntu/Debian** and **RHEL/Rocky/AlmaLinux/CentOS**.

> 📖 **Comprehensive Manual & Playbooks**: For in-depth architectural specifications and incident response runbooks (100% full disk recovery, ghost file hunting, inode exhaustion, and broken dynamic linkers), see the [Operational & Disaster Recovery Manual](MANUAL.txt).


> **Comprehensive Operational Reference**: For complete kernel mechanisms, failure modes, anti-kill armor, and in-depth runbooks, refer to [MANUAL.md](MANUAL.md) or [MANUAL.txt](MANUAL.txt).

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

## Complete Built-in Reference (164 Built-in Commands)

`minish` bundles 164 zero-dependency built-in recovery and triage utilities directly into a single static binary with no external coreutils, bash, or python dependencies required.

### Shell Primitives & Session Control

| Command / Syntax | Description |
| :--- | :--- |
| `cd [dir|-]` | Change working directory (supports ~, -, deferred evaluation) |
| `exit [code]` | Terminate minish shell session with exit status |
| `export [VAR=VAL]` | Set and export environment variables into process environment |
| `unset [VAR]` | Remove variables from shell environment |
| `set [-e|+e] [-x|+x]` | Toggle errexit (-e: abort on error) and trace mode (-x: print commands) |
| `source <file>` / `. <file>` | Evaluate external script inside current shell memory context |
| `exec <cmd...> [args]` | Replace shell process in-place with command (clears bash parentage) |
| `chroot <dir> [cmd]` | Enter new filesystem root directory and optionally execute recovery shell |
| `setproctitle <name>` | Rename running process in kernel (/proc/[pid]/comm and cmdline; Aliases: `procrename`, `renameproc`) |
| `help [cmd]` | Display interactive command index or comprehensive runbook for target tool |

### Process Detachment & Background Job Management

| Command / Syntax | Description |
| :--- | :--- |
| `detach <cmd...> [args]` | Execute command in detached background session with disassociated I/O |
| `jobs` | List all actively running detached background jobs, commands, and PIDs |
| `disown <job_id>` | Disown target background job from shell job table to persist across exits |
| `stop <job_id>` | Send SIGTERM (or SIGKILL on repeated invocation) to target detached job |
| `attach <job_id>` | Reattach to detached background job for live output monitoring |

### Disaster Recovery In-Memory Text Editor

| Command / Syntax | Description |
| :--- | :--- |
| `vim [file]` / `vi [file]` | Zero-dependency modal in-memory text editor (Normal, Insert, Ex modes; :w, :q!, :x) |

### Out-of-Space & Full-Disk Recovery (ENOSPC Guarantees)

| Command / Syntax | Description |
| :--- | :--- |
| `df [path]` | Inspect storage blocks and inode table exhaustion side-by-side (statvfs) |
| `truncate <f> [sz]` | In-place zero-allocation shrink (drops files to 0B without unlinking or breaking handles) |
| `ghostfind [-t]` | Scan /proc/*/fd/ for unlinked deleted files held open; -t truncates in-place |
| `findlarge [p] [MB]` | Recursively traverse directory tree to find files exceeding size threshold (default 50MB) |
| `inodescan [p] [N]` | Inode hoarder scanner pinpointing directories hoarding excess file counts |
| `zerolog [path]` | Fast batch log truncator shrinking all *.log files in-place to 0 bytes |
| `findempty [p] [-d]` | Discovers and optionally purges 0-byte orphan files wasting filesystem inode slots |
| `dusage [p] [depth]` | Fast recursive directory space usage breakdown (built-in ncdu/du alternative) |
| `findinode <ino> [p]` | Reverse inode-to-path resolver identifying files by physical inode number |
| `findgrowth [p] [s]` | Real-time file growth rate monitor detecting rapidly expanding runaway files |
| `fdsize [pid]` | Storage-centric open file descriptor profiler across processes |
| `topwriters [sec]` | Process storage write throughput monitor sampling /proc/*/io |
| `ramscratch [MB]` | One-touch volatile in-memory workspace (/dev/shm/.scratch and TMPDIR redirect) |
| `ramclone <f> [dest]` | Zero-disk file stager cloning critical files into RAM when cp fails with ENOSPC |
| `tmpfs <dir> [MB]` | Mount emergency RAM tmpfs to unblock /tmp on full or read-only disks |

### In-Memory Binary Staging & Anonymous Execution

| Command / Syntax | Description |
| :--- | :--- |
| `memfile <op> [name]` | In-memory volatile RAM-backed file storage table (create, list, dump, drop) |
| `memrun <n|->` / `memexec` | Stream binary from network/stdin directly into RAM and execute via memfd_create + fexecve |
| `b64exec <name> [args]` | Terminal Base64 binary loader; pastes Base64 stream into memfd and executes without disk |

### In-Memory Defense, Threat Hunting & Adversary Neutralization

| Command / Syntax | Description |
| :--- | :--- |
| `stealth [disguise]` | Full live defense cloaking: disguises process, masks SIGTERM/INT/QUIT, sets OOM -1000 |
| `sigshield [on|off]` | Anti-kill armor; shields recovery shell against termination signals and OOM reaper |
| `exehunt` | Detect hidden malware running from deleted binaries, volatile RAM, or disguised process names |
| `deletedgrab <p> <f>` | Extract deleted malware binaries or trapped logs directly out of /proc/*/fd into RAM |
| `ramoverlay <dir> [MB]` | Mount writable copy-on-write RAM overlayfs over full/ro filesystems to unblock tool writes |
| `memscript <intp> [a]` | Execute scripts (Python, Perl, Bash) directly out of RAM without temporary disk writes |
| `memunshare [-m|-p|-n]` | Run investigation commands inside private PID, mount, and network namespaces |
| `memgrep <pid> <str>` | Sniff secrets, C2 domains, and encryption keys directly from live process virtual memory |
| `ptracehunt` | Detect active process injection, code hooking, and ptrace tracing across system daemons |
| `promischunt` | Audit promiscuous interfaces and detect stealth portless packet sniffers (BpfDoor/AF_PACKET) |
| `persistpeek` | Audit crontabs, systemd drop-ins, and shell profile startup hooks for backdoors |
| `lockdown <dir>` | Recursively apply immutable (+i) flag to directory files to freeze against ransomware |
| `entropy <file|->` | Calculate Shannon entropy to distinguish plaintext from encrypted ransomware payloads |

### Process, Thread & Memory Forensics (Anti-Rootkit)

| Command / Syntax | Description |
| :--- | :--- |
| `ps` / `proclist` | Native process table inspection (PID, PPID, RSS memory, state, command name) |
| `procpeek [pid]` | Deep inspection of process status, virtual memory mappings, and open file descriptors |
| `killtree <pid> [-sig]` | Recursively traverse and terminate entire process trees (prevents respawn loops) |
| `mapspeek <pid>` | Inspect memory maps; flags anonymous executable memory (rwxp) indicating shellcode injection |
| `fdpeek <pid>` | Audit open file descriptors and identify deleted or trapped file handles |
| `stackpeek <pid>` | Dump kernel backtrace for D-state uninterruptible hung processes from /proc/*/stack |
| `wchanpeek <pid>` | Display kernel wait-channel sleep symbol to identify process lockup causes |
| `oomadj [pid] [score]` | Inspect or adjust process Out-Of-Memory kill score (-1000 to +1000) |

### File Surgery & POSIX File System Utilities

| Command / Syntax | Description |
| :--- | :--- |
| `echo [-n] [-e] [text]` | Print text to standard output with escape interpretation and newline control |
| `cat [file...]` | Concatenate and stream files to stdout without coreutils |
| `cp <src> <dst>` | Copy files retaining permission bits and file attributes |
| `mv <src> <dst>` | Atomically move or rename files |
| `rm [-r] [-f] <f...>` | Remove files or recursively remove directories with safety checks |
| `chmod <mode> <file>` | Change file permissions using octal (0755) or symbolic (+x, -w) modes |
| `chown <uid[:gid]> <f>` | Change file owner and group attributes |
| `umask [mode]` | Display or configure process file mode creation mask |
| `touch <file...>` | Update file timestamps or create empty files |
| `mkdir [-p] <dir...>` | Create directories with parent directory creation support (-p) |
| `ls [-a] [-l] [path]` | List directory contents with permissions, sizes, and timestamps |
| `pwd` | Print current absolute working directory |
| `sync` | Flush dirty filesystem page caches to physical storage |
| `remount <rw|ro> [p]` | Remount root or target filesystem read-write or read-only |
| `wipe <file> [passes]` | Multi-pass cryptographic random overwriter and unlinker for anti-forensic sanitization |

### Stream & Text Pipeline Surgery (Zero-Coreutils)

| Command / Syntax | Description |
| :--- | :--- |
| `grep [-i|-v|-n] <p>` | Fast substring search and stream filter (case-insensitive, invert, line numbering) |
| `head [-n N] [file]` | Output initial N lines of stream or file (default 10) |
| `tail [-n N] [file]` | Output trailing N lines of stream or file using circular in-memory buffer |
| `wc [-l|-w|-c] [file]` | Count lines, words, and/or bytes across input streams |
| `cut -d <d> -f <col>` | Delimited column and field extractor for tabular and CSV streams |
| `sort [file...]` | In-memory lexicographical line sorter |
| `uniq [-c] [file...]` | Consecutive duplicate line filter and occurrence frequency counter |
| `tr [-d] <set1> [set2]` | Single-byte character translation and deletion filter |
| `diff <file1> <file2>` | Lightweight line-by-line file comparison and patch generator |
| `replace <f> <s> <r>` | Atomic in-place configuration file patcher (safe sed replacement without temp files) |
| `strings [file] [len]` | Extract printable ASCII strings from binary files or memory dumps |

### Storage, Block Devices & Initramfs Rescue

| Command / Syntax | Description |
| :--- | :--- |
| `dd if=.. of=.. [bs=N]` | Raw block carver and imager for disk recovery and MBR/GPT surgery |
| `fiemap <file>` | Map physical disk LBA sectors and file extents (Linux ext4/xfs) |
| `losetup [-d] [dev] [f]` | Direct loop device attachment and detachment ioctl interface |
| `pivot_root <new> <old>` | Direct kernel syscall for initramfs PID 1 boot handoff to target rootfs |
| `swapon <dev|file>` | Activate emergency swap partition or file |
| `swapoff <dev|file>` | Deactivate swap partition or file |
| `dropcaches [1|2|3]` | Flush pagecache (1), dentries/inodes (2), or both (3) from kernel memory |
| `diskstat` | Storage I/O throughput, read/write sector counters, and in-flight request statistics |
| `blkdiscard <device>` | Issue BLKDISCARD ioctl to trim and sanitize SSDs and virtual disk blocks |

### Network Triage, Packet Capture & Socket Hunting

| Command / Syntax | Description |
| :--- | :--- |
| `nc [-l] <h|p> [p]` | Micro-Netcat client & listener for raw TCP data streaming and serial consoles |
| `tcpping <h> <p> [ms]` | Non-blocking TCP connect liveness test (works across ICMP-blocked firewalls) |
| `pcapdump <if> <N> [out]` | Zero-dependency micro packet sniffer generating standard PCAP files (raw AF_PACKET) |
| `ipaddr [if] [ip/mask]` | Direct ioctl network interface IP address and netmask configurator |
| `dnsquery <h> [dns_ip]` | Direct UDP DNS query bypassing /etc/resolv.conf to test resolver reachability |
| `sockhunt <port>` | Pinpoint PID, process name, and executable path holding a specific TCP/UDP port |
| `killbyport <port> [-s]` | Immediately terminate whichever process is listening on target network port |
| `sockstat` | List active listening and connected TCP/UDP network sockets from kernel tables |
| `netif` | Network interface traffic and packet error counters from /proc/net/dev |
| `arppeek` | Local LAN ARP neighbor table inspector from /proc/net/arp |
| `routepeek` | Kernel IPv4 routing table inspector from /proc/net/route |
| `portscan <h> <s> <e>` | High-speed multi-port TCP connect scanner for local and remote hosts |
| `httpget <url> [dest]` | Download file over raw TCP HTTP socket without curl or wget |
| `dnslookup <host>` | Resolve hostname to IPv4/IPv6 addresses via getaddrinfo |

### Hardware, Firmware & Hypervisor Introspection

| Command / Syntax | Description |
| :--- | :--- |
| `dmipeek` / `smbios` | Motherboard, BIOS, chassis, and hypervisor identification (AWS, GCP, KVM, VMware) |
| `cpuid` / `cpuinfo` | CPU microcode, core architecture, and hardware vulnerability flags (Spectre/Meltdown) |
| `pcipeek` | Inspect PCI hardware bus controllers and devices without lspci |
| `usbpeek` | USB bus hardware sniffer to detect rogue USB devices or keyloggers |

### Security, Capabilities & LSM Defense

| Command / Syntax | Description |
| :--- | :--- |
| `cappeek [pid]` | Decode POSIX capability bitmasks (Effective, Permitted, Inheritable) |
| `nspeek [pid]` | Inspect and compare Linux namespace inode IDs across processes |
| `chattr <+i|-i> <file>` | Toggle ext2/3/4/xfs immutable bit (FS_IOC_SETFLAGS) to prevent file tampering |
| `lsmaudit` | Audit active Linux Security Modules (SELinux, AppArmor, Smack, Tomoyo) |
| `taintpeek` | Decode Linux kernel tainted status bitmask to identify hardware/driver anomalies |
| `id [user]` / `whoami` | Display effective and real UID, GID, and supplemental group memberships |

### Scripting, Cryptography, Hashing & Math

| Command / Syntax | Description |
| :--- | :--- |
| `read [-r] [VAR]` | Prompt for interactive user input into shell variable |
| `calc <n1> <op> <n2>` | 64-bit integer arithmetic calculator (+, -, *, /, %, &, |, ^) |
| `clear` | Reset and clear terminal screen via standard ANSI escape codes |
| `timestomp <f> <r|ep>` | Set nanosecond-precision file access and modification timestamps (utimensat) |
| `uptime` | Display system uptime and 1, 5, and 15-minute load averages |
| `symlink <tgt> <link>` | Create symbolic link without /bin/ln |
| `readlink [-f] <link>` | Read and resolve symbolic link target |
| `time <command...>` | Measure precise execution duration (real, user, sys CPU time) |
| `md5 <file|->` | Standalone RFC 1321 MD5 cryptographic hash calculator |
| `sha256 <file|->` | FIPS 180-4 SHA-256 cryptographic hash generator |
| `crc32 <file|->` | Compute IEEE 802.3 CRC32 checksum for stream integrity verification |
| `xor <f1> <f2> [out]` | Bitwise XOR data stream transformer for obfuscated malware analysis |
| `randhex [bytes]` | Generate cryptographically secure random hexadecimal byte tokens |

### Kernel Diagnostics, System Power & Nonstandard Triage

| Command / Syntax | Description |
| :--- | :--- |
| `sysinfo` / `free` | Display system uptime, load average, and RAM/swap utilization |
| `dmesg` | Dump kernel ring buffer messages (/dev/kmsg) without systemd |
| `uname [-a|-r|-m]` | Print operating system name, release, and hardware machine architecture |
| `reboot` | Issue direct kernel reboot syscall (bypasses systemd/init) |
| `poweroff` | Issue direct kernel poweroff syscall (bypasses systemd/init) |
| `sysrq <key>` | Trigger direct Linux Magic SysRq functions (s: sync, u: remount-ro, b: reboot, f: oom-kill) |
| `probeblk <device>` | Sniff filesystem magic headers (ext4, xfs, btrfs, swap, squashfs) |
| `hexview <file> [off]` | Dual-column Hexadecimal + ASCII binary data viewer for files and raw disks |
| `falloc <MB> <path>` | Instantaneously preallocate multi-megabyte dummy file via posix_fallocate |
| `watch <sec> <cmd>` | Periodically execute command with automatic terminal refresh |
| `sleep <seconds>` | Suspend execution for specified interval |
| `kill [-sig] <pid...>` | Send standard or numerical termination signal to target processes |
| `true` / `false` | POSIX return code primitives (exit code 0 or 1) |
| `which <program>` | Locate executable binary across system PATH |
| `test <expr>` / `[ <expr> ]` | POSIX conditional expression evaluator for file tests and string comparisons |
| `elfpeek <binary>` | Zero-execution ELF header and dynamic shared library dependency inspector |
| `envpeek [pid]` | Sniff process environment variables and secrets directly from /proc/*/environ |
| `modpeek` | Audit loaded kernel drivers and potential rootkits from /proc/modules |
| `memdump <pid> [out|-]` | Extract live process virtual memory regions from /proc/*/mem |
| `finfo <f>` / `statpeek` | Nanosecond-precision inode metadata, permissions, and anti-timestomp auditor |
| `base64 [-e|-d] [file]` | Bit-shift Base64 transceiver for air-gapped terminal data transfer |
| `mknod <p> <c|b> M m` | Direct device node reconstruction syscall for broken /dev entries |
| `mount [-t t] [-o o]` | Kernel syscall filesystem and bind mounter for emergency initramfs rescue |
| `umount [-f] <target>` | Direct kernel unmount syscall |

## Top Disaster Recovery Recipes

### Quickstart Playbook: Ubuntu Setup, Stealth Operation & Immediate Threat Triage

Deploy onto a compromised or suspicious Ubuntu host, sever process lineage, evade attacker monitoring, and uncover anomalous activity in under 60 seconds:

#### 1. Setup & Sever Shell Lineage (Zero-Trace Execution)
```bash
# Install .deb or drop static binary:
sudo dpkg -i minish_1.0.0_amd64.deb || chmod +x minish

# Sever bash parentage in-place (never run './minish' under bash!):
exec minish
```
*Effect:* `exec` replaces the running `bash` process in-place at the same PID. `minish` automatically cloaks its process name in `ps -ef`, `ps aux`, and `top` to `-bash`. Attackers running `ps -ef | grep minish` see zero matching processes.

#### 2. Arm Anti-Kill Defenses & Detach Background Collectors
```bash
# Arm anti-kill armor (masks SIGTERM/SIGINT/SIGQUIT and sets OOM score to -1000):
minish$ stealth "[kworker/0:0]"

# Detach long-running monitors into background sessions:
minish$ detach watch 5 findgrowth /var/log 5
[+] Detached Job [1] (PID: 4892) running: watch 5 findgrowth /var/log 5

# Manage background jobs without losing terminal access:
minish$ jobs
minish$ attach 1    # Live output monitor
minish$ stop 1      # Terminate runaway scanner
minish$ disown 1    # Persist as independent daemon under PID 1 across disconnects
```

#### 3. 60-Second Threat Hunting Workflow
```bash
# 1. Spot unlinked malware binaries running in RAM (e.g. /tmp/.miner (deleted)):
minish$ exehunt

# 2. Detect live process injection or ptrace hooks across system daemons:
minish$ ptracehunt

# 3. Detect portless raw packet sniffers (BpfDoor / AF_PACKET) and promiscuous NICs:
minish$ promischunt

# 4. Check active sockets and pinpoint rogue listening processes:
minish$ sockstat
minish$ sockhunt 4444

# 5. Sniff live process memory for C2 domains or encryption keys:
minish$ memgrep 3412 "http"

# 6. Audit crontabs, systemd overrides, and profile backdoors:
minish$ persistpeek

# 7. Rescue deleted malware binary directly out of RAM without touching disk:
minish$ deletedgrab 3412 4

# 8. Recursively lock down directory against ransomware (+i immutable):
minish$ lockdown /var/www
```

---

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

### Option 4: FreeBSD, pfSense & TrueNAS (`.tar.gz`)
A pure native FreeBSD 14 ELF static binary (`OS/ABI: UNIX - FreeBSD`) is distributed for FreeBSD, pfSense, and TrueNAS systems:
```bash
# Extract FreeBSD package archive:
tar -xzf minish-1.0.0-freebsd-amd64.tar.gz

# Run standalone self-verifying installer:
sudo ./install.sh
```
The installer automatically validates execution, tests ELF binary compatibility, checks `brandelf` if needed, and falls back to native compilation using the host's `cc`/`clang` if required.

## Process Camouflage & Anti-Detection Execution

By design, `minish` is engineered for stealth threat hunting and disaster recovery on compromised hosts:
- **Default Disguise (`-bash`)**: When invoked without options, `minish` automatically cloaks its process name in `/proc/[pid]/comm` and `/proc/[pid]/cmdline` (`ps -ef`, `top`, `htop`) to `-bash`. Attackers running `ps -ef | grep minish` will see zero matching processes.
- **Custom Disguise**: Disguise as any legitimate system worker or daemon:
  ```bash
  minish -a "[kworker/u2:0]"
  # or
  minish -s "sshd: [priv]"
  # or via environment
  MINISH_TITLE="-sh" minish
  ```
- **Disable Disguise**: To keep the process named `minish` for testing or container scripting:
  ```bash
  minish --no-disguise
  # or
  MINISH_NO_CLOAK=1 minish
  ```
- **Clean Terminal Disconnect**: Sessions terminate immediately upon terminal window closure or SSH disconnect via dedicated SIGHUP handling and EOF detection, preventing orphaned recovery processes.

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
