# `minish` Operational Architecture & Disaster Recovery Manual

A definitive reference manual and incident response runbook for the Minimalist POSIX Micro-Shell & Emergency Rescue Utility (`minish`).

---

## Table of Contents

1. [Architectural Overview & Core Philosophy](#1-architectural-overview--core-philosophy)
2. [Failure-Mode Resilience (Why Standard Shells Fail)](#2-failure-mode-resilience-why-standard-shells-fail)
3. [Exhaustive Command Reference](#3-exhaustive-command-reference)
   - [3.1 Shell Primitives & Flow Control](#31-shell-primitives--flow-control)
   - [3.2 File Surgery & System Maintenance](#32-file-surgery--system-maintenance)
   - [3.3 Full-Disk & Out-of-Space Rescue (`ENOSPC`)](#33-full-disk--out-of-space-rescue-enospc)
   - [3.4 Kernel Control & Hardware Diagnostics](#34-kernel-control--hardware-diagnostics)
   - [3.5 Nonstandard Triage & Inspection Tools](#35-nonstandard-triage--inspection-tools)
   - [3.6 Forensic Triage, Anti-Tamper & Live Response Suite](#36-forensic-triage-anti-tamper--live-response-suite)
   - [3.7 Stream & Pipeline Surgery (Zero-Coreutils Filters)](#37-stream--pipeline-surgery-zero-coreutils-filters)
   - [3.8 Process, Thread & Memory Forensics (Anti-Rootkit)](#38-process-thread--memory-forensics-anti-rootkit)
   - [3.9 Security, Capabilities & LSM Defense](#39-security-capabilities--lsm-defense)
   - [3.10 Storage, Block Devices & Initramfs Rescue](#310-storage-block-devices--initramfs-rescue)
   - [3.11 Network & Air-Gap Triage](#311-network--air-gap-triage)
   - [3.12 Hardware, Firmware & Hypervisor Introspection](#312-hardware-firmware--hypervisor-introspection)
   - [3.13 Interactive Scripting, Cryptography & System Control](#313-interactive-scripting-cryptography--system-control)
  - [3.14 In-Memory Defense Execution & Adversary Hunting Suite](#314-in-memory-defense-execution--adversary-hunting-suite)
4. [Emergency Triage Runbooks](#4-emergency-triage-runbooks)
   - [Runbook A: The 100% Full Disk Outage (`ENOSPC`)](#runbook-a-the-100-full-disk-outage-enospc)
   - [Runbook B: The "Ghost File" Trap (Unlinked but Open Descriptors)](#runbook-b-the-ghost-file-trap-unlinked-but-open-descriptors)
   - [Runbook C: Inode Exhaustion (`df -i 100%`)](#runbook-c-inode-exhaustion-df--i-100)
   - [Runbook D: Corrupted `/usr/bin` or Broken Dynamic Linker](#runbook-d-corrupted-usrbin-or-broken-dynamic-linker)
   - [Runbook E: Read-Only Filesystem & Diskless Triage](#runbook-e-read-only-filesystem--diskless-triage)
   - [Runbook F: Fork Bombs & Runaway Process Trees](#runbook-f-fork-bombs--runaway-process-trees)
   - [Runbook G: Running External Binaries on a Full or `noexec`-Hardened Host](#runbook-g-running-external-binaries-on-a-full-or-noexec-hardened-host)
   - [Runbook H: Live Threat Hunting, Memory Forensics & Off-Host Egress (RFC 3227)](#runbook-h-live-threat-hunting-memory-forensics--off-host-egress-rfc-3227)
   - [Runbook I: Emergency Initramfs & Bare-Metal Chroot Rescue](#runbook-i-emergency-initramfs--bare-metal-chroot-rescue)
   - [Runbook J: Ransomware Incident Response & Immutable Directory Lockdown](#runbook-j-ransomware-incident-response--immutable-directory-lockdown)
   - [Runbook K: Network Blackout & Out-of-Band Raw Packet Capture](#runbook-k-network-blackout--out-of-band-raw-packet-capture)
   - [Runbook L: Uninterruptible Sleep (D-State) & Kernel Taint Diagnosis](#runbook-l-uninterruptible-sleep-d-state--kernel-taint-diagnosis)
   - [Runbook M: Adversary Live Threat Hunting & Portless Backdoor Neutralization](#runbook-m-adversary-live-threat-hunting--portless-backdoor-neutralization)
   - [Runbook N: Air-Gapped In-Memory Tool Injection & Writable RAM Overlays](#runbook-n-air-gapped-in-memory-tool-injection--writable-ram-overlays)
5. [Packaging, UsrMerge & System Deployment](#5-packaging-usrmerge--system-deployment)

---

## 1. Architectural Overview & Core Philosophy

Standard modern shells (GNU Bash, Zsh) are large, dynamic interactive environments with thousands of features designed for user comfort: tab completion databases, extensive history management, multi-file configuration startup cascades (`/etc/profile`, `~/.bashrc`, `~/.bash_profile`), and dynamic linking to shared libraries (`libreadline`, `libtinfo`, `libc`).

In enterprise disaster recovery and micro-container environments, this complexity creates severe vulnerabilities:
- When a disk fills to 100% capacity (`ENOSPC`), history writes crash or lock terminals.
- When `/usr` is corrupted or unmounted, dynamically linked shells cannot start because `libreadline.so` or `libc.so` cannot be loaded.
- When an emergency container or initramfs boots, full-featured shells bring dozens of unnecessary dependencies, expanding attack surface and memory footprint.

### Core Architecture of `minish`

`minish` is engineered specifically to eliminate these failure modes:
1. **Single-File Pure C Implementation**: Built strictly in `shell.c` using standard POSIX 2008 and Linux kernel system calls. Compiles cleanly under `gcc -Wall -Wextra -std=c99 -pedantic -Os`.
2. **True Static Compilation**: When compiled with `-static`, `minish` produces a completely self-contained ELF binary with zero dependencies on external shared objects or dynamic linkers.
3. **Zero History / Zero Noise Policy**: `minish` **never** reads, writes, opens, or touches command history files (`.bash_history`, `.minish_history`). It produces zero disk writes and zero interactive dotfile reads, guaranteeing execution on 100% full, read-only, or degraded storage.
4. **Autonomous Zombie Reaping & Container Subreaper**:
   - Registers a `SIGCHLD` handler with `SA_RESTART | SA_NOCLDSTOP` to reap background jobs asynchronously.
   - Invokes `prctl(PR_SET_CHILD_SUBREAPER, 1)` at process initialization, ensuring that when `minish` runs as PID 1 inside a container or namespace, orphaned grandchild processes are adopted and cleaned up automatically.
5. **Just-In-Time Word Expansion**: Command lines preserve literal syntax until immediate execution, supporting quote-aware variable expansion (`$VAR`, `${VAR}`, `$?`, `$$`, `$#`, `$0`..`$9`), tilde expansion (`~`), and standalone assignments (`NAME=val`).

---

## 2. Failure-Mode Resilience (Why Standard Shells Fail)

| Production Failure Mode | Standard GNU Bash / Coreutils Behavior | `minish` Behavior |
| :--- | :--- | :--- |
| **Disk 100% Full (`ENOSPC`)** | Write errors on `~/.bash_history`; SSH sessions freeze or abort; `sed -i` and `vi` fail to create temporary files. | **Zero disk I/O**. History is never written. Native `truncate` drops file sizes in-place without temporary files. |
| **Deleted Log Still Open ("Ghost File")** | `rm /var/log/app.log` unlinks the path, but running daemons keep file descriptors open. `df` stays 100% full. Without `lsof`, the admin is blind. | **`ghostfind -t`** scans `/proc/*/fd/`, identifies open unlinked files, and truncates them in-place, instantly releasing disk blocks. |
| **Inode Table 100% Full (`df -i`)** | Standard commands report generic `No space left on device` even when gigabytes of free blocks exist. | **`df`** displays both block capacity and inode availability side-by-side, immediately identifying inode exhaustion. |
| **`/usr/bin` Corrupted / Unmounted** | Shell fails to execute `ls`, `cp`, `mv`, `cat`, `chmod`, `rm`. Disaster recovery becomes impossible. | All file surgery and triage commands are **compiled directly into `minish`**; recovery proceeds with zero external binaries. |
| **Broken Dynamic Linker (`ld-linux.so`)** | Every dynamically linked binary fails with `cannot open shared object file`. | Static `minish` binary operates entirely without dynamic linkers. |
| **Container Orphan Leaks** | Long-running background processes reparent to PID 1. Standard lightweight entrypoints fail to reap them, resulting in kernel PID exhaustion. | Native **`PR_SET_CHILD_SUBREAPER`** adopts all orphans and reaps them with asynchronous `waitpid(-1, WNOHANG)`. |

---

## 3. Exhaustive Command Reference

### 3.1 Shell Primitives & Flow Control

#### `cd [dir|-]`
- **Description**: Changes the current working directory.
- **Features**: Supports home directory tilde expansion (`~`, `~/path`), environment variable expansion (`cd $MY_DIR`), and directory toggle (`cd -` to return to `$OLDPWD`).
- **Statefulness**: Stateful built-in executed directly in the parent shell process.

#### `export [NAME=value]`
- **Description**: Sets and exports environment variables to child processes.
- **Example**: `export BACKUP_DIR=/mnt/backup`

#### `unset [NAME]`
- **Description**: Removes an environment variable from the shell environment.

#### `set [-e|+e] [-x|+x]`
- **Description**: Configures execution safety and debugging flags.
  - `-e` / `+e`: Enable / disable POSIX *errexit* (abort script execution immediately if any command returns a non-zero exit code).
  - `-x` / `+x`: Enable / disable execution tracing (prints `+ cmd` before executing each command).

#### `.` / `source <file>`
- **Description**: Evaluates the specified shell script within the **current** shell process context.
- **Use Case**: Loading configuration files (`. /etc/environment`) without spawning a subshell.

#### `exec <cmd...> [args]`
- **Description**: Replaces the current shell process image with the specified command via `execvp()`.
- **Use Case**: Container entrypoint scripts handing over control to the primary application without retaining PID 1 overhead.

#### `chroot <dir> [cmd]`
- **Description**: Changes root directory via `chroot()` syscall. If `cmd` is omitted, attempts to spawn `/bin/sh` or `minish` inside the jail.
- **Use Case**: Accessing a broken host filesystem from an emergency live CD or initramfs.

#### `setproctitle <name>` (Aliases: `procrename`, `renameproc`)
- **Description**: Dynamically renames the running shell process in-place.
- **System Calls**: Invokes `prctl(PR_SET_NAME, name)` to rewrite `/proc/self/comm` (`top`, `ps -o comm`) and overwrites the initial contiguous `argv` memory block (`/proc/self/cmdline`, `ps -ef`, `ps aux`).
- **Example**: `setproctitle rescue_worker`

#### `exit [code]`
- **Description**: Terminates the `minish` shell session cleanly.
- **Exit Status**: If an integer `code` argument is supplied, the process exits with that status. If omitted, it exits with the return code of the last executed command (`$?`).
- **Example**: `exit 0`

#### `help`
- **Description**: Prints an interactive reference manual grouping all 156 built-in commands and diagnostic engines into their operational domains directly to stdout without requiring `/usr/bin/man` or external pager tools.

---

### 3.2 File Surgery & System Maintenance

#### `cat [file...]`
- **Description**: Streams file contents to standard output. If no file is specified, reads from `stdin`.

#### `cp <src> <dst>`
- **Description**: Copies files from source to destination.
- **Safety**: Automatically captures source permissions via `stat()` and applies them to the newly created destination file via `fchmod()`.

#### `mv <src> <dst>`
- **Description**: Renames or moves files atomically via `rename()` system call.

#### `rm [-r] [-f] <file...>`
- **Description**: Deletes files and directories.
- **Safety Guard**: Prevents accidental deletion of directories unless the recursive flag (`-r` or `-R`) is explicitly supplied.

#### `chmod <mode> <file...>`
- **Description**: Modifies file access permissions.
- **Syntax**: Supports octal modes (`chmod 0755 script.sh`, `chmod 644 config.txt`) and common symbolic shortcuts (`chmod +x binary`, `chmod -x file`).

#### `chown <uid[:gid]> <file...>`
- **Description**: Modifies user and group ownership of files via `chown()` syscall.

#### `umask [mode]`
- **Description**: Displays the current file creation mask, or updates it if an octal mode is supplied (`umask 027`).

#### `touch <file...>`
- **Description**: Updates file access and modification timestamps via `utime()`. Creates a zero-byte regular file if the target does not exist.

#### `mkdir [-p] <dir...>`
- **Description**: Creates directories. With `-p`, creates intermediate parent directories as needed and does not return an error if the directory already exists.

#### `ls [-a] [-l] [path]`
- **Description**: Lists directory contents.
  - `-a`: Includes hidden files starting with `.`.
  - `-l`: Formatted long listing displaying file mode permissions, link count, size in bytes, modification date, and filename.

#### `sync`
- **Description**: Invokes the `sync()` system call to flush dirty filesystem page caches to disk. Essential before unmounting, remounting, or hard-rebooting.

#### `remount <rw|ro> [path]`
- **Description**: Issues an emergency filesystem remount directly via `mount(NULL, path, NULL, MS_REMOUNT | ..., NULL)`.
- **Examples**:
  - `remount rw /`: Unlocks a read-only rootfs during emergency single-user boot.
  - `remount ro /`: Protects a damaged disk before pulling power.

#### `pwd`
- **Description**: Prints the current working directory to standard output via `getcwd()`.
- **Zero-Dependency Guarantee**: Fully functional even if `/bin/pwd` is missing or inaccessible.

#### `echo [-n] [-e] [text...]`
- **Description**: Streams text strings and evaluated variables to standard output.
- **Flags**:
  - `-n`: Do not output trailing newline.
  - `-e`: Enable interpretation of standard backslash escape sequences (`\n`, `\t`, `\r`, `\\`, etc.).
- **Use Case**: Generating structured payloads, configuration strings, or piping binary streams.

#### `sleep <seconds>`
- **Description**: Suspends shell execution for the specified integer duration in seconds via the `sleep()` system call.
- **Signal Handling**: Resumes gracefully if interrupted by reaped child process signals (`SIGCHLD`).

#### `kill [-signal] <pid...>`
- **Description**: Transmits POSIX termination signals directly to target process IDs via `kill()` syscall.
- **Syntax**: Accepts numeric signals (`kill -9 1248`, `kill -15 3102`) or symbolic signal identifiers (`kill -TERM 1248`, `kill -KILL 3102`, `kill -HUP 840`, `kill -INT 991`).
- **Default**: Sends `SIGTERM` (15) if no signal argument is provided.

#### `true` and `false`
- **Description**: Native POSIX boolean built-ins returning exit code 0 (`true`) or 1 (`false`).
- **Use Case**: Infinite control loops (`while true; do ... done`), default fallback chains (`cmd || true`), and script assertions.

#### `which <command...>`
- **Description**: Scans directories listed in the current `$PATH` environment variable and resolves the absolute path to executable binary files.
- **Return Code**: Returns 0 if all specified commands were found, 1 if any command was not found.

#### `test` / `[ <expression>`
- **Description**: POSIX conditional evaluation engine. Evaluates file attributes, string comparisons, and 64-bit integer relations, returning exit code 0 (true) or 1 (false). When invoked via `[`, the closing argument must be `]`.
- **Supported File Operators**:
  - `-e <path>`: True if path exists.
  - `-f <path>`: True if path exists and is a regular file.
  - `-d <path>`: True if path exists and is a directory.
  - `-s <path>`: True if path exists and has size greater than 0 bytes.
  - `-r <path>`: True if path exists and read permission is granted.
  - `-w <path>`: True if path exists and write permission is granted.
  - `-x <path>`: True if path exists and execute permission is granted.
  - `-L <path>` / `-h <path>`: True if path exists and is a symbolic link.
- **Supported String Operators**:
  - `-z <str>`: True if string length is zero.
  - `-n <str>`: True if string length is non-zero.
  - `<s1> = <s2>`: True if strings are identical.
  - `<s1> != <s2>`: True if strings are not equal.
- **Supported Integer Operators**:
  - `<n1> -eq <n2>`: Equal.
  - `<n1> -ne <n2>`: Not equal.
  - `<n1> -lt <n2>`: Less than.
  - `<n1> -le <n2>`: Less than or equal.
  - `<n1> -gt <n2>`: Greater than.
  - `<n1> -ge <n2>`: Greater than or equal.
- **Negation**: `! <expr>` inverts the evaluation result.

---

### 3.3 Full-Disk & Out-of-Space Rescue (`ENOSPC`)

The Full-Disk Disaster Recovery Suite is the operational core of `minish`. It is specifically engineered for environments where storage capacity hits 100% (`ENOSPC`), the inode table is exhausted (`df -i` = 100%), root is mounted read-only (`EROFS`), or `/tmp` is locked by hardened `noexec` mount flags.

#### The Mechanics of Full-Disk Failure: Why Standard Tools Fail

When a Linux storage volume reaches 0 bytes free, the operating system enters a cascading failure state that renders standard GNU/Linux shells and utilities unusable:

1. **The Coreutils Scratch Buffer Trap**:
   - GNU Bash and Zsh attempt to write to `~/.bash_history` on interactive commands or session exit. When `write()` returns `ENOSPC`, the shell freezes, crashes, or drops the connection.
   - Shell features like here-documents (`cat <<EOF`), multi-stage subshells, and process substitutions (`<(cmd)`) create hidden temporary files in `/tmp`. On a full disk, these operations fail immediately.
   - Standard text editors (`vi`, `nano`, `sed -i`) require writable scratch space in `/tmp` or adjacent to the target file to create swap/temp files. They refuse to edit configuration files when disk space is 0 bytes.

2. **The "Ghost File" Trap (`i_nlink == 0` vs `i_count > 0`)**:
   - When administrators notice a disk is 100% full, the instinctual reaction is running `rm -f /var/log/app.log`.
   - In Linux VFS architecture, `unlink()` only removes the directory entry (`dentry`) and decrements `inode->i_nlink`. If an active daemon (e.g., `systemd-journald`, `nginx`, `mysqld`, `rsyslog`) still has the file descriptor open, the kernel inode reference count (`inode->i_count`) remains positive.
   - **Result**: The storage blocks remain allocated and held on disk. `df` continues to report 100% full, but `ls`, `du`, and `find` can no longer see the file. Without `lsof` (which is rarely installed on minimal systems), the administrator is completely blind.

3. **Inode Table Exhaustion vs Block Exhaustion**:
   - A filesystem can fail with `No space left on device` even when gigabytes of free blocks remain.
   - Every file, directory, socket, and FIFO requires a dedicated inode metadata structure. If millions of tiny files (e.g., PHP sessions, mail spool files, docker overlay layers) consume all available inodes (`f_ffree == 0`), the kernel rejects new file creation with `ENOSPC`. Standard `df -h` shows plenty of free space, misleading incident responders.

4. **Directory Block Extension Failure**:
   - Large directories store directory entries across multiple disk blocks. On a 100% full disk, attempting to `touch` or `mv` files into a large directory can fail because the directory cannot allocate a new block to hold the entry.

5. **The Hardened `noexec` Barrier**:
   - Under security baselines (CIS Benchmarks, DISA STIG), `/tmp`, `/var/tmp`, and `/dev/shm` are mounted with the `noexec` mount option.
   - If an incident responder attempts to download a vendor recovery utility (e.g., RAID tool, hardware diagnostic) to `/tmp`, the kernel blocks execution with `Permission denied` (`EACCES`), even if free space is available.

`minish` is architected to eliminate every one of these failure modes through native in-memory and kernel system call primitives.

---

#### Detailed Command Reference: Full-Disk Rescue

#### `df [path]`
- **Description**: Inspects storage block allocation and inode capacity side-by-side via direct `statvfs()` system call invocation.
- **Kernel Mechanism**: Queries `f_bsize` (filesystem block size), `f_frsize` (fundamental allocation fragment size), `f_blocks` (total blocks), `f_bfree` (free blocks including root reserve), `f_bavail` (free blocks available to non-root users), `f_files` (total inodes), and `f_ffree` (free inodes).
- **Root Reserve Transparency**: Standard `df` hides root-reserved blocks (typically 5% on ext4). `minish df` explicitly prints both `Avail(User)` and `Free(Root)` in megabytes, allowing responders to see whether root emergency headroom still exists.
- **Automated Threshold Warnings**:
  - Emits `[!] CRITICAL ALERT: Storage space is XX% full (ENOSPC risk)!` when block usage exceeds 90%.
  - Emits `[!] CRITICAL ALERT: Inode table is XX% full! New files cannot be created.` when inode usage exceeds 90%.
- **Example Output**:
  ```text
  === Filesystem Triage: /var ===
  Storage Blocks:
    Total: 51200 MB | Used: 51200 MB (100%) | Avail(User): 0 MB | Free(Root): 0 MB
  Inode Metadata:
    Total: 3276800 | Used: 412050 (12%) | Free: 2864750
  [!] CRITICAL ALERT: Storage space is 100% full (ENOSPC risk)!
  ```

#### `truncate <file> [bytes]`
- **Description**: In-place zero-allocation file shrinking engine. Drops file sizes to 0 bytes (or a specified byte limit) immediately.
- **Why It Succeeds When `rm` Fails**:
  - Does **not** unlink or recreate the directory entry.
  - Does **not** require allocating any new inode or directory block metadata.
  - Releases disk block extents directly back to the filesystem free block bitmap via `truncate()` / `ftruncate()`.
  - **Crucial Advantage**: If a logging daemon (e.g. `nginx`, `syslog`) has the file open, `truncate` collapses the file in-place without destroying the file descriptor. The daemon continues writing to the file at offset 0, and disk space is reclaimed **instantly without restarting the service**.
- **Multi-Stage Fallback Implementation**:
  1. Primary: Direct `truncate(path, target_size)` syscall.
  2. Fallback (for `/proc/<pid>/fd/` magic symlinks): Opens path with `open(path, O_WRONLY | O_TRUNC)` or `ftruncate(fd, target_size)`.
- **Examples**:
  ```bash
  # Instantly collapse runaway syslog to 0 bytes:
  minish$ truncate /var/log/syslog 0

  # Shrink huge access log to exactly 10 MB:
  minish$ truncate /var/log/nginx/access.log 10485760
  ```

#### `ghostfind [-t]`
- **Description**: The Ghost File Hunter and Destroyer. Scans the Linux `/proc` filesystem to uncover deleted files that are still consuming physical disk space because active processes hold open file descriptors.
- **How It Works**:
  1. Traverses `/proc/[0-9]*/fd/` across all running processes.
  2. Queries each descriptor target via `readlink()`.
  3. Detects targets ending with the Linux kernel annotation `" (deleted)"`.
  4. Invokes `stat()` on `/proc/<pid>/fd/<fd>` to resolve the actual allocated byte size on disk.
  5. Displays the PID, process command name, file descriptor number, trapped size in megabytes, and original pathname.
  6. Calculates and reports the total cumulative trapped disk space across the entire system.
- **The `-t` In-Place Truncation Feature**:
  - When invoked with `-t`, `ghostfind` opens each identified ghost file via its `/proc/<pid>/fd/<fd>` magic link with `O_WRONLY | O_TRUNC`.
  - The Linux VFS routes the truncation directly to the underlying orphan inode, freeing all associated disk extents immediately.
  - **Result**: Trapped gigabytes are released to the kernel **without killing, restarting, or interrupting the holding daemon**.
- **Example Output**:
  ```text
  minish$ ghostfind
  === Ghost File Finder (Open Deleted File Descriptors) ===
  PID  1248 (nginx          ) | FD 4    | Size: 45200.00 MB | /var/log/nginx/access.log
  PID  3102 (mysqld         ) | FD 12   | Size: 12400.00 MB | /tmp/ibzT7x9A
  --------------------------------------------------------------------------------
  Total trapped disk space: 57600.00 MB (56.25 GB) across 2 ghost file(s).

  minish$ ghostfind -t
  [+] Truncated PID 1248 FD 4 (/var/log/nginx/access.log) to 0 bytes
  [+] Truncated PID 3102 FD 12 (/tmp/ibzT7x9A) to 0 bytes
  [+] Reclaimed 57600.00 MB of trapped storage!
  ```

#### `findlarge [path] [min_MB]`
- **Description**: High-speed recursive directory traversal scanner that pinpoints oversized runaway files.
- **Defaults**: If omitted, scans the current working directory (`.`) for files `>= 50 MB`.
- **Safety**: Automatically skips virtual and pseudo-filesystems (`/proc`, `/sys`, `/dev`) to avoid hanging on infinite kernel synthetic loops or memory tables.
- **Examples**:
  ```bash
  # Scan /var for files exceeding 100 MB:
  minish$ findlarge /var 100

  # Scan entire root filesystem for files exceeding 1 GB:
  minish$ findlarge / 1024
  ```

#### `tmpfs <mountpoint> [size_MB]`
- **Description**: Mounts an emergency in-memory RAM disk filesystem directly via the Linux `mount()` system call.
- **Default Size**: 64 MB (or user-specified in megabytes).
- **Permissions**: Mounts with mode `1777` (`rwxrwxrwt`) and explicit execution permissions (`MS_EXEC`), bypassing host hardened `noexec` restrictions on `/tmp`.
- **Why It Unblocks Frozen Systems**:
  - Package managers (`dpkg`, `rpm`, `apt`), database daemons, and compiler toolchains require a functioning `/tmp` directory to create temporary lockfiles, UNIX domain sockets, and transaction logs.
  - When the physical root filesystem is 100% full, all such tools crash with `ENOSPC`.
  - Running `tmpfs /tmp 64` instantly overlays an in-memory RAM disk on top of the frozen `/tmp`. All package managers and diagnostic tools immediately resume functioning without writing a single block to disk.
- **Example**: `tmpfs /tmp 128`

#### `memrun` / `memexec <name|-> [args...]`
- **Description**: Anonymous in-memory binary execution engine. Streams and executes compiled ELF binaries directly out of volatile RAM using Linux `memfd_create()` and `fexecve()`.
- **The Execution Lifecycle**:
  1. **Anonymous RAM Allocation**: Calls `int fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);`. The file descriptor exists exclusively in kernel RAM pages—it has no directory entry and consumes 0 physical disk blocks and 0 disk inodes.
  2. **Streaming Ingestion**: Reads binary bytes directly from standard input (pipe) or from `memfile` storage into `fd`.
  3. **Write-Sealing**: Calls `fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE);` to lock the descriptor against further modifications, preventing `ETXTBSY` (Text file busy).
  4. **Kernel Execution**: Executes the in-memory binary via `fexecve(fd, argv, environ)` or through `/proc/self/fd/<fd>`.
- **Why It Bypasses `noexec` Mount Options**:
  - `noexec` is a filesystem mount flag attached to VFS directory trees.
  - Because `memfd_create` descriptors originate from anonymous kernel memory and not from a block device mount, the kernel does **not** enforce `noexec` mount restrictions against them.
- **Examples**:
  ```bash
  # Stream vendor RAID recovery tool directly over HTTP into RAM and execute:
  minish$ httpget http://192.168.1.50/megacli | memrun - -AdpAllInfo -aAll

  # Stream compiled binary over raw TCP socket and execute:
  minish$ nc 192.168.1.50 9000 | memrun - --scan-all --fix
  ```

#### `memfile <save|cat|run|exec|list|rm> [name] [args...]`
- **Description**: Volatile in-memory virtual file storage table living in `minish` process heap memory. Allows staging configuration backups, scripts, and recovery binaries without touching physical disk.
- **Subcommands**:
  - `memfile save <name> < file`: Reads stream from standard input into RAM storage.
  - `memfile cat <name>`: Streams memory-resident file to stdout.
  - `memfile run <name> [args...]` (or `exec`): Passes resident memory file directly to `memrun` for execution.
  - `memfile list`: Displays all resident files, count, and byte sizes.
  - `memfile rm <name>`: Frees heap allocation.
- **Example**:
  ```bash
  minish$ httpget http://10.0.0.1/recovery.sh | memfile save fix.sh
  minish$ memfile list
  minish$ memfile cat fix.sh | minish
  minish$ memfile rm fix.sh
  ```

#### `dropcaches [1|2|3]`
- **Description**: Direct interface to kernel cache reclamation. Writes to `/proc/sys/vm/drop_caches`.
  - `dropcaches 1`: Frees clean pagecache pages from RAM.
  - `dropcaches 2`: Frees slab objects, including dentries and inode metadata caches.
  - `dropcaches 3`: Frees both pagecache and slab caches simultaneously.
- **Rescue Value**: Synchronizes kernel memory state with storage free block bitmaps, especially after massive truncations.

#### `falloc <MB> <path>`
- **Description**: Instant sparse/preallocated file allocation via `posix_fallocate()` / `fallocate()`.
- **Rescue Value**: Tests whether the filesystem can allocate contiguous physical extents without writing zeroes block-by-block, or preallocates emergency swap containers.
- **Example**: `falloc 512 /mnt/swapfile`

---

#### `findgrowth [path] [seconds]`
- **Description**: Real-time file expansion and disk-fill monitor. Takes a lightweight snapshot of file sizes in the target directory tree, pauses for `seconds` (default 2), and lists files that grew in size during the window along with growth rate.
- **Why It Matters**: Answers the critical question: *"Which file is eating my disk space right this second?"*
- **Example**: `findgrowth /var/log 2`

#### `fdsize [pid]`
- **Description**: Storage-centric file descriptor profiler. Scans `/proc/<pid>/fd/` (or all running processes if PID omitted) and calculates the physical disk space allocated to each open file descriptor, highlighting unlinked and trapped descriptors.
- **Why It Matters**: Instantly uncovers which running daemons are holding multi-gigabyte files or unlinked logs open.
- **Example**: `fdsize 1248`

#### `topwriters [seconds]`
- **Description**: Process I/O write rate monitor. Samples `/proc/[0-9]*/io` (`write_bytes`) over a sampling window (default 2 seconds) and ranks active processes by write throughput (PID, process name, MB/s, and total MB written).
- **Why It Matters**: Identifies the exact runaway daemon or logging loop actively writing data to the full disk.
- **Example**: `topwriters 1`

#### `ramscratch [size_MB]`
- **Description**: One-touch volatile in-memory workspace generator. Allocates an isolated, executable RAM disk at `/dev/shm/.scratch` (or `/tmp/.scratch`), sets permissions to `0700`, navigates (`cd`) into it, and sets `TMPDIR=$PWD`.
- **Why It Matters**: Gives incident responders a guaranteed writable workspace in a single command with **zero disk writes**.
- **Example**: `ramscratch 64`

#### `ramclone <src_file> [dest_name]`
- **Description**: Zero-disk file stager and cloner. Reads `src_file` and writes it directly into the in-memory virtual storage table (`memfile`) and into the active RAM scratchpad with **0 disk block allocations**.
- **Why It Matters**: Solves the classic dilemma where an admin needs to back up a configuration file (like `/etc/fstab`) before editing, but `cp` fails with `ENOSPC`.
- **Example**: `ramclone /etc/resolv.conf resolv.bak`

#### `inodescan [path] [threshold]`
- **Description**: Inode hoarding scanner. Traverses the directory hierarchy starting at `path` (default `.`) and audits directory file density. Identifies directories containing `>= threshold` files (default 1000 files/dir).
- **Filesystem & Kernel Context**: On ext4, XFS, and btrfs, millions of tiny files (e.g. PHP session files in `/var/lib/php/sessions`, spool files in `/var/spool`, or container overlay debris) can exhaust the filesystem inode table (`df -i 100%`) while gigabytes of disk block storage remain free. Standard tools like `find` or `ls` often fail with `E2BIG` (Argument list too long) or lock directory locks. `inodescan` streams directory entries via `readdir()`, counts entries per directory, skips `/proc`, `/sys`, `/dev`, and immediately prints the hoarding directories and total scanned files.
- **Example**:
  ```text
  minish$ inodescan /var 5000
  === Inode Exhaustion Scanner: /var (>= 5000 files/dir) ===
  [!] Inode Hoarder: /var/lib/php/sessions (142,500 files)
  [!] Inode Hoarder: /var/spool/clientmqueue (18,402 files)
  Found 2 directory(ies) with >= 5000 files (total scanned files: 165902)
  ```

#### `zerolog [path]`
- **Description**: Emergency batch log file truncator. Recursively traverses `path` (default `/var/log`) up to depth 15 for files ending with `.log` or containing `.log.`, and truncates them in-place to 0 bytes via `truncate()`.
- **Why It Matters**: When a server suffers a sudden disk fill from runaway debug logs, an administrator often has to run dozens of `truncate -s 0` commands manually. `zerolog` performs automated in-place truncation across all active log files in seconds, freeing megabytes or gigabytes without deleting files or disrupting running syslog/nginx/systemd-journald daemons.
- **Example**:
  ```text
  minish$ zerolog /var/log
  === Emergency In-Place Log Truncation: /var/log ===
  [+] Truncated: /var/log/syslog (4200.50 MB freed)
  [+] Truncated: /var/log/nginx/access.log (1840.10 MB freed)
  [+] Truncated: /var/log/nginx/error.log (120.40 MB freed)
  Truncated 3 log file(s), reclaimed 6161.00 MB in-place
  ```

#### `findempty [path] [-d]`
- **Description**: 0-byte orphan file scanner and purger. Recursively searches `path` (default `.`) for empty regular files (`st_size == 0`).
- **Options**:
  - Scan-only mode (default): Lists all 0-byte files wasting inode slots.
  - `-d` (Delete mode): Immediately unlinks each 0-byte file via `unlink()`, reclaiming an inode slot back to the filesystem free inode table for each deleted file.
- **Why It Matters**: Inode exhaustion (`df -i 100%`) is frequently caused by failed scripts or crashes that create millions of 0-byte lock, state, or session files. `findempty -d` cleans them up without spawning external subshells or running out of memory.
- **Example**:
  ```text
  minish$ findempty /tmp/locks -d
  === Empty 0-Byte File Scanner: /tmp/locks (DELETE MODE) ===
  [-] Deleted 0-byte file: /tmp/locks/sess_a9f82b (1 inode reclaimed)
  [-] Deleted 0-byte file: /tmp/locks/sess_c011e4 (1 inode reclaimed)
  Reclaimed 2 inode(s) by deleting empty files
  ```

#### `dusage [path] [depth]`
- **Description**: Recursive directory space consumption profiler (built-in zero-dependency `ncdu` / `du -h --max-depth=N` alternative).
- **Arguments**:
  - `path`: Starting directory (default `.`).
  - `depth`: Maximum recursion depth to report (default 1).
- **Output**: Calculates the cumulative storage consumption of each subdirectory in megabytes and prints a sorted hierarchy followed by the total subtree size.
- **Safety**: Automatically skips pseudo-filesystems (`/proc`, `/sys`, `/dev`) and guards against filesystem recursion loops (depth limit 20).
- **Example**:
  ```text
  minish$ dusage /var 1
  === Directory Storage Usage: /var (depth 1) ===
  [  420.50 MB] /var/cache
  [ 5820.10 MB] /var/log
  [12450.00 MB] /var/lib
  [   12.40 MB] /var/spool
  Total subtree size (/var): 18703.00 MB
  ```

#### `findinode <inode_number> [path]`
- **Description**: Reverse inode-to-path resolver. Traverses `path` (default `.`) and resolves which file corresponds to a specific physical inode number reported by kernel logs, dmesg I/O errors, or filesystem audit tools.
- **Use Case**: When `dmesg` reports `EXT4-fs error: inode #1441793: comm worker: corrupt block bitmap`, standard tools require `find / -inum 1441793`. `findinode` executes this natively without `/usr/bin/find`, returning the full path, size in bytes, and octal file mode.
- **Example**:
  ```text
  minish$ findinode 1441793 /var
  === Searching for Inode #1441793 starting from /var ===
  [+] Inode 1441793 -> /var/log/audit/audit.log (Size: 104857600 bytes, Mode: 0600)
  Resolved 1 match(es) for Inode #1441793
  ```

---

#### The 5 Golden Rules of 100% Full-Disk Survival

1. **NEVER use `rm` on an active log file held by a running service**:
   - `rm` unlinks the filename but leaves the blocks allocated to the running daemon. Always use `truncate <file> 0` to release disk blocks immediately.
2. **ALWAYS run `df` first to diagnose Block vs. Inode exhaustion**:
   - If `Avail(User)` is 0 MB, storage blocks are exhausted. If `Used Inodes` is 100%, millions of tiny files are exhausting the inode table.
3. **CHECK for Ghost Files before assuming disk is unrecoverable**:
   - Run `ghostfind`. In 80% of enterprise production disk outages, tens of gigabytes of disk space are trapped in unlinked open log descriptors. Run `ghostfind -t` to reclaim them instantly.
4. **NEVER download recovery tools to disk**:
   - Stream binaries over the network directly into memory using `httpget ... | memrun -`. This avoids `ENOSPC` disk errors and bypasses host `noexec` restrictions.
5. **OVERLAY an emergency `tmpfs` on `/tmp`**:
   - If package managers (`apt`, `dpkg`, `rpm`) fail with `ENOSPC`, run `tmpfs /tmp 64`. This immediately provides a functional, writable, executable scratchpad to unblock package installations.

---

### 3.4 Kernel Control & Hardware Diagnostics

#### `sysinfo` (Alias: `free`)
- **Description**: Reads system metrics via `sysinfo()` system call.
- **Output**: System uptime (days, hours, minutes), active process count, 1/5/15 minute load averages, total/free/used RAM, and swap usage.

#### `dmesg`
- **Description**: Dumps kernel ring buffer diagnostic messages directly via `klogctl()`.
- **Use Case**: Diagnosing kernel panics, OOM-killer events, drive I/O errors, or hardware failures when `/var/log/dmesg` is inaccessible.

#### `uname [-a|-r|-m|-s]`
- **Description**: Prints operating system name, hostname, kernel release version, and hardware machine architecture via `uname()`.

#### `reboot` / `poweroff`
- **Description**: Direct kernel reboot or system halt via `reboot()` syscall (`RB_AUTOBOOT` / `RB_POWER_OFF`).
- **Use Case**: Clean hardware restart when `/sbin/reboot` or `systemd` are hung or unresponsive.

#### `sysrq <key>`
- **Description**: Directly triggers Linux Magic SysRq functions by writing to `/proc/sysrq-trigger`.
- **Keys**:
  - `sysrq s`: Emergency sync of all mounted filesystems.
  - `sysrq u`: Emergency remount of all filesystems in read-only mode.
  - `sysrq b`: Immediate hard reboot without unmounting (clean reboot if preceded by `s` and `u`).
  - `sysrq f`: Manually trigger the kernel Out-Of-Memory (OOM) killer.
  - `sysrq t`: Dump current process backtraces to the console.

---

### 3.5 Nonstandard Triage & Inspection Tools

#### `memfile <save|cat|list|rm> [name]`
- **Description**: In-memory virtual file storage table living entirely in volatile shell memory.
- **Commands**:
  - `memfile save <name> < file`: Saves stream into memory buffer.
  - `memfile cat <name>`: Streams memory buffer to stdout.
  - `memfile list`: Displays all resident RAM files and their byte sizes.
  - `memfile rm <name>`: Frees memory buffer.
- **Use Case**: Staging scripts, configs, and keys on diskless, read-only, or full hosts.

#### `probeblk <device>`
- **Description**: Block device filesystem sniffer. Reads the first 2 KB of a raw drive partition (`/dev/sda1`) and inspects magic superblock bytes.
- **Identifies**: `ext4/ext3/ext2` (`0xef53`), `XFS` (`XFSB`), `Btrfs` (`_BHRfS_M`), `Linux Swap` (`SWAPSPACE2`), `FAT32/VFAT`, `NTFS`, `GPT Partition Header`, and `MBR Boot Sector`.

#### `hexview <file> [offset]`
- **Description**: Formatted hex and ASCII inspector displaying 16-byte rows with offset counters and printable characters.
- **Use Case**: Examining corrupted partition tables, binary file headers, or encrypted disk sectors without `hexdump` or `xxd`.

#### `falloc <MB> <path>`
- **Description**: Instant multi-megabyte sparse or preallocated file creation via `posix_fallocate()`.
- **Use Case**: Creating emergency swap files or zero-allocated disk containers in milliseconds.

#### `sockstat`
- **Description**: Zero-dependency network socket triage tool. Directly parses `/proc/net/tcp` and `/proc/net/udp`.
- **Output**: Protocol, local IP:port, remote IP:port, and connection state (`LISTEN`, `ESTABLISHED`, `TIME_WAIT`, `CLOSE`). Replaces `netstat` and `ss`.

#### `killtree <pid> [-sig]`
- **Description**: Recursive process hierarchy destroyer.
- **Mechanism**: Traverses `/proc/*/stat` to build the parent-child PID tree and recursively terminates all child processes before terminating the target parent. Eliminates orphaned forks.

#### `procpeek [pid]`
- **Description**: Deep process introspection tool. Inspects `/proc/<pid>/status` for UID, PPID, state, virtual memory size, and resident memory (`VmRSS`), and lists all open file descriptors with their `readlink()` targets.

#### `httpget <url> [dest_file]`
- **Description**: Standalone socket-level HTTP/1.0 client. Connects over raw TCP to fetch scripts, kernel modules, or configs.
- **Advantage**: Downloads over the network without requiring `curl`, `wget`, or external OpenSSL shared libraries.

#### `dnslookup <hostname>`
- **Description**: Tests DNS resolution via libc `getaddrinfo()`, outputting all resolved IPv4 and IPv6 addresses.

#### `randhex [bytes]`
- **Description**: Reads from `/dev/urandom` to generate cryptographically secure random hexadecimal strings for temporary tokens, passwords, or salts.

#### `watch <interval_sec> <command>`
- **Description**: Periodically executes a shell command with an interval delay and ANSI screen clear.
- **Example**: `watch 2 sysinfo`

### 3.6 Forensic Triage, Anti-Tamper & Live Response Suite

#### `sha256 <file|->`
- **Description**: Standalone FIPS 180-4 SHA-256 cryptographic hash generator.
- **Advantage**: Calculates cryptographic digests of suspect binaries, kernel modules, or configs without relying on host `sha256sum` (which may be backdoored) or external OpenSSL libraries.
- **Stream Support**: Hashes directly from standard input (`cat /dev/sda1 | sha256 -` or `memdump 1337 - | sha256 -`).

#### `nc [-l] <host|port> [port]`
- **Description**: Micro-Netcat client and listening socket server for raw TCP data streaming.
- **Client Mode**: `nc <host> <port>` connects over TCP and streams `stdin` to remote server and socket output to `stdout`.
- **Server Mode**: `nc -l <port>` opens a TCP listener on `0.0.0.0:<port>` to receive incoming data streams.
- **Forensic Egress**: Streams raw disk partitions, memory dumps, or audit logs off-box to an external evidence collector without writing a single byte to the compromised host's storage.

#### `elfpeek <binary>`
- **Description**: Zero-execution dynamic shared library and ELF header inspector.
- **Safety**: Standard `ldd` is a shell script that *executes* the target binary under `LD_TRACE_LOADED_OBJECTS=1`. If the binary is malicious or corrupted, running `ldd` triggers attacker code execution. `elfpeek` safely parses `Elf64_Ehdr`, `PT_INTERP`, and `PT_DYNAMIC` (`DT_NEEDED`) directly from disk without executing a single instruction.

#### `envpeek [pid]`
- **Description**: Process runtime environment sniffer.
- **Mechanism**: Reads `/proc/<pid>/environ` directly from the kernel ring and translates null bytes (`\0`) into newlines, revealing active environment variables, API tokens, cloud keys (AWS/GCP/Azure), and database passwords.

#### `modpeek`
- **Description**: Loaded kernel module and driver auditor.
- **Mechanism**: Reads `/proc/modules` directly, bypassing `/sbin/lsmod` (which rootkits often tamper with or delete). Displays module names, memory footprints, reference counts, and dependent modules.

#### `base64 [-e|-d] [file]`
- **Description**: Pure RFC 4648 bit-shift Base64 encoder and decoder.
- **Air-Gap Rescue**: Allows transfer of binary utilities and extraction of triage dumps across text-only serial consoles (IPMI SOL, AWS serial console, physical RS-232) where network interfaces are down.

#### `replace <file> <search> <replace>`
- **Description**: Atomic in-place configuration file patcher.
- **Advantage**: Replaces target strings line-by-line and atomically commits via `rename()`, preserving permissions. Fixes broken `/etc/fstab`, `/etc/resolv.conf`, `/etc/shadow`, or bootloader configs without `sed`, `awk`, `perl`, or text editors.

#### `mknod <path> <c|b> <major> <minor>`
- **Description**: Direct `mknod()` system call wrapper with `makedev()`.
- **Rescue Value**: Reconstructs missing or deleted device nodes (`/dev/null`, `/dev/zero`, `/dev/console`, `/dev/sda`) when `udev` or `systemd-udevd` fails.

#### `mount [-t type] [-o options] <source> <target>` & `umount [-f] <target>`
- **Description**: Direct kernel system call filesystem and bind mounter.
- **Features**: Supports `-t <fstype>`, comma-separated options (`bind`, `ro`, `rw`, `remount`, `noexec`, `nosuid`, `nodev`, `relatime`), and dumps `/proc/mounts` when run without arguments. Enables full bare-metal `chroot` resuscitation without `/bin/mount`.

#### `memdump <pid> [out_file|-]`
- **Description**: Live process virtual memory extraction engine.
- **Forensic Power**: Parses `/proc/<pid>/maps` and streams readable segments (`r--p`, `rw-p`) directly out of `/proc/<pid>/mem`. Dumps in-memory malware that deleted its binary on disk (`/proc/<pid>/exe (deleted)`), injected shellcode, or recovers trapped database data from crashed daemons.

#### `finfo` / `statpeek <path>`
- **Description**: Deep inode, permission, and nanosecond timestamp inspector.
- **Anti-Timestomp**: Standard `ls -l` only shows `mtime`. Attackers use `touch -r` to forge modification dates. `finfo` displays nanosecond-accurate `atime`, `mtime`, and kernel `ctime` (which cannot be spoofed by `touch`), immediately raising an alert if `mtime` is older than `ctime`.

#### `strings [file] [min_length]`
- **Description**: Zero-dependency ASCII string and artifact extractor.
- **Triage Power**: Extracts printable ASCII sequences (>= 4 chars by default) from raw binaries, memory dumps, or disk partitions without GNU `binutils`.

#### `wipe <file> [passes]`
- **Description**: Secure anti-forensic overwriter and unlinker.
- **Mechanism**: Overwrites the target file in-place with zeroes and bit-patterns before unlinking, preventing residual data recovery from unallocated disk sectors.

---

### 3.7 Stream & Pipeline Surgery (Zero-Coreutils Filters)

Operating without GNU coreutils or standard userland filter binaries, these built-in pipeline primitives process streams and files directly via memory buffers and UNIX pipes without creating temporary disk scratch files.

#### `grep [-i] [-v] [-n] <pattern> [file...]`
- **Description**: Fast string matching and inverted filter utility.
- **Flags**:
  - `-i`: Case-insensitive search.
  - `-v`: Invert match (prints non-matching lines).
  - `-n`: Prefix each matching line with its 1-indexed line number.
- **Stream Support**: Reads from stdin when no file is specified or when `-` is supplied.
- **Example**: `dmesg | grep -i "error"`

#### `head [-n N] [file...]`
- **Description**: Emits the first N lines of standard input or target files (defaults to 10 lines).
- **Example**: `cat /etc/passwd | head -n 5`

#### `tail [-n N] [file...]`
- **Description**: Emits the last N lines of a stream or file using an in-memory circular line buffer.
- **Example**: `tail -n 20 /var/log/syslog`

#### `wc [-l|-w|-c] [file...]`
- **Description**: Counts lines (`-l`), whitespace-delimited words (`-w`), and raw bytes (`-c`).
- **Example**: `wc -l /etc/passwd`

#### `cut -d <delimiter> -f <field> [file...]`
- **Description**: Column and field extractor for delimited text files (CSV, colon-separated, tab-separated).
- **Example**: `cut -d : -f 1 /etc/passwd` (extracts all usernames)

#### `sort [file...]`
- **Description**: In-memory line sorter using pure C `qsort()`. Reads entire stream or file and emits lexicographically ordered lines.
- **Example**: `cat list.txt | sort`

#### `uniq [-c] [file...]`
- **Description**: Consecutive duplicate line deduplicator. With `-c`, prefixes each line with its recurrence count.
- **Example**: `cat access.log | cut -d ' ' -f 1 | sort | uniq -c`

#### `tr [-d] <set1> [set2]`
- **Description**: Single-byte character translation and deletion filter.
- **Flags**:
  - `-d`: Deletes all occurrences of characters in `set1`.
- **Example**: `cat input.txt | tr "a-z" "A-Z"` or `cat dirty.txt | tr -d "\r"`

#### `diff <file1> <file2>`
- **Description**: Lightweight line-by-line file comparison engine. Highlights line differences with `-` (file1) and `+` (file2) annotations without requiring external `diffutils`.
- **Example**: `diff /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak`

---

### 3.8 Process, Thread & Memory Forensics (Anti-Rootkit)

Bypasses compromised userland binaries (`/bin/ps`, `/usr/bin/top`, `/usr/bin/lsof`) by extracting ground truth directly from the Linux `/proc` pseudo-filesystem.

#### `ps` / `proclist`
- **Description**: Native kernel process table walker.
- **Output**: PID, PPID, State (`R`, `S`, `D`, `Z`, `T`), resident memory (`RSS` in KB), and process command name (`comm`).
- **Safety**: Reads `/proc/[0-9]*/stat` and `/proc/[0-9]*/status` directly.

#### `mapspeek <pid>`
- **Description**: Memory segment inspector for detecting process injection and fileless malware.
- **Mechanism**: Reads `/proc/<pid>/maps`. Highlights executable anonymous memory pages (`rwxp`) where shellcode or injected payload code typically resides.
- **Example**: `mapspeek 1337`

#### `fdpeek <pid>`
- **Description**: Deep file descriptor auditor.
- **Mechanism**: Scans `/proc/<pid>/fd/*` via `readlink()`, pinpointing deleted files held open in memory, raw network sockets (`socket:[...]`), pipes, and character devices.
- **Example**: `fdpeek 1248`

#### `stackpeek <pid>`
- **Description**: Kernel call stack extractor for deadlocked and uninterruptible sleep processes.
- **Mechanism**: Reads `/proc/<pid>/stack`. Displays kernel function call traces, revealing whether a process is hung waiting on NFS I/O, disk block allocation, or a kernel lock.
- **Example**: `stackpeek 892`

#### `wchanpeek <pid>`
- **Description**: Displays the exact kernel wait-channel symbol where a sleeping or blocked thread is waiting (from `/proc/<pid>/wchan`).
- **Example**: `wchanpeek 892`

#### `oomadj [pid] [score]`
- **Description**: Linux Out-Of-Memory killer score inspector and manipulator.
- **Mechanism**: Reads or updates `/proc/<pid>/oom_score_adj`. Scores range from `-1000` (completely immune to OOM killer) to `+1000` (first sacrifice).
- **Rescue Value**: Set `oomadj $$ -1000` to prevent your emergency rescue shell from being killed during extreme memory pressure.

---

### 3.9 Security, Capabilities & LSM Defense

Enforces low-level Linux security policies, audits container namespaces, and defends critical files against ransomware or accidental deletion.

#### `cappeek [pid]`
- **Description**: Decodes POSIX capability bitmasks into human-readable strings.
- **Mechanism**: Parses `CapEff` (Effective), `CapPrm` (Permitted), and `CapInh` (Inheritable) from `/proc/<pid>/status` and decodes each bit to its `CAP_*` identifier (e.g. `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`).
- **Example**: `cappeek 1`

#### `nspeek [pid]`
- **Description**: Namespace inode auditor and container escape detector.
- **Mechanism**: Reads `/proc/<pid>/ns/*` (`mnt`, `pid`, `net`, `uts`, `ipc`, `user`, `cgroup`). Compare namespace inode IDs across processes to prove whether a process is truly jailed inside a container or sharing host namespaces.
- **Example**: `nspeek $$`

#### `chattr <+i|-i> <file>`
- **Description**: Direct ioctl wrapper for filesystem extended attributes (`FS_IOC_SETFLAGS`).
- **Flags**:
  - `+i`: Sets the immutable attribute. Files cannot be modified, truncated, deleted, renamed, or linked to, even by the `root` user.
  - `-i`: Clears the immutable attribute.
- **Example**: `chattr +i /etc/passwd`

#### `lockdown <dir>`
- **Description**: Batch recursive directory immutable lockdown.
- **Mechanism**: Recursively traverses the target directory and applies `FS_IOC_SETFLAGS` (`+i`) to every file, immediately halting active ransomware or wiper scripts from encrypting or destroying data.
- **Example**: `lockdown /var/www`

#### `lsmaudit`
- **Description**: Audits active Linux Security Modules and enforcing modes.
- **Mechanism**: Checks `/sys/fs/selinux/enforce`, `/sys/kernel/security/apparmor`, and Smack interfaces to report active MAC engines.

#### `taintpeek`
- **Description**: Kernel taint decoder.
- **Mechanism**: Reads `/proc/sys/kernel/tainted` bitmask and translates bits into human-readable flags (e.g. Out-of-tree module loaded, Kernel warning occurred, Unsigned module loaded).

#### `id` / `whoami` `[user]`
- **Description**: Displays real and effective UID, GID, and supplemental group IDs and names.
- **Example**: `id` or `whoami`

#### `entropy <file|->`
- **Description**: Standalone Shannon entropy calculator (`0.00` to `8.00`).
- **Mechanism**: Reads stream or file byte frequencies and computes entropy using pure integer and rational approximations (zero `-lm` math library dependency).
- **Forensic Value**: Files with entropy > 7.50 are either encrypted (ransomware/keys) or compressed blobs. Plaintext configs and code have entropy < 5.50.
- **Example**: `entropy suspicious_file.bin`

---

### 3.10 Storage, Block Devices & Initramfs Rescue

Low-level storage carving, loopback device management, and initramfs handoff primitives.

#### `dd if=.. of=.. [bs=N] [count=N]`
- **Description**: Raw block carver and device imager.
- **Features**: Supports input file (`if=`), output file (`of=`), block size in bytes (`bs=`), and block count (`count=`).
- **Rescue Value**: Carves MBR/GPT partition tables, backs up boot sectors, or wipes partitions directly.
- **Example**: `dd if=/dev/sda of=/mnt/mbr_backup.bin bs=512 count=1`

#### `fiemap <file>`
- **Description**: Physical LBA disk extent mapper via `FS_IOC_FIEMAP` ioctl.
- **Output**: Displays the physical block numbers, logical offsets, and extent lengths on the underlying physical storage drive.
- **Example**: `fiemap /boot/vmlinuz`

#### `losetup [-d dev] [dev] [file]`
- **Description**: Direct kernel loop device manager.
- **Mechanism**: Uses `LOOP_SET_FD` and `LOOP_CLR_FD` ioctls directly on `/dev/loop*` devices without requiring external `losetup` binary.
- **Example**: `losetup /dev/loop0 /mnt/disk.img` or `losetup -d /dev/loop0`

#### `pivot_root <new_root> <old_put>`
- **Description**: Direct system call wrapper around `pivot_root(new, old)`.
- **Rescue Value**: The core primitive required for initramfs PID 1 boot handoff to transition from the ramdisk into the real physical rootfs.

#### `swapon` / `swapoff <device|file>`
- **Description**: Direct kernel syscall wrappers for `swapon()` and `swapoff()`.
- **Rescue Value**: Activates emergency swap files created via `falloc` when physical RAM is exhausted.
- **Example**: `swapon /mnt/swapfile`

#### `dropcaches [1|2|3]`
- **Description**: Flushes Linux kernel page caches and memory slabs.
  - `1`: Flush pagecache.
  - `2`: Flush dentries and inodes.
  - `3`: Flush pagecache, dentries, and inodes.
- **Example**: `dropcaches 3`

#### `diskstat`
- **Description**: Parses `/proc/diskstats` to report total reads, writes, sectors transferred, and active I/O time per block device.
- **Example**: `diskstat`

#### `blkdiscard <device>`
- **Description**: Issues `BLKDISCARD` ioctl to immediately trim or securely discard physical SSD blocks or thin-provisioned SAN/VM disk images.
- **Example**: `blkdiscard /dev/sdb`

---

### 3.11 Network & Air-Gap Triage

Independent network discovery, packet capture, and interface configuration without external networking tools.

#### `tcpping <host> <port> [timeout_ms]`
- **Description**: Non-blocking TCP connect liveness tester.
- **Advantage**: Verifies remote port availability when ICMP ping is blocked by network firewalls.
- **Example**: `tcpping 192.168.1.1 443 1000`

#### `pcapdump <iface> <packet_count> [out.pcap]`
- **Description**: Zero-dependency raw packet sniffer using Linux `AF_PACKET` raw sockets (`SOCK_RAW`, `htons(ETH_P_ALL)`).
- **Features**: Generates fully compliant standard `.pcap` files readable by Wireshark and tcpdump.
- **Example**: `pcapdump eth0 50 /tmp/traffic.pcap`

#### `ipaddr [iface] [ip/mask]`
- **Description**: Direct network interface IP configurator via `ioctl(SIOCSIFADDR)` and `ioctl(SIOCSIFNETMASK)`.
- **Rescue Value**: Assigns static IP addresses to bring up network connectivity when `ip` or `ifconfig` are missing or corrupted.
- **Example**: `ipaddr eth0 192.168.1.50/24`

#### `dnsquery <hostname> [dns_server_ip]`
- **Description**: Crafts and sends raw UDP DNS queries directly to port 53 (defaults to `8.8.8.8`).
- **Advantage**: Bypasses corrupted or hijacked `/etc/resolv.conf` files to verify external name resolution.
- **Example**: `dnsquery example.com 1.1.1.1`

#### `sockhunt <port>`
- **Description**: Network port-to-process correlation engine.
- **Mechanism**: Parses `/proc/net/tcp` and `/proc/net/udp` for socket inodes, then scans all `/proc/*/fd/*` links to reveal the exact PID, process name, and executable path holding that port.
- **Example**: `sockhunt 8080`

#### `killbyport <port> [-sig]`
- **Description**: Discovers the process listening on the specified network port and terminates it.
- **Example**: `killbyport 3306 -9`

#### `netif`
- **Description**: Displays live network interface RX and TX byte/packet counters and drop rates parsed from `/proc/net/dev`.

#### `arppeek`
- **Description**: Displays the kernel ARP neighbor cache parsed from `/proc/net/arp` (IP, MAC address, interface, flags).

#### `routepeek`
- **Description**: Displays the active IPv4 kernel routing table parsed from `/proc/net/route` (Destination, Gateway, Mask, Flags, Interface).

#### `portscan <host> <start_port> <end_port>`
- **Description**: Rapid multi-port TCP connect scanner for local network or localhost port auditing.
- **Example**: `portscan 127.0.0.1 20 100`

---

### 3.12 Hardware, Firmware & Hypervisor Introspection

Direct hardware discovery without external packages (`dmidecode`, `lscpu`, `lspci`, `lsusb`).

#### `dmipeek` / `smbios`
- **Description**: Motherboard, BIOS, and hypervisor identification.
- **Mechanism**: Reads `/sys/class/dmi/id/*` (`bios_vendor`, `bios_version`, `product_name`, `sys_vendor`, `chassis_serial`).
- **Example**: `dmipeek`

#### `cpuid` / `cpuinfo`
- **Description**: CPU microarchitecture, cores, microcode version, and hardware vulnerability mitigations (Meltdown, Spectre, MDS).
- **Mechanism**: Reads `/proc/cpuinfo` and `/sys/devices/system/cpu/vulnerabilities/*`.

#### `pcipeek`
- **Description**: Audits PCI hardware bus controllers (storage RAID, network controllers, GPUs) by reading `/sys/bus/pci/devices/*/uevent`.
- **Example**: `pcipeek`

#### `usbpeek`
- **Description**: Scans `/sys/bus/usb/devices/*/` for plugged USB devices, vendor IDs, and product strings to detect rogue hardware.
- **Example**: `usbpeek`

---

### 3.13 Interactive Scripting, Cryptography & System Control

Administrative execution utilities and standalone cryptographic hash algorithms.

#### `read [-r] [VAR]`
- **Description**: Prompts for interactive terminal input and assigns the entered text to the specified shell variable.
- **Example**: `read -r CONFIRM`

#### `calc <n1> <op> <n2>`
- **Description**: 64-bit signed integer arithmetic calculator supporting `+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`.
- **Example**: `calc 1048576 * 64`

#### `clear`
- **Description**: Resets the terminal screen using standard ANSI terminal escape sequences (`\033[2J\033[H`).

#### `timestomp <file> <ref_file|epoch>`
- **Description**: Updates file nanosecond access and modification timestamps via `utimensat()`. Can synchronize timestamps to match another reference file.
- **Example**: `timestomp /var/log/audit.log /etc/hosts`

#### `uptime`
- **Description**: Displays system uptime and 1/5/15-minute load averages parsed from `/proc/uptime` and `/proc/loadavg`.

#### `symlink <target> <linkpath>`
- **Description**: Creates a symbolic link directly via the `symlink()` system call without `/bin/ln`.
- **Example**: `symlink /usr/bin/minish /bin/sh`

#### `readlink [-f] <linkpath>`
- **Description**: Resolves symbolic link targets via `readlink()` / `realpath()`.
- **Example**: `readlink -f /bin/sh`

#### `time <command...>`
- **Description**: Measures the execution duration of any command, reporting real elapsed wall-clock time, user CPU time, and system CPU time via `getrusage()`.
- **Example**: `time sha256 bigfile.iso`

#### `md5 <file|->`
- **Description**: Standalone RFC 1321 MD5 cryptographic hasher (zero external dependencies).
- **Example**: `md5 /etc/passwd`

#### `crc32 <file|->`
- **Description**: High-speed IEEE 802.3 32-bit checksum calculator.
- **Example**: `crc32 firmware.bin`

#### `xor <file|-> <key>`
- **Description**: In-memory byte-stream XOR encoder and decoder for simple stream obfuscation and data recovery.
- **Example**: `cat secret.dat | xor - "MyKey"`

---

### 3.14 In-Memory Defense Execution & Adversary Hunting Suite

Engineered specifically for environments under active adversary compromise where the host disk is full, read-only, or strictly monitored.

#### `deletedgrab <pid> <fd|exe> [mem_name|-]`
- **Description**: Universal volatile file and descriptor extractor. Recovers deleted files, configs, databases, crash dumps, and unlinked malware binaries directly from `/proc/<pid>/fd/<fd>` or `/proc/<pid>/exe`.
- **Destinations**:
  - `mem_name`: Saves directly into `memfile` in-memory RAM storage (zero disk writes).
  - `-`: Streams raw recovered bytes to stdout for piping over `nc` or `sha256`.
- **Examples**:
  ```bash
  # Recover deleted unlinked bash history from PID 4120 into RAM:
  deletedgrab 4120 3 recovered_history

  # Stream unlinked malware binary directly to remote forensic station:
  deletedgrab 3412 exe - | nc 192.168.1.50 9000
  ```

#### `sigshield [on|off|status]`
- **Description**: Anti-kill self-defense armor for the recovery shell.
- **Protection Vectors**:
  - Sets `SIG_IGN` for `SIGTERM`, `SIGHUP`, `SIGINT`, and `SIGQUIT`.
  - Sets `/proc/self/oom_score_adj` to `-1000` (immune to kernel OOM killer).
- **Tactical Value**: Prevents an adversary's automated watchdog scripts (`pkill -9`, `killall`, signal flooding) or dropped terminal connections from killing your recovery session.
- **Example**: `sigshield on`

#### `b64exec <proc_name> [args...]`
- **Description**: Air-gapped in-memory terminal loader. Reads a Base64-encoded binary from standard input, decodes it straight into an anonymous `memfd_create()` in RAM, write-seals it, disguises its process title to `proc_name`, and executes it via `fexecve()`.
- **Tactical Value**: Allows incident responders to paste static binaries directly into an air-gapped or serial console and execute them entirely in RAM without writing a single byte to disk or hitting `noexec` blocks.
- **Example**: `base64 tool | b64exec kworker/u:2 --scan`

#### `ramoverlay <dir> [size_MB]`
- **Description**: Copy-on-write RAM overlayfs generator. Mounts a volatile `overlayfs` using RAM (`tmpfs`) as the writable upper layer over an existing full or read-only directory (`dir`).
- **Tactical Value**: All existing files in the directory remain 100% visible, but all new writes, lockfiles, and logs are captured in volatile RAM. Allows defense tools and daemons to run unhindered on 100% full disks.
- **Example**: `ramoverlay /var 64`

#### `exehunt`
- **Description**: In-memory and disguised process auditor. Scans `/proc/[0-9]*/exe` across all running processes to identify adversarial persistence and stealth techniques:
  - **`[UNLINKED MALWARE]`**: Detects processes executing from deleted files (`unlink` evasion).
  - **`[VOLATILE RAM EXEC]`**: Detects processes running out of `/dev/shm`, `/tmp`, or anonymous `memfd:`.
  - **`[DISGUISED COMM]`**: Detects processes where `/proc/<pid>/comm` does not match the real binary executable.
- **Example**: `exehunt`

#### `memscript <interpreter> [args...]`
- **Description**: Direct in-memory script execution engine. Reads arbitrary scripts (Python, Bash, Perl, AWK) from standard input into an anonymous `memfd` in RAM and launches `<interpreter> /proc/self/fd/<fd> [args...]`.
- **Tactical Value**: Executes defense scripts entirely from RAM with zero disk writes, bypassing `noexec` mount restrictions on `/tmp`.
- **Example**: `cat audit.py | memscript python3 - --deep`

#### `memunshare [-m] [-p] [-n] <cmd...>`
- **Description**: Anti-detection stealth process isolator. Invokes Linux `unshare()` to execute defense tools inside private namespaces:
  - `-p`: Private PID namespace (hides the defense tool from the host's `/proc` and `ps`).
  - `-m`: Private mount namespace backed by a RAM tmpfs on `/tmp`.
  - `-n`: Private network namespace (disconnects tool from host network).
- **Example**: `memunshare -p -m topwriters 2`

#### `memgrep <pid> <string>`
- **Description**: Live process virtual memory sniffer. Parses `/proc/<pid>/maps` for readable memory regions (heap, stack, anon) and reads `/proc/<pid>/mem` to find matching ASCII strings.
- **Tactical Value**: Sniffs decrypted C2 URLs, passwords, encryption keys, and tokens directly from an attacker's running process memory with zero disk footprint.
- **Example**: `memgrep 3412 "http://"`

#### `ptracehunt`
- **Description**: Process injection and code-hooking detector. Audits `/proc/[0-9]*/status` across all running daemons for the `TracerPid:` field.
- **Tactical Value**: Any daemon with `TracerPid != 0` is being actively monitored, hooked, or injected with shellcode by another process. Pinpoints both the tracer (injection harness) and tracee (hijacked daemon).
- **Example**: `ptracehunt`

#### `promischunt`
- **Description**: Promiscuous interface and raw sniffer auditor.
  - Queries all network interfaces via `SIOCGIFFLAGS` ioctl for the `IFF_PROMISC` promiscuous mode flag.
  - Inspects `/proc/net/packet` and `/proc/net/raw` to identify processes holding raw packet sockets (`AF_PACKET`).
- **Tactical Value**: Exposes stealth packet sniffers and portless listeners (such as *BpfDoor*) that never open standard TCP/UDP listening ports.
- **Example**: `promischunt`

#### `persistpeek`
- **Description**: Fast non-standard persistence sweeper. Audits crontabs, systemd unit drop-ins, `/etc/profile.d/`, `/etc/rc.local`, and user shell profiles for suspicious commands referencing volatile paths (`/dev/shm`, `/tmp`), reverse shells, or remote downloaders (`curl | sh`).
- **Example**: `persistpeek`

---

## 4. Emergency Triage Runbooks

### Runbook A: The 100% Full Disk Outage (`ENOSPC`)

**Symptoms**: SSH login fails with `fatal: mm_receive_fd: no local file descriptors`; commands fail with `No space left on device`; services crash; editing files with `vi` or `sed` fails.

```bash
# 1. Start minish (zero disk I/O, works on 100% full disks)
./minish

# 2. Inspect storage block and inode capacity
minish$ df /

# 3. Locate large runaway log files or dumps (> 100 MB)
minish$ findlarge /var 100

# 4. Truncate runaway logs in-place (DO NOT use rm if the service is still running)
minish$ truncate /var/log/syslog 0
minish$ truncate /var/log/nginx/access.log 0

# 5. Verify reclaimed storage
minish$ df /

# 6. If external tools need temporary scratch space, mount a RAM tmpfs on /tmp
minish$ tmpfs /tmp 64
```

---

### Runbook B: The "Ghost File" Trap (Unlinked but Open Descriptors)

**Symptoms**: `df` shows 100% full, but `du` shows only 10 GB used on a 100 GB drive. The administrator deleted large log files using `rm`, but disk space was not freed.

```bash
# 1. Identify open deleted files held by active processes
minish$ ghostfind
# Output will display:
# PID  1248 (nginx          ) | FD 4    | Size: 45200.00 MB | /var/log/nginx/access.log

# 2. Immediately truncate the open descriptor and reclaim disk space
minish$ ghostfind -t

# 3. Verify disk blocks are returned to the kernel
minish$ df /
```

---

### Runbook C: Inode Exhaustion (`df -i 100%`)

**Symptoms**: `df -h` shows 50 GB of free disk space, but `touch test.txt` or creating a file fails with `No space left on device`.

```bash
# 1. Confirm inode table exhaustion
minish$ df /
# Inode Metadata will show: Total: 67108864 | Used: 67108864 (100%) | Free: 0

# 2. Locate directories containing millions of tiny session or spool files
minish$ cd /var/spool || cd /var/lib/php/sessions

# 3. Clean up stale sessions using native rm without triggering E2BIG
minish$ ls | cat > /tmp/file_list.txt 2>/dev/null || true
minish$ rm -rf /var/spool/clientmqueue/*

# 4. Confirm inode availability has been restored
minish$ df /
```

---

### Runbook D: Corrupted `/usr/bin` or Broken Dynamic Linker

**Symptoms**: Running any standard command returns `bash: /usr/bin/ls: No such file or directory` or `/lib64/ld-linux-x86-64.so.2: bad ELF interpreter`.

```bash
# 1. Execute static minish binary (requires zero external libraries or loaders)
/bin/minish

# 2. Inspect filesystem and hardware health
minish$ uname -a
minish$ dmesg | cat

# 3. Repair missing libraries or copy backups using native built-ins
minish$ cp /backup/lib64/libc.so.6 /lib64/libc.so.6
minish$ chmod 0755 /lib64/libc.so.6

# 4. Atomic file replacements
minish$ mv /backup/bin/ls /usr/bin/ls
minish$ chmod +x /usr/bin/ls

# 5. Flush page caches to disk
minish$ sync
```

---

### Runbook E: Read-Only Filesystem & Diskless Triage

**Symptoms**: Filesystem mounted read-only due to journal errors or storage network disconnect; `mkdir` or writing configs returns `Read-only file system`.

```bash
# 1. Attempt to unlock read-write mode directly via kernel mount
minish$ remount rw /

# 2. If storage remains read-only, utilize in-memory virtual storage
minish$ echo "nameserver 8.8.8.8" | memfile save resolv.conf
minish$ memfile list
minish$ memfile cat resolv.conf

# 3. Mount an emergency RAM scratchpad for downloads
minish$ tmpfs /tmp 128

# 4. Fetch emergency recovery script into RAM and execute
minish$ httpget http://192.168.1.50/repair.sh /tmp/repair.sh
minish$ chmod +x /tmp/repair.sh
minish$ /tmp/repair.sh

# 5. Flush all buffers prior to rebooting
minish$ sync
```

---

### Runbook F: Fork Bombs & Runaway Process Trees

**Symptoms**: System load spikes; system refuses to spawn new processes with `fork: retry: Resource temporarily unavailable`.

```bash
# 1. Rename your rescue shell so it is easily identifiable in ps/top
minish$ setproctitle RESCUE_SHELL_PID1

# 2. Inspect system load averages and process count
minish$ sysinfo

# 3. Identify the parent PID of the runaway process tree
minish$ procpeek <target_pid>

# 4. Recursively destroy the entire process tree from leaves to root
minish$ killtree <target_pid> -9

# 5. Verify system stabilizes
minish$ watch 1 sysinfo
```

---

### Runbook G: Running External Binaries on a Full or `noexec`-Hardened Host

**Symptoms**: The host disk is 100% full (`ENOSPC`), root is mounted read-only (`EROFS`), or `/tmp` is mounted with the `noexec` security flag. You need to execute an external vendor recovery binary (e.g. RAID manager, disk formatter, or diagnostic tool).

```bash
# Option 1: Stream the binary over the network directly into RAM and execute:
minish$ httpget http://192.168.1.100/raid_recover | memrun - --rebuild-array

# Option 2: Load binary into minish RAM storage, inspect, and execute:
minish$ httpget http://192.168.1.100/diag_tool | memfile save diag
minish$ memfile list
# Execute with arguments directly out of memory:
minish$ memrun diag --scan-all --fix

# Option 3: Clean up memory buffer when operation is complete:
minish$ memfile rm diag
```

---

### Runbook H: Live Threat Hunting, Memory Forensics & Off-Host Egress (RFC 3227)

**Scenario**: A compromised mission-critical server has active malware running in memory. The attacker has unlinked the malware binary from disk (`/proc/<pid>/exe (deleted)`), tampered with `/sbin/lsmod`, and placed backdoors in standard userland binaries. According to RFC 3227 (Order of Volatility), evidence must be gathered without modifying disk blocks or stomping on inode timestamps.

```bash
# 1. Camouflage the investigation process from attacker monitoring
minish$ setproctitle "[kworker/1:2-events]"

# 2. Inspect active network connections directly from kernel procfs
minish$ sockstat

# 3. Identify suspicious listening ports or outbound C2 beacons and find the PID
minish$ procpeek 1337

# 4. Sniff process environment variables (exposes stolen API keys, C2 tokens, or credentials)
minish$ envpeek 1337

# 5. Extract loaded kernel modules to detect hidden rootkits without /sbin/lsmod
minish$ modpeek

# 6. Stream live process virtual memory directly off-host to a forensic workstation via raw TCP
# (Leaves ZERO bytes of forensic evidence written to the target disk!)
minish$ memdump 1337 - | nc 10.0.0.50 9000

# 7. Compute cryptographic hash of memory dump for chain-of-custody verification
minish$ memdump 1337 - | sha256 -

# 8. Extract C2 domain strings and hardcoded IPs from suspicious memory segments
minish$ memdump 1337 /dev/shm/dump.raw
minish$ strings /dev/shm/dump.raw 8

# 9. Audit file modification timestamps on system configs to catch timestomping
minish$ finfo /etc/sudoers
minish$ finfo /etc/shadow

# 10. Sanitize temporary forensic artifacts from memory storage
minish$ wipe /dev/shm/dump.raw 3
```

---

### Runbook I: Emergency Initramfs & Bare-Metal Chroot Rescue

**Scenario**: A catastrophic kernel update or corrupted `/etc/fstab` left the system unbootable at an emergency initramfs shell. The root filesystem `/dev/sda2` is unmounted, dynamic libraries are inaccessible, and `/bin/mount` is non-functional.

```bash
# 1. Sniff partition table and filesystem superblocks
minish$ probeblk /dev/sda2

# 2. Reconstruct missing device nodes if devtmpfs is corrupted
minish$ mknod /dev/sda2 b 8 2
minish$ mknod /dev/null c 1 3
minish$ mknod /dev/zero c 1 5

# 3. Mount root filesystem directly using kernel system call
minish$ mkdir -p /mnt/sysroot
minish$ mount /dev/sda2 /mnt/sysroot

# 4. Mount pseudo-filesystems and bind /dev for full chroot operation
minish$ mount -t proc proc /mnt/sysroot/proc
minish$ mount -t sysfs sysfs /mnt/sysroot/sys
minish$ mount -o bind /dev /mnt/sysroot/dev

# 5. Fix broken /etc/fstab atomically in-place without sed or text editors
minish$ replace /mnt/sysroot/etc/fstab UUID=bad-id-1234 UUID=good-id-5678

# 6. Chroot into the restored system to rebuild initramfs or reconfigure grub
minish$ chroot /mnt/sysroot /bin/bash

# 7. Flush buffers and issue clean kernel reboot
minish$ sync
minish$ reboot
```

---

### Runbook J: Ransomware Incident Response & Immutable Directory Lockdown

**Scenario**: An attacker or rogue automated wiper/ransomware script has gained access and is beginning to traverse directory trees to encrypt or destroy web application data, databases, and configuration files.

```bash
# 1. Immediately place critical directories into immutable lockdown
# (Calls FS_IOC_SETFLAGS to set +i on all files, instantly halting write/truncate/delete attempts)
minish$ lockdown /var/www
minish$ lockdown /etc
minish$ lockdown /home

# 2. Inspect active processes and find high-CPU or high-I/O encryptors
minish$ ps
minish$ diskstat

# 3. Calculate Shannon entropy on suspicious new files
# (Entropy > 7.50 confirms encryption/ciphertext; standard plaintext is < 5.0)
minish$ entropy /var/www/index.html.enc

# 4. Pinpoint process memory and open handles of the encrypting process
minish$ procpeek 4821
minish$ fdpeek 4821

# 5. Terminate the entire malware process hierarchy from leaf to root
minish$ killtree 4821 -9

# 6. Verify filesystem integrity and flush caches
minish$ sync
```

---

### Runbook K: Network Blackout & Out-of-Band Raw Packet Capture

**Scenario**: A production server is compromised or disconnected. Host networking tools (`ip`, `ifconfig`, `tcpdump`, `curl`) are absent or deleted. You need to configure a static IP, verify gateway reachability, audit network traffic, and diagnose external connectivity over an emergency out-of-band serial console.

```bash
# 1. Audit active physical network interfaces and link counters
minish$ netif

# 2. Manually bring up network interface and configure static IP directly via ioctl
minish$ ipaddr eth0 192.168.1.150/24

# 3. Check kernel ARP table for gateway reachability
minish$ arppeek

# 4. Test TCP connection liveness to internal router (no ICMP required)
minish$ tcpping 192.168.1.1 80 1000

# 5. Query DNS directly over raw UDP to verify external DNS resolution without /etc/resolv.conf
minish$ dnsquery google.com 8.8.8.8

# 6. Sniff and capture 100 raw network packets into standard .pcap for forensic analysis
minish$ pcapdump eth0 100 /tmp/investigation.pcap

# 7. Identify which rogue process is listening on an unauthorized port and terminate it
minish$ sockhunt 4444
minish$ killbyport 4444 -9
```

---

### Runbook L: Uninterruptible Sleep (D-State) & Kernel Taint Diagnosis

**Scenario**: System load average spikes to 60.0+. Crucial services hang and refuse to respond to `kill -9`. The administrator needs to identify whether hardware controller failure, NFS timeout, or kernel deadlock is responsible.

```bash
# 1. Inspect kernel tainted status to check for unstable third-party drivers or hardware errors
minish$ taintpeek

# 2. Walk the process table and identify threads in uninterruptible sleep ('D' state)
minish$ ps
# Output identifies: PID 3104 | PPID 1 | State D | Comm backup_agent

# 3. Read the kernel wait-channel symbol to see what function the process is blocking on
minish$ wchanpeek 3104
# Output: nfs_wait_bit_uninterruptible

# 4. Extract the full kernel call stack trace to inspect the blocking subsystem
minish$ stackpeek 3104
# Displays kernel call trace:
# [<0>] io_schedule+0x16/0x40
# [<0>] nfs_wait_bit_uninterruptible+0x2a/0x50
# [<0>] nfs_block_bits+0x42/0x70

# 5. Audit disk I/O throughput to confirm if the underlying storage queue is frozen
minish$ diskstat

# 6. If storage is completely deadlocked, invoke emergency kernel sync and reboot
minish$ sysrq s
minish$ sysrq u
minish$ sysrq b
```

---

### Runbook M: Adversary Live Threat Hunting & Portless Backdoor Neutralization

**Scenario**: An advanced persistent threat (APT) has established residence on a compromised Linux server. The attacker is operating stealthily: running malware from deleted unlinked files, sniffing credentials via raw packet sockets without opening ports (e.g. BpfDoor), injecting code into system daemons via `ptrace`, and running watchdog scripts to kill any administrator or incident responder who connects.

```bash
# 1. Arm recovery shell with anti-kill armor
# (Masks SIGTERM/SIGHUP/SIGINT and sets OOM score to -1000 so attacker scripts cannot kill minish)
minish$ sigshield on

# 2. In-place camouflage: disguise recovery shell as a legitimate kernel thread
minish$ setproctitle [kworker/u:2]

# 3. Detect unlinked malware binaries, volatile RAM drops, and disguised process names
minish$ exehunt
# Output: [!] PID 3412 (kworker/0:1) -> /tmp/.miner (deleted) [UNLINKED MALWARE]

# 4. Check for code injection and active ptrace hooking across system daemons
minish$ ptracehunt
# Output: [!] INJECTION ALERT: PID 940 (sshd) is actively TRACED/INJECTED by PID 3412 (kworker/0:1)!

# 5. Detect stealth portless raw packet sniffers and promiscuous interfaces
minish$ promischunt
# Output: [!] RAW AF_PACKET SOCKET: Proto 0x0003 on Iface 2 (Socket Inode 48192)

# 6. Extract the deleted malware binary directly out of kernel memory for analysis (zero disk writes)
minish$ deletedgrab 3412 exe malware_sample
minish$ memfile list
# Output: RAM Files (1): malware_sample (45120 bytes)

# 7. Sniff C2 IP/domain or encryption keys directly from the live attacker process memory
minish$ memgrep 3412 "http://"
# Output: [0x00007ffdaf7c0968] ([heap]): http://198.51.100.24:8080/c2...

# 8. Check persistence vectors (crontabs, systemd drop-ins, shell profiles) for triggers
minish$ persistpeek

# 9. Neutralize the entire adversary process tree from leaf to root
minish$ killtree 3412 -9

# 10. Verify processes and sockets are clear
minish$ ps
minish$ sockstat
```

---

### Runbook N: Air-Gapped In-Memory Tool Injection & Writable RAM Overlays

**Scenario**: The target machine has reached 100% full disk (`ENOSPC`), root is mounted read-only (`EROFS`), `/tmp` has the hardened `noexec` mount flag, and external outbound network access is severed. You need to run proprietary forensic scripts, update configs, and execute external binaries without writing a single block to the physical storage device.

```bash
# 1. Activate an isolated in-memory RAM scratchpad
# (Sets up /dev/shm/.scratch, navigates into it, and sets TMPDIR with 0 disk allocation)
minish$ ramscratch 64

# 2. Mount a volatile copy-on-write RAM overlay over a full or read-only directory
# (Existing files remain visible; all new files, logs, and lockfiles are captured in RAM)
minish$ ramoverlay /var 64

# 3. Clone critical configuration into RAM before editing (cp fails with ENOSPC)
minish$ ramclone /etc/fstab fstab.bak

# 4. Inject and execute a static defense binary directly over serial terminal as Base64 text
# (Decodes into anonymous memfd in RAM, write-seals, disguises process name, and runs via fexecve)
minish$ b64exec triage_agent -v --deep-scan < triage_agent.b64

# 5. Execute an interpreted Python or Bash triage script directly out of RAM (zero disk writes)
minish$ cat forensic_scan.py | memscript python3 - --report-json /dev/shm/.scratch/report.json

# 6. Run sensitive investigative commands in a hidden, isolated PID and mount namespace
# (Prevents on-host attacker processes from seeing your tool running in /proc or ps)
minish$ memunshare -p -m topwriters 2

# 7. Inspect in-memory files and stream evidence off-host via micro-netcat
minish$ memfile list
minish$ memfile cat malware_sample | nc 192.168.1.50 9000
```

---

## 5. Packaging, UsrMerge & System Deployment

`minish` is distributed as native standalone packages for major enterprise Linux distributions, strictly conforming to modern filesystem hierarchy standards.

### Debian & Ubuntu (`.deb`) Package
- **Packaging Standard**: Fully compliant with **DEP17 UsrMerge** specifications.
- **Binary Placement**: Installs the static binary exclusively to `/usr/bin/minish`. `/bin/minish` is provided automatically via the canonical distribution symlink (`/bin -> /usr/bin`), preventing packaging conflicts.
- **Shell Registration**:
  - `postinst`: Validates and registers `/bin/minish` and `/usr/bin/minish` in `/etc/shells`.
  - `postrm`: Deregisters `minish` from `/etc/shells` upon package removal.
- **Build & Install**:
  ```bash
  make deb
  sudo dpkg -i minish_1.0.0_amd64.deb
  ```

### RHEL, Rocky, AlmaLinux, CentOS (`.rpm`) Package
- **Packaging Standard**: Conforms to Red Hat RPM packaging guidelines.
- **Binary Placement**: Installs binary to `/usr/bin/minish`, automatically satisfying `/bin/minish` via system symlinks without directory ownership collisions.
- **Build & Install**:
  ```bash
  make rpm
  sudo rpm -ivh minish-1.0.0-1.x86_64.rpm
  ```
