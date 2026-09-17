# Contributing to `minish`

Thank you for your interest in contributing to `minish`! `minish` is a high-reliability, zero-dependency emergency rescue micro-shell designed for disaster recovery, 100% full-disk (`ENOSPC`) outages, air-gapped environments, and container PID 1 resilience.

To ensure `minish` remains rock-solid in mission-critical recovery scenarios, all contributions must adhere to the core architectural principles below.

---

## Core Architectural Invariants

1. **The One-File Rule (`shell.c`)**:
   - The entire C implementation resides strictly within a single source file: `shell.c`.
   - Do **not** create separate `.c` or `.h` header files or helper libraries.
   - All engines, parsers, and built-ins must be self-contained within `shell.c`.

2. **Zero Compiler Warnings Policy**:
   - The codebase must compile with **zero warnings** under strict flags:
     ```bash
     gcc -Wall -Wextra -std=c99 -pedantic -Os -static shell.c -o minish
     ```
   - No unused variables, unhandled return values, format truncation warnings, or signed/unsigned comparison mismatches.

3. **Zero Disk Footprint Policy**:
   - `minish` must **never** write command history (`.bash_history`), temporary dotfiles, or scratch buffers to physical disk.
   - Any temporary buffers, staging storage, or script injection must operate entirely in volatile memory (`memfile`, `memfd_create()`, or user-specified `/dev/shm`).
   - Binaries and tools must function even if the root filesystem is 100% full (`ENOSPC`) or mounted read-only (`EROFS`).

4. **POSIX 2008 & Direct Linux Syscalls**:
   - Avoid glibc-specific non-portable extensions where direct Linux system calls (`statvfs`, `memfd_create`, `klogctl`, `prctl`, `fexecve`, `mount`, `umount2`) provide cleaner zero-dependency recovery capabilities.

5. **Subreaper & Container Cleanliness**:
   - Asynchronous `SIGCHLD` reaping (`SA_RESTART | SA_NOCLDSTOP`) and child subreaper adoption (`PR_SET_CHILD_SUBREAPER`) must never be broken.

---

## Development Workflow

1. **Prerequisites**:
   - GCC (`gcc`)
   - Standard C99 library (`glibc` or `musl`)
   - `make`

2. **Building Locally**:
   ```bash
   # Build optimized dynamic binary:
   make

   # Build completely self-contained static binary:
   make static
   ```

3. **Running the Verification Suite**:
   All 49 automated verification suites must pass before submitting a pull request:
   ```bash
   make test
   # or:
   ./minish test_suite.sh
   ```

4. **Adding New Built-ins**:
   - If a new built-in mutates shell parent state (e.g. changes directory, environment, signal masks, or in-memory tables), mark it with `is_stateful = 1` in `builtins[]`.
   - Add automated test assertions to `test_suite.sh`.
   - Document the command in both `README.md` and `MANUAL.md`.
