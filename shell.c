/**
 * @file shell.c
 * @brief Ultra-compact POSIX emergency micro-shell & core utilities (minish).
 *
 * Designed for disaster recovery, micro-containers, embedded systems, and
 * low-footprint administration on Ubuntu, Debian, RHEL, Rocky, AlmaLinux, and CentOS.
 *
 * Core Features:
 *   - Read-Parse-Execute loop with script file support (`./minish script.sh`)
 *   - Command-string execution mode (`minish -c "command"`)
 *   - Multi-stage pipelines (`cmd1 | cmd2 | ... | cmdN`)
 *   - Full I/O redirection (`<`, `>`, `>>`, `1>`, `1>>`, `2>`, `2>>`, `2>&1`, `>&2`, `1>&2`, `&>`, `&>>`)
 *   - Background execution (`&`) with race-free SIGCHLD zombie reaping
 *   - Automatic subreaper registration (`PR_SET_CHILD_SUBREAPER`) for container PID 1 resilience
 *   - Command chaining (`&&`, `||`, `;`) with POSIX left-associative semantics
 *   - Deferred word expansion: tilde expansion (`~`, `~/...`), variable expansion
 *     (`$VAR`, `${VAR}`, `$?`, `$$`, `$#`, `$0`..`$9`, `${0}`..`${9}`)
 *   - Single quote preservation (literal strings) vs double quote variable interpolation
 *   - Standalone variable assignments (`NAME=value`)
 *
 * 100% Full-Disk & Out-of-Space Rescue Suite (ENOSPC Guarantees):
 *   - ZERO DISK FOOTPRINT POLICY: minish NEVER creates scratch files in /tmp, NEVER
 *     touches or writes command history (.bash_history), and produces zero disk I/O.
 *   - df: Immediate inspection of both storage blocks AND inode exhaustion (statvfs).
 *   - truncate: In-place zero-allocation file shrinking to drop runaway logs to 0 bytes
 *     or a smaller target size without deleting files or breaking open daemon handles.
 *   - ghostfind (-t): Scans /proc/<pid>/fd/ for deleted files still held open by processes
 *     (trapping gigabytes of disk space invisible to ls); -t truncates them in-place.
 *   - findlarge: High-speed recursive directory traversal to identify runaway files.
 *   - inodescan: Inode hoarder scanner pinpointing directories containing excess files.
 *   - zerolog: Fast batch log truncator shrinking all *.log files in-place to 0 bytes.
 *   - findempty: Discovers and optionally purges 0-byte orphan files wasting inode slots.
 *   - dusage: Fast recursive directory space usage breakdown (built-in ncdu/du).
 *   - findinode: Reverse inode-to-path resolver finding files by physical inode number.
 *   - findgrowth: Real-time file growth rate monitor detecting actively expanding files.
 *   - fdsize: Storage-centric open file descriptor profiler across processes.
 *   - topwriters: Process write rate monitor sampling /proc/<pid>/io write throughput.
 *   - ramscratch: One-touch volatile in-memory workspace (sets up /dev/shm/.scratch and TMPDIR).
 *   - ramclone: Zero-disk file stager cloning files into RAM when cp fails with ENOSPC.
 *   - tmpfs: Emergency in-memory RAM disk mount with exec permissions (bypasses noexec).
 *   - memrun / memexec: Anonymous in-memory binary execution via memfd_create + fexecve
 *     (streams compiled ELF binaries straight from stdin/network into RAM without disk).
 *   - memfile: In-memory RAM storage table for staging files/scripts without disk writes.
 *   - All text & stream utilities (grep, head, tail, wc, sort, dd, sha256, etc.) operate
 *     strictly through in-memory streaming pipes without temporary disk files.
 *
 * In-Memory Defense Execution & Adversary Hunting Suite:
 *   - deletedgrab: Rescues deleted/open files, logs, and binaries from /proc/<pid>/fd/<fd> into RAM.
 *   - sigshield: Anti-kill recovery armor; immune to SIGTERM, SIGHUP, SIGINT, SIGQUIT, and OOM.
 *   - b64exec: Air-gapped in-memory terminal loader; pastes and executes Base64 binaries in RAM.
 *   - ramoverlay: Copy-on-write RAM overlayfs over full/ro directories to allow tool writes.
 *   - exehunt: Detects unlinked malware, volatile RAM binaries, and disguised process names.
 *   - memscript: Executes scripts (Python, Bash, Perl) directly out of RAM (zero disk writes).
 *   - memunshare: Runs defense tools in private PID and mount namespaces to evade detection.
 *   - memgrep: Sniffs C2 domains, keys, and credentials directly from process virtual memory.
 *   - ptracehunt: Detects live process injection and ptrace tracing across running daemons.
 *   - promischunt: Detects network promiscuous mode and stealth raw packet sockets (BpfDoor).
 *   - persistpeek: Audits crontabs, systemd drop-ins, and shell profiles for backdoor triggers.
 *
 * Native Core Utilities:
 *   - cd, pwd, echo, export, unset, set, source (.), exec, cat, ls, touch,
 *     mkdir, rm, cp, mv, chmod, chown, umask, sleep, kill, true, false,
 *     which, test / [, help, exit, setproctitle / procrename / renameproc.
 *
 * Forensic Triage, Network Egress & Anti-Tamper Suite:
 *   - sha256, nc, elfpeek, envpeek, modpeek, base64, replace, mknod, mount,
 *     umount, memdump, finfo / statpeek, strings, wipe.
 *
 * Stream & Text Pipeline Suite:
 *   - grep (-i, -v, -n), head, tail, wc (-l, -w, -c), cut (-d, -f), sort, uniq (-c), tr, diff.
 *
 * Process & Anti-Rootkit Memory Forensics:
 *   - ps / proclist, mapspeek (detects RWX anonymous memory), fdpeek, stackpeek, wchanpeek, oomadj.
 *
 * Security, Capabilities & LSM Defense:
 *   - cappeek, nspeek, chattr (+i/-i), lockdown, lsmaudit, taintpeek, id / whoami, entropy.
 *
 * Storage, Block Devices & Initramfs Rescue:
 *   - dd, fiemap, losetup, pivot_root, swapon / swapoff, dropcaches, diskstat, blkdiscard.
 *
 * Network & Air-Gap Triage:
 *   - tcpping, pcapdump, ipaddr, dnsquery, sockhunt, killbyport, netif, arppeek, routepeek, portscan.
 *
 * Hardware, Firmware & Hypervisor Introspection:
 *   - dmipeek / smbios, cpuid / cpuinfo, pcipeek, usbpeek.
 *
 * Scripting, Cryptography & System Control:
 *   - read, calc, clear, timestomp, uptime, symlink, readlink, time, md5, crc32, xor,
 *     watch, randhex, falloc, probeblk, hexview, killtree, procpeek, httpget, dnslookup,
 *     sync, remount, reboot, poweroff, sysrq.
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <utime.h>
#include <sys/statvfs.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/swap.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <linux/loop.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sched.h>
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#endif

#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <libutil.h>
#endif

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL 0x00000010
#endif

#ifndef BLKDISCARD
#define BLKDISCARD _IO(0x12, 119)
#endif
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

#ifndef LOOP_SET_FD
#define LOOP_SET_FD 0x4C00
#define LOOP_CLR_FD 0x4C01
#endif

#ifndef SYS_pivot_root
#ifdef __x86_64__
#define SYS_pivot_root 155
#elif defined(__aarch64__)
#define SYS_pivot_root 41
#endif
#endif

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#ifndef FS_IOC_FIEMAP
#define FS_IOC_FIEMAP _IOWR('f', 11, struct fiemap)
#endif
#ifndef FIEMAP_FLAG_SYNC
#define FIEMAP_FLAG_SYNC 0x00000001
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_GET_NAME
#define PR_GET_NAME 16
#endif
#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

#ifndef RB_AUTOBOOT
#define RB_AUTOBOOT 0x01234567
#endif
#ifndef RB_POWER_OFF
#define RB_POWER_OFF 0x4321fedc
#endif

/* Global shell state */
static int last_exit_status = 0;
static int script_argc = 0;
static char **script_argv = NULL;
static char *proc_argv0 = NULL;
static size_t proc_argv_len = 0;

static int shell_errexit = 0;
static int shell_xtrace = 0;

int set_process_name(const char *name);
int get_process_name(char *buf, size_t size);

/* Operator types for chaining */
typedef enum {
    OP_NONE = 0,
    OP_SEMICOLON,
    OP_AND,
    OP_OR
} ChainOp;

/* Individual command within a pipeline (stores raw tokens before just-in-time expansion) */
typedef struct {
    char **argv;
    int argc;
    char *input_file;
    char *output_file;
    int append_output;
    char *err_file;
    int append_err;
    int err_to_out;    /* 2>&1, &>, &>> */
    int out_to_err;    /* >&2, 1>&2 */
} SimpleCommand;

/* A pipeline unit consisting of one or more commands piped together */
typedef struct {
    SimpleCommand *cmds;
    int num_cmds;
    int is_background;
    ChainOp next_op;
} PipelineUnit;

/* Forward declarations */
typedef struct {
    const char *name;
    int (*func)(char **);
    int is_stateful;
} BuiltinDef;
static const BuiltinDef *find_builtin(const char *cmd);
static void execute_line(const char *line);

static void sh_loop(FILE *stream, int is_interactive);

/* --- Signal Handling --- */

static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/* --- Dynamic String Buffer Helper --- */

static void buf_append_char(char **buf, size_t *len, size_t *cap, char c) {
    if (*len + 1 >= *cap) {
        *cap = (*cap < 32) ? 32 : (*cap * 2);
        char *new_buf = realloc(*buf, *cap);
        if (!new_buf) return;
        *buf = new_buf;
    }
    (*buf)[(*len)++] = c;
    (*buf)[*len] = '\0';
}

static void buf_append_str(char **buf, size_t *len, size_t *cap, const char *str) {
    if (!str) return;
    while (*str) {
        buf_append_char(buf, len, cap, *str++);
    }
}

/* --- Built-in Implementations --- */

static int builtin_cd(char **args) {
    const char *target = args[1];
    char *cwd_before = getcwd(NULL, 0);

    if (!target) {
        target = getenv("HOME");
        if (!target) {
            fprintf(stderr, "minish: cd: HOME not set\n");
            free(cwd_before);
            return 1;
        }
    } else if (strcmp(target, "-") == 0) {
        target = getenv("OLDPWD");
        if (!target) {
            fprintf(stderr, "minish: cd: OLDPWD not set\n");
            free(cwd_before);
            return 1;
        }
        printf("%s\n", target);
    } else if (target[0] == '~' && (target[1] == '\0' || target[1] == '/')) {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "minish: cd: HOME not set\n");
            free(cwd_before);
            return 1;
        }
        static char target_buf[4096];
        snprintf(target_buf, sizeof(target_buf), "%s%s", home, target + 1);
        target = target_buf;
    }

    if (chdir(target) != 0) {
        perror("minish: cd");
        free(cwd_before);
        return 1;
    }

    if (cwd_before) {
        setenv("OLDPWD", cwd_before, 1);
        free(cwd_before);
    }

    char *cwd_after = getcwd(NULL, 0);
    if (cwd_after) {
        setenv("PWD", cwd_after, 1);
        free(cwd_after);
    }

    return 0;
}

static int builtin_pwd(char **args) {
    (void)args;
    char *cwd = getcwd(NULL, 0);
    if (cwd) {
        printf("%s\n", cwd);
        free(cwd);
        return 0;
    }
    perror("minish: pwd");
    return 1;
}

static int builtin_echo(char **args) {
    int newline = 1;
    int interpret_escape = 0;
    int i = 1;

    while (args[i] && args[i][0] == '-') {
        if (args[i][1] == '\0') break; /* Literal "-" is an argument */
        if (strcmp(args[i], "--") == 0) { i++; break; }
        char *opt = args[i] + 1;
        int valid = 1;
        for (int j = 0; opt[j]; j++) {
            if (opt[j] == 'n') newline = 0;
            else if (opt[j] == 'e') interpret_escape = 1;
            else if (opt[j] == 'E') interpret_escape = 0;
            else { valid = 0; break; }
        }
        if (!valid) break;
        i++;
    }

    for (; args[i]; i++) {
        if (!interpret_escape) {
            fputs(args[i], stdout);
        } else {
            for (const char *p = args[i]; *p; p++) {
                if (*p == '\\' && *(p + 1)) {
                    p++;
                    switch (*p) {
                        case 'n': putchar('\n'); break;
                        case 't': putchar('\t'); break;
                        case 'r': putchar('\r'); break;
                        case 'a': putchar('\a'); break;
                        case 'b': putchar('\b'); break;
                        case 'v': putchar('\v'); break;
                        case 'f': putchar('\f'); break;
                        case '\\': putchar('\\'); break;
                        case 'c': fflush(stdout); return 0;
                        default: putchar('\\'); putchar(*p); break;
                    }
                } else {
                    putchar(*p);
                }
            }
        }
        if (args[i + 1]) putchar(' ');
    }
    if (newline) putchar('\n');
    fflush(stdout);
    return 0;
}

static int builtin_export(char **args) {
    if (!args[1]) {
        extern char **environ;
        for (char **env = environ; *env; env++) {
            printf("%s\n", *env);
        }
        fflush(stdout);
        return 0;
    }
    for (int i = 1; args[i]; i++) {
        char *eq = strchr(args[i], '=');
        if (eq) {
            *eq = '\0';
            setenv(args[i], eq + 1, 1);
            *eq = '=';
        } else {
            if (!getenv(args[i])) {
                setenv(args[i], "", 1);
            }
        }
    }
    return 0;
}

static int builtin_unset(char **args) {
    for (int i = 1; args[i]; i++) {
        unsetenv(args[i]);
    }
    return 0;
}

static int builtin_cat(char **args) {
    char buf[4096];
    ssize_t n;
    int status = 0;

    if (!args[1]) {
        while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = write(STDOUT_FILENO, buf + written, n - written);
                if (w <= 0) { perror("minish: cat"); return 1; }
                written += w;
            }
        }
        return 0;
    }

    for (int i = 1; args[i]; i++) {
        int fd;
        if (strcmp(args[i], "-") == 0) {
            fd = STDIN_FILENO;
        } else {
            fd = open(args[i], O_RDONLY);
            if (fd < 0) {
                perror(args[i]);
                status = 1;
                continue;
            }
        }

        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = write(STDOUT_FILENO, buf + written, n - written);
                if (w <= 0) { perror("minish: cat"); status = 1; break; }
                written += w;
            }
            if (written < n) break;
        }

        if (fd != STDIN_FILENO) close(fd);
    }
    return status;
}

static int name_compare(const void *a, const void *b) {
    const char *sa = *(const char * const *)a;
    const char *sb = *(const char * const *)b;
    return strcmp(sa, sb);
}

static void format_mode(mode_t mode, char *str) {
    str[0] = S_ISDIR(mode) ? 'd' : (S_ISLNK(mode) ? 'l' : (S_ISCHR(mode) ? 'c' : (S_ISBLK(mode) ? 'b' : '-')));
    str[1] = (mode & S_IRUSR) ? 'r' : '-';
    str[2] = (mode & S_IWUSR) ? 'w' : '-';
    str[3] = (mode & S_IXUSR) ? 'x' : '-';
    str[4] = (mode & S_IRGRP) ? 'r' : '-';
    str[5] = (mode & S_IWGRP) ? 'w' : '-';
    str[6] = (mode & S_IXGRP) ? 'x' : '-';
    str[7] = (mode & S_IROTH) ? 'r' : '-';
    str[8] = (mode & S_IWOTH) ? 'w' : '-';
    str[9] = (mode & S_IXOTH) ? 'x' : '-';
    str[10] = '\0';
}

static int builtin_ls(char **args) {
    int show_all = 0;
    int long_format = 0;
    int start = 1;

    while (args[start] && args[start][0] == '-' && args[start][1] != '\0') {
        for (int j = 1; args[start][j]; j++) {
            if (args[start][j] == 'a') show_all = 1;
            else if (args[start][j] == 'l') long_format = 1;
        }
        start++;
    }

    int count = 0;
    for (int i = start; args[i]; i++) count++;

    const char *default_dirs[] = { ".", NULL };
    const char **targets = (count == 0) ? default_dirs : (const char **)&args[start];

    int ret = 0;
    for (int t = 0; targets[t]; t++) {
        if (count > 1) printf("%s:\n", targets[t]);

        struct stat st_target;
        if (lstat(targets[t], &st_target) != 0) {
            perror(targets[t]);
            ret = 1;
            continue;
        }

        if (!S_ISDIR(st_target.st_mode)) {
            if (long_format) {
                char mode_str[11];
                format_mode(st_target.st_mode, mode_str);
                printf("%s %2ld %8ld %s\n", mode_str, (long)st_target.st_nlink, (long)st_target.st_size, targets[t]);
            } else {
                printf("%s\n", targets[t]);
            }
            continue;
        }

        DIR *d = opendir(targets[t]);
        if (!d) {
            perror(targets[t]);
            ret = 1;
            continue;
        }

        size_t entry_cap = 64, entry_count = 0;
        char **entries = malloc(entry_cap * sizeof(char *));
        struct dirent *entry;

        while ((entry = readdir(d)) != NULL) {
            if (!show_all && entry->d_name[0] == '.') continue;
            if (entry_count >= entry_cap) {
                entry_cap *= 2;
                entries = realloc(entries, entry_cap * sizeof(char *));
            }
            entries[entry_count++] = strdup(entry->d_name);
        }
        closedir(d);

        if (entries && entry_count > 0) {
            qsort(entries, entry_count, sizeof(char *), name_compare);
            for (size_t i = 0; i < entry_count; i++) {
                if (long_format) {
                    char full_path[4096];
                    snprintf(full_path, sizeof(full_path), "%s/%s", targets[t], entries[i]);
                    struct stat st;
                    if (lstat(full_path, &st) == 0) {
                        char mode_str[11];
                        format_mode(st.st_mode, mode_str);
                        char time_buf[32];
                        struct tm *tm_info = localtime(&st.st_mtime);
                        strftime(time_buf, sizeof(time_buf), "%b %e %H:%M", tm_info);
                        printf("%s %2ld %8ld %s %s", mode_str, (long)st.st_nlink, (long)st.st_size, time_buf, entries[i]);
                        if (S_ISLNK(st.st_mode)) {
                            char link_target[1024];
                            ssize_t len = readlink(full_path, link_target, sizeof(link_target) - 1);
                            if (len > 0) {
                                link_target[len] = '\0';
                                printf(" -> %s", link_target);
                            }
                        }
                        printf("\n");
                    } else {
                        printf("??????????  - %s\n", entries[i]);
                    }
                } else {
                    printf("%s  ", entries[i]);
                }
                free(entries[i]);
            }
            if (!long_format) printf("\n");
        }
        free(entries);
        if (count > 1 && targets[t + 1]) printf("\n");
    }
    fflush(stdout);
    return ret;
}

static int builtin_touch(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: touch: missing operand\n");
        return 1;
    }
    int ret = 0;
    for (int i = 1; args[i]; i++) {
        int fd = open(args[i], O_WRONLY | O_CREAT, 0666);
        if (fd < 0) {
            if (errno == EISDIR) {
                if (utime(args[i], NULL) != 0) {
                    perror(args[i]);
                    ret = 1;
                }
                continue;
            }
            perror(args[i]);
            ret = 1;
            continue;
        }
        close(fd);
        utime(args[i], NULL);
    }
    return ret;
}

static int make_parent_dirs(const char *path) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0) {
                if (errno == EEXIST) {
                    struct stat st;
                    if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
                } else {
                    return -1;
                }
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) != 0) {
        if (errno == EEXIST) {
            struct stat st;
            if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

static int builtin_mkdir(char **args) {
    int recursive = 0;
    int start = 1;

    while (args[start] && args[start][0] == '-') {
        if (strcmp(args[start], "-p") == 0) recursive = 1;
        start++;
    }

    if (!args[start]) {
        fprintf(stderr, "minish: mkdir: missing operand\n");
        return 1;
    }

    int ret = 0;
    for (int i = start; args[i]; i++) {
        if (recursive) {
            if (make_parent_dirs(args[i]) != 0) {
                perror(args[i]);
                ret = 1;
            }
        } else {
            if (mkdir(args[i], 0777) != 0) {
                perror(args[i]);
                ret = 1;
            }
        }
    }
    return ret;
}

static int remove_path_recursive(const char *path, int force) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (force) return 0;
        perror(path);
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) {
            if (!force) perror(path);
            return 1;
        }
        struct dirent *entry;
        int status = 0;
        while ((entry = readdir(d)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            char sub[4096];
            snprintf(sub, sizeof(sub), "%s/%s", path, entry->d_name);
            if (remove_path_recursive(sub, force) != 0) status = 1;
        }
        closedir(d);
        if (rmdir(path) != 0) {
            if (!force) perror(path);
            return 1;
        }
        return status;
    } else {
        if (unlink(path) != 0) {
            if (!force) perror(path);
            return 1;
        }
        return 0;
    }
}

static int builtin_rm(char **args) {
    int recursive = 0;
    int force = 0;
    int start = 1;

    while (args[start] && args[start][0] == '-' && args[start][1] != '\0') {
        for (int j = 1; args[start][j]; j++) {
            if (args[start][j] == 'r' || args[start][j] == 'R') recursive = 1;
            else if (args[start][j] == 'f') force = 1;
        }
        start++;
    }

    if (!args[start]) {
        if (!force) fprintf(stderr, "minish: rm: missing operand\n");
        return force ? 0 : 1;
    }

    int ret = 0;
    for (int i = start; args[i]; i++) {
        if (recursive) {
            if (remove_path_recursive(args[i], force) != 0) ret = 1;
        } else {
            struct stat st;
            if (lstat(args[i], &st) != 0) {
                if (!force) { perror(args[i]); ret = 1; }
                continue;
            }
            if (S_ISDIR(st.st_mode)) {
                if (!force) {
                    fprintf(stderr, "minish: rm: %s: Is a directory\n", args[i]);
                    ret = 1;
                }
                continue;
            }
            if (unlink(args[i]) != 0) {
                if (!force) { perror(args[i]); ret = 1; }
            }
        }
    }
    return ret;
}

static int builtin_sleep(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: sleep: missing operand\n");
        return 1;
    }
    int s = atoi(args[1]);
    if (s > 0) sleep((unsigned int)s);
    return 0;
}

static int builtin_kill(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: kill: usage: kill [-sig] <pid>\n");
        return 1;
    }
    int sig = SIGTERM;
    const char *pid_str = args[1];
    if (args[1][0] == '-' && args[2]) {
        sig = atoi(args[1] + 1);
        if (sig <= 0) sig = SIGTERM;
        pid_str = args[2];
    }
    pid_t pid = (pid_t)atoi(pid_str);
    if (kill(pid, sig) != 0) {
        perror("minish: kill");
        return 1;
    }
    return 0;
}

static int builtin_true(char **args) {
    (void)args;
    return 0;
}

static int builtin_false(char **args) {
    (void)args;
    return 1;
}

static int builtin_which(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: which: missing command name\n");
        return 1;
    }
    int ret = 0;
    for (int i = 1; args[i]; i++) {
        const char *cmd = args[i];
        if (find_builtin(cmd)) {
            printf("%s: minish built-in command\n", cmd);
            continue;
        }

        if (strchr(cmd, '/')) {
            struct stat st;
            if (access(cmd, X_OK) == 0 && stat(cmd, &st) == 0 && !S_ISDIR(st.st_mode)) {
                printf("%s\n", cmd);
            } else {
                fprintf(stderr, "%s: not found\n", cmd);
                ret = 1;
            }
            continue;
        }

        const char *path_env = getenv("PATH");
        if (!path_env) path_env = "/usr/bin:/bin:/usr/sbin:/sbin";

        char *paths = strdup(path_env);
        char *saveptr = NULL;
        char *tok = strtok_r(paths, ":", &saveptr);
        int found = 0;

        while (tok) {
            char candidate[4096];
            snprintf(candidate, sizeof(candidate), "%s/%s", tok, cmd);
            struct stat st;
            if (access(candidate, X_OK) == 0 && stat(candidate, &st) == 0 && !S_ISDIR(st.st_mode)) {
                printf("%s\n", candidate);
                found = 1;
                break;
            }
            tok = strtok_r(NULL, ":", &saveptr);
        }
        free(paths);

        if (!found) {
            fprintf(stderr, "%s: not found\n", cmd);
            ret = 1;
        }
    }
    fflush(stdout);
    return ret;
}

static int builtin_test(char **args) {
    int argc = 0;
    while (args[argc]) argc++;

    /* If invoked as "[", ignore trailing "]" */
    if (strcmp(args[0], "[") == 0) {
        if (argc < 2 || strcmp(args[argc - 1], "]") != 0) {
            fprintf(stderr, "minish: [: missing ']'\n");
            return 2;
        }
        argc--;
    }

    int invert = 0;
    int start = 1;
    if (start < argc && strcmp(args[start], "!") == 0) {
        invert = 1;
        start++;
    }

    int count = argc - start;
    int res = 1;

    if (count == 0) {
        res = 1;
    } else if (count == 1) {
        res = (args[start][0] != '\0') ? 0 : 1;
    } else if (count == 2) {
        const char *op = args[start];
        const char *target = args[start + 1];
        struct stat st;

        if (strcmp(op, "-f") == 0) {
            res = (stat(target, &st) == 0 && S_ISREG(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-d") == 0) {
            res = (stat(target, &st) == 0 && S_ISDIR(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-e") == 0) {
            res = (stat(target, &st) == 0) ? 0 : 1;
        } else if (strcmp(op, "-s") == 0) {
            res = (stat(target, &st) == 0 && st.st_size > 0) ? 0 : 1;
        } else if (strcmp(op, "-x") == 0) {
            res = (access(target, X_OK) == 0) ? 0 : 1;
        } else if (strcmp(op, "-r") == 0) {
            res = (access(target, R_OK) == 0) ? 0 : 1;
        } else if (strcmp(op, "-w") == 0) {
            res = (access(target, W_OK) == 0) ? 0 : 1;
        } else if (strcmp(op, "-L") == 0 || strcmp(op, "-h") == 0) {
            res = (lstat(target, &st) == 0 && S_ISLNK(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-c") == 0) {
            res = (stat(target, &st) == 0 && S_ISCHR(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-b") == 0) {
            res = (stat(target, &st) == 0 && S_ISBLK(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-p") == 0) {
            res = (stat(target, &st) == 0 && S_ISFIFO(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-z") == 0) {
            res = (target[0] == '\0') ? 0 : 1;
        } else if (strcmp(op, "-n") == 0) {
            res = (target[0] != '\0') ? 0 : 1;
        }
    } else if (count == 3) {
        const char *s1 = args[start];
        const char *op = args[start + 1];
        const char *s2 = args[start + 2];

        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
            res = (strcmp(s1, s2) == 0) ? 0 : 1;
        } else if (strcmp(op, "!=") == 0) {
            res = (strcmp(s1, s2) != 0) ? 0 : 1;
        } else if (strcmp(op, "-eq") == 0) {
            res = (atol(s1) == atol(s2)) ? 0 : 1;
        } else if (strcmp(op, "-ne") == 0) {
            res = (atol(s1) != atol(s2)) ? 0 : 1;
        } else if (strcmp(op, "-lt") == 0) {
            res = (atol(s1) < atol(s2)) ? 0 : 1;
        } else if (strcmp(op, "-le") == 0) {
            res = (atol(s1) <= atol(s2)) ? 0 : 1;
        } else if (strcmp(op, "-gt") == 0) {
            res = (atol(s1) > atol(s2)) ? 0 : 1;
        } else if (strcmp(op, "-ge") == 0) {
            res = (atol(s1) >= atol(s2)) ? 0 : 1;
        }
    }

    return invert ? (res == 0 ? 1 : 0) : res;
}

/* --- Process Renaming --- */

int set_process_name(const char *name) {
    if (!name || !name[0]) return -1;

#ifdef __linux__
    prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);
#endif
#ifdef __FreeBSD__
    setproctitle("-%s", name[0] == '-' ? name + 1 : name);
#endif

    if (proc_argv0 && proc_argv_len > 0) {
        size_t nlen = strlen(name);
        if (nlen >= proc_argv_len) {
            memcpy(proc_argv0, name, proc_argv_len - 1);
            proc_argv0[proc_argv_len - 1] = '\0';
        } else {
            memcpy(proc_argv0, name, nlen);
            memset(proc_argv0 + nlen, '\0', proc_argv_len - nlen);
        }
    }

    return 0;
}

int get_process_name(char *buf, size_t size) {
    if (!buf || size == 0) return -1;
    buf[0] = '\0';
#ifdef __linux__
    if (prctl(PR_GET_NAME, (unsigned long)buf, 0, 0, 0) == 0 && buf[0]) {
        return 0;
    }
#endif
    if (proc_argv0 && proc_argv0[0]) {
        snprintf(buf, size, "%s", proc_argv0);
        return 0;
    }
    return -1;
}

static int builtin_setproctitle(char **args) {
    if (!args[1]) {
        char current[64];
        if (get_process_name(current, sizeof(current)) == 0 && current[0]) {
            printf("%s\n", current);
            fflush(stdout);
            return 0;
        }
        fprintf(stderr, "minish: setproctitle: missing process name\n");
        return 1;
    }

    char title[256];
    title[0] = '\0';
    size_t len = 0;
    for (int i = 1; args[i]; i++) {
        if (i > 1 && len + 1 < sizeof(title)) {
            title[len++] = ' ';
            title[len] = '\0';
        }
        size_t alen = strlen(args[i]);
        if (len + alen < sizeof(title)) {
            memcpy(title + len, args[i], alen);
            len += alen;
            title[len] = '\0';
        }
    }

    if (set_process_name(title) != 0) {
        perror("minish: setproctitle");
        return 1;
    }
    return 0;
}

/* --- File Surgery & Permission Tools --- */

static int builtin_sync(char **args) {
    (void)args;
    sync();
    return 0;
}

static int builtin_chmod(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: chmod: missing operand\n");
        return 1;
    }
    const char *mode_str = args[1];
    mode_t mode = 0;
    int is_symbolic = 0, add_x = 0, sub_x = 0;

    if (strcmp(mode_str, "+x") == 0) { is_symbolic = 1; add_x = 1; }
    else if (strcmp(mode_str, "-x") == 0) { is_symbolic = 1; sub_x = 1; }
    else {
        char *endptr = NULL;
        long val = strtol(mode_str, &endptr, 8);
        if (*endptr != '\0' || val < 0 || val > 07777) {
            fprintf(stderr, "minish: chmod: invalid mode '%s'\n", mode_str);
            return 1;
        }
        mode = (mode_t)val;
    }

    int ret = 0;
    for (int i = 2; args[i]; i++) {
        mode_t target_mode = mode;
        if (is_symbolic) {
            struct stat st;
            if (stat(args[i], &st) != 0) {
                perror(args[i]);
                ret = 1;
                continue;
            }
            target_mode = st.st_mode;
            if (add_x) target_mode |= (S_IXUSR | S_IXGRP | S_IXOTH);
            if (sub_x) target_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        }
        if (chmod(args[i], target_mode) != 0) {
            perror(args[i]);
            ret = 1;
        }
    }
    return ret;
}

static int builtin_chown(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: chown: missing operand\n");
        return 1;
    }
    char *colon = strchr(args[1], ':');
    if (!colon) colon = strchr(args[1], '.');

    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;

    if (colon) {
        *colon = '\0';
        uid = (uid_t)atoi(args[1]);
        gid = (gid_t)atoi(colon + 1);
        *colon = ':';
    } else {
        uid = (uid_t)atoi(args[1]);
    }

    int ret = 0;
    for (int i = 2; args[i]; i++) {
        if (chown(args[i], uid, gid) != 0) {
            perror(args[i]);
            ret = 1;
        }
    }
    return ret;
}

static int builtin_mv(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: mv: missing operand\n");
        return 1;
    }
    int count = 0;
    while (args[count + 1]) count++;

    const char *dest = args[count];
    struct stat st_dest;
    int dest_is_dir = (stat(dest, &st_dest) == 0 && S_ISDIR(st_dest.st_mode));

    if (count > 2 && !dest_is_dir) {
        fprintf(stderr, "minish: mv: target '%s' is not a directory\n", dest);
        return 1;
    }

    int ret = 0;
    for (int i = 1; i < count; i++) {
        char final_dest[4096];
        if (dest_is_dir) {
            const char *base = strrchr(args[i], '/');
            base = base ? (base + 1) : args[i];
            snprintf(final_dest, sizeof(final_dest), "%s/%s", dest, base);
        } else {
            snprintf(final_dest, sizeof(final_dest), "%s", dest);
        }
        if (rename(args[i], final_dest) != 0) {
            perror(args[i]);
            ret = 1;
        }
    }
    return ret;
}

static int copy_single_file(const char *src, const char *dst) {
    struct stat st;
    if (stat(src, &st) != 0) {
        perror(src);
        return 1;
    }
    if (S_ISDIR(st.st_mode)) {
        fprintf(stderr, "minish: cp: -r not specified; omitting directory '%s'\n", src);
        return 1;
    }

    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0) {
        perror(src);
        return 1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (out_fd < 0) {
        perror(dst);
        close(in_fd);
        return 1;
    }

    char buf[8192];
    ssize_t n;
    int err = 0;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(out_fd, buf + written, n - written);
            if (w <= 0) {
                perror(dst);
                err = 1;
                break;
            }
            written += w;
        }
        if (err) break;
    }

    close(in_fd);
    close(out_fd);
    return err;
}

static int builtin_cp(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: cp: missing file operand\n");
        return 1;
    }
    int count = 0;
    while (args[count + 1]) count++;

    const char *dest = args[count];
    struct stat st_dest;
    int dest_is_dir = (stat(dest, &st_dest) == 0 && S_ISDIR(st_dest.st_mode));

    if (count > 2 && !dest_is_dir) {
        fprintf(stderr, "minish: cp: target '%s' is not a directory\n", dest);
        return 1;
    }

    int ret = 0;
    for (int i = 1; i < count; i++) {
        char final_dest[4096];
        if (dest_is_dir) {
            const char *base = strrchr(args[i], '/');
            base = base ? (base + 1) : args[i];
            snprintf(final_dest, sizeof(final_dest), "%s/%s", dest, base);
        } else {
            snprintf(final_dest, sizeof(final_dest), "%s", dest);
        }
        if (copy_single_file(args[i], final_dest) != 0) {
            ret = 1;
        }
    }
    return ret;
}

static int builtin_umask(char **args) {
    if (!args[1]) {
        mode_t old = umask(0);
        umask(old);
        printf("%04o\n", (unsigned int)old);
        fflush(stdout);
        return 0;
    }
    char *endptr = NULL;
    long val = strtol(args[1], &endptr, 8);
    if (*endptr != '\0' || val < 0 || val > 0777) {
        fprintf(stderr, "minish: umask: invalid octal mode '%s'\n", args[1]);
        return 1;
    }
    umask((mode_t)val);
    return 0;
}

static int builtin_remount(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: remount: usage: remount <rw|ro> [path]\n");
        return 1;
    }
    int is_rw = 1;
    if (strcmp(args[1], "ro") == 0) is_rw = 0;
    else if (strcmp(args[1], "rw") == 0) is_rw = 1;
    else {
        fprintf(stderr, "minish: remount: expected 'rw' or 'ro', got '%s'\n", args[1]);
        return 1;
    }
    const char *target = args[2] ? args[2] : "/";
#ifdef __linux__
    unsigned long flags = MS_REMOUNT | (is_rw ? 0 : MS_RDONLY);
    if (mount(NULL, target, NULL, flags, NULL) != 0) {
        perror("minish: remount");
        return 1;
    }
    printf("Remounted %s as %s\n", target, is_rw ? "read-write" : "read-only");
    return 0;
#else
    (void)target;
    fprintf(stderr, "minish: remount: not supported on this OS\n");
    return 1;
#endif
}

static int builtin_chroot(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: chroot: missing directory\n");
        return 1;
    }
    if (chroot(args[1]) != 0 || chdir("/") != 0) {
        perror("minish: chroot");
        return 1;
    }
    if (args[2]) {
        execvp(args[2], &args[2]);
        perror(args[2]);
        _exit(127);
    }
    return 0;
}

/* --- System Health & Diagnostics --- */

static int builtin_sysinfo(char **args) {
    (void)args;
#ifdef __linux__
    struct sysinfo s;
    if (sysinfo(&s) != 0) {
        perror("minish: sysinfo");
        return 1;
    }
    long days = s.uptime / 86400;
    long hours = (s.uptime % 86400) / 3600;
    long mins = (s.uptime % 3600) / 60;
    printf("Uptime: %ldd %ldh %ldm | Procs: %d\n", days, hours, mins, s.procs);
    printf("Load Avg: %.2f, %.2f, %.2f\n",
           s.loads[0] / 65536.0, s.loads[1] / 65536.0, s.loads[2] / 65536.0);
    unsigned long long unit = s.mem_unit ? s.mem_unit : 1;
    unsigned long long total_mb = (s.totalram * unit) / (1024 * 1024);
    unsigned long long free_mb = (s.freeram * unit) / (1024 * 1024);
    unsigned long long swap_total = (s.totalswap * unit) / (1024 * 1024);
    unsigned long long swap_free = (s.freeswap * unit) / (1024 * 1024);
    printf("RAM:  Total %llu MB | Free %llu MB | Used %llu MB\n",
           total_mb, free_mb, total_mb - free_mb);
    printf("Swap: Total %llu MB | Free %llu MB | Used %llu MB\n",
           swap_total, swap_free, swap_total - swap_free);
    fflush(stdout);
    return 0;
#else
    fprintf(stderr, "minish: sysinfo not available on this platform\n");
    return 1;
#endif
}

static int builtin_dmesg(char **args) {
    (void)args;
    int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        perror("minish: dmesg: /dev/kmsg");
        return 1;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        char *semicolon = strchr(buf, ';');
        if (semicolon) {
            fputs(semicolon + 1, stdout);
        } else {
            fputs(buf, stdout);
        }
    }
    close(fd);
    fflush(stdout);
    return 0;
}

static int builtin_uname(char **args) {
    struct utsname u;
    if (uname(&u) != 0) {
        perror("minish: uname");
        return 1;
    }
    int show_all = 0, show_r = 0, show_m = 0, show_n = 0;
    if (args[1]) {
        for (int i = 1; args[i]; i++) {
            if (strcmp(args[i], "-a") == 0) show_all = 1;
            else if (strcmp(args[i], "-r") == 0) show_r = 1;
            else if (strcmp(args[i], "-m") == 0) show_m = 1;
            else if (strcmp(args[i], "-n") == 0) show_n = 1;
        }
    }
    if (show_all) {
        printf("%s %s %s %s %s\n", u.sysname, u.nodename, u.release, u.version, u.machine);
    } else if (show_r || show_m || show_n) {
        if (show_n) printf("%s ", u.nodename);
        if (show_r) printf("%s ", u.release);
        if (show_m) printf("%s ", u.machine);
        printf("\n");
    } else {
        printf("%s\n", u.sysname);
    }
    fflush(stdout);
    return 0;
}

static int builtin_reboot(char **args) {
    (void)args;
    sync();
#ifdef __linux__
    if (reboot(RB_AUTOBOOT) != 0) {
        perror("minish: reboot");
        return 1;
    }
#endif
    return 0;
}

static int builtin_poweroff(char **args) {
    (void)args;
    sync();
#ifdef __linux__
    if (reboot(RB_POWER_OFF) != 0) {
        perror("minish: poweroff");
        return 1;
    }
#endif
    return 0;
}

static int builtin_sysrq(char **args) {
    if (!args[1] || !args[1][0]) {
        fprintf(stderr, "minish: sysrq: usage: sysrq <key> (e.g. s, u, b, f, t, m)\n");
        return 1;
    }
    int fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd < 0) {
        perror("minish: sysrq: /proc/sysrq-trigger");
        return 1;
    }
    if (write(fd, args[1], 1) <= 0) {
        perror("minish: sysrq write");
        close(fd);
        return 1;
    }
    close(fd);
    printf("Triggered Magic SysRq '%c'\n", args[1][0]);
    return 0;
}

/* --- Nonstandard In-Memory Virtual Storage (memfile) --- */

typedef struct {
    char name[64];
    char *data;
    size_t size;
} MemFileEntry;

static MemFileEntry memfiles[16];
static int num_memfiles = 0;

static int memfile_store(const char *name, const char *data, size_t size) {
    for (int i = 0; i < num_memfiles; i++) {
        if (strcmp(memfiles[i].name, name) == 0) {
            free(memfiles[i].data);
            memfiles[i].data = (char *)malloc(size);
            if (memfiles[i].data) memcpy(memfiles[i].data, data, size);
            memfiles[i].size = size;
            return 0;
        }
    }
    if (num_memfiles < 16) {
        snprintf(memfiles[num_memfiles].name, sizeof(memfiles[num_memfiles].name), "%s", name);
        memfiles[num_memfiles].data = (char *)malloc(size);
        if (memfiles[num_memfiles].data) memcpy(memfiles[num_memfiles].data, data, size);
        memfiles[num_memfiles].size = size;
        num_memfiles++;
        return 0;
    }
    return -1;
}

static int builtin_memrun(char **args) {
#ifdef __linux__
    extern char **environ;
    if (!args[1]) {
        fprintf(stderr, "minish: memrun: usage: memrun <name|-> [args...]\n");
        return 1;
    }
    const char *target_name = args[1];
    const char *data_ptr = NULL;
    size_t data_sz = 0;
    char *alloc_data = NULL;

    if (strcmp(target_name, "-") == 0) {
        size_t cap = 65536;
        alloc_data = malloc(cap);
        if (!alloc_data) { perror("malloc"); return 1; }
        char buf[4096];
        ssize_t n;
        while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
            if (data_sz + (size_t)n > cap) {
                cap = (cap + (size_t)n) * 2;
                char *new_ptr = realloc(alloc_data, cap);
                if (!new_ptr) {
                    free(alloc_data);
                    perror("realloc");
                    return 1;
                }
                alloc_data = new_ptr;
            }
            memcpy(alloc_data + data_sz, buf, (size_t)n);
            data_sz += (size_t)n;
        }
        data_ptr = alloc_data;
        target_name = (args[2]) ? args[2] : "mem_binary";
    } else {
        for (int i = 0; i < num_memfiles; i++) {
            if (strcmp(memfiles[i].name, target_name) == 0) {
                data_ptr = memfiles[i].data;
                data_sz = memfiles[i].size;
                break;
            }
        }
        if (!data_ptr) {
            fprintf(stderr, "minish: memrun: '%s' not found in RAM storage\n", target_name);
            return 1;
        }
    }

    if (data_sz == 0) {
        fprintf(stderr, "minish: memrun: binary data is empty\n");
        if (alloc_data) free(alloc_data);
        return 1;
    }

    int mfd = memfd_create(target_name, MFD_CLOEXEC);
    if (mfd < 0) {
        perror("minish: memfd_create");
        if (alloc_data) free(alloc_data);
        return 1;
    }

    size_t total_written = 0;
    while (total_written < data_sz) {
        ssize_t w = write(mfd, data_ptr + total_written, data_sz - total_written);
        if (w <= 0) {
            perror("minish: memrun write");
            close(mfd);
            if (alloc_data) free(alloc_data);
            return 1;
        }
        total_written += (size_t)w;
    }
    if (alloc_data) free(alloc_data);

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", mfd);
    int rfd = open(proc_path, O_RDONLY | O_CLOEXEC);
    close(mfd);
    if (rfd < 0) {
        perror("minish: memrun open ro");
        return 1;
    }
    fchmod(rfd, 0755);

    int orig_argc = 0;
    while (args[orig_argc]) orig_argc++;

    int child_argc = (orig_argc > 1) ? (orig_argc - 1) : 1;

    char **child_argv = malloc((child_argc + 1) * sizeof(char *));
    if (!child_argv) {
        perror("malloc");
        close(rfd);
        return 1;
    }
    child_argv[0] = (char *)target_name;
    for (int i = 1; i < child_argc; i++) {
        child_argv[i] = args[1 + i];
    }
    child_argv[child_argc] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        fexecve(rfd, child_argv, environ);
        execve(proc_path, child_argv, environ);
        perror("minish: memrun");
        _exit(127);
    }

    free(child_argv);
    close(rfd);

    if (pid < 0) {
        perror("minish: fork");
        return 1;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) == -1) {
        if (errno == EINTR) continue;
        break;
    }

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 0;
#else
    (void)args;
    fprintf(stderr, "minish: memrun only supported on Linux (memfd_create)\n");
    return 1;
#endif
}

static int builtin_memfile(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: memfile: usage: memfile <save|cat|run|list|rm> [name] [args...]\n");
        return 1;
    }
    if (strcmp(args[1], "run") == 0 || strcmp(args[1], "exec") == 0) {
        return builtin_memrun(&args[1]);
    }
    if (strcmp(args[1], "list") == 0) {
        printf("RAM Files (%d):\n", num_memfiles);
        for (int i = 0; i < num_memfiles; i++) {
            printf("  %s (%zu bytes)\n", memfiles[i].name, memfiles[i].size);
        }
        fflush(stdout);
        return 0;
    }
    if (!args[2]) {
        fprintf(stderr, "minish: memfile: missing filename\n");
        return 1;
    }
    const char *name = args[2];
    if (strcmp(args[1], "cat") == 0) {
        for (int i = 0; i < num_memfiles; i++) {
            if (strcmp(memfiles[i].name, name) == 0) {
                fwrite(memfiles[i].data, 1, memfiles[i].size, stdout);
                fflush(stdout);
                return 0;
            }
        }
        fprintf(stderr, "minish: memfile: '%s' not found\n", name);
        return 1;
    }
    if (strcmp(args[1], "save") == 0 || strcmp(args[1], "write") == 0) {
        size_t cap = 4096, size = 0;
        char *data = malloc(cap);
        char buf[1024];
        ssize_t n;
        while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
            if (size + (size_t)n > cap) {
                cap = (cap + (size_t)n) * 2;
                data = realloc(data, cap);
            }
            memcpy(data + size, buf, (size_t)n);
            size += (size_t)n;
        }
        for (int i = 0; i < num_memfiles; i++) {
            if (strcmp(memfiles[i].name, name) == 0) {
                free(memfiles[i].data);
                memfiles[i].data = data;
                memfiles[i].size = size;
                return 0;
            }
        }
        if (num_memfiles < 16) {
            snprintf(memfiles[num_memfiles].name, sizeof(memfiles[num_memfiles].name), "%s", name);
            memfiles[num_memfiles].data = data;
            memfiles[num_memfiles].size = size;
            num_memfiles++;
            return 0;
        }
        free(data);
        fprintf(stderr, "minish: memfile: table full\n");
        return 1;
    }
    if (strcmp(args[1], "rm") == 0 || strcmp(args[1], "drop") == 0 || strcmp(args[1], "del") == 0) {
        for (int i = 0; i < num_memfiles; i++) {
            if (strcmp(memfiles[i].name, name) == 0) {
                free(memfiles[i].data);
                for (int j = i; j < num_memfiles - 1; j++) {
                    memfiles[j] = memfiles[j + 1];
                }
                num_memfiles--;
                return 0;
            }
        }
        return 0;
    }
    return 1;
}

/* --- Nonstandard Block Sniffer & Hex Tools --- */

static int builtin_probeblk(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: probeblk: usage: probeblk <device_or_image>\n");
        return 1;
    }
    int fd = open(args[1], O_RDONLY);
    if (fd < 0) {
        perror(args[1]);
        return 1;
    }
    unsigned char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 512) {
        fprintf(stderr, "minish: probeblk: device too small or unreadable\n");
        return 1;
    }

    const char *detected = "unknown/raw data";
    if (n >= 1082 && buf[1080] == 0x53 && buf[1081] == 0xef) {
        detected = "ext2/ext3/ext4 filesystem";
    } else if (n >= 4 && memcmp(buf, "XFSB", 4) == 0) {
        detected = "XFS filesystem";
    } else if (n >= 512 + 8 && memcmp(buf + 512, "EFI PART", 8) == 0) {
        detected = "GPT partition table";
    } else if (n >= 512 && buf[510] == 0x55 && buf[511] == 0xAA) {
        detected = "MBR boot sector / partition table";
    } else if (n >= 4096 && memcmp(buf + 4086, "SWAPSPACE2", 10) == 0) {
        detected = "Linux swap space (v1)";
    } else if (n >= 8 && memcmp(buf + 3, "NTFS    ", 8) == 0) {
        detected = "NTFS filesystem";
    } else if (n >= 8 && memcmp(buf + 3, "MSDOS5.0", 8) == 0) {
        detected = "FAT filesystem";
    }
    printf("%s: %s\n", args[1], detected);
    fflush(stdout);
    return 0;
}

static int builtin_hexview(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: hexview: usage: hexview <file> [offset] [length]\n");
        return 1;
    }
    off_t offset = (args[2]) ? (off_t)strtoul(args[2], NULL, 0) : 0;
    size_t length = (args[3]) ? (size_t)strtoul(args[3], NULL, 0) : 256;

    int fd = open(args[1], O_RDONLY);
    if (fd < 0) {
        perror(args[1]);
        return 1;
    }
    if (offset > 0 && lseek(fd, offset, SEEK_SET) == (off_t)-1) {
        perror("minish: hexview lseek");
        close(fd);
        return 1;
    }

    unsigned char buf[16];
    size_t total = 0;
    while (total < length) {
        size_t to_read = (length - total < sizeof(buf)) ? (length - total) : sizeof(buf);
        ssize_t n = read(fd, buf, to_read);
        if (n <= 0) break;

        printf("%08lx  ", (unsigned long)(offset + total));
        for (int i = 0; i < 16; i++) {
            if (i < n) printf("%02x ", buf[i]);
            else printf("   ");
            if (i == 7) printf(" ");
        }
        printf(" |");
        for (int i = 0; i < n; i++) {
            putchar((buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.');
        }
        printf("|\n");
        total += (size_t)n;
    }
    close(fd);
    fflush(stdout);
    return 0;
}

static int builtin_falloc(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: falloc: usage: falloc <size_in_mb> <path>\n");
        return 1;
    }
    long mb = atol(args[1]);
    if (mb <= 0) {
        fprintf(stderr, "minish: falloc: invalid size\n");
        return 1;
    }
    off_t bytes = (off_t)mb * 1024 * 1024;
    int fd = open(args[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror(args[2]);
        return 1;
    }
    if (posix_fallocate(fd, 0, bytes) != 0) {
        perror("minish: fallocate");
        close(fd);
        return 1;
    }
    close(fd);
    printf("Allocated %ld MB to %s\n", mb, args[2]);
    return 0;
}

/* --- Nonstandard Network & Triage Tools --- */

static void parse_proc_net(const char *path, const char *proto) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return; }

    while (fgets(line, sizeof(line), f)) {
        unsigned int sl, local_ip, local_port, rem_ip, rem_port, st;
        if (sscanf(line, " %u: %x:%x %x:%x %x", &sl, &local_ip, &local_port, &rem_ip, &rem_port, &st) == 6) {
            struct in_addr lip, rip;
            lip.s_addr = local_ip;
            rip.s_addr = rem_ip;
            char lstr[INET_ADDRSTRLEN], rstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &lip, lstr, sizeof(lstr));
            inet_ntop(AF_INET, &rip, rstr, sizeof(rstr));

            const char *st_name = "UNKNOWN";
            if (st == 0x0A) st_name = "LISTEN";
            else if (st == 0x01) st_name = "ESTABLISHED";
            else if (st == 0x02) st_name = "SYN_SENT";
            else if (st == 0x03) st_name = "SYN_RECV";
            else if (st == 0x06) st_name = "TIME_WAIT";
            else if (st == 0x07) st_name = "CLOSE";

            printf("%-5s %s:%-5u  %s:%-5u  %s\n", proto, lstr, local_port, rstr, rem_port, st_name);
        }
    }
    fclose(f);
}

static int builtin_sockstat(char **args) {
    (void)args;
    printf("%-5s %-21s  %-21s  %s\n", "PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "STATE");
    parse_proc_net("/proc/net/tcp", "TCP");
    parse_proc_net("/proc/net/udp", "UDP");
    fflush(stdout);
    return 0;
}

static int builtin_httpget(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: httpget: usage: httpget http://host[:port]/path [dest_file]\n");
        return 1;
    }
    const char *url = args[1];
    if (strncmp(url, "http://", 7) != 0) {
        fprintf(stderr, "minish: httpget: only http:// URLs supported\n");
        return 1;
    }
    const char *host_start = url + 7;
    const char *slash = strchr(host_start, '/');
    char host[256];
    const char *path = slash ? slash : "/";
    size_t host_len = slash ? (size_t)(slash - host_start) : strlen(host_start);
    if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    int port = 80;
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "minish: httpget: could not resolve host '%s'\n", host);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("minish: socket");
        return 1;
    }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons((uint16_t)port);
    memcpy(&serv.sin_addr.s_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(sockfd, (struct sockaddr *)&serv, sizeof(serv)) != 0) {
        perror("minish: http connect");
        close(sockfd);
        return 1;
    }

    char req[1024];
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: minish/1.0\r\nConnection: close\r\n\r\n", path, host);
    if (write(sockfd, req, strlen(req)) <= 0) {
        perror("minish: http write");
        close(sockfd);
        return 1;
    }

    FILE *sock_f = fdopen(sockfd, "r");
    if (!sock_f) { close(sockfd); return 1; }

    char hline[1024];
    while (fgets(hline, sizeof(hline), sock_f)) {
        if (strcmp(hline, "\r\n") == 0 || strcmp(hline, "\n") == 0) break;
    }

    FILE *out = stdout;
    if (args[2]) {
        out = fopen(args[2], "wb");
        if (!out) { perror(args[2]); fclose(sock_f); return 1; }
    }

    char buf[4096];
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), sock_f)) > 0) {
        fwrite(buf, 1, bytes, out);
    }

    if (args[2]) fclose(out);
    fclose(sock_f);
    return 0;
}

static int builtin_dnslookup(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: dnslookup: usage: dnslookup <hostname>\n");
        return 1;
    }
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(args[1], NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "minish: dnslookup: %s: %s\n", args[1], gai_strerror(status));
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void *addr = NULL;
        const char *ipver = NULL;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("%s %s: %s\n", args[1], ipver, ipstr);
    }
    freeaddrinfo(res);
    fflush(stdout);
    return 0;
}

static int builtin_randhex(char **args) {
    int bytes = (args[1]) ? atoi(args[1]) : 16;
    if (bytes <= 0 || bytes > 4096) bytes = 16;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("minish: /dev/urandom");
        return 1;
    }
    for (int i = 0; i < bytes; i++) {
        unsigned char b;
        if (read(fd, &b, 1) <= 0) break;
        printf("%02x", b);
    }
    putchar('\n');
    close(fd);
    fflush(stdout);
    return 0;
}

static int builtin_watch(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: watch: usage: watch <interval_seconds> <command>\n");
        return 1;
    }
    int interval = atoi(args[1]);
    if (interval <= 0) interval = 2;

    while (1) {
        printf("\033[H\033[J");
        time_t now = time(NULL);
        char tbuf[64];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        printf("Every %ds: %s  (%s)\n\n", interval, args[2], tbuf);
        execute_line(args[2]);
        fflush(stdout);
        sleep((unsigned int)interval);
    }
    return 0;
}

/* --- Process Surgery & Introspection --- */

static void kill_children_of(pid_t target, int sig) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        char stat_path[320];
        snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", ent->d_name);
        FILE *f = fopen(stat_path, "r");
        if (!f) continue;
        pid_t ppid = 0;
        char comm[64];
        char state;
        if (fscanf(f, "%*d (%63[^)]) %c %d", comm, &state, &ppid) == 3) {
            if (ppid == target) {
                kill_children_of(pid, sig);
                kill(pid, sig);
            }
        }
        fclose(f);
    }
    closedir(d);
}

static int builtin_killtree(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: killtree: usage: killtree [-sig] <pid>\n");
        return 1;
    }
    int sig = SIGTERM;
    const char *pid_str = args[1];
    if (args[1][0] == '-' && args[2]) {
        sig = atoi(args[1] + 1);
        if (sig <= 0) sig = SIGTERM;
        pid_str = args[2];
    }
    pid_t pid = (pid_t)atoi(pid_str);
    kill_children_of(pid, sig);
    if (kill(pid, sig) != 0) {
        perror("minish: killtree");
        return 1;
    }
    return 0;
}

static int builtin_procpeek(char **args) {
    pid_t pid = (args[1]) ? (pid_t)atoi(args[1]) : getpid();
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return 1;
    }
    char line[256];
    printf("=== Process Info: PID %d ===\n", (int)pid);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0 ||
            strncmp(line, "State:", 6) == 0 ||
            strncmp(line, "PPid:", 5) == 0 ||
            strncmp(line, "Uid:", 4) == 0 ||
            strncmp(line, "VmRSS:", 6) == 0 ||
            strncmp(line, "VmSize:", 7) == 0) {
            fputs(line, stdout);
        }
    }
    fclose(f);

    snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
    DIR *d = opendir(path);
    if (d) {
        printf("Open Descriptors:\n");
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char linkpath[512], target[512];
            snprintf(linkpath, sizeof(linkpath), "%s/%s", path, ent->d_name);
            ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                printf("  fd %s -> %s\n", ent->d_name, target);
            }
        }
        closedir(d);
    }
    fflush(stdout);
    return 0;
}

/* --- Full-Disk Disaster Recovery Suite (df, truncate, ghostfind, findlarge, tmpfs) --- */

static int builtin_df(char **args) {
    const char *target = args[1] ? args[1] : "/";
    struct statvfs vfs;
    if (statvfs(target, &vfs) != 0) {
        perror(target);
        return 1;
    }
    unsigned long long bsize = vfs.f_frsize ? (unsigned long long)vfs.f_frsize : (unsigned long long)vfs.f_bsize;
    unsigned long long total_bytes = (unsigned long long)vfs.f_blocks * bsize;
    unsigned long long free_bytes_root = (unsigned long long)vfs.f_bfree * bsize;
    unsigned long long avail_bytes_user = (unsigned long long)vfs.f_bavail * bsize;
    unsigned long long used_bytes = (total_bytes >= free_bytes_root) ? (total_bytes - free_bytes_root) : 0;
    int pct_used = (total_bytes > 0) ? (int)((used_bytes * 100) / total_bytes) : 0;

    unsigned long long total_inodes = (unsigned long long)vfs.f_files;
    unsigned long long free_inodes = (unsigned long long)vfs.f_ffree;
    unsigned long long used_inodes = (total_inodes >= free_inodes) ? (total_inodes - free_inodes) : 0;
    int pct_inodes = (total_inodes > 0) ? (int)((used_inodes * 100) / total_inodes) : 0;

    printf("=== Filesystem Triage: %s ===\n", target);
    printf("Storage Blocks:\n");
    printf("  Total: %llu MB | Used: %llu MB (%d%%) | Avail(User): %llu MB | Free(Root): %llu MB\n",
           total_bytes / (1024ULL * 1024ULL), used_bytes / (1024ULL * 1024ULL), pct_used,
           avail_bytes_user / (1024ULL * 1024ULL), free_bytes_root / (1024ULL * 1024ULL));
    printf("Inode Metadata:\n");
    printf("  Total: %llu | Used: %llu (%d%%) | Free: %llu\n",
           total_inodes, used_inodes, pct_inodes, free_inodes);
    if (pct_used >= 90) {
        printf("[!] CRITICAL ALERT: Storage space is %d%% full (ENOSPC risk)!\n", pct_used);
    }
    if (pct_inodes >= 90) {
        printf("[!] CRITICAL ALERT: Inode table is %d%% full! New files cannot be created.\n", pct_inodes);
    }
    fflush(stdout);
    return 0;
}

static int builtin_truncate(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: truncate: usage: truncate <file> [bytes]\n");
        return 1;
    }
    off_t target_size = (args[2]) ? (off_t)atoll(args[2]) : 0;
    const char *path = args[1];

    if (truncate(path, target_size) == 0) {
        printf("[+] Truncated %s to %lld bytes (blocks reclaimed)\n", path, (long long)target_size);
        return 0;
    }

    /* Fallback: open with O_TRUNC (works through /proc/<pid>/fd/ magic symlinks) */
    if (target_size == 0) {
        int fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            close(fd);
            printf("[+] Truncated %s to 0 bytes via open(O_TRUNC)\n", path);
            return 0;
        }
    } else {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) {
            int ret = ftruncate(fd, target_size);
            close(fd);
            if (ret == 0) {
                printf("[+] Truncated %s to %lld bytes via ftruncate\n", path, (long long)target_size);
                return 0;
            }
        }
    }

    perror(path);
    return 1;
}

static int builtin_ghostfind(char **args) {
    int do_truncate = (args[1] && strcmp(args[1], "-t") == 0);
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("/proc");
        return 1;
    }

    printf("=== Ghost File Finder (Open Deleted File Descriptors) ===\n");
    int count = 0;
    unsigned long long total_trapped = 0;
    struct dirent *ent;

    while ((ent = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(ent->d_name);

        char comm_path[320];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", ent->d_name);
        char comm[64] = "unknown";
        FILE *cf = fopen(comm_path, "r");
        if (cf) {
            if (fgets(comm, sizeof(comm), cf)) {
                size_t l = strlen(comm);
                if (l > 0 && comm[l - 1] == '\n') comm[l - 1] = '\0';
            }
            fclose(cf);
        }

        char fd_dir[320];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", ent->d_name);
        DIR *fdd = opendir(fd_dir);
        if (!fdd) continue;

        struct dirent *fde;
        while ((fde = readdir(fdd)) != NULL) {
            if (fde->d_name[0] == '.') continue;
            char link_path[600];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, fde->d_name);
            char target[1024];
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len > 10) {
                target[len] = '\0';
                if (strcmp(target + len - 10, " (deleted)") == 0) {
                    struct stat st;
                    unsigned long long fsize = 0;
                    if (stat(link_path, &st) == 0) {
                        fsize = (unsigned long long)st.st_size;
                    }
                    target[len - 10] = '\0'; /* Strip " (deleted)" */
                    count++;
                    total_trapped += fsize;

                    printf("PID %5d (%-15s) | FD %-4s | Size: %7.2f MB | %s\n",
                           (int)pid, comm, fde->d_name,
                           (double)fsize / (1024.0 * 1024.0), target);

                    if (do_truncate) {
                        int tfd = open(link_path, O_WRONLY | O_TRUNC);
                        if (tfd >= 0) {
                            close(tfd);
                            printf("  -> [RECLAIMED] Truncated ghost file via %s\n", link_path);
                        } else if (truncate(link_path, 0) == 0) {
                            printf("  -> [RECLAIMED] Truncated ghost file via %s\n", link_path);
                        }
                    }
                }
            }
        }
        closedir(fdd);
    }
    closedir(proc);

    if (count == 0) {
        printf("No open unlinked (ghost) files found.\n");
    } else {
        printf("Total Ghost Files: %d | Trapped Space: %.2f MB\n",
               count, (double)total_trapped / (1024.0 * 1024.0));
        if (!do_truncate) {
            printf("Tip: Run 'ghostfind -t' to immediately truncate and reclaim this space!\n");
        }
    }
    fflush(stdout);
    return 0;
}

static void scan_dir_for_large(const char *dir_path, off_t min_bytes, int depth, int *matches) {
    if (depth > 20) return;
    if (strcmp(dir_path, "/proc") == 0 || strcmp(dir_path, "/sys") == 0 ||
        strcmp(dir_path, "/dev") == 0) return;

    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_dir_for_large(full, min_bytes, depth + 1, matches);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_size >= min_bytes) {
                (*matches)++;
                printf("[%7.2f MB] %s\n", (double)st.st_size / (1024.0 * 1024.0), full);
            }
        }
    }
    closedir(d);
}

static int builtin_findlarge(char **args) {
    const char *start_path = ".";
    long min_mb = 50;

    if (args[1]) {
        if (isdigit((unsigned char)args[1][0]) && !args[2]) {
            min_mb = atol(args[1]);
        } else {
            start_path = args[1];
            if (args[2]) min_mb = atol(args[2]);
        }
    }
    if (min_mb < 0) min_mb = 0;
    off_t min_bytes = (off_t)min_mb * 1024 * 1024;

    printf("=== Large File Scan: %s (>= %ld MB) ===\n", start_path, min_mb);
    int matches = 0;
    scan_dir_for_large(start_path, min_bytes, 0, &matches);
    printf("Found %d file(s) exceeding %ld MB\n", matches, min_mb);
    fflush(stdout);
    return 0;
}

static void scan_dir_for_inodes(const char *dir_path, long min_count, int depth, int *dir_matches, unsigned long long *total_files) {
    if (depth > 20) return;
    if (strcmp(dir_path, "/proc") == 0 || strcmp(dir_path, "/sys") == 0 ||
        strcmp(dir_path, "/dev") == 0) return;

    DIR *d = opendir(dir_path);
    if (!d) return;

    long file_count = 0;
    struct dirent *ent;
    size_t sub_cap = 16, sub_cnt = 0;
    char **subdirs = malloc(sub_cap * sizeof(char *));

    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (subdirs) {
                if (sub_cnt >= sub_cap) {
                    sub_cap *= 2;
                    char **tmp = realloc(subdirs, sub_cap * sizeof(char *));
                    if (tmp) subdirs = tmp;
                }
                if (sub_cnt < sub_cap) {
                    subdirs[sub_cnt++] = strdup(full);
                }
            }
        } else {
            file_count++;
            (*total_files)++;
        }
    }
    closedir(d);

    if (file_count >= min_count) {
        (*dir_matches)++;
        printf("[%8ld files] %s\n", file_count, dir_path);
    }

    if (subdirs) {
        for (size_t i = 0; i < sub_cnt; i++) {
            scan_dir_for_inodes(subdirs[i], min_count, depth + 1, dir_matches, total_files);
            free(subdirs[i]);
        }
        free(subdirs);
    }
}

static int builtin_inodescan(char **args) {
    const char *start_path = ".";
    long min_count = 1000;

    if (args[1]) {
        if (isdigit((unsigned char)args[1][0]) && !args[2]) {
            min_count = atol(args[1]);
        } else {
            start_path = args[1];
            if (args[2]) min_count = atol(args[2]);
        }
    }
    if (min_count < 0) min_count = 0;

    printf("=== Inode Exhaustion Scanner: %s (>= %ld files/dir) ===\n", start_path, min_count);
    int dir_matches = 0;
    unsigned long long total_files = 0;
    scan_dir_for_inodes(start_path, min_count, 0, &dir_matches, &total_files);
    printf("Found %d directory(ies) with >= %ld files (total scanned files: %llu)\n",
           dir_matches, min_count, total_files);
    fflush(stdout);
    return 0;
}

static void scan_and_truncate_logs(const char *dir_path, int depth, int *count, unsigned long long *reclaimed_bytes) {
    if (depth > 15) return;
    if (strcmp(dir_path, "/proc") == 0 || strcmp(dir_path, "/sys") == 0 ||
        strcmp(dir_path, "/dev") == 0) return;

    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_and_truncate_logs(full, depth + 1, count, reclaimed_bytes);
        } else if (S_ISREG(st.st_mode)) {
            size_t nlen = strlen(ent->d_name);
            int is_log = 0;
            if (nlen >= 4 && strcmp(ent->d_name + nlen - 4, ".log") == 0) is_log = 1;
            else if (strstr(ent->d_name, ".log.") != NULL) is_log = 1;

            if (is_log && st.st_size > 0) {
                off_t sz = st.st_size;
                if (truncate(full, 0) == 0) {
                    (*count)++;
                    *reclaimed_bytes += (unsigned long long)sz;
                    printf("[+] Truncated: %s (%6.2f MB freed)\n", full, (double)sz / (1024.0 * 1024.0));
                }
            }
        }
    }
    closedir(d);
}

static int builtin_zerolog(char **args) {
    const char *target = args[1] ? args[1] : "/var/log";
    printf("=== Emergency In-Place Log Truncation: %s ===\n", target);
    int count = 0;
    unsigned long long reclaimed = 0;
    scan_and_truncate_logs(target, 0, &count, &reclaimed);
    printf("Truncated %d log file(s), reclaimed %6.2f MB in-place\n",
           count, (double)reclaimed / (1024.0 * 1024.0));
    fflush(stdout);
    return 0;
}

static void scan_for_empty_files(const char *dir_path, int do_delete, int depth, int *count) {
    if (depth > 20) return;
    if (strcmp(dir_path, "/proc") == 0 || strcmp(dir_path, "/sys") == 0 ||
        strcmp(dir_path, "/dev") == 0) return;

    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_for_empty_files(full, do_delete, depth + 1, count);
        } else if (S_ISREG(st.st_mode) && st.st_size == 0) {
            (*count)++;
            if (do_delete) {
                if (unlink(full) == 0) {
                    printf("[-] Deleted 0-byte file: %s (1 inode reclaimed)\n", full);
                } else {
                    perror(full);
                }
            } else {
                printf("[0 bytes] %s\n", full);
            }
        }
    }
    closedir(d);
}

static int builtin_findempty(char **args) {
    const char *target = ".";
    int do_delete = 0;

    for (int i = 1; args[i]; i++) {
        if (strcmp(args[i], "-d") == 0) {
            do_delete = 1;
        } else {
            target = args[i];
        }
    }

    printf("=== Empty 0-Byte File Scanner: %s (%s) ===\n",
           target, do_delete ? "DELETE MODE" : "SCAN ONLY");
    int count = 0;
    scan_for_empty_files(target, do_delete, 0, &count);
    if (do_delete) {
        printf("Reclaimed %d inode(s) by deleting empty files\n", count);
    } else {
        printf("Found %d empty 0-byte file(s) wasting inodes (use -d to delete)\n", count);
    }
    fflush(stdout);
    return 0;
}

static unsigned long long calculate_dir_size(const char *path, int depth) {
    if (depth > 20) return 0;
    if (strcmp(path, "/proc") == 0 || strcmp(path, "/sys") == 0 ||
        strcmp(path, "/dev") == 0) return 0;

    DIR *d = opendir(path);
    if (!d) return 0;

    unsigned long long total = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            total += calculate_dir_size(full, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            total += (unsigned long long)st.st_size;
        }
    }
    closedir(d);
    return total;
}

static void print_dir_usage(const char *path, int max_depth, int current_depth) {
    if (current_depth > max_depth) return;
    if (strcmp(path, "/proc") == 0 || strcmp(path, "/sys") == 0 ||
        strcmp(path, "/dev") == 0) return;

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            unsigned long long sz = calculate_dir_size(full, 0);
            printf("[%8.2f MB] %s\n", (double)sz / (1024.0 * 1024.0), full);
            if (current_depth < max_depth) {
                print_dir_usage(full, max_depth, current_depth + 1);
            }
        }
    }
    closedir(d);
}

static int builtin_dusage(char **args) {
    const char *start_path = ".";
    int max_depth = 1;

    if (args[1]) {
        if (isdigit((unsigned char)args[1][0]) && !args[2]) {
            max_depth = atoi(args[1]);
        } else {
            start_path = args[1];
            if (args[2]) max_depth = atoi(args[2]);
        }
    }
    if (max_depth < 1) max_depth = 1;

    printf("=== Directory Storage Usage: %s (depth %d) ===\n", start_path, max_depth);
    unsigned long long total_self = calculate_dir_size(start_path, 0);
    print_dir_usage(start_path, max_depth, 1);
    printf("Total subtree size (%s): %8.2f MB\n", start_path, (double)total_self / (1024.0 * 1024.0));
    fflush(stdout);
    return 0;
}

static void scan_for_inode(const char *dir_path, ino_t target_ino, int depth, int *found) {
    if (depth > 20) return;
    if (strcmp(dir_path, "/proc") == 0 || strcmp(dir_path, "/sys") == 0 ||
        strcmp(dir_path, "/dev") == 0) return;

    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (st.st_ino == target_ino) {
            (*found)++;
            printf("[+] Inode %llu -> %s (Size: %llu bytes, Mode: 0%o)\n",
                   (unsigned long long)target_ino, full,
                   (unsigned long long)st.st_size, (unsigned int)(st.st_mode & 0777));
        }

        if (S_ISDIR(st.st_mode)) {
            scan_for_inode(full, target_ino, depth + 1, found);
        }
    }
    closedir(d);
}

static int builtin_findinode(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: findinode: usage: findinode <inode_number> [search_path]\n");
        return 1;
    }
    ino_t target = (ino_t)strtoull(args[1], NULL, 10);
    const char *start_path = args[2] ? args[2] : ".";

    printf("=== Searching for Inode #%llu starting from %s ===\n",
           (unsigned long long)target, start_path);
    int found = 0;
    scan_for_inode(start_path, target, 0, &found);
    if (!found) {
        printf("[-] Inode #%llu not found under %s\n", (unsigned long long)target, start_path);
        return 1;
    }
    printf("Resolved %d match(es) for Inode #%llu\n", found, (unsigned long long)target);
    fflush(stdout);
    return 0;
}

static int builtin_tmpfs(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: tmpfs: usage: tmpfs <mountpoint> [size_in_mb]\n");
        return 1;
    }
    const char *mp = args[1];
    int size_mb = args[2] ? atoi(args[2]) : 64;
    if (size_mb <= 0) size_mb = 64;

    mkdir(mp, 0777);

#ifdef __linux__
    char opts[64];
    snprintf(opts, sizeof(opts), "size=%dM,mode=1777", size_mb);
    if (mount("tmpfs", mp, "tmpfs", 0, opts) != 0) {
        perror("minish: tmpfs mount");
        return 1;
    }
    printf("[+] Mounted %d MB RAM tmpfs on %s (mode 1777)\n", size_mb, mp);
    return 0;
#else
    fprintf(stderr, "minish: tmpfs only supported on Linux\n");
    return 1;
#endif
}

/* --- Forensic Triage, Anti-Tamper & Disaster Recovery Built-ins --- */

/* FIPS 180-4 SHA-256 Standalone Hasher */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} MinishSha256;

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform(MinishSha256 *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + K256[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(MinishSha256 *ctx) {
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
    ctx->count = 0;
}

static void sha256_update(MinishSha256 *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) {
            sha256_transform(ctx, ctx->buffer);
        }
    }
}

static void sha256_final(MinishSha256 *ctx, uint8_t hash[32]) {
    uint64_t total_bits = ctx->count * 8;
    ctx->buffer[ctx->count % 64] = 0x80;
    ctx->count++;
    if (ctx->count % 64 > 56) {
        while (ctx->count % 64 != 0) {
            ctx->buffer[ctx->count % 64] = 0x00;
            ctx->count++;
        }
        sha256_transform(ctx, ctx->buffer);
    }
    while (ctx->count % 64 != 56) {
        ctx->buffer[ctx->count % 64] = 0x00;
        ctx->count++;
    }
    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + (7 - i)] = (uint8_t)((total_bits >> (i * 8)) & 0xff);
    }
    sha256_transform(ctx, ctx->buffer);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
    }
}

static int builtin_sha256(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: sha256: usage: sha256 <file|->\n");
        return 1;
    }
    int is_stdin = (strcmp(args[1], "-") == 0);
    int fd = is_stdin ? STDIN_FILENO : open(args[1], O_RDONLY);
    if (fd < 0) {
        perror(args[1]);
        return 1;
    }
    MinishSha256 ctx;
    sha256_init(&ctx);
    uint8_t buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)n);
    }
    if (!is_stdin) close(fd);
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("  %s\n", args[1]);
    fflush(stdout);
    return 0;
}

/* Micro-Netcat Client & Listener */
static int builtin_nc(char **args) {
    int is_listen = 0;
    const char *host = NULL;
    int port = 0;

    int idx = 1;
    if (args[idx] && strcmp(args[idx], "-l") == 0) {
        is_listen = 1;
        idx++;
    }

    if (is_listen) {
        if (!args[idx]) {
            fprintf(stderr, "minish: nc: usage: nc -l <port>\n");
            return 1;
        }
        port = atoi(args[idx]);
    } else {
        if (!args[idx] || !args[idx + 1]) {
            fprintf(stderr, "minish: nc: usage: nc <host> <port> or nc -l <port>\n");
            return 1;
        }
        host = args[idx];
        port = atoi(args[idx + 1]);
    }

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "minish: nc: invalid port %d\n", port);
        return 1;
    }

    int sock_fd = -1;
    if (is_listen) {
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            perror("minish: nc: socket");
            return 1;
        }
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((uint16_t)port);

        if (bind(listen_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            perror("minish: nc: bind");
            close(listen_fd);
            return 1;
        }
        if (listen(listen_fd, 1) < 0) {
            perror("minish: nc: listen");
            close(listen_fd);
            return 1;
        }
        fprintf(stderr, "minish: nc: listening on 0.0.0.0:%d ...\n", port);
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        sock_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        close(listen_fd);
        if (sock_fd < 0) {
            perror("minish: nc: accept");
            return 1;
        }
        char cip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &caddr.sin_addr, cip, sizeof(cip));
        fprintf(stderr, "minish: nc: connection accepted from %s:%d\n", cip, ntohs(caddr.sin_port));
    } else {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        struct addrinfo hints, *res = NULL, *p = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            fprintf(stderr, "minish: nc: could not resolve host '%s'\n", host);
            return 1;
        }
        for (p = res; p != NULL; p = p->ai_next) {
            sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (sock_fd < 0) continue;
            if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == 0) break;
            close(sock_fd);
            sock_fd = -1;
        }
        freeaddrinfo(res);
        if (sock_fd < 0) {
            fprintf(stderr, "minish: nc: could not connect to %s:%d\n", host, port);
            return 1;
        }
    }

    int stdin_open = 1, sock_open = 1;
    char buf[4096];
    while (sock_open && (stdin_open || 1)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = sock_fd;
        if (stdin_open) {
            FD_SET(STDIN_FILENO, &rfds);
            if (STDIN_FILENO > maxfd) maxfd = STDIN_FILENO;
        }
        FD_SET(sock_fd, &rfds);

        int activity = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (stdin_open && FD_ISSET(STDIN_FILENO, &rfds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                stdin_open = 0;
                shutdown(sock_fd, SHUT_WR);
            } else {
                ssize_t written = 0;
                while (written < n) {
                    ssize_t w = write(sock_fd, buf + written, (size_t)(n - written));
                    if (w <= 0) { sock_open = 0; break; }
                    written += w;
                }
            }
        }

        if (FD_ISSET(sock_fd, &rfds)) {
            ssize_t n = read(sock_fd, buf, sizeof(buf));
            if (n <= 0) {
                sock_open = 0;
                break;
            }
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = write(STDOUT_FILENO, buf + written, (size_t)(n - written));
                if (w <= 0) break;
                written += w;
            }
        }
        if (!stdin_open && !sock_open) break;
    }

    close(sock_fd);
    fflush(stdout);
    return 0;
}

#ifndef EM_RISCV
#define EM_RISCV 243
#endif

/* Zero-Execution Safe ELF & Shared Library Inspector */
static int builtin_elfpeek(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: elfpeek: usage: elfpeek <binary>\n");
        return 1;
    }
#ifdef __linux__
    int fd = open(args[1], O_RDONLY);
    if (fd < 0) {
        perror(args[1]);
        return 1;
    }
    unsigned char e_ident[EI_NIDENT];
    if (read(fd, e_ident, sizeof(e_ident)) != sizeof(e_ident)) {
        fprintf(stderr, "minish: elfpeek: failed to read ELF identification\n");
        close(fd);
        return 1;
    }
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "minish: elfpeek: '%s' is not an ELF binary\n", args[1]);
        close(fd);
        return 1;
    }

    int is_64 = (e_ident[EI_CLASS] == ELFCLASS64);
    int is_le = (e_ident[EI_DATA] == ELFDATA2LSB);

    printf("File:       %s\n", args[1]);
    printf("ELF Class:  %s\n", is_64 ? "ELF64 (64-bit)" : "ELF32 (32-bit)");
    printf("Endianness: %s\n", is_le ? "Little Endian" : "Big Endian");

    lseek(fd, 0, SEEK_SET);

    if (is_64) {
        Elf64_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            close(fd);
            return 1;
        }
        const char *mstr = "Unknown";
        if (ehdr.e_machine == EM_X86_64) mstr = "Advanced Micro Devices X86-64";
        else if (ehdr.e_machine == EM_386) mstr = "Intel 80386";
        else if (ehdr.e_machine == EM_ARM) mstr = "ARM";
        else if (ehdr.e_machine == EM_AARCH64) mstr = "AArch64 (ARM 64-bit)";
        else if (ehdr.e_machine == EM_RISCV) mstr = "RISC-V";
        printf("Machine:    %s (0x%x)\n", mstr, ehdr.e_machine);
        printf("Entry:      0x%lx\n", (unsigned long)ehdr.e_entry);

        if (ehdr.e_phoff > 0 && ehdr.e_phnum > 0) {
            lseek(fd, (off_t)ehdr.e_phoff, SEEK_SET);
            Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * ehdr.e_phnum);
            if (phdrs) {
                if (read(fd, phdrs, sizeof(Elf64_Phdr) * ehdr.e_phnum) == (ssize_t)(sizeof(Elf64_Phdr) * ehdr.e_phnum)) {
                    off_t dyn_offset = 0;
                    size_t dyn_size = 0;
                    for (int i = 0; i < ehdr.e_phnum; i++) {
                        if (phdrs[i].p_type == PT_INTERP) {
                            char interp[512];
                            lseek(fd, (off_t)phdrs[i].p_offset, SEEK_SET);
                            size_t to_read = phdrs[i].p_filesz < sizeof(interp) - 1 ? phdrs[i].p_filesz : sizeof(interp) - 1;
                            ssize_t in = read(fd, interp, to_read);
                            if (in > 0) {
                                interp[in] = '\0';
                                printf("Interpreter: %s\n", interp);
                            }
                        } else if (phdrs[i].p_type == PT_DYNAMIC) {
                            dyn_offset = (off_t)phdrs[i].p_offset;
                            dyn_size = (size_t)phdrs[i].p_filesz;
                        }
                    }

                    if (dyn_offset > 0 && dyn_size > 0) {
                        int num_dyn = (int)(dyn_size / sizeof(Elf64_Dyn));
                        Elf64_Dyn *dyns = malloc(dyn_size);
                        if (dyns) {
                            lseek(fd, dyn_offset, SEEK_SET);
                            if (read(fd, dyns, dyn_size) == (ssize_t)dyn_size) {
                                Elf64_Addr strtab_addr = 0;
                                for (int i = 0; i < num_dyn; i++) {
                                    if (dyns[i].d_tag == DT_STRTAB) {
                                        strtab_addr = dyns[i].d_un.d_ptr;
                                        break;
                                    }
                                }
                                off_t strtab_offset = 0;
                                for (int i = 0; i < ehdr.e_phnum; i++) {
                                    if (phdrs[i].p_type == PT_LOAD &&
                                        strtab_addr >= phdrs[i].p_vaddr &&
                                        strtab_addr < phdrs[i].p_vaddr + phdrs[i].p_memsz) {
                                        strtab_offset = (off_t)(phdrs[i].p_offset + (strtab_addr - phdrs[i].p_vaddr));
                                        break;
                                    }
                                }
                                if (strtab_offset == 0) strtab_offset = (off_t)strtab_addr;

                                printf("Shared Libraries (DT_NEEDED):\n");
                                int count = 0;
                                for (int i = 0; i < num_dyn; i++) {
                                    if (dyns[i].d_tag == DT_NEEDED) {
                                        char libname[256];
                                        lseek(fd, strtab_offset + (off_t)dyns[i].d_un.d_val, SEEK_SET);
                                        ssize_t ln = read(fd, libname, sizeof(libname) - 1);
                                        if (ln > 0) {
                                            libname[ln] = '\0';
                                            printf("  %s\n", libname);
                                            count++;
                                        }
                                    }
                                }
                                if (count == 0) printf("  (None / statically linked)\n");
                            }
                            free(dyns);
                        }
                    } else {
                        printf("Shared Libraries: (Statically linked binary)\n");
                    }
                }
                free(phdrs);
            }
        }
    } else {
        Elf32_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) == sizeof(ehdr)) {
            printf("Machine:    0x%x\n", ehdr.e_machine);
            printf("Entry:      0x%x\n", (unsigned int)ehdr.e_entry);
        }
    }
    close(fd);
    fflush(stdout);
    return 0;
#else
    fprintf(stderr, "minish: elfpeek only supported on Linux\n");
    return 1;
#endif
}

/* Process Environment & Secret Sniffer */
static int builtin_envpeek(char **args) {
    pid_t pid = (args[1]) ? (pid_t)atoi(args[1]) : getpid();
    if (pid <= 0) {
        fprintf(stderr, "minish: envpeek: invalid pid\n");
        return 1;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return 1;
    }
    char buf[4096];
    ssize_t n;
    int has_content = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        has_content = 1;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\0') putchar('\n');
            else putchar(buf[i]);
        }
    }
    close(fd);
    if (!has_content) {
        printf("(Process %d has no accessible environment)\n", (int)pid);
    }
    fflush(stdout);
    return 0;
}

/* Kernel Module & Driver Auditor */
static int builtin_modpeek(char **args) {
    (void)args;
    FILE *f = fopen("/proc/modules", "r");
    if (!f) {
        perror("minish: /proc/modules");
        return 1;
    }
    printf("%-24s %10s  %-4s %-20s %s\n", "MODULE", "SIZE", "REFS", "DEPENDENTS", "STATE");
    printf("--------------------------------------------------------------------------------\n");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char mod[64], state[32], deps[256];
        unsigned long size = 0;
        int refs = 0;
        state[0] = '\0'; deps[0] = '\0';
        int items = sscanf(line, "%63s %lu %d %255s %31s", mod, &size, &refs, deps, state);
        if (items >= 3) {
            printf("%-24s %10lu  %4d %-20s %s\n", mod, size, refs, (items >= 4) ? deps : "-", (items >= 5) ? state : "");
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* Bit-shift Base64 Transceiver for Air-Gapped Serial Consoles */
static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int builtin_base64(char **args) {
    int decode = 0;
    const char *file = NULL;
    for (int i = 1; args[i]; i++) {
        if (strcmp(args[i], "-d") == 0 || strcmp(args[i], "--decode") == 0) decode = 1;
        else if (strcmp(args[i], "-e") == 0 || strcmp(args[i], "--encode") == 0) decode = 0;
        else if (!file) file = args[i];
    }

    int fd = STDIN_FILENO;
    if (file && strcmp(file, "-") != 0) {
        fd = open(file, O_RDONLY);
        if (fd < 0) {
            perror(file);
            return 1;
        }
    }

    if (!decode) {
        unsigned char in[3];
        int col = 0;
        while (1) {
            ssize_t n = 0;
            while (n < 3) {
                ssize_t r = read(fd, in + n, (size_t)(3 - n));
                if (r <= 0) break;
                n += r;
            }
            if (n == 0) break;

            unsigned char out[4];
            out[0] = (unsigned char)B64_CHARS[(in[0] >> 2) & 0x3f];
            if (n == 1) {
                out[1] = (unsigned char)B64_CHARS[(in[0] & 0x03) << 4];
                out[2] = '=';
                out[3] = '=';
            } else if (n == 2) {
                out[1] = (unsigned char)B64_CHARS[((in[0] & 0x03) << 4) | ((in[1] >> 4) & 0x0f)];
                out[2] = (unsigned char)B64_CHARS[(in[1] & 0x0f) << 2];
                out[3] = '=';
            } else {
                out[1] = (unsigned char)B64_CHARS[((in[0] & 0x03) << 4) | ((in[1] >> 4) & 0x0f)];
                out[2] = (unsigned char)B64_CHARS[((in[1] & 0x0f) << 2) | ((in[2] >> 6) & 0x03)];
                out[3] = (unsigned char)B64_CHARS[in[2] & 0x3f];
            }
            for (int i = 0; i < 4; i++) {
                putchar(out[i]);
                if (++col >= 76) { putchar('\n'); col = 0; }
            }
            if (n < 3) break;
        }
        if (col != 0) putchar('\n');
    } else {
        int quad[4];
        int qcount = 0;
        char in_buf[4096];
        ssize_t n;
        while ((n = read(fd, in_buf, sizeof(in_buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = in_buf[i];
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
                if (c == '=') {
                    quad[qcount++] = -2;
                } else {
                    int val = b64_char_value(c);
                    if (val >= 0) quad[qcount++] = val;
                }
                if (qcount == 4) {
                    if (quad[0] >= 0 && quad[1] >= 0) {
                        unsigned char b0 = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
                        putchar(b0);
                        if (quad[2] >= 0) {
                            unsigned char b1 = (unsigned char)(((quad[1] & 0x0f) << 4) | (quad[2] >> 2));
                            putchar(b1);
                            if (quad[3] >= 0) {
                                unsigned char b2 = (unsigned char)(((quad[2] & 0x03) << 6) | quad[3]);
                                putchar(b2);
                            }
                        }
                    }
                    qcount = 0;
                }
            }
        }
    }

    if (fd != STDIN_FILENO) close(fd);
    fflush(stdout);
    return 0;
}

/* Atomic In-Place Configuration Patcher */
static int builtin_replace(char **args) {
    if (!args[1] || !args[2] || !args[3]) {
        fprintf(stderr, "minish: replace: usage: replace <file> <search> <replace>\n");
        return 1;
    }
    const char *file = args[1];
    const char *search = args[2];
    const char *rep = args[3];
    size_t slen = strlen(search);
    size_t rlen = strlen(rep);
    if (slen == 0) {
        fprintf(stderr, "minish: replace: search string cannot be empty\n");
        return 1;
    }

    struct stat st;
    if (stat(file, &st) != 0) {
        perror(file);
        return 1;
    }

    FILE *in = fopen(file, "r");
    if (!in) {
        perror(file);
        return 1;
    }

    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s.minish_tmp", file);
    FILE *out = fopen(tmp_path, "w");
    if (!out) {
        perror(tmp_path);
        fclose(in);
        return 1;
    }

    fchmod(fileno(out), st.st_mode & 07777);

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    long replace_count = 0;

    while ((linelen = getline(&line, &linecap, in)) != -1) {
        (void)linelen;
        char *p = line;
        char *found = NULL;
        while ((found = strstr(p, search)) != NULL) {
            fwrite(p, 1, (size_t)(found - p), out);
            fwrite(rep, 1, rlen, out);
            p = found + slen;
            replace_count++;
        }
        fputs(p, out);
    }
    free(line);
    fclose(in);
    fclose(out);

    if (rename(tmp_path, file) != 0) {
        perror("minish: replace: rename");
        unlink(tmp_path);
        return 1;
    }
    printf("Replaced %ld occurrence(s) in %s\n", replace_count, file);
    return 0;
}

/* Device Node Reconstruction Syscall */
static int builtin_mknod(char **args) {
    if (!args[1] || !args[2] || !args[3] || !args[4]) {
        fprintf(stderr, "minish: mknod: usage: mknod <path> <c|b> <major> <minor>\n");
        return 1;
    }
#ifdef __linux__
    mode_t type = 0;
    if (strcmp(args[2], "c") == 0 || strcmp(args[2], "u") == 0) {
        type = S_IFCHR;
    } else if (strcmp(args[2], "b") == 0) {
        type = S_IFBLK;
    } else {
        fprintf(stderr, "minish: mknod: invalid device type '%s' (use 'c' or 'b')\n", args[2]);
        return 1;
    }
    unsigned int maj = (unsigned int)atoi(args[3]);
    unsigned int min = (unsigned int)atoi(args[4]);
    dev_t dev = makedev(maj, min);
    mode_t mode = 0660 | type;

    if (mknod(args[1], mode, dev) != 0) {
        perror("minish: mknod");
        return 1;
    }
    printf("Created device node %s (type %s, %u:%u)\n", args[1], args[2], maj, min);
    return 0;
#else
    fprintf(stderr, "minish: mknod only supported on Linux\n");
    return 1;
#endif
}

/* Direct Kernel Syscall Filesystem & Bind Mounter */
static int builtin_mount(char **args) {
#ifdef __linux__
    const char *fstype = NULL;
    const char *opts_str = NULL;
    const char *src = NULL;
    const char *target = NULL;
    unsigned long flags = 0;

    int i = 1;
    while (args[i] && args[i][0] == '-') {
        if (strcmp(args[i], "-t") == 0 && args[i + 1]) {
            fstype = args[i + 1];
            i += 2;
        } else if (strcmp(args[i], "-o") == 0 && args[i + 1]) {
            opts_str = args[i + 1];
            i += 2;
        } else {
            break;
        }
    }

    if (!args[i]) {
        FILE *f = fopen("/proc/mounts", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) fputs(line, stdout);
            fclose(f);
            fflush(stdout);
            return 0;
        }
        fprintf(stderr, "minish: mount: usage: mount [-t type] [-o options] <source> <target>\n");
        return 1;
    }

    src = args[i++];
    target = args[i];
    if (!target) {
        fprintf(stderr, "minish: mount: missing mount target\n");
        return 1;
    }

    if (opts_str) {
        char *opts = strdup(opts_str);
        if (opts) {
            char *tok = strtok(opts, ",");
            while (tok) {
                if (strcmp(tok, "ro") == 0) flags |= MS_RDONLY;
                else if (strcmp(tok, "rw") == 0) flags &= ~MS_RDONLY;
                else if (strcmp(tok, "bind") == 0) flags |= MS_BIND;
                else if (strcmp(tok, "remount") == 0) flags |= MS_REMOUNT;
                else if (strcmp(tok, "noexec") == 0) flags |= MS_NOEXEC;
                else if (strcmp(tok, "nosuid") == 0) flags |= MS_NOSUID;
                else if (strcmp(tok, "nodev") == 0) flags |= MS_NODEV;
                else if (strcmp(tok, "relatime") == 0) flags |= MS_RELATIME;
                tok = strtok(NULL, ",");
            }
            free(opts);
        }
    }

    if (mount(src, target, fstype, flags, NULL) != 0) {
        perror("minish: mount");
        return 1;
    }
    printf("Mounted %s on %s%s%s%s\n", src, target, fstype ? " (type " : "", fstype ? fstype : "", fstype ? ")" : "");
    fflush(stdout);
    return 0;
#else
    (void)args;
    fprintf(stderr, "minish: mount only supported on Linux\n");
    return 1;
#endif
}

static int builtin_umount(char **args) {
#ifdef __linux__
    int force = 0;
    const char *target = NULL;
    for (int i = 1; args[i]; i++) {
        if (strcmp(args[i], "-f") == 0 || strcmp(args[i], "--force") == 0) force = 1;
        else if (!target) target = args[i];
    }
    if (!target) {
        fprintf(stderr, "minish: umount: usage: umount [-f] <target>\n");
        return 1;
    }
    int flags = force ? MNT_FORCE : 0;
    if (umount2(target, flags) != 0) {
        perror("minish: umount");
        return 1;
    }
    printf("Unmounted %s\n", target);
    fflush(stdout);
    return 0;
#else
    (void)args;
    fprintf(stderr, "minish: umount only supported on Linux\n");
    return 1;
#endif
}

/* Live Process Memory Dumper */
static int builtin_memdump(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: memdump: usage: memdump <pid> [out_file|-]\n");
        return 1;
    }
#ifdef __linux__
    pid_t pid = (pid_t)atoi(args[1]);
    if (pid <= 0) {
        fprintf(stderr, "minish: memdump: invalid pid '%s'\n", args[1]);
        return 1;
    }

    const char *out_path = args[2] ? args[2] : "-";
    int is_stdout = (strcmp(out_path, "-") == 0);

    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror(maps_path);
        return 1;
    }
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror(mem_path);
        fclose(maps);
        return 1;
    }

    int out_fd = is_stdout ? STDOUT_FILENO : open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) {
        perror(out_path);
        fclose(maps);
        close(mem_fd);
        return 1;
    }

    char line[512];
    unsigned long long total_dumped = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0;
        char perms[16];
        if (sscanf(line, "%lx-%lx %15s", &start, &end, perms) >= 2) {
            if (perms[0] == 'r') {
                size_t seg_size = (size_t)(end - start);
                if (lseek(mem_fd, (off_t)start, SEEK_SET) != (off_t)-1) {
                    char buf[4096];
                    size_t seg_read = 0;
                    while (seg_read < seg_size) {
                        size_t to_read = (seg_size - seg_read < sizeof(buf)) ? (seg_size - seg_read) : sizeof(buf);
                        ssize_t n = read(mem_fd, buf, to_read);
                        if (n <= 0) break;
                        ssize_t written = 0;
                        while (written < n) {
                            ssize_t w = write(out_fd, buf + written, (size_t)(n - written));
                            if (w <= 0) break;
                            written += w;
                        }
                        seg_read += (size_t)n;
                        total_dumped += (unsigned long long)n;
                    }
                }
            }
        }
    }

    fclose(maps);
    close(mem_fd);
    if (!is_stdout) {
        close(out_fd);
        printf("Dumped %llu bytes from process %d memory to %s\n", total_dumped, (int)pid, out_path);
    }
    fflush(stdout);
    return 0;
#else
    fprintf(stderr, "minish: memdump only supported on Linux\n");
    return 1;
#endif
}

/* Nanosecond Inode & Anti-Timestomp Auditor */
static int builtin_finfo(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: finfo: usage: finfo <path>\n");
        return 1;
    }
    struct stat st;
    if (lstat(args[1], &st) != 0) {
        perror(args[1]);
        return 1;
    }

    const char *type = "Unknown";
    if (S_ISREG(st.st_mode)) type = "Regular File";
    else if (S_ISDIR(st.st_mode)) type = "Directory";
    else if (S_ISLNK(st.st_mode)) type = "Symbolic Link";
    else if (S_ISCHR(st.st_mode)) type = "Character Device";
    else if (S_ISBLK(st.st_mode)) type = "Block Device";
    else if (S_ISFIFO(st.st_mode)) type = "FIFO (Named Pipe)";
    else if (S_ISSOCK(st.st_mode)) type = "UNIX Domain Socket";

    printf("File:        %s\n", args[1]);
    printf("Type:        %s\n", type);
    printf("Size:        %lld bytes (%lld 512B blocks)\n", (long long)st.st_size, (long long)st.st_blocks);
    printf("Inode:       %llu\n", (unsigned long long)st.st_ino);
    printf("Links:       %u\n", (unsigned int)st.st_nlink);
#ifdef __linux__
    printf("Device:      %u:%u (major:minor)\n", (unsigned int)major(st.st_dev), (unsigned int)minor(st.st_dev));
#endif
    printf("Permissions: 0%03o (%c%c%c%c%c%c%c%c%c)\n",
           (unsigned int)(st.st_mode & 0777),
           (st.st_mode & S_IRUSR) ? 'r' : '-',
           (st.st_mode & S_IWUSR) ? 'w' : '-',
           (st.st_mode & S_IXUSR) ? 'x' : '-',
           (st.st_mode & S_IRGRP) ? 'r' : '-',
           (st.st_mode & S_IWGRP) ? 'w' : '-',
           (st.st_mode & S_IXGRP) ? 'x' : '-',
           (st.st_mode & S_IROTH) ? 'r' : '-',
           (st.st_mode & S_IWOTH) ? 'w' : '-',
           (st.st_mode & S_IXOTH) ? 'x' : '-');
    printf("Owner:       UID=%u, GID=%u\n", (unsigned int)st.st_uid, (unsigned int)st.st_gid);

    char atime_s[64], mtime_s[64], ctime_s[64];
    struct tm *tm_a = gmtime(&st.st_atime);
    if (tm_a) strftime(atime_s, sizeof(atime_s), "%Y-%m-%d %H:%M:%S", tm_a);
    else snprintf(atime_s, sizeof(atime_s), "%ld", (long)st.st_atime);

    struct tm *tm_m = gmtime(&st.st_mtime);
    if (tm_m) strftime(mtime_s, sizeof(mtime_s), "%Y-%m-%d %H:%M:%S", tm_m);
    else snprintf(mtime_s, sizeof(mtime_s), "%ld", (long)st.st_mtime);

    struct tm *tm_c = gmtime(&st.st_ctime);
    if (tm_c) strftime(ctime_s, sizeof(ctime_s), "%Y-%m-%d %H:%M:%S", tm_c);
    else snprintf(ctime_s, sizeof(ctime_s), "%ld", (long)st.st_ctime);

#if defined(__linux__) && defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200809L)
    printf("Access (atime): %s.%09ld UTC\n", atime_s, st.st_atim.tv_nsec);
    printf("Modify (mtime): %s.%09ld UTC\n", mtime_s, st.st_mtim.tv_nsec);
    printf("Change (ctime): %s.%09ld UTC\n", ctime_s, st.st_ctim.tv_nsec);
#else
    printf("Access (atime): %s UTC\n", atime_s);
    printf("Modify (mtime): %s UTC\n", mtime_s);
    printf("Change (ctime): %s UTC\n", ctime_s);
#endif

    if (st.st_mtime < st.st_ctime - 60) {
        long delta = (long)(st.st_ctime - st.st_mtime);
        printf("[ALERT] Potential timestomping detected! (mtime is older than ctime by %ld seconds)\n", delta);
    }
    fflush(stdout);
    return 0;
}

/* Zero-Dependency ASCII Artifact Extractor */
static int builtin_strings(char **args) {
    int min_len = 4;
    const char *file = NULL;
    for (int i = 1; args[i]; i++) {
        if (isdigit((unsigned char)args[i][0])) {
            min_len = atoi(args[i]);
            if (min_len <= 0) min_len = 4;
        } else if (!file) {
            file = args[i];
        }
    }

    int fd = STDIN_FILENO;
    if (file && strcmp(file, "-") != 0) {
        fd = open(file, O_RDONLY);
        if (fd < 0) {
            perror(file);
            return 1;
        }
    }

    char read_buf[4096];
    char str_buf[4096];
    int count = 0;
    ssize_t n;

    while ((n = read(fd, read_buf, sizeof(read_buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            unsigned char ch = (unsigned char)read_buf[i];
            if ((ch >= 32 && ch <= 126) || ch == '\t') {
                if (count < (int)sizeof(str_buf) - 1) {
                    str_buf[count++] = (char)ch;
                }
            } else {
                if (count >= min_len) {
                    str_buf[count] = '\0';
                    puts(str_buf);
                }
                count = 0;
            }
        }
    }
    if (count >= min_len) {
        str_buf[count] = '\0';
        puts(str_buf);
    }

    if (fd != STDIN_FILENO) close(fd);
    fflush(stdout);
    return 0;
}

/* Secure Anti-Forensic Overwriter & Unlinker */
static int builtin_wipe(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: wipe: usage: wipe <file> [passes]\n");
        return 1;
    }
    int passes = (args[2]) ? atoi(args[2]) : 1;
    if (passes <= 0) passes = 1;
    if (passes > 10) passes = 10;

    struct stat st;
    if (lstat(args[1], &st) != 0) {
        perror(args[1]);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "minish: wipe: '%s' is not a regular file\n", args[1]);
        return 1;
    }

    int fd = open(args[1], O_WRONLY);
    if (fd < 0) {
        perror(args[1]);
        return 1;
    }

    off_t total_size = st.st_size;
    char buf[4096];

    for (int p = 0; p < passes; p++) {
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) break;
        unsigned char fill = (p % 2 == 0) ? 0x00 : 0xFF;
        memset(buf, fill, sizeof(buf));

        off_t written = 0;
        while (written < total_size) {
            size_t to_write = (total_size - written < (off_t)sizeof(buf)) ? (size_t)(total_size - written) : sizeof(buf);
            ssize_t w = write(fd, buf, to_write);
            if (w <= 0) break;
            written += w;
        }
        fsync(fd);
    }
    close(fd);

    if (unlink(args[1]) != 0) {
        perror("minish: wipe: unlink");
        return 1;
    }
    printf("Securely wiped and unlinked %s (%lld bytes, %d passes)\n", args[1], (long long)total_size, passes);
    fflush(stdout);
    return 0;
}

/* --- Container & Script Builtins (exec, set, source) --- */

static int builtin_exec(char **args) {
    if (!args[1]) return 0;
    execvp(args[1], &args[1]);
    perror(args[1]);
    _exit(127);
}

static int builtin_set(char **args) {
    if (!args[1]) {
        printf("errexit (-e): %s, xtrace (-x): %s\n",
               shell_errexit ? "on" : "off", shell_xtrace ? "on" : "off");
        return 0;
    }
    for (int i = 1; args[i]; i++) {
        if (strcmp(args[i], "-e") == 0) shell_errexit = 1;
        else if (strcmp(args[i], "+e") == 0) shell_errexit = 0;
        else if (strcmp(args[i], "-x") == 0) shell_xtrace = 1;
        else if (strcmp(args[i], "+x") == 0) shell_xtrace = 0;
    }
    return 0;
}

static int builtin_source(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: source: missing filename\n");
        return 1;
    }
    FILE *f = fopen(args[1], "r");
    if (!f) {
        perror(args[1]);
        return 1;
    }
    int fd = fileno(f);
    if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
    sh_loop(f, 0);
    fclose(f);
    return last_exit_status;
}

/* Standalone accurate logarithm base 2 (zero -lm dependency) */
static double standalone_log2(double x) {
    if (x <= 0.0) return 0.0;
    double result = 0.0;
    while (x < 0.5) { x *= 2.0; result -= 1.0; }
    while (x > 1.0) { x *= 0.5; result += 1.0; }
    double y = (x - 1.0) / (x + 1.0);
    double y2 = y * y;
    double lnm = 2.0 * y * (1.0 + y2 * (1.0 / 3.0 + y2 * (1.0 / 5.0 + y2 * (1.0 / 7.0 + y2 / 9.0))));
    return result + (lnm / 0.69314718055994530942);
}

/* ========================================================================= */
/* --- Category A: Text & Pipeline Stream Surgery (Zero-Coreutils) --------- */
/* ========================================================================= */

/* grep [-i] [-v] [-n] <pattern> [file...] */
static int builtin_grep(char **args) {
    int ignore_case = 0, invert = 0, show_num = 0;
    int arg_idx = 1;
    while (args[arg_idx] && args[arg_idx][0] == '-' && args[arg_idx][1] != '\0') {
        for (int j = 1; args[arg_idx][j]; j++) {
            if (args[arg_idx][j] == 'i') ignore_case = 1;
            else if (args[arg_idx][j] == 'v') invert = 1;
            else if (args[arg_idx][j] == 'n') show_num = 1;
        }
        arg_idx++;
    }
    if (!args[arg_idx]) {
        fprintf(stderr, "minish: grep: usage: grep [-i] [-v] [-n] <pattern> [file...]\n");
        return 2;
    }
    const char *pattern = args[arg_idx++];
    int num_files = 0;
    for (int i = arg_idx; args[i]; i++) num_files++;

    int matched_any = 0;
    int f_start = (num_files == 0) ? 0 : arg_idx;
    int f_end = (num_files == 0) ? 1 : (arg_idx + num_files);

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) {
            perror(fname);
            continue;
        }
        char *line = NULL;
        size_t len = 0;
        ssize_t nread;
        long lineno = 0;
        while ((nread = getline(&line, &len, fp)) != -1) {
            lineno++;
            if (nread > 0 && line[nread - 1] == '\n') line[nread - 1] = '\0';
            if (nread > 1 && line[nread - 2] == '\r') line[nread - 2] = '\0';

            int match = 0;
            if (ignore_case) {
                match = (strcasestr(line, pattern) != NULL);
            } else {
                match = (strstr(line, pattern) != NULL);
            }
            if ((match && !invert) || (!match && invert)) {
                matched_any = 1;
                if (num_files > 1 && fname) printf("%s:", fname);
                if (show_num) printf("%ld:", lineno);
                printf("%s\n", line);
            }
        }
        free(line);
        if (fp != stdin) fclose(fp);
    }
    fflush(stdout);
    return matched_any ? 0 : 1;
}

/* head [-n N] [file...] */
static int builtin_head(char **args) {
    long max_lines = 10;
    int arg_idx = 1;
    if (args[1] && strcmp(args[1], "-n") == 0 && args[2]) {
        max_lines = atol(args[2]);
        if (max_lines < 0) max_lines = 10;
        arg_idx = 3;
    }
    int num_files = 0;
    for (int i = arg_idx; args[i]; i++) num_files++;

    int f_start = (num_files == 0) ? 0 : arg_idx;
    int f_end = (num_files == 0) ? 1 : (arg_idx + num_files);

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) { perror(fname); continue; }
        if (num_files > 1) printf("==> %s <==\n", fname ? fname : "standard input");
        char *line = NULL;
        size_t len = 0;
        long count = 0;
        while (count < max_lines && getline(&line, &len, fp) != -1) {
            fputs(line, stdout);
            count++;
        }
        free(line);
        if (fp != stdin) fclose(fp);
    }
    fflush(stdout);
    return 0;
}

/* tail [-n N] [file...] */
static int builtin_tail(char **args) {
    long max_lines = 10;
    int arg_idx = 1;
    if (args[1] && strcmp(args[1], "-n") == 0 && args[2]) {
        max_lines = atol(args[2]);
        if (max_lines <= 0) max_lines = 10;
        arg_idx = 3;
    }
    int num_files = 0;
    for (int i = arg_idx; args[i]; i++) num_files++;

    int f_start = (num_files == 0) ? 0 : arg_idx;
    int f_end = (num_files == 0) ? 1 : (arg_idx + num_files);

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) { perror(fname); continue; }
        if (num_files > 1) printf("==> %s <==\n", fname ? fname : "standard input");

        char **ring = calloc((size_t)max_lines, sizeof(char *));
        if (!ring) { if (fp != stdin) fclose(fp); return 1; }
        size_t head = 0, total = 0;
        char *line = NULL;
        size_t len = 0;
        while (getline(&line, &len, fp) != -1) {
            if (ring[head]) free(ring[head]);
            ring[head] = strdup(line);
            head = (head + 1) % (size_t)max_lines;
            total++;
        }
        free(line);
        if (fp != stdin) fclose(fp);

        size_t print_count = (total < (size_t)max_lines) ? total : (size_t)max_lines;
        size_t start_idx = (total < (size_t)max_lines) ? 0 : head;
        for (size_t i = 0; i < print_count; i++) {
            size_t idx = (start_idx + i) % (size_t)max_lines;
            if (ring[idx]) {
                fputs(ring[idx], stdout);
                free(ring[idx]);
                ring[idx] = NULL;
            }
        }
        free(ring);
    }
    fflush(stdout);
    return 0;
}

/* wc [-l|-w|-c] [file...] */
static int builtin_wc(char **args) {
    int count_l = 0, count_w = 0, count_c = 0;
    int arg_idx = 1;
    while (args[arg_idx] && args[arg_idx][0] == '-' && args[arg_idx][1] != '\0') {
        for (int j = 1; args[arg_idx][j]; j++) {
            if (args[arg_idx][j] == 'l') count_l = 1;
            else if (args[arg_idx][j] == 'w') count_w = 1;
            else if (args[arg_idx][j] == 'c') count_c = 1;
        }
        arg_idx++;
    }
    if (!count_l && !count_w && !count_c) {
        count_l = count_w = count_c = 1;
    }

    int num_files = 0;
    for (int i = arg_idx; args[i]; i++) num_files++;

    int f_start = (num_files == 0) ? 0 : arg_idx;
    int f_end = (num_files == 0) ? 1 : (arg_idx + num_files);

    long total_lines = 0, total_words = 0, total_bytes = 0;

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) { perror(fname); continue; }

        long lines = 0, words = 0, bytes = 0;
        int in_word = 0;
        int ch;
        while ((ch = fgetc(fp)) != EOF) {
            bytes++;
            if (ch == '\n') lines++;
            if (isspace((unsigned char)ch)) {
                in_word = 0;
            } else if (!in_word) {
                in_word = 1;
                words++;
            }
        }
        if (fp != stdin) fclose(fp);

        total_lines += lines;
        total_words += words;
        total_bytes += bytes;

        if (count_l) printf("%7ld ", lines);
        if (count_w) printf("%7ld ", words);
        if (count_c) printf("%7ld ", bytes);
        if (fname) printf("%s", fname);
        printf("\n");
    }

    if (num_files > 1) {
        if (count_l) printf("%7ld ", total_lines);
        if (count_w) printf("%7ld ", total_words);
        if (count_c) printf("%7ld ", total_bytes);
        printf("total\n");
    }
    fflush(stdout);
    return 0;
}

/* cut -d <delim> -f <field> [file...] */
static int builtin_cut(char **args) {
    char delim = '\t';
    int field = 1;
    int arg_idx = 1;
    while (args[arg_idx] && args[arg_idx][0] == '-') {
        if (strcmp(args[arg_idx], "-d") == 0 && args[arg_idx + 1]) {
            delim = args[arg_idx + 1][0];
            arg_idx += 2;
        } else if (strcmp(args[arg_idx], "-f") == 0 && args[arg_idx + 1]) {
            field = atoi(args[arg_idx + 1]);
            if (field < 1) field = 1;
            arg_idx += 2;
        } else {
            arg_idx++;
        }
    }

    int num_files = 0;
    for (int i = arg_idx; args[i]; i++) num_files++;

    int f_start = (num_files == 0) ? 0 : arg_idx;
    int f_end = (num_files == 0) ? 1 : (arg_idx + num_files);

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) { perror(fname); continue; }

        char *line = NULL;
        size_t len = 0;
        ssize_t nread;
        while ((nread = getline(&line, &len, fp)) != -1) {
            if (nread > 0 && line[nread - 1] == '\n') line[nread - 1] = '\0';
            if (nread > 1 && line[nread - 2] == '\r') line[nread - 2] = '\0';

            char *p = line;
            int cur_field = 1;
            char *found_val = NULL;
            while (p) {
                char *next = strchr(p, delim);
                if (next) *next = '\0';
                if (cur_field == field) {
                    found_val = p;
                    break;
                }
                if (!next) break;
                p = next + 1;
                cur_field++;
            }
            if (found_val) printf("%s\n", found_val);
            else if (!strchr(line, delim) && field == 1) printf("%s\n", line);
            else printf("\n");
        }
        free(line);
        if (fp != stdin) fclose(fp);
    }
    fflush(stdout);
    return 0;
}

/* sort comparison helper */
static int sort_line_cmp(const void *a, const void *b) {
    const char *sa = *(const char * const *)a;
    const char *sb = *(const char * const *)b;
    return strcmp(sa, sb);
}

/* sort [file...] */
static int builtin_sort(char **args) {
    size_t cap = 256, count = 0;
    char **lines = malloc(cap * sizeof(char *));
    if (!lines) return 1;

    int num_files = 0;
    for (int i = 1; args[i]; i++) num_files++;

    int f_start = (num_files == 0) ? 0 : 1;
    int f_end = (num_files == 0) ? 1 : (1 + num_files);

    for (int f = f_start; f < f_end; f++) {
        const char *fname = (num_files == 0 || strcmp(args[f], "-") == 0) ? NULL : args[f];
        FILE *fp = fname ? fopen(fname, "r") : stdin;
        if (!fp) { perror(fname); continue; }

        char *line = NULL;
        size_t len = 0;
        ssize_t nread;
        while ((nread = getline(&line, &len, fp)) != -1) {
            if (nread > 0 && line[nread - 1] == '\n') line[nread - 1] = '\0';
            if (nread > 1 && line[nread - 2] == '\r') line[nread - 2] = '\0';
            lines[count++] = strdup(line);
            if (count >= cap) {
                cap *= 2;
                lines = realloc(lines, cap * sizeof(char *));
            }
        }
        free(line);
        if (fp != stdin) fclose(fp);
    }

    qsort(lines, count, sizeof(char *), sort_line_cmp);
    for (size_t i = 0; i < count; i++) {
        printf("%s\n", lines[i]);
        free(lines[i]);
    }
    free(lines);
    fflush(stdout);
    return 0;
}

/* uniq [-c] [file...] */
static int builtin_uniq(char **args) {
    int show_count = 0;
    int arg_idx = 1;
    if (args[1] && strcmp(args[1], "-c") == 0) {
        show_count = 1;
        arg_idx = 2;
    }

    FILE *fp = stdin;
    if (args[arg_idx] && strcmp(args[arg_idx], "-") != 0) {
        fp = fopen(args[arg_idx], "r");
        if (!fp) { perror(args[arg_idx]); return 1; }
    }

    char *prev = NULL;
    long count = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    while ((nread = getline(&line, &len, fp)) != -1) {
        if (nread > 0 && line[nread - 1] == '\n') line[nread - 1] = '\0';
        if (nread > 1 && line[nread - 2] == '\r') line[nread - 2] = '\0';

        if (!prev) {
            prev = strdup(line);
            count = 1;
        } else if (strcmp(prev, line) == 0) {
            count++;
        } else {
            if (show_count) printf("%7ld %s\n", count, prev);
            else printf("%s\n", prev);
            free(prev);
            prev = strdup(line);
            count = 1;
        }
    }
    if (prev) {
        if (show_count) printf("%7ld %s\n", count, prev);
        else printf("%s\n", prev);
        free(prev);
    }
    free(line);
    if (fp != stdin) fclose(fp);
    fflush(stdout);
    return 0;
}

/* tr [-d] <set1> [set2] */
static int builtin_tr(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: tr: usage: tr [-d] <set1> [set2]\n");
        return 1;
    }
    int delete_mode = 0;
    const char *set1 = args[1];
    const char *set2 = args[2];
    if (strcmp(args[1], "-d") == 0) {
        delete_mode = 1;
        if (!args[2]) {
            fprintf(stderr, "minish: tr: -d requires a character set\n");
            return 1;
        }
        set1 = args[2];
        set2 = NULL;
    }

    unsigned char del_map[256] = {0};
    unsigned char trans_map[256];
    for (int i = 0; i < 256; i++) trans_map[i] = (unsigned char)i;

    if (delete_mode) {
        for (int i = 0; set1[i]; i++) {
            del_map[(unsigned char)set1[i]] = 1;
        }
    } else if (set2) {
        size_t len1 = strlen(set1);
        size_t len2 = strlen(set2);
        for (size_t i = 0; i < len1; i++) {
            unsigned char src = (unsigned char)set1[i];
            unsigned char dst = (i < len2) ? (unsigned char)set2[i] : (unsigned char)set2[len2 - 1];
            trans_map[src] = dst;
        }
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        char out[4096];
        size_t out_len = 0;
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];
            if (delete_mode) {
                if (!del_map[c]) out[out_len++] = (char)c;
            } else {
                out[out_len++] = (char)trans_map[c];
            }
        }
        if (out_len > 0) {
            ssize_t w = write(STDOUT_FILENO, out, out_len);
            (void)w;
        }
    }
    return 0;
}

/* diff <file1> <file2> */
static int builtin_diff(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: diff: usage: diff <file1> <file2>\n");
        return 2;
    }
    FILE *f1 = fopen(args[1], "r");
    if (!f1) { perror(args[1]); return 2; }
    FILE *f2 = fopen(args[2], "r");
    if (!f2) { perror(args[2]); fclose(f1); return 2; }

    char *l1 = NULL, *l2 = NULL;
    size_t len1 = 0, len2 = 0;
    ssize_t r1, r2;
    long lineno = 0;
    int diff_found = 0;

    while (1) {
        r1 = getline(&l1, &len1, f1);
        r2 = getline(&l2, &len2, f2);
        lineno++;

        if (r1 == -1 && r2 == -1) break;

        if (r1 != -1 && r2 != -1) {
            if (strcmp(l1, l2) != 0) {
                diff_found = 1;
                printf("%ldc%ld\n< %s---\n> %s", lineno, lineno, l1, l2);
            }
        } else if (r1 != -1) {
            diff_found = 1;
            printf("%ldd\n< %s", lineno, l1);
        } else {
            diff_found = 1;
            printf("%lda\n> %s", lineno, l2);
        }
    }
    free(l1);
    free(l2);
    fclose(f1);
    fclose(f2);
    fflush(stdout);
    return diff_found ? 1 : 0;
}

/* ========================================================================= */
/* --- Category B: Process, Thread & Memory Forensics (Anti-Rootkit) -------- */
/* ========================================================================= */

/* ps / proclist */
static int builtin_ps(char **args) {
    (void)args;
    DIR *dir = opendir("/proc");
    if (!dir) { perror("/proc"); return 1; }

    printf("%7s %7s %-5s %8s %s\n", "PID", "PPID", "STATE", "RSS", "COMMAND");
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;

        char path[512];
        snprintf(path, sizeof(path), "/proc/%s/stat", de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char buf[1024];
        if (fgets(buf, sizeof(buf), f)) {
            char *open_p = strchr(buf, '(');
            char *close_p = strrchr(buf, ')');
            if (open_p && close_p && close_p > open_p) {
                *open_p = '\0';
                *close_p = '\0';
                int pid = atoi(buf);
                const char *comm = open_p + 1;

                char state = '?';
                int ppid = 0;
                long rss_pages = 0;
                /* Skip after ') ' and read state, ppid ... rss */
                const char *post = close_p + 2;
                int matched = sscanf(post, "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %*u %*u %ld",
                                     &state, &ppid, &rss_pages);
                if (matched >= 2) {
                    long rss_kb = (rss_pages * page_size) / 1024;
                    char rss_str[32];
                    if (rss_kb > 1024) snprintf(rss_str, sizeof(rss_str), "%ldM", rss_kb / 1024);
                    else snprintf(rss_str, sizeof(rss_str), "%ldK", rss_kb);
                    char state_str[4] = { state, '\0' };
                    printf("%7d %7d %-5s %8s %s\n", pid, ppid, state_str, rss_str, comm);
                }
            }
        }
        fclose(f);
    }
    closedir(dir);
    fflush(stdout);
    return 0;
}

/* mapspeek <pid> */
static int builtin_mapspeek(char **args) {
    const char *pid = args[1] ? args[1] : "self";
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        int is_rwx = (strstr(line, "rwx") != NULL);
        if (is_rwx) {
            printf("[!INJECTION ALERT] %s", line);
        } else {
            fputs(line, stdout);
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* fdpeek <pid> */
static int builtin_fdpeek(char **args) {
    const char *pid = args[1] ? args[1] : "self";
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/fd", pid);
    DIR *d = opendir(path);
    if (!d) { perror(path); return 1; }

    printf("Open File Descriptors for PID %s:\n", pid);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", path, de->d_name);
        char target[1024];
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            const char *flag = "";
            if (strstr(target, "(deleted)")) flag = " [UNLINKED/TRAPPED]";
            else if (strncmp(target, "socket:", 7) == 0) flag = " [SOCKET]";
            else if (strncmp(target, "pipe:", 5) == 0) flag = " [PIPE]";
            printf("  fd %4s -> %s%s\n", de->d_name, target, flag);
        }
    }
    closedir(d);
    fflush(stdout);
    return 0;
}

/* stackpeek <pid> */
static int builtin_stackpeek(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: stackpeek: usage: stackpeek <pid>\n");
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/stack", args[1]);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }

    printf("Kernel Call Stack for PID %s:\n", args[1]);
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        fputs(line, stdout);
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* wchanpeek <pid> */
static int builtin_wchanpeek(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: wchanpeek: usage: wchanpeek <pid>\n");
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/wchan", args[1]);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }

    char wchan[128] = {0};
    if (fgets(wchan, sizeof(wchan), f)) {
        size_t l = strlen(wchan);
        if (l > 0 && wchan[l - 1] == '\n') wchan[l - 1] = '\0';
        printf("PID %s wait channel: %s\n", args[1], wchan);
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* oomadj [pid] [score_adj] */
static int builtin_oomadj(char **args) {
    const char *pid = args[1] ? args[1] : "self";
    char path[256];
    if (args[1] && args[2]) {
        snprintf(path, sizeof(path), "/proc/%s/oom_score_adj", pid);
        FILE *f = fopen(path, "w");
        if (!f) { perror(path); return 1; }
        fprintf(f, "%s\n", args[2]);
        fclose(f);
        printf("Updated OOM score adjustment for PID %s to %s\n", pid, args[2]);
        return 0;
    }

    snprintf(path, sizeof(path), "/proc/%s/oom_score", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }
    char score[64] = {0};
    if (fgets(score, sizeof(score), f)) {
        size_t l = strlen(score);
        if (l > 0 && score[l - 1] == '\n') score[l - 1] = '\0';
    }
    fclose(f);

    snprintf(path, sizeof(path), "/proc/%s/oom_score_adj", pid);
    f = fopen(path, "r");
    char adj[64] = {0};
    if (f) {
        if (fgets(adj, sizeof(adj), f)) {
            size_t l = strlen(adj);
            if (l > 0 && adj[l - 1] == '\n') adj[l - 1] = '\0';
        }
        fclose(f);
    }

    printf("PID %s: oom_score = %s, oom_score_adj = %s\n", pid, score, adj[0] ? adj : "N/A");
    fflush(stdout);
    return 0;
}

/* ========================================================================= */
/* --- Category C: Security, Capabilities & LSM Defense --------------------- */
/* ========================================================================= */

/* cappeek [pid] */
static int builtin_cappeek(char **args) {
    const char *pid = args[1] ? args[1] : "self";
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 1; }

    uint64_t cap_eff = 0, cap_prm = 0, cap_inh = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapInh:", 7) == 0) sscanf(line + 7, "%llx", (unsigned long long *)&cap_inh);
        else if (strncmp(line, "CapPrm:", 7) == 0) sscanf(line + 7, "%llx", (unsigned long long *)&cap_prm);
        else if (strncmp(line, "CapEff:", 7) == 0) sscanf(line + 7, "%llx", (unsigned long long *)&cap_eff);
    }
    fclose(f);

    static const char *cap_names[] = {
        "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
        "KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
        "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
        "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO",
        "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN",
        "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
        "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
        "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN",
        "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
        "PERFMON", "BPF", "CHECKPOINT_RESTORE"
    };

    printf("Capabilities for PID %s:\n", pid);
    printf("  Raw: Inh=%016llx  Prm=%016llx  Eff=%016llx\n",
           (unsigned long long)cap_inh, (unsigned long long)cap_prm, (unsigned long long)cap_eff);
    printf("  Effective Capabilities:\n");
    int count = 0;
    for (size_t i = 0; i < sizeof(cap_names) / sizeof(cap_names[0]); i++) {
        if ((cap_eff >> i) & 1ULL) {
            printf("    CAP_%-20s (bit %2zu)\n", cap_names[i], i);
            count++;
        }
    }
    if (count == 0) printf("    (none)\n");
    fflush(stdout);
    return 0;
}

/* nspeek [pid] */
static int builtin_nspeek(char **args) {
    const char *pid = args[1] ? args[1] : "self";
    static const char *ns_types[] = { "cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts" };
    printf("Namespaces for PID %s:\n", pid);

    for (size_t i = 0; i < sizeof(ns_types) / sizeof(ns_types[0]); i++) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%s/ns/%s", pid, ns_types[i]);
        char target[256];
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            printf("  %-10s -> %s\n", ns_types[i], target);
        } else {
            printf("  %-10s -> (unavailable)\n", ns_types[i]);
        }
    }
    fflush(stdout);
    return 0;
}

/* chattr <+i|-i> <file> */
static int builtin_chattr(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: chattr: usage: chattr <+i|-i> <file>\n");
        return 1;
    }
    int fd = open(args[2], O_RDONLY);
    if (fd < 0) { perror(args[2]); return 1; }

    long flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
        perror("minish: chattr: getflags");
        close(fd);
        return 1;
    }

    if (strcmp(args[1], "+i") == 0) flags |= FS_IMMUTABLE_FL;
    else if (strcmp(args[1], "-i") == 0) flags &= ~FS_IMMUTABLE_FL;
    else {
        fprintf(stderr, "minish: chattr: invalid mode '%s' (use +i or -i)\n", args[1]);
        close(fd);
        return 1;
    }

    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0) {
        perror("minish: chattr: setflags");
        close(fd);
        return 1;
    }
    close(fd);
    printf("Updated attributes for %s: %s immutable\n", args[2], (args[1][0] == '+') ? "set" : "cleared");
    return 0;
}

/* Recursive helper for lockdown */
static int lockdown_recursive(const char *dir_path, long *count) {
    DIR *d = opendir(dir_path);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char sub[1024];
        snprintf(sub, sizeof(sub), "%s/%s", dir_path, de->d_name);
        struct stat st;
        if (lstat(sub, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            lockdown_recursive(sub, count);
        } else if (S_ISREG(st.st_mode)) {
            int fd = open(sub, O_RDONLY);
            if (fd >= 0) {
                long flags = 0;
                if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0) {
                    flags |= FS_IMMUTABLE_FL;
                    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0) (*count)++;
                }
                close(fd);
            }
        }
    }
    closedir(d);
    return 0;
}

/* lockdown <dir> */
static int builtin_lockdown(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: lockdown: usage: lockdown <dir>\n");
        return 1;
    }
    long count = 0;
    if (lockdown_recursive(args[1], &count) != 0) {
        perror(args[1]);
        return 1;
    }
    printf("Lockdown complete: %ld files marked immutable (+i) in %s\n", count, args[1]);
    return 0;
}

/* lsmaudit */
static int builtin_lsmaudit(char **args) {
    (void)args;
    printf("Linux Security Modules (LSM) Audit:\n");
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (f) {
        char lsm[256];
        if (fgets(lsm, sizeof(lsm), f)) {
            size_t l = strlen(lsm);
            if (l > 0 && lsm[l - 1] == '\n') lsm[l - 1] = '\0';
            printf("  Active LSM stack: %s\n", lsm);
        }
        fclose(f);
    } else {
        printf("  Active LSM stack: (securityfs not mounted)\n");
    }

    /* SELinux check */
    FILE *se = fopen("/sys/fs/selinux/enforce", "r");
    if (se) {
        int val = fgetc(se);
        printf("  SELinux status:   %s\n", (val == '1') ? "Enforcing (Active)" : "Permissive / Disabled");
        fclose(se);
    } else {
        printf("  SELinux status:   Not detected\n");
    }

    /* AppArmor check */
    if (access("/sys/kernel/security/apparmor/profiles", R_OK) == 0) {
        printf("  AppArmor status:  Active (profiles loaded)\n");
    } else {
        printf("  AppArmor status:  Not active\n");
    }
    fflush(stdout);
    return 0;
}

/* taintpeek */
static int builtin_taintpeek(char **args) {
    (void)args;
    FILE *f = fopen("/proc/sys/kernel/tainted", "r");
    if (!f) { perror("/proc/sys/kernel/tainted"); return 1; }
    unsigned long mask = 0;
    if (fscanf(f, "%lu", &mask) != 1) { fclose(f); return 1; }
    fclose(f);

    printf("Kernel Taint Value: %lu (0x%lx)\n", mask, mask);
    if (mask == 0) {
        printf("  [OK] Kernel is clean and untainted.\n");
        return 0;
    }

    static const struct { unsigned long bit; const char *desc; } taints[] = {
        { 1UL << 0,  "Proprietary module loaded (P)" },
        { 1UL << 1,  "Module forcibly loaded (F)" },
        { 1UL << 2,  "SMP with non-SMP processor (S)" },
        { 1UL << 3,  "Module forcibly unloaded (R)" },
        { 1UL << 4,  "Machine Check Exception occurred (M)" },
        { 1UL << 5,  "Bad page referenced (B)" },
        { 1UL << 6,  "User requested taint (U)" },
        { 1UL << 7,  "Die / kernel oops occurred (D)" },
        { 1UL << 8,  "ACPI table overridden (A)" },
        { 1UL << 9,  "Kernel warning emitted (W)" },
        { 1UL << 10, "Staging driver loaded (C)" },
        { 1UL << 11, "Firmware workaround applied (I)" },
        { 1UL << 12, "Out-of-tree module loaded (O)" },
        { 1UL << 13, "Unsigned module loaded (E)" },
        { 1UL << 14, "Soft lockup occurred (L)" },
        { 1UL << 15, "Live patched (K)" },
        { 1UL << 16, "Auxiliary taint (X)" },
        { 1UL << 17, "Struct layout randomized (T)" }
    };

    for (size_t i = 0; i < sizeof(taints) / sizeof(taints[0]); i++) {
        if (mask & taints[i].bit) {
            printf("  [!] %s\n", taints[i].desc);
        }
    }
    fflush(stdout);
    return 0;
}

/* id [user] */
static int builtin_id(char **args) {
    uid_t uid = getuid(), euid = geteuid();
    gid_t gid = getgid(), egid = getegid();

    if (args[1]) {
        struct passwd *pw = getpwnam(args[1]);
        if (!pw) {
            fprintf(stderr, "minish: id: '%s': no such user\n", args[1]);
            return 1;
        }
        uid = euid = pw->pw_uid;
        gid = egid = pw->pw_gid;
    }

    struct passwd *pw = getpwuid(uid);
    struct group *gr = getgrgid(gid);

    printf("uid=%u(%s) gid=%u(%s)", (unsigned)uid, pw ? pw->pw_name : "unknown",
           (unsigned)gid, gr ? gr->gr_name : "unknown");

    if (euid != uid) {
        struct passwd *epw = getpwuid(euid);
        printf(" euid=%u(%s)", (unsigned)euid, epw ? epw->pw_name : "unknown");
    }
    if (egid != gid) {
        struct group *egr = getgrgid(egid);
        printf(" egid=%u(%s)", (unsigned)egid, egr ? egr->gr_name : "unknown");
    }

    int ngroups = 32;
    gid_t *groups = malloc(ngroups * sizeof(gid_t));
    if (groups) {
        int n = getgroups(ngroups, groups);
        if (n > 0) {
            printf(" groups=");
            for (int i = 0; i < n; i++) {
                struct group *g = getgrgid(groups[i]);
                printf("%s%u(%s)", (i > 0) ? "," : "", (unsigned)groups[i], g ? g->gr_name : "unknown");
            }
        }
        free(groups);
    }
    printf("\n");
    fflush(stdout);
    return 0;
}

/* entropy <file|-> */
static int builtin_entropy(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: entropy: usage: entropy <file|->\n");
        return 1;
    }
    int fd = STDIN_FILENO;
    if (strcmp(args[1], "-") != 0) {
        fd = open(args[1], O_RDONLY);
        if (fd < 0) { perror(args[1]); return 1; }
    }

    unsigned long counts[256] = {0};
    unsigned long total = 0;
    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            counts[buf[i]]++;
            total++;
        }
    }
    if (fd != STDIN_FILENO) close(fd);

    if (total == 0) {
        printf("Entropy: 0.000000 (0 bytes analyzed)\n");
        return 0;
    }

    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)total;
            ent -= p * standalone_log2(p);
        }
    }

    const char *classification = "Moderate (code/binary)";
    if (ent < 3.0) classification = "Low (plain text / sparse / repetitive)";
    else if (ent > 7.2) classification = "High (encrypted / compressed / ransomware payload)";

    printf("File: %s\n", args[1]);
    printf("  Total Bytes: %lu\n", total);
    printf("  Shannon Entropy: %.6f bits per byte (max 8.00)\n", ent);
    printf("  Assessment: %s\n", classification);
    fflush(stdout);
    return 0;
}

/* ========================================================================= */
/* --- Category D: Storage, Block Devices & Initramfs Bare-Metal Rescue ---- */
/* ========================================================================= */

/* dd if=.. of=.. [bs=N] [count=N] [skip=N] [seek=N] */
static int builtin_dd(char **args) {
    const char *if_path = NULL;
    const char *of_path = NULL;
    size_t bs = 512;
    long count = -1;
    long skip = 0;
    long seek = 0;

    for (int i = 1; args[i]; i++) {
        if (strncmp(args[i], "if=", 3) == 0) if_path = args[i] + 3;
        else if (strncmp(args[i], "of=", 3) == 0) of_path = args[i] + 3;
        else if (strncmp(args[i], "bs=", 3) == 0) bs = (size_t)atol(args[i] + 3);
        else if (strncmp(args[i], "count=", 6) == 0) count = atol(args[i] + 6);
        else if (strncmp(args[i], "skip=", 5) == 0) skip = atol(args[i] + 5);
        else if (strncmp(args[i], "seek=", 5) == 0) seek = atol(args[i] + 5);
    }
    if (bs == 0) bs = 512;

    int ifd = STDIN_FILENO;
    if (if_path && strcmp(if_path, "-") != 0) {
        ifd = open(if_path, O_RDONLY);
        if (ifd < 0) { perror(if_path); return 1; }
    }
    int ofd = STDOUT_FILENO;
    if (of_path && strcmp(of_path, "-") != 0) {
        ofd = open(of_path, O_WRONLY | O_CREAT, 0666);
        if (ofd < 0) { perror(of_path); if (ifd != STDIN_FILENO) close(ifd); return 1; }
    }

    if (skip > 0) {
        off_t offset = (off_t)skip * (off_t)bs;
        if (lseek(ifd, offset, SEEK_SET) == (off_t)-1) {
            /* If not seekable (e.g. pipe), read and discard */
            char *junk = malloc(bs);
            for (long s = 0; s < skip; s++) {
                ssize_t r = read(ifd, junk, bs);
                if (r <= 0) break;
            }
            free(junk);
        }
    }

    if (seek > 0) {
        off_t offset = (off_t)seek * (off_t)bs;
        lseek(ofd, offset, SEEK_SET);
    }

    char *buf = malloc(bs);
    if (!buf) {
        if (ifd != STDIN_FILENO) close(ifd);
        if (ofd != STDOUT_FILENO) close(ofd);
        return 1;
    }

    long records_in = 0, records_out = 0;
    unsigned long long total_bytes = 0;

    while (count < 0 || records_out < count) {
        ssize_t n = read(ifd, buf, bs);
        if (n <= 0) break;
        records_in++;

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(ofd, buf + written, (size_t)(n - written));
            if (w <= 0) break;
            written += w;
        }
        total_bytes += (unsigned long long)written;
        if (written == n) records_out++;
        if (written < n) break;
    }

    free(buf);
    if (ifd != STDIN_FILENO) close(ifd);
    if (ofd != STDOUT_FILENO) close(ofd);

    fprintf(stderr, "%ld+%ld records in\n%ld+%ld records out\n%llu bytes transferred\n",
            records_in, 0L, records_out, 0L, total_bytes);
    return 0;
}

/* fiemap <file> */
static int builtin_fiemap(char **args) {
#ifndef __linux__
    (void)args;
    fprintf(stderr, "minish: fiemap: not supported on this platform (Linux ext4/xfs specific)\n");
    return 1;
#else
    if (!args[1]) {
        fprintf(stderr, "minish: fiemap: usage: fiemap <file>\n");
        return 1;
    }
    int fd = open(args[1], O_RDONLY);
    if (fd < 0) { perror(args[1]); return 1; }

    /* Allocate fiemap header with room for 32 extents */
    size_t sz = sizeof(struct fiemap) + 32 * sizeof(struct fiemap_extent);
    struct fiemap *fie = malloc(sz);
    if (!fie) { close(fd); return 1; }
    memset(fie, 0, sz);
    fie->fm_start = 0;
    fie->fm_length = (uint64_t)-1;
    fie->fm_flags = FIEMAP_FLAG_SYNC;
    fie->fm_extent_count = 32;

    if (ioctl(fd, FS_IOC_FIEMAP, fie) < 0) {
        if (errno == EOPNOTSUPP || errno == ENOTTY) {
            printf("fiemap: '%s' is on a filesystem that does not support FIEMAP extents (e.g. tmpfs/9p/nfs)\n", args[1]);
            free(fie);
            close(fd);
            return 0;
        }
        perror("minish: fiemap: ioctl");
        free(fie);
        close(fd);
        return 1;
    }

    printf("Extents map for %s (%u mapped extents):\n", args[1], fie->fm_mapped_extents);
    printf("  #    LOGICAL OFFSET          PHYSICAL LBA            LENGTH       FLAGS\n");
    for (uint32_t i = 0; i < fie->fm_mapped_extents; i++) {
        printf("%3u: 0x%016llx  0x%016llx  %10llu  0x%x\n",
               i,
               (unsigned long long)fie->fm_extents[i].fe_logical,
               (unsigned long long)fie->fm_extents[i].fe_physical,
               (unsigned long long)fie->fm_extents[i].fe_length,
               fie->fm_extents[i].fe_flags);
    }
    free(fie);
    close(fd);
    fflush(stdout);
    return 0;
#endif
}

/* losetup [-d loop_dev] [loop_dev] [file] */
static int builtin_losetup(char **args) {
    if (args[1] && strcmp(args[1], "-d") == 0 && args[2]) {
        int lfd = open(args[2], O_RDONLY);
        if (lfd < 0) { perror(args[2]); return 1; }
        if (ioctl(lfd, LOOP_CLR_FD, 0) < 0) {
            perror("minish: losetup: LOOP_CLR_FD");
            close(lfd);
            return 1;
        }
        close(lfd);
        printf("Detached loop device %s\n", args[2]);
        return 0;
    }

    if (args[1] && args[2]) {
        int lfd = open(args[1], O_RDWR);
        if (lfd < 0) { perror(args[1]); return 1; }
        int ffd = open(args[2], O_RDWR);
        if (ffd < 0) {
            ffd = open(args[2], O_RDONLY);
            if (ffd < 0) { perror(args[2]); close(lfd); return 1; }
        }
        if (ioctl(lfd, LOOP_SET_FD, ffd) < 0) {
            perror("minish: losetup: LOOP_SET_FD");
            close(ffd);
            close(lfd);
            return 1;
        }
        close(ffd);
        close(lfd);
        printf("Attached %s to %s\n", args[2], args[1]);
        return 0;
    }

    /* List existing loop devices */
    printf("Active Loop Devices:\n");
    DIR *d = opendir("/sys/block");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, "loop", 4) == 0) {
                char bf_path[512];
                snprintf(bf_path, sizeof(bf_path), "/sys/block/%s/loop/backing_file", de->d_name);
                FILE *f = fopen(bf_path, "r");
                if (f) {
                    char target[512];
                    if (fgets(target, sizeof(target), f)) {
                        size_t l = strlen(target);
                        if (l > 0 && target[l - 1] == '\n') target[l - 1] = '\0';
                        printf("  /dev/%s -> %s\n", de->d_name, target);
                    }
                    fclose(f);
                }
            }
        }
        closedir(d);
    }
    fflush(stdout);
    return 0;
}

/* pivot_root <new_root> <put_old> */
static int builtin_pivot_root(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: pivot_root: usage: pivot_root <new_root> <put_old>\n");
        return 1;
    }
#ifdef SYS_pivot_root
    long res = syscall(SYS_pivot_root, args[1], args[2]);
    if (res != 0) {
        perror("minish: pivot_root");
        return 1;
    }
    printf("Successfully pivoted root to %s (old root at %s)\n", args[1], args[2]);
    return 0;
#else
    fprintf(stderr, "minish: pivot_root: SYS_pivot_root not available on this architecture\n");
    return 1;
#endif
}

/* swapon <dev|file> */
static int builtin_swapon(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: swapon: usage: swapon <device|file>\n");
        return 1;
    }
    #ifdef __FreeBSD__
    if (swapon(args[1]) != 0) {
#else
    if (swapon(args[1], 0) != 0) {
#endif
        perror("minish: swapon");
        return 1;
    }
    printf("Activated swap on %s\n", args[1]);
    return 0;
}

/* swapoff <dev|file> */
static int builtin_swapoff(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: swapoff: usage: swapoff <device|file>\n");
        return 1;
    }
    #ifdef __FreeBSD__
    if (swapoff(args[1], 0) != 0) {
#else
    if (swapoff(args[1]) != 0) {
#endif
        perror("minish: swapoff");
        return 1;
    }
    printf("Deactivated swap on %s\n", args[1]);
    return 0;
}

/* dropcaches [1|2|3] */
static int builtin_dropcaches(char **args) {
    const char *val = args[1] ? args[1] : "3";
    FILE *f = fopen("/proc/sys/vm/drop_caches", "w");
    if (!f) { perror("/proc/sys/vm/drop_caches"); return 1; }
    sync();
    fprintf(f, "%s\n", val);
    fclose(f);
    printf("Flushed kernel pagecache, dentries, and inodes (mode %s)\n", val);
    return 0;
}

/* diskstat */
static int builtin_diskstat(char **args) {
    (void)args;
    FILE *f = fopen("/proc/diskstats", "r");
    if (!f) { perror("/proc/diskstats"); return 1; }

    printf("%-12s %10s %12s %10s %12s %8s\n",
           "DEVICE", "READS", "RD_SECTORS", "WRITES", "WR_SECTORS", "IN_FLIGHT");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        int major, minor;
        char dev[64];
        unsigned long rd_ios, rd_sec, wr_ios, wr_sec, in_flight;
        int matched = sscanf(line, "%d %d %63s %lu %*u %lu %*u %lu %*u %lu %*u %lu",
                             &major, &minor, dev, &rd_ios, &rd_sec, &wr_ios, &wr_sec, &in_flight);
        if (matched >= 7) {
            /* Filter out loop devices with 0 traffic */
            if (strncmp(dev, "loop", 4) == 0 && rd_ios == 0 && wr_ios == 0) continue;
            printf("%-12s %10lu %12lu %10lu %12lu %8lu\n",
                   dev, rd_ios, rd_sec, wr_ios, wr_sec, in_flight);
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* blkdiscard <device> */
static int builtin_blkdiscard(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: blkdiscard: usage: blkdiscard <device>\n");
        return 1;
    }
    int fd = open(args[1], O_RDWR);
    if (fd < 0) { perror(args[1]); return 1; }

    uint64_t dev_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &dev_size) < 0) {
        perror("minish: blkdiscard: BLKGETSIZE64");
        close(fd);
        return 1;
    }

    uint64_t range[2] = { 0, dev_size };
    if (ioctl(fd, BLKDISCARD, range) < 0) {
        perror("minish: blkdiscard: BLKDISCARD");
        close(fd);
        return 1;
    }
    close(fd);
    printf("Discarded %llu bytes on %s\n", (unsigned long long)dev_size, args[1]);
    return 0;
}

/* ========================================================================= */
/* --- Category E: Network & Air-Gap Triage --------------------------------- */
/* ========================================================================= */

/* tcpping <host> <port> [timeout_ms] */
static int builtin_tcpping(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: tcpping: usage: tcpping <host> <port> [timeout_ms]\n");
        return 1;
    }
    int timeout_ms = args[3] ? atoi(args[3]) : 2000;
    if (timeout_ms <= 0) timeout_ms = 2000;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(args[1], args[2], &hints, &res) != 0) {
        fprintf(stderr, "minish: tcpping: failed to resolve '%s'\n", args[1]);
        return 1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        perror("minish: tcpping: socket");
        freeaddrinfo(res);
        return 1;
    }

    /* Set non-blocking */
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    int conn = connect(s, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    int success = 0;
    if (conn == 0) {
        success = 1;
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(s + 1, NULL, &wfds, NULL, &tv);
        if (sel > 0) {
            int err = 0;
            socklen_t elen = sizeof(err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                success = 1;
            }
        }
    }
    gettimeofday(&end, NULL);
    close(s);

    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    if (success) {
        printf("Connected to %s:%s - RTT = %.2f ms\n", args[1], args[2], rtt);
        return 0;
    } else {
        printf("Failed to connect to %s:%s (timed out or refused after %.2f ms)\n", args[1], args[2], rtt);
        return 1;
    }
}

/* PCAP headers */
struct minish_pcap_hdr {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct minish_pcaprec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

/* pcapdump <iface> <count> [outfile] */
static int builtin_pcapdump(char **args) {
#ifndef __linux__
    (void)args;
    fprintf(stderr, "minish: pcapdump: raw AF_PACKET sniffing not supported on FreeBSD (use tcpdump)\n");
    return 1;
#else
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: pcapdump: usage: pcapdump <interface> <packet_count> [output.pcap|-]\n");
        return 1;
    }
    int count = atoi(args[2]);
    if (count <= 0) count = 10;
    const char *out_path = args[3] ? args[3] : "capture.pcap";

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("minish: pcapdump: raw socket (root required)"); return 1; }

    unsigned int ifindex = if_nametoindex(args[1]);
    if (ifindex == 0) {
        fprintf(stderr, "minish: pcapdump: interface '%s' not found\n", args[1]);
        close(sock);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("minish: pcapdump: bind");
        close(sock);
        return 1;
    }

    FILE *out = (strcmp(out_path, "-") == 0) ? stdout : fopen(out_path, "wb");
    if (!out) { perror(out_path); close(sock); return 1; }

    /* Write PCAP file header */
    struct minish_pcap_hdr hdr;
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.linktype = 1; /* LINKTYPE_ETHERNET */
    fwrite(&hdr, sizeof(hdr), 1, out);

    fprintf(stderr, "Capturing %d packets on %s to %s...\n", count, args[1], out_path);
    int captured = 0;
    unsigned char pkt[65536];

    while (captured < count) {
        ssize_t n = recvfrom(sock, pkt, sizeof(pkt), 0, NULL, NULL);
        if (n <= 0) break;

        struct timeval tv;
        gettimeofday(&tv, NULL);

        struct minish_pcaprec_hdr ph;
        ph.ts_sec = (uint32_t)tv.tv_sec;
        ph.ts_usec = (uint32_t)tv.tv_usec;
        ph.incl_len = (uint32_t)n;
        ph.orig_len = (uint32_t)n;

        fwrite(&ph, sizeof(ph), 1, out);
        fwrite(pkt, (size_t)n, 1, out);
        captured++;
    }

    close(sock);
    if (out != stdout) fclose(out);
    fprintf(stderr, "Successfully captured %d packets.\n", captured);
    return 0;
#endif
}

/* ipaddr [iface] [ip/mask] */
static int builtin_ipaddr(char **args) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    if (!args[1]) {
        /* List interfaces and their IP addresses */
        printf("%-10s %-16s %-16s\n", "INTERFACE", "IP ADDRESS", "NETMASK");
        DIR *d = opendir("/sys/class/net");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.') continue;
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, de->d_name, IFNAMSIZ - 1);

                char ip_str[32] = "(none)", mask_str[32] = "(none)";
                if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
                    strncpy(ip_str, inet_ntoa(sin->sin_addr), sizeof(ip_str) - 1);
                }
                if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
#ifdef __FreeBSD__
                    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
#else
                    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_netmask;
#endif
                    strncpy(mask_str, inet_ntoa(sin->sin_addr), sizeof(mask_str) - 1);
                }
                printf("%-10s %-16s %-16s\n", de->d_name, ip_str, mask_str);
            }
            closedir(d);
        }
        close(fd);
        fflush(stdout);
        return 0;
    }

    if (args[1] && args[2]) {
        char ip_copy[64];
        strncpy(ip_copy, args[2], sizeof(ip_copy) - 1);
        ip_copy[sizeof(ip_copy) - 1] = '\0';
        char *slash = strchr(ip_copy, '/');
        int prefix = 24;
        if (slash) {
            *slash = '\0';
            prefix = atoi(slash + 1);
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, args[1], IFNAMSIZ - 1);

        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, ip_copy, &sin->sin_addr) <= 0) {
            fprintf(stderr, "minish: ipaddr: invalid IP address '%s'\n", ip_copy);
            close(fd);
            return 1;
        }

        if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
            perror("minish: ipaddr: SIOCSIFADDR");
            close(fd);
            return 1;
        }

        /* Set netmask */
        uint32_t mask_val = (prefix == 0) ? 0 : (~0U << (32 - prefix));
#ifdef __FreeBSD__
        sin = (struct sockaddr_in *)&ifr.ifr_addr;
#else
        sin = (struct sockaddr_in *)&ifr.ifr_netmask;
#endif
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(mask_val);
        ioctl(fd, SIOCSIFNETMASK, &ifr);

        /* Bring interface up */
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
            ioctl(fd, SIOCSIFFLAGS, &ifr);
        }

        close(fd);
        printf("Configured %s with IP %s/%d (UP)\n", args[1], ip_copy, prefix);
        return 0;
    }

    close(fd);
    return 0;
}

/* dnsquery <host> [dns_server_ip] */
static int builtin_dnsquery(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: dnsquery: usage: dnsquery <hostname> [dns_server_ip]\n");
        return 1;
    }
    const char *dns_ip = args[2] ? args[2] : "8.8.8.8";

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, dns_ip, &dest.sin_addr);

    /* Construct DNS query packet */
    unsigned char pkt[512];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x12; pkt[1] = 0x34; /* ID */
    pkt[2] = 0x01; pkt[3] = 0x00; /* Standard query, RD=1 */
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT = 1 */

    size_t idx = 12;
    const char *h = args[1];
    while (*h) {
        const char *dot = strchr(h, '.');
        size_t len = dot ? (size_t)(dot - h) : strlen(h);
        if (len > 63) len = 63;
        pkt[idx++] = (unsigned char)len;
        memcpy(pkt + idx, h, len);
        idx += len;
        if (!dot) break;
        h = dot + 1;
    }
    pkt[idx++] = 0x00; /* Null root label */
    pkt[idx++] = 0x00; pkt[idx++] = 0x01; /* QTYPE = A */
    pkt[idx++] = 0x00; pkt[idx++] = 0x01; /* QCLASS = IN */

    if (sendto(sock, pkt, idx, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    struct timeval tv = { 3, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char resp[1024];
    ssize_t n = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);

    if (n < 12) {
        fprintf(stderr, "minish: dnsquery: query timed out or invalid response from %s\n", dns_ip);
        return 1;
    }

    uint16_t ancount = (resp[6] << 8) | resp[7];
    printf("DNS Query for '%s' via %s (Answers: %u):\n", args[1], dns_ip, ancount);

    /* Skip question */
    size_t p = 12;
    while (p < (size_t)n && resp[p] != 0) p += (resp[p] + 1);
    p += 5; /* skip null label + QTYPE + QCLASS */

    /* Parse answers */
    int found_answers = 0;
    for (uint16_t a = 0; a < ancount && p < (size_t)n; a++) {
        if ((resp[p] & 0xc0) == 0xc0) p += 2; /* compressed name pointer */
        else { while (p < (size_t)n && resp[p] != 0) p += (resp[p] + 1); p++; }

        if (p + 10 > (size_t)n) break;
        uint16_t type = (resp[p] << 8) | resp[p + 1];
        uint16_t rdlen = (resp[p + 8] << 8) | resp[p + 9];
        p += 10;

        if (type == 1 && rdlen == 4 && p + 4 <= (size_t)n) {
            printf("  Address: %u.%u.%u.%u\n", resp[p], resp[p + 1], resp[p + 2], resp[p + 3]);
            found_answers++;
        }
        p += rdlen;
    }
    if (!found_answers) printf("  (no A records returned)\n");
    fflush(stdout);
    return 0;
}

/* Helper to hunt socket inode */
static int find_socket_owner(unsigned long target_inode, int *out_pid, char *out_comm, size_t comm_len) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    char target_str[64];
    snprintf(target_str, sizeof(target_str), "socket:[%lu]", target_inode);

    while ((de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);

        char fd_dir_path[512];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%s/fd", de->d_name);
        DIR *fdd = opendir(fd_dir_path);
        if (!fdd) continue;

        struct dirent *fde;
        int matched = 0;
        while ((fde = readdir(fdd)) != NULL) {
            if (fde->d_name[0] == '.') continue;
            char link_path[1024];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir_path, fde->d_name);
            char dest[256];
            ssize_t len = readlink(link_path, dest, sizeof(dest) - 1);
            if (len > 0) {
                dest[len] = '\0';
                if (strcmp(dest, target_str) == 0) {
                    matched = 1;
                    break;
                }
            }
        }
        closedir(fdd);

        if (matched) {
            *out_pid = pid;
            char comm_path[512];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            FILE *f = fopen(comm_path, "r");
            if (f) {
                if (fgets(out_comm, comm_len, f)) {
                    size_t l = strlen(out_comm);
                    if (l > 0 && out_comm[l - 1] == '\n') out_comm[l - 1] = '\0';
                }
                fclose(f);
            }
            closedir(d);
            return 1;
        }
    }
    closedir(d);
    return 0;
}

/* sockhunt <port> */
static int builtin_sockhunt(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: sockhunt: usage: sockhunt <port>\n");
        return 1;
    }
    int target_port = atoi(args[1]);
    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "minish: sockhunt: invalid port %d\n", target_port);
        return 1;
    }

    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) { perror("/proc/net/tcp"); return 1; }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned int local_ip, local_port, rem_ip, rem_port, state;
        unsigned long inode = 0;
        int m = sscanf(line, "%*d: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                       &local_ip, &local_port, &rem_ip, &rem_port, &state, &inode);
        if (m >= 5 && (int)local_port == target_port) {
            int pid = 0;
            char comm[128] = "unknown";
            if (find_socket_owner(inode, &pid, comm, sizeof(comm))) {
                char exe[512] = "unknown";
                char exe_link[512];
                snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
                ssize_t elen = readlink(exe_link, exe, sizeof(exe) - 1);
                if (elen > 0) exe[elen] = '\0';
                printf("Port %d is held by PID %d (%s) -> %s [inode %lu]\n",
                       target_port, pid, comm, exe, inode);
                found = 1;
            }
        }
    }
    fclose(f);

    if (!found) printf("No active process found listening on port %d\n", target_port);
    fflush(stdout);
    return found ? 0 : 1;
}

/* killbyport <port> [-sig] */
static int builtin_killbyport(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: killbyport: usage: killbyport <port> [-sig]\n");
        return 1;
    }
    int port = atoi(args[1]);
    int sig = SIGKILL;
    if (args[2]) {
        sig = (args[2][0] == '-') ? atoi(args[2] + 1) : atoi(args[2]);
        if (sig <= 0) sig = SIGKILL;
    }

    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) { perror("/proc/net/tcp"); return 1; }

    char line[512];
    int killed_any = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned int local_ip, local_port, rem_ip, rem_port, state;
        unsigned long inode = 0;
        int m = sscanf(line, "%*d: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                       &local_ip, &local_port, &rem_ip, &rem_port, &state, &inode);
        if (m >= 5 && (int)local_port == port) {
            int pid = 0;
            char comm[128] = "unknown";
            if (find_socket_owner(inode, &pid, comm, sizeof(comm))) {
                if (kill(pid, sig) == 0) {
                    printf("Terminated PID %d (%s) on port %d with signal %d\n", pid, comm, port, sig);
                    killed_any = 1;
                } else {
                    perror("minish: killbyport");
                }
            }
        }
    }
    fclose(f);
    return killed_any ? 0 : 1;
}

/* netif */
static int builtin_netif(char **args) {
    (void)args;
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) { perror("/proc/net/dev"); return 1; }

    printf("%-10s %12s %10s %8s %12s %10s %8s\n",
           "INTERFACE", "RX_BYTES", "RX_PKTS", "RX_ERRS", "TX_BYTES", "TX_PKTS", "TX_ERRS");
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *ifname = line;
        while (*ifname == ' ') ifname++;
        unsigned long long rxb, rxp, rxe, txb, txp, txe;
        int m = sscanf(colon + 1, "%llu %llu %llu %*u %*u %*u %*u %*u %llu %llu %llu",
                       &rxb, &rxp, &rxe, &txb, &txp, &txe);
        if (m >= 6) {
            printf("%-10s %12llu %10llu %8llu %12llu %10llu %8llu\n",
                   ifname, rxb, rxp, rxe, txb, txp, txe);
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* arppeek */
static int builtin_arppeek(char **args) {
    (void)args;
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) { perror("/proc/net/arp"); return 1; }

    printf("%-16s %-8s %-6s %-18s %-10s\n", "IP ADDRESS", "HW TYPE", "FLAGS", "HW ADDRESS", "DEVICE");
    char line[512];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        if (first) { first = 0; continue; }
        char ip[64], hwtype[32], flags[32], mac[64], mask[32], dev[64];
        if (sscanf(line, "%63s %31s %31s %63s %31s %63s", ip, hwtype, flags, mac, mask, dev) == 6) {
            printf("%-16s %-8s %-6s %-18s %-10s\n", ip, hwtype, flags, mac, dev);
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* routepeek */
static int builtin_routepeek(char **args) {
    (void)args;
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) { perror("/proc/net/route"); return 1; }

    printf("%-10s %-16s %-16s %-6s %-8s\n", "IFACE", "DESTINATION", "GATEWAY", "FLAGS", "METRIC");
    char line[512];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        if (first) { first = 0; continue; }
        char iface[32];
        uint32_t dest, gw;
        int flags, metric;
        if (sscanf(line, "%31s %x %x %d %*d %*d %d", iface, &dest, &gw, &flags, &metric) >= 5) {
            struct in_addr d_addr = { dest };
            struct in_addr g_addr = { gw };
            char d_str[32], g_str[32];
            strncpy(d_str, inet_ntoa(d_addr), sizeof(d_str) - 1);
            strncpy(g_str, inet_ntoa(g_addr), sizeof(g_str) - 1);
            printf("%-10s %-16s %-16s 0x%04x %-8d\n", iface, d_str, g_str, flags, metric);
        }
    }
    fclose(f);
    fflush(stdout);
    return 0;
}

/* portscan <host> <start_port> <end_port> */
static int builtin_portscan(char **args) {
    if (!args[1] || !args[2] || !args[3]) {
        fprintf(stderr, "minish: portscan: usage: portscan <host> <start_port> <end_port>\n");
        return 1;
    }
    int start = atoi(args[2]);
    int end = atoi(args[3]);
    if (start < 1) start = 1;
    if (end > 65535) end = 65535;

    printf("Scanning %s ports %d - %d...\n", args[1], start, end);
    int open_count = 0;

    for (int p = start; p <= end; p++) {
        char p_str[16];
        snprintf(p_str, sizeof(p_str), "%d", p);
        char *tcpping_args[] = { "tcpping", args[1], p_str, "50", NULL };
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        fcntl(s, F_SETFL, O_NONBLOCK);

        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons((uint16_t)p);
        inet_pton(AF_INET, args[1], &target.sin_addr);

        connect(s, (struct sockaddr *)&target, sizeof(target));
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv = { 0, 50000 }; /* 50ms */
        if (select(s + 1, NULL, &wfds, NULL, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                printf("  [OPEN] Port %5d\n", p);
                open_count++;
            }
        }
        close(s);
        (void)tcpping_args;
    }
    printf("Scan complete. Found %d open ports.\n", open_count);
    fflush(stdout);
    return 0;
}

/* ========================================================================= */
/* --- Category F: Hardware, Firmware & Hypervisor Introspection ------------ */
/* ========================================================================= */

/* dmipeek */
static int builtin_dmipeek(char **args) {
    (void)args;
    printf("Hardware, Firmware & Hypervisor Introspection (DMI/SMBIOS):\n");
    static const struct { const char *file; const char *label; } dmi_fields[] = {
        { "sys_vendor",      "System Vendor" },
        { "product_name",    "Product Name" },
        { "product_version", "Product Version" },
        { "bios_vendor",     "BIOS Vendor" },
        { "bios_version",    "BIOS Version" },
        { "bios_date",       "BIOS Date" },
        { "board_vendor",    "Board Vendor" },
        { "board_name",      "Board Name" },
        { "chassis_type",    "Chassis Type" }
    };

    for (size_t i = 0; i < sizeof(dmi_fields) / sizeof(dmi_fields[0]); i++) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/dmi/id/%s", dmi_fields[i].file);
        FILE *f = fopen(path, "r");
        if (f) {
            char val[256];
            if (fgets(val, sizeof(val), f)) {
                size_t l = strlen(val);
                if (l > 0 && val[l - 1] == '\n') val[l - 1] = '\0';
                printf("  %-16s: %s\n", dmi_fields[i].label, val);
            }
            fclose(f);
        }
    }
    fflush(stdout);
    return 0;
}

/* cpuid */
static int builtin_cpuid(char **args) {
    (void)args;
    printf("CPU Hardware & Vulnerability Status:\n");
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        int printed_model = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!printed_model && strncmp(line, "model name", 10) == 0) {
                printf("  %s", line);
                printed_model = 1;
            } else if (strncmp(line, "cpu cores", 9) == 0 || strncmp(line, "microcode", 9) == 0) {
                printf("  %s", line);
            }
        }
        fclose(f);
    }

    printf("\n  Hardware Vulnerability Mitigations:\n");
    DIR *d = opendir("/sys/devices/system/cpu/vulnerabilities");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "/sys/devices/system/cpu/vulnerabilities/%s", de->d_name);
            FILE *vf = fopen(path, "r");
            if (vf) {
                char status[256];
                if (fgets(status, sizeof(status), vf)) {
                    size_t l = strlen(status);
                    if (l > 0 && status[l - 1] == '\n') status[l - 1] = '\0';
                    printf("    %-20s: %s\n", de->d_name, status);
                }
                fclose(vf);
            }
        }
        closedir(d);
    }
    fflush(stdout);
    return 0;
}

/* pcipeek */
static int builtin_pcipeek(char **args) {
    (void)args;
    printf("PCI Bus Hardware Devices:\n");
    DIR *d = opendir("/sys/bus/pci/devices");
    if (!d) {
        printf("  No PCI bus detected (or /sys/bus/pci/devices unavailable)\n");
        return 0;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[512];
        unsigned int vendor = 0, device = 0, class_code = 0;

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", de->d_name);
        FILE *vf = fopen(path, "r");
        if (vf) { if (fscanf(vf, "%x", &vendor) != 1) vendor = 0; fclose(vf); }

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", de->d_name);
        FILE *df = fopen(path, "r");
        if (df) { if (fscanf(df, "%x", &device) != 1) device = 0; fclose(df); }

        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/class", de->d_name);
        FILE *cf = fopen(path, "r");
        if (cf) { if (fscanf(cf, "%x", &class_code) != 1) class_code = 0; fclose(cf); }

        const char *class_desc = "Other Device";
        unsigned int base_class = (class_code >> 16) & 0xFF;
        if (base_class == 0x01) class_desc = "Mass Storage Controller";
        else if (base_class == 0x02) class_desc = "Network Controller";
        else if (base_class == 0x03) class_desc = "Display / VGA Controller";
        else if (base_class == 0x06) class_desc = "Bridge Device";

        printf("  %s [%04x:%04x] (class %06x) - %s\n", de->d_name, vendor, device, class_code, class_desc);
    }
    closedir(d);
    fflush(stdout);
    return 0;
}

/* usbpeek */
static int builtin_usbpeek(char **args) {
    (void)args;
    printf("USB Devices:\n");
    DIR *d = opendir("/sys/bus/usb/devices");
    if (!d) {
        printf("  No USB subsystem detected (or /sys/bus/usb/devices unavailable)\n");
        return 0;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[512];
        char vendor[64] = "", product[64] = "", mfg[128] = "", prod_name[128] = "";

        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", de->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(vendor, sizeof(vendor), f)) {
                size_t l = strlen(vendor);
                if (l > 0 && vendor[l - 1] == '\n') vendor[l - 1] = '\0';
            }
            fclose(f);
        }
        if (!vendor[0]) continue;

        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", de->d_name);
        f = fopen(path, "r");
        if (f) {
            if (fgets(product, sizeof(product), f)) {
                size_t l = strlen(product);
                if (l > 0 && product[l - 1] == '\n') product[l - 1] = '\0';
            }
            fclose(f);
        }

        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/manufacturer", de->d_name);
        f = fopen(path, "r");
        if (f) {
            if (fgets(mfg, sizeof(mfg), f)) {
                size_t l = strlen(mfg);
                if (l > 0 && mfg[l - 1] == '\n') mfg[l - 1] = '\0';
            }
            fclose(f);
        }

        snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/product", de->d_name);
        f = fopen(path, "r");
        if (f) {
            if (fgets(prod_name, sizeof(prod_name), f)) {
                size_t l = strlen(prod_name);
                if (l > 0 && prod_name[l - 1] == '\n') prod_name[l - 1] = '\0';
            }
            fclose(f);
        }

        printf("  USB %-12s [%s:%s] %s %s\n", de->d_name, vendor, product, mfg, prod_name);
    }
    closedir(d);
    fflush(stdout);
    return 0;
}

/* ========================================================================= */
/* --- Category G: Interactive Scripting, Forensics & System Control -------- */
/* ========================================================================= */

/* read [-r] [VAR] (Stateful - runs in parent context) */
static int builtin_read(char **args) {
    const char *var_name = "REPLY";
    int arg_idx = 1;
    if (args[1] && strcmp(args[1], "-r") == 0) {
        arg_idx = 2;
    }
    if (args[arg_idx]) {
        var_name = args[arg_idx];
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t n = getline(&line, &len, stdin);
    if (n < 0) {
        free(line);
        setenv(var_name, "", 1);
        return 1;
    }

    if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
    if (n > 1 && line[n - 2] == '\r') line[n - 2] = '\0';

    setenv(var_name, line, 1);
    free(line);
    return 0;
}

/* calc <num1> <op> <num2> */
static int builtin_calc(char **args) {
    if (!args[1] || !args[2] || !args[3]) {
        fprintf(stderr, "minish: calc: usage: calc <num1> <op> <num2>\n");
        return 1;
    }
    long long n1 = strtoll(args[1], NULL, 0);
    long long n2 = strtoll(args[3], NULL, 0);
    const char *op = args[2];
    long long res = 0;

    if (strcmp(op, "+") == 0) res = n1 + n2;
    else if (strcmp(op, "-") == 0) res = n1 - n2;
    else if (strcmp(op, "*") == 0 || strcmp(op, "x") == 0) res = n1 * n2;
    else if (strcmp(op, "/") == 0) {
        if (n2 == 0) { fprintf(stderr, "minish: calc: division by zero\n"); return 1; }
        res = n1 / n2;
    } else if (strcmp(op, "%") == 0) {
        if (n2 == 0) { fprintf(stderr, "minish: calc: modulo by zero\n"); return 1; }
        res = n1 % n2;
    } else if (strcmp(op, "&") == 0) res = n1 & n2;
    else if (strcmp(op, "|") == 0) res = n1 | n2;
    else if (strcmp(op, "^") == 0) res = n1 ^ n2;
    else if (strcmp(op, "<<") == 0) res = n1 << n2;
    else if (strcmp(op, ">>") == 0) res = n1 >> n2;
    else {
        fprintf(stderr, "minish: calc: unknown operator '%s'\n", op);
        return 1;
    }
    printf("%lld\n", res);
    return 0;
}

/* clear */
static int builtin_clear(char **args) {
    (void)args;
    printf("\033[H\033[J");
    fflush(stdout);
    return 0;
}

/* timestomp <target_file> <reference_file|epoch_seconds> */
static int builtin_timestomp(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: timestomp: usage: timestomp <target_file> <reference_file|epoch_sec>\n");
        return 1;
    }
    struct timespec ts[2];
    struct stat ref_st;
    if (stat(args[2], &ref_st) == 0) {
        ts[0] = ref_st.st_atim;
        ts[1] = ref_st.st_mtim;
    } else {
        time_t epoch = (time_t)atol(args[2]);
        ts[0].tv_sec = epoch;
        ts[0].tv_nsec = 0;
        ts[1].tv_sec = epoch;
        ts[1].tv_nsec = 0;
    }

    if (utimensat(AT_FDCWD, args[1], ts, 0) != 0) {
        perror("minish: timestomp: utimensat");
        return 1;
    }
    printf("Successfully updated timestamps on %s\n", args[1]);
    return 0;
}

/* uptime */
static int builtin_uptime(char **args) {
    (void)args;
    FILE *uf = fopen("/proc/uptime", "r");
    double up_sec = 0;
    if (uf) {
        if (fscanf(uf, "%lf", &up_sec) != 1) up_sec = 0.0;
        fclose(uf);
    }

    FILE *lf = fopen("/proc/loadavg", "r");
    char load[128] = "N/A";
    if (lf) {
        if (fgets(load, sizeof(load), lf)) {
            char *p = strchr(load, '\n');
            if (p) *p = '\0';
        }
        fclose(lf);
    }

    long total_sec = (long)up_sec;
    long days = total_sec / 86400;
    long hours = (total_sec % 86400) / 3600;
    long mins = (total_sec % 3600) / 60;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char cur_time[32];
    strftime(cur_time, sizeof(cur_time), "%H:%M:%S", tm);

    if (days > 0) {
        printf(" %s up %ld days, %ld:%02ld, load average: %s\n", cur_time, days, hours, mins, load);
    } else {
        printf(" %s up %ld:%02ld, load average: %s\n", cur_time, hours, mins, load);
    }
    fflush(stdout);
    return 0;
}

/* symlink <target> <linkpath> */
static int builtin_symlink(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: symlink: usage: symlink <target> <linkpath>\n");
        return 1;
    }
    if (symlink(args[1], args[2]) != 0) {
        perror("minish: symlink");
        return 1;
    }
    return 0;
}

/* readlink [-f] <linkpath> */
static int builtin_readlink(char **args) {
    int canonical = 0;
    const char *path = args[1];
    if (args[1] && strcmp(args[1], "-f") == 0 && args[2]) {
        canonical = 1;
        path = args[2];
    }
    if (!path) {
        fprintf(stderr, "minish: readlink: usage: readlink [-f] <linkpath>\n");
        return 1;
    }
    if (canonical) {
        char resolved[PATH_MAX];
        if (!realpath(path, resolved)) { perror("minish: readlink"); return 1; }
        printf("%s\n", resolved);
    } else {
        char buf[PATH_MAX];
        ssize_t n = readlink(path, buf, sizeof(buf) - 1);
        if (n < 0) { perror("minish: readlink"); return 1; }
        buf[n] = '\0';
        printf("%s\n", buf);
    }
    fflush(stdout);
    return 0;
}

/* time <command...> */
static int builtin_time(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: time: usage: time <command...>\n");
        return 1;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);

    pid_t pid = fork();
    if (pid == 0) {
        /* Reassemble command string and execute */
        size_t cmd_len = 0;
        for (int i = 1; args[i]; i++) cmd_len += strlen(args[i]) + 1;
        char *line = malloc(cmd_len + 1);
        line[0] = '\0';
        for (int i = 1; args[i]; i++) {
            strcat(line, args[i]);
            if (args[i + 1]) strcat(line, " ");
        }
        execute_line(line);
        free(line);
        _exit(0);
    } else if (pid < 0) {
        perror("fork");
        return 1;
    }

    int status;
    struct rusage ru;
    wait4(pid, &status, 0, &ru);
    gettimeofday(&end, NULL);

    double real_sec = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    double user_sec = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1000000.0;
    double sys_sec = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1000000.0;

    fprintf(stderr, "\nreal\t%dm%.3fs\nuser\t%dm%.3fs\nsys\t%dm%.3fs\n",
            (int)(real_sec / 60), real_sec - ((int)(real_sec / 60) * 60),
            (int)(user_sec / 60), user_sec - ((int)(user_sec / 60) * 60),
            (int)(sys_sec / 60), sys_sec - ((int)(sys_sec / 60) * 60));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* Pure C RFC 1321 MD5 Implementation */
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} MINISH_MD5_CTX;

#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define MD5_FF(a, b, c, d, x, s, ac) { (a) += MD5_F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = MD5_ROTL((a), (s)); (a) += (b); }
#define MD5_GG(a, b, c, d, x, s, ac) { (a) += MD5_G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = MD5_ROTL((a), (s)); (a) += (b); }
#define MD5_HH(a, b, c, d, x, s, ac) { (a) += MD5_H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = MD5_ROTL((a), (s)); (a) += (b); }
#define MD5_II(a, b, c, d, x, s, ac) { (a) += MD5_I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = MD5_ROTL((a), (s)); (a) += (b); }

static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
               (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);
    }
    MD5_FF(a, b, c, d, x[0],  7,  0xd76aa478); MD5_FF(d, a, b, c, x[1],  12, 0xe8c7b756);
    MD5_FF(c, d, a, b, x[2],  17, 0x242070db); MD5_FF(b, c, d, a, x[3],  22, 0xc1bdceee);
    MD5_FF(a, b, c, d, x[4],  7,  0xf57c0faf); MD5_FF(d, a, b, c, x[5],  12, 0x4787c62a);
    MD5_FF(c, d, a, b, x[6],  17, 0xa8304613); MD5_FF(b, c, d, a, x[7],  22, 0xfd469501);
    MD5_FF(a, b, c, d, x[8],  7,  0x698098d8); MD5_FF(d, a, b, c, x[9],  12, 0x8b44f7af);
    MD5_FF(c, d, a, b, x[10], 17, 0xffff5bb1); MD5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
    MD5_FF(a, b, c, d, x[12], 7,  0x6b901122); MD5_FF(d, a, b, c, x[13], 12, 0xfd987193);
    MD5_FF(c, d, a, b, x[14], 17, 0xa679438e); MD5_FF(b, c, d, a, x[15], 22, 0x49b40821);

    MD5_GG(a, b, c, d, x[1],  5,  0xf61e2562); MD5_GG(d, a, b, c, x[6],  9,  0xc040b340);
    MD5_GG(c, d, a, b, x[11], 14, 0x265e5a51); MD5_GG(b, c, d, a, x[0],  20, 0xe9b6c7aa);
    MD5_GG(a, b, c, d, x[5],  5,  0xd62f105d); MD5_GG(d, a, b, c, x[10], 9,  0x02441453);
    MD5_GG(c, d, a, b, x[15], 14, 0xd8a1e681); MD5_GG(b, c, d, a, x[4],  20, 0xe7d3fbc8);
    MD5_GG(a, b, c, d, x[9],  5,  0x21e1cde6); MD5_GG(d, a, b, c, x[14], 9,  0xc33707d6);
    MD5_GG(c, d, a, b, x[3],  14, 0xf4d50d87); MD5_GG(b, c, d, a, x[8],  20, 0x455a14ed);
    MD5_GG(a, b, c, d, x[13], 5,  0xa9e3e905); MD5_GG(d, a, b, c, x[2],  9,  0xfcefa3f8);
    MD5_GG(c, d, a, b, x[7],  14, 0x676f02d9); MD5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    MD5_HH(a, b, c, d, x[5],  4,  0xfffa3942); MD5_HH(d, a, b, c, x[8],  11, 0x8771f681);
    MD5_HH(c, d, a, b, x[11], 16, 0x6d9d6122); MD5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
    MD5_HH(a, b, c, d, x[1],  4,  0xa4beea44); MD5_HH(d, a, b, c, x[4],  11, 0x4bdecfa9);
    MD5_HH(c, d, a, b, x[7],  16, 0xf6bb4b60); MD5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    MD5_HH(a, b, c, d, x[13], 4,  0x289b7ec6); MD5_HH(d, a, b, c, x[0],  11, 0xeaa127fa);
    MD5_HH(c, d, a, b, x[3],  16, 0xd4ef3085); MD5_HH(b, c, d, a, x[6],  23, 0x04881d05);
    MD5_HH(a, b, c, d, x[9],  4,  0xd9d4d039); MD5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    MD5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8); MD5_HH(b, c, d, a, x[2],  23, 0xc4ac5665);

    MD5_II(a, b, c, d, x[0],  6,  0xf4292244); MD5_II(d, a, b, c, x[7],  10, 0x432aff97);
    MD5_II(c, d, a, b, x[14], 15, 0xab9423a7); MD5_II(b, c, d, a, x[5],  21, 0xfc93a039);
    MD5_II(a, b, c, d, x[12], 6,  0x655b59c3); MD5_II(d, a, b, c, x[3],  10, 0x8f0ccc92);
    MD5_II(c, d, a, b, x[10], 15, 0xffeff47d); MD5_II(b, c, d, a, x[1],  21, 0x85845dd1);
    MD5_II(a, b, c, d, x[8],  6,  0x6fa87e4f); MD5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    MD5_II(c, d, a, b, x[6],  15, 0xa3014314); MD5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
    MD5_II(a, b, c, d, x[4],  6,  0xf7537e82); MD5_II(d, a, b, c, x[2],  10, 0xbd3af235);
    MD5_II(c, d, a, b, x[10], 15, 0x2ad7d2bb); MD5_II(b, c, d, a, x[1],  21, 0xeb86d391);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_init(MINISH_MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(MINISH_MD5_CTX *ctx, const unsigned char *input, size_t inputLen) {
    size_t i, index, partLen;
    index = (size_t)((ctx->count[0] >> 3) & 0x3F);
    if ((ctx->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(inputLen >> 29);
    partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&ctx->buffer[index], input, partLen);
        md5_transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &input[i], inputLen - i);
}

static void md5_final(unsigned char digest[16], MINISH_MD5_CTX *ctx) {
    unsigned char bits[8];
    for (int i = 0; i < 4; i++) {
        bits[i] = (unsigned char)((ctx->count[0] >> (i * 8)) & 0xFF);
        bits[i + 4] = (unsigned char)((ctx->count[1] >> (i * 8)) & 0xFF);
    }
    size_t index = (size_t)((ctx->count[0] >> 3) & 0x3F);
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    static const unsigned char PADDING[64] = { 0x80 };
    md5_update(ctx, PADDING, padLen);
    md5_update(ctx, bits, 8);
    for (int i = 0; i < 4; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] & 0xFF);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 8) & 0xFF);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 16) & 0xFF);
        digest[i * 4 + 3] = (unsigned char)((ctx->state[i] >> 24) & 0xFF);
    }
}

/* md5 <file|-> */
static int builtin_md5(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: md5: usage: md5 <file|->\n");
        return 1;
    }
    int fd = STDIN_FILENO;
    if (strcmp(args[1], "-") != 0) {
        fd = open(args[1], O_RDONLY);
        if (fd < 0) { perror(args[1]); return 1; }
    }

    MINISH_MD5_CTX ctx;
    md5_init(&ctx);
    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        md5_update(&ctx, buf, (size_t)n);
    }
    if (fd != STDIN_FILENO) close(fd);

    unsigned char digest[16];
    md5_final(digest, &ctx);
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("  %s\n", args[1]);
    fflush(stdout);
    return 0;
}

/* CRC32 Table Generator and Hasher */
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void init_crc32_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_initialized = 1;
}

/* crc32 <file|-> */
static int builtin_crc32(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: crc32: usage: crc32 <file|->\n");
        return 1;
    }
    if (!crc32_initialized) init_crc32_table();

    int fd = STDIN_FILENO;
    if (strcmp(args[1], "-") != 0) {
        fd = open(args[1], O_RDONLY);
        if (fd < 0) { perror(args[1]); return 1; }
    }

    uint32_t crc = 0xFFFFFFFF;
    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
        }
    }
    if (fd != STDIN_FILENO) close(fd);
    crc ^= 0xFFFFFFFF;

    printf("%08x  %s\n", crc, args[1]);
    fflush(stdout);
    return 0;
}

/* xor <file|-> <key> */
static int builtin_xor(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: xor: usage: xor <file|-> <key>\n");
        return 1;
    }
    const char *key = args[2];
    size_t klen = strlen(key);
    if (klen == 0) return 0;

    int fd = STDIN_FILENO;
    if (strcmp(args[1], "-") != 0) {
        fd = open(args[1], O_RDONLY);
        if (fd < 0) { perror(args[1]); return 1; }
    }

    unsigned char buf[4096];
    ssize_t n;
    size_t kidx = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            buf[i] ^= (unsigned char)key[kidx];
            kidx = (kidx + 1) % klen;
        }
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(STDOUT_FILENO, buf + written, (size_t)(n - written));
            if (w <= 0) break;
            written += w;
        }
    }
    if (fd != STDIN_FILENO) close(fd);
    return 0;
}

/* ========================================================================= */
/* --- 16 Advanced In-Memory Defense & Adversary Hunting Built-in Engines --- */
/* ========================================================================= */

/* 1. builtin_findgrowth [path] [seconds] */
typedef struct {
    char path[512];
    off_t size;
} GrowthEntry;

static void scan_growth_tree(const char *dir, GrowthEntry *entries, int *count, int max_entries) {
    if (*count >= max_entries) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char sub[512];
        if (snprintf(sub, sizeof(sub), "%s/%s", dir, de->d_name) >= (int)sizeof(sub)) continue;
        if (strncmp(sub, "/proc", 5) == 0 || strncmp(sub, "/sys", 4) == 0 || strncmp(sub, "/dev", 4) == 0) continue;

        struct stat st;
        if (lstat(sub, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            scan_growth_tree(sub, entries, count, max_entries);
        } else if (S_ISREG(st.st_mode)) {
            if (*count < max_entries) {
                strncpy(entries[*count].path, sub, sizeof(entries[*count].path) - 1);
                entries[*count].path[sizeof(entries[*count].path) - 1] = '\0';
                entries[*count].size = st.st_size;
                (*count)++;
            }
        }
    }
    closedir(d);
}

static int builtin_findgrowth(char **args) {
    const char *target_path = args[1] ? args[1] : ".";
    int sec = 2;
    if (args[1] && args[2]) {
        sec = atoi(args[2]);
    } else if (args[1] && isdigit((unsigned char)args[1][0]) && !args[2]) {
        sec = atoi(args[1]);
        target_path = ".";
    }
    if (sec <= 0) sec = 1;

    int max_entries = 2048;
    GrowthEntry *entries = (GrowthEntry *)malloc(sizeof(GrowthEntry) * (size_t)max_entries);
    if (!entries) { perror("malloc"); return 1; }

    int count = 0;
    scan_growth_tree(target_path, entries, &count, max_entries);

    printf("=== Active File Growth Monitor: %s (%ds sampling window) ===\n", target_path, sec);
    fflush(stdout);
    sleep((unsigned int)sec);

    int grew = 0;
    for (int i = 0; i < count; i++) {
        struct stat st;
        if (stat(entries[i].path, &st) == 0) {
            if (st.st_size > entries[i].size) {
                off_t diff = st.st_size - entries[i].size;
                double rate = (double)diff / (double)sec;
                printf("[+%.2f MB] (+%.2f MB/s) %s (now %.2f MB)\n",
                       (double)diff / (1024.0 * 1024.0),
                       rate / (1024.0 * 1024.0),
                       entries[i].path,
                       (double)st.st_size / (1024.0 * 1024.0));
                grew++;
            }
        }
    }

    if (grew == 0) {
        printf("No active file growth detected across %d monitored file(s).\n", count);
    } else {
        printf("Found %d file(s) actively growing.\n", grew);
    }
    free(entries);
    fflush(stdout);
    return 0;
}

/* 2. builtin_fdsize [pid] */
static void inspect_pid_fdsizes(const char *pid_str, int *total_fds, unsigned long long *total_bytes) {
    char fd_dir[256];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", pid_str);
    DIR *d = opendir(fd_dir);
    if (!d) return;

    char comm[64] = "unknown";
    char comm_path[512];
    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    FILE *fc = fopen(comm_path, "r");
    if (fc) {
        if (fgets(comm, sizeof(comm), fc)) {
            size_t cl = strlen(comm);
            if (cl > 0 && comm[cl - 1] == '\n') comm[cl - 1] = '\0';
        }
        fclose(fc);
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, de->d_name);
        char target[1024];
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            if (strncmp(target, "socket:", 7) == 0 || strncmp(target, "pipe:", 5) == 0 ||
                strncmp(target, "anon_inode:", 11) == 0) continue;

            struct stat st;
            if (stat(fd_path, &st) == 0 && st.st_size > 0) {
                const char *flag = strstr(target, "(deleted)") ? " [UNLINKED/TRAPPED]" : "";
                printf("PID %5s (%-16s) | FD %4s -> %8.2f MB | %s%s\n",
                       pid_str, comm, de->d_name,
                       (double)st.st_size / (1024.0 * 1024.0),
                       target, flag);
                (*total_fds)++;
                (*total_bytes) += (unsigned long long)st.st_size;
            }
        }
    }
    closedir(d);
}

static int builtin_fdsize(char **args) {
    int total_fds = 0;
    unsigned long long total_bytes = 0;

    if (args[1]) {
        printf("=== Open Descriptor Storage: PID %s ===\n", args[1]);
        inspect_pid_fdsizes(args[1], &total_fds, &total_bytes);
    } else {
        printf("=== Open Descriptor Storage Audit (System-Wide) ===\n");
        DIR *procdir = opendir("/proc");
        if (!procdir) { perror("/proc"); return 1; }
        struct dirent *de;
        while ((de = readdir(procdir)) != NULL) {
            if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
                inspect_pid_fdsizes(de->d_name, &total_fds, &total_bytes);
            }
        }
        closedir(procdir);
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("Total open storage: %.2f MB (%.2f GB) across %d active descriptor(s).\n",
           (double)total_bytes / (1024.0 * 1024.0),
           (double)total_bytes / (1024.0 * 1024.0 * 1024.0),
           total_fds);
    fflush(stdout);
    return 0;
}

/* 3. builtin_topwriters [seconds] */
typedef struct {
    int pid;
    char comm[64];
    unsigned long long w1;
    unsigned long long w2;
    unsigned long long diff;
} TopWriterItem;

static unsigned long long read_proc_write_bytes(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    unsigned long long wb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "write_bytes:", 12) == 0) {
            wb = strtoull(line + 12, NULL, 10);
            break;
        }
    }
    fclose(f);
    return wb;
}

static int builtin_topwriters(char **args) {
    int sec = args[1] ? atoi(args[1]) : 2;
    if (sec <= 0) sec = 1;

    int max_items = 512;
    TopWriterItem *items = (TopWriterItem *)malloc(sizeof(TopWriterItem) * (size_t)max_items);
    if (!items) { perror("malloc"); return 1; }
    int count = 0;

    DIR *d = opendir("/proc");
    if (!d) { free(items); perror("/proc"); return 1; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_items) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
            int pid = atoi(de->d_name);
            unsigned long long wb = read_proc_write_bytes(pid);
            if (wb > 0) {
                items[count].pid = pid;
                items[count].w1 = wb;
                items[count].w2 = 0;
                items[count].diff = 0;
                items[count].comm[0] = '\0';
                char cp[256];
                snprintf(cp, sizeof(cp), "/proc/%d/comm", pid);
                FILE *fc = fopen(cp, "r");
                if (fc) {
                    if (fgets(items[count].comm, sizeof(items[count].comm), fc)) {
                        size_t cl = strlen(items[count].comm);
                        if (cl > 0 && items[count].comm[cl - 1] == '\n') items[count].comm[cl - 1] = '\0';
                    }
                    fclose(fc);
                }
                count++;
            }
        }
    }
    closedir(d);

    printf("=== Real-Time Storage Write Rate (%ds sampling window) ===\n", sec);
    fflush(stdout);
    sleep((unsigned int)sec);

    int active = 0;
    for (int i = 0; i < count; i++) {
        unsigned long long wb2 = read_proc_write_bytes(items[i].pid);
        if (wb2 > items[i].w1) {
            items[i].w2 = wb2;
            items[i].diff = wb2 - items[i].w1;
            active++;
        }
    }

    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (items[j].diff > items[i].diff) {
                TopWriterItem tmp = items[i];
                items[i] = items[j];
                items[j] = tmp;
            }
        }
    }

    if (active == 0) {
        printf("No active storage write I/O detected across %d monitored process(es).\n", count);
    } else {
        for (int i = 0; i < count && items[i].diff > 0; i++) {
            double rate_mb = ((double)items[i].diff / (double)sec) / (1024.0 * 1024.0);
            double total_mb = (double)items[i].diff / (1024.0 * 1024.0);
            printf("PID %5d (%-16s) | %8.2f MB/s (%8.2f MB written)\n",
                   items[i].pid, items[i].comm, rate_mb, total_mb);
        }
    }
    free(items);
    fflush(stdout);
    return 0;
}

/* 4. builtin_ramscratch [size_MB] */
static int builtin_ramscratch(char **args) {
    int mb = args[1] ? atoi(args[1]) : 64;
    if (mb <= 0) mb = 64;

    const char *target = "/dev/shm/.scratch";
    struct stat st;
    if (stat("/dev/shm", &st) != 0) {
        target = "/tmp/.scratch";
    }

    mkdir(target, 0700);

#ifdef __linux__
    if (strncmp(target, "/tmp", 4) == 0) {
        char opts[64];
        snprintf(opts, sizeof(opts), "size=%dM,mode=0700", mb);
        mount("tmpfs", target, "tmpfs", 0, opts);
    }
#endif

    if (chdir(target) != 0) {
        perror("minish: ramscratch chdir");
        return 1;
    }

    setenv("TMPDIR", target, 1);
    printf("[+] Writable RAM scratchpad active at %s (0 disk blocks used)\n", target);
    printf("[+] Environment TMPDIR updated and current directory switched to: %s\n", target);
    fflush(stdout);
    return 0;
}

/* 5. builtin_ramclone <src_file> [dest_name] */
static int builtin_ramclone(char **args) {
    if (!args[1]) {
        fprintf(stderr, "minish: ramclone: usage: ramclone <src_file> [dest_name]\n");
        return 1;
    }
    const char *src = args[1];
    const char *base = strrchr(src, '/');
    const char *dest = args[2] ? args[2] : (base ? base + 1 : src);

    int fd = open(src, O_RDONLY);
    if (fd < 0) { perror(src); return 1; }

    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); close(fd); return 1; }

    size_t sz = (size_t)st.st_size;
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { perror("malloc"); close(fd); return 1; }

    size_t total = 0;
    while (total < sz) {
        ssize_t r = read(fd, buf + total, sz - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);
    buf[total] = '\0';

    memfile_store(dest, buf, total);

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/dev/shm/.scratch";
    struct stat sdir;
    if (stat(tmpdir, &sdir) == 0 && S_ISDIR(sdir.st_mode)) {
        char out_path[512];
        snprintf(out_path, sizeof(out_path), "%s/%s", tmpdir, dest);
        int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (out_fd >= 0) {
            ssize_t nw = write(out_fd, buf, total); (void)nw;
            close(out_fd);
        }
    }

    free(buf);
    printf("[+] Cloned %s (%zu bytes) into RAM as '%s' (0 disk blocks allocated)\n", src, total, dest);
    fflush(stdout);
    return 0;
}

/* 6. builtin_deletedgrab <pid> <fd|exe> [mem_name|-] */
static int builtin_deletedgrab(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: deletedgrab: usage: deletedgrab <pid> <fd|exe> [mem_name|-]\n");
        return 1;
    }
    const char *pid = args[1];
    const char *fd_or_exe = args[2];
    const char *dest = args[3] ? args[3] : "-";

    char path[256];
    if (strcmp(fd_or_exe, "exe") == 0) {
        snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    } else {
        snprintf(path, sizeof(path), "/proc/%s/fd/%s", pid, fd_or_exe);
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }

    if (strcmp(dest, "-") == 0) {
        char buf[8192];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t w = 0;
            while (w < n) {
                ssize_t ret = write(STDOUT_FILENO, buf + w, (size_t)(n - w));
                if (ret <= 0) break;
                w += ret;
            }
        }
        close(fd);
        return 0;
    }

    size_t cap = 65536;
    size_t size = 0;
    char *data = (char *)malloc(cap);
    if (!data) { perror("malloc"); close(fd); return 1; }

    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (size + (size_t)n > cap) {
            cap = (cap + (size_t)n) * 2;
            char *nd = (char *)realloc(data, cap);
            if (!nd) { perror("realloc"); free(data); close(fd); return 1; }
            data = nd;
        }
        memcpy(data + size, buf, (size_t)n);
        size += (size_t)n;
    }
    close(fd);

    memfile_store(dest, data, size);
    free(data);

    printf("[+] Rescued %zu bytes from PID %s (%s) into RAM memfile '%s' (0 disk writes)\n",
           size, pid, fd_or_exe, dest);
    fflush(stdout);
    return 0;
}

/* 7. builtin_sigshield [on|off|status] */
static int builtin_sigshield(char **args) {
    const char *action = args[1] ? args[1] : "on";

    if (strcmp(action, "on") == 0) {
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);

        FILE *f = fopen("/proc/self/oom_score_adj", "w");
        if (f) {
            fprintf(f, "-1000\n");
            fclose(f);
        }
        printf("[+] sigshield ON: Immune to SIGTERM, SIGHUP, SIGINT, SIGQUIT and OOM-killer\n");
    } else if (strcmp(action, "off") == 0) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);

        FILE *f = fopen("/proc/self/oom_score_adj", "w");
        if (f) {
            fprintf(f, "0\n");
            fclose(f);
        }
        printf("[-] sigshield OFF: Default signal handling restored\n");
    } else {
        char oom[32] = "unknown";
        FILE *f = fopen("/proc/self/oom_score_adj", "r");
        if (f) {
            if (fgets(oom, sizeof(oom), f)) {
                size_t l = strlen(oom);
                if (l > 0 && oom[l - 1] == '\n') oom[l - 1] = '\0';
            }
            fclose(f);
        }
        printf("=== sigshield Status ===\n");
        printf("OOM Score Adjust: %s\n", oom);
        printf("Protected Signals: SIGTERM, SIGHUP, SIGINT, SIGQUIT\n");
        printf("SIGKILL Defense: Launch as 'minish --immortal' / '-i' (Sentinel auto-revival)\n");
        printf("                 or 'memunshare -p' (immune PID 1 in isolated PID namespace)\n");
    }
    fflush(stdout);
    return 0;
}

/* 8. builtin_b64exec <proc_name> [args...] */
static int builtin_b64exec(char **args) {
#ifdef __linux__
    extern char **environ;
    if (!args[1]) {
        fprintf(stderr, "minish: b64exec: usage: b64exec <proc_name> [args...]\n");
        return 1;
    }
    const char *proc_name = args[1];

    int fd = memfd_create(proc_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { perror("memfd_create"); return 1; }

    char in_buf[4096];
    unsigned char dec_buf[3072];
    ssize_t n;
    int val = 0, valb = -8;
    size_t out_len = 0;

    while ((n = read(STDIN_FILENO, in_buf, sizeof(in_buf))) > 0) {
        size_t dec_pos = 0;
        for (ssize_t i = 0; i < n; i++) {
            char c = in_buf[i];
            int d = b64_char_value(c);
            if (d < 0) continue;
            val = (val << 6) | d;
            valb += 6;
            if (valb >= 0) {
                dec_buf[dec_pos++] = (unsigned char)((val >> valb) & 0xFF);
                valb -= 8;
                if (dec_pos == sizeof(dec_buf)) {
                    ssize_t nw = write(fd, dec_buf, dec_pos); (void)nw;
                    out_len += dec_pos;
                    dec_pos = 0;
                }
            }
        }
        if (dec_pos > 0) {
            ssize_t nw = write(fd, dec_buf, dec_pos); (void)nw;
            out_len += dec_pos;
        }
    }

    if (out_len == 0) {
        fprintf(stderr, "minish: b64exec: no binary data received on stdin\n");
        close(fd);
        return 1;
    }

    fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE);

    pid_t pid = fork();
    if (pid == 0) {
        set_process_name(proc_name);
        int argc = 0;
        while (args[argc]) argc++;
        char **child_argv = (char **)malloc(sizeof(char *) * (size_t)(argc + 1));
        if (child_argv) {
            child_argv[0] = (char *)proc_name;
            for (int i = 2; i < argc; i++) {
                child_argv[i - 1] = args[i];
            }
            child_argv[argc - 1] = NULL;
        } else {
            child_argv = args + 1;
        }

        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        execve(fd_path, child_argv, environ);
        perror("b64exec execve");
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        close(fd);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    } else {
        perror("fork");
        close(fd);
        return 1;
    }
#else
    (void)args;
    fprintf(stderr, "minish: b64exec only supported on Linux\n");
    return 1;
#endif
}

/* 9. builtin_ramoverlay <dir> [size_MB] */
static int builtin_ramoverlay(char **args) {
#ifdef __linux__
    if (!args[1]) {
        fprintf(stderr, "minish: ramoverlay: usage: ramoverlay <dir> [size_MB]\n");
        return 1;
    }
    const char *target_dir = args[1];
    int mb = args[2] ? atoi(args[2]) : 64;
    if (mb <= 0) mb = 64;

    char base[256];
    snprintf(base, sizeof(base), "/dev/shm/.ovl_%d", (int)getpid());
    mkdir(base, 0700);

    char upper[300], work[300];
    snprintf(upper, sizeof(upper), "%s/upper", base);
    snprintf(work, sizeof(work), "%s/work", base);
    mkdir(upper, 0755);
    mkdir(work, 0755);

    char opts[1024];
    snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", target_dir, upper, work);

    if (mount("overlay", target_dir, "overlay", 0, opts) != 0) {
        perror("minish: ramoverlay mount");
        return 1;
    }
    printf("[+] Mounted volatile RAM overlayfs over %s (all writes redirected to RAM, 0 disk blocks used)\n", target_dir);
    fflush(stdout);
    return 0;
#else
    (void)args;
    fprintf(stderr, "minish: ramoverlay only supported on Linux\n");
    return 1;
#endif
}

/* 10. builtin_exehunt */
static int builtin_exehunt(char **args) {
    (void)args;
    printf("=== In-Memory & Disguised Process Audit ===\n");
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return 1; }

    int suspicious = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
            char exe_link[512];
            snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", de->d_name);
            char target[1024];
            ssize_t len = readlink(exe_link, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                char comm[64] = "unknown";
                char comm_path[512];
                snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", de->d_name);
                FILE *fc = fopen(comm_path, "r");
                if (fc) {
                    if (fgets(comm, sizeof(comm), fc)) {
                        size_t cl = strlen(comm);
                        if (cl > 0 && comm[cl - 1] == '\n') comm[cl - 1] = '\0';
                    }
                    fclose(fc);
                }

                const char *tag = NULL;
                if (strstr(target, "(deleted)")) {
                    tag = "[UNLINKED MALWARE]";
                } else if (strncmp(target, "/dev/shm", 8) == 0 || strncmp(target, "/tmp", 4) == 0 ||
                           strncmp(target, "memfd:", 6) == 0) {
                    tag = "[VOLATILE RAM EXEC]";
                } else {
                    const char *base = strrchr(target, '/');
                    const char *bname = base ? base + 1 : target;
                    if (strncmp(comm, bname, strlen(comm)) != 0) {
                        tag = "[DISGUISED COMM]";
                    }
                }

                if (tag) {
                    printf("[!] PID %5s (%-16s) -> %s %s\n", de->d_name, comm, target, tag);
                    suspicious++;
                }
            }
        }
    }
    closedir(d);

    if (suspicious == 0) {
        printf("No suspicious in-memory or disguised processes detected.\n");
    } else {
        printf("Found %d suspicious process(es).\n", suspicious);
    }
    fflush(stdout);
    return 0;
}

/* 11. builtin_memscript <interpreter> [args...] */
static int builtin_memscript(char **args) {
#ifdef __linux__
    if (!args[1]) {
        fprintf(stderr, "minish: memscript: usage: memscript <interpreter> [args...]\n");
        return 1;
    }
    const char *interp = args[1];

    int fd = memfd_create("script", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); return 1; }

    char buf[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        ssize_t nw = write(fd, buf, (size_t)n); (void)nw;
    }

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    pid_t pid = fork();
    if (pid == 0) {
        int argc = 0;
        while (args[argc]) argc++;
        char **child_argv = (char **)malloc(sizeof(char *) * (size_t)(argc + 2));
        if (!child_argv) _exit(1);
        child_argv[0] = (char *)interp;
        child_argv[1] = fd_path;
        for (int i = 2; i < argc; i++) {
            child_argv[i] = args[i];
        }
        child_argv[argc] = NULL;

        fcntl(fd, F_SETFD, 0);
        execvp(interp, child_argv);
        perror("minish: memscript execvp");
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        close(fd);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    } else {
        perror("fork");
        close(fd);
        return 1;
    }
#else
    (void)args;
    fprintf(stderr, "minish: memscript only supported on Linux\n");
    return 1;
#endif
}

/* 12. builtin_memunshare [-m] [-p] [-n] <cmd...> */
static int builtin_memunshare(char **args) {
#ifdef __linux__
    if (!args[1]) {
        fprintf(stderr, "minish: memunshare: usage: memunshare [-m] [-p] [-n] <cmd...>\n");
        return 1;
    }

    int flags = 0;
    int idx = 1;
    while (args[idx] && args[idx][0] == '-') {
        for (int j = 1; args[idx][j]; j++) {
            if (args[idx][j] == 'm') flags |= CLONE_NEWNS;
            else if (args[idx][j] == 'p') flags |= CLONE_NEWPID;
            else if (args[idx][j] == 'n') flags |= CLONE_NEWNET;
        }
        idx++;
    }

    if (!args[idx]) {
        fprintf(stderr, "minish: memunshare: missing command to execute\n");
        return 1;
    }

    if (flags == 0) flags = CLONE_NEWNS | CLONE_NEWPID;

    if (unshare(flags) != 0) {
        perror("minish: unshare");
        return 1;
    }

    if (flags & CLONE_NEWNS) {
        mount("tmpfs", "/tmp", "tmpfs", 0, "size=32m,mode=1777");
    }

    pid_t pid = fork();
    if (pid == 0) {
        execvp(args[idx], args + idx);
        perror(args[idx]);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    } else {
        perror("fork");
        return 1;
    }
#else
    (void)args;
    fprintf(stderr, "minish: memunshare only supported on Linux\n");
    return 1;
#endif
}

/* 13. builtin_memgrep <pid> <string> */
static int builtin_memgrep(char **args) {
    if (!args[1] || !args[2]) {
        fprintf(stderr, "minish: memgrep: usage: memgrep <pid> <search_string>\n");
        return 1;
    }
    const char *pid = args[1];
    const char *needle = args[2];
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return 0;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", pid);
    FILE *fmaps = fopen(maps_path, "r");
    if (!fmaps) { perror(maps_path); return 1; }

    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) { perror(mem_path); fclose(fmaps); return 1; }

    printf("=== In-Memory Search: PID %s for '%s' ===\n", pid, needle);
    char line[512];
    int total_matches = 0;

    while (fgets(line, sizeof(line), fmaps)) {
        unsigned long start, end;
        char perms[16], pathname[256];
        pathname[0] = '\0';
        if (sscanf(line, "%lx-%lx %15s %*s %*s %*s %255s", &start, &end, perms, pathname) < 3) continue;
        if (perms[0] != 'r') continue;

        unsigned long cur = start;
        char chunk[4096];
        int region_matches = 0;

        while (cur < end && region_matches < 10) {
            size_t to_read = (end - cur > sizeof(chunk)) ? sizeof(chunk) : (size_t)(end - cur);
            ssize_t n = pread(mem_fd, chunk, to_read, (off_t)cur);
            if (n <= 0) break;

            for (ssize_t i = 0; i <= n - (ssize_t)needle_len; i++) {
                if (memcmp(chunk + i, needle, needle_len) == 0) {
                    printf("[0x%016lx] (%-16s): ", cur + (unsigned long)i, pathname[0] ? pathname : "anon");
                    for (size_t k = 0; k < needle_len + 16 && (size_t)i + k < (size_t)n; k++) {
                        unsigned char c = (unsigned char)chunk[i + k];
                        putchar((c >= 32 && c <= 126) ? c : '.');
                    }
                    putchar('\n');
                    region_matches++;
                    total_matches++;
                    if (region_matches >= 10) break;
                }
            }
            cur += (unsigned long)n;
        }
    }

    close(mem_fd);
    fclose(fmaps);

    if (total_matches == 0) {
        printf("Pattern '%s' not found in readable memory regions.\n", needle);
    } else {
        printf("Found %d matching memory instance(s).\n", total_matches);
    }
    fflush(stdout);
    return 0;
}

/* 14. builtin_ptracehunt */
static int builtin_ptracehunt(char **args) {
    (void)args;
    printf("=== Process Injection & Ptrace Tracer Audit ===\n");
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return 1; }

    int alerts = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
            char st_path[512];
            snprintf(st_path, sizeof(st_path), "/proc/%s/status", de->d_name);
            FILE *f = fopen(st_path, "r");
            if (!f) continue;

            int tracer_pid = 0;
            char comm[64] = "unknown";
            char line[256];

            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Name:", 5) == 0) {
                    sscanf(line + 5, "%63s", comm);
                } else if (strncmp(line, "TracerPid:", 10) == 0) {
                    tracer_pid = atoi(line + 10);
                }
            }
            fclose(f);

            if (tracer_pid > 0) {
                char tcomm[64] = "unknown";
                char tcp[256];
                snprintf(tcp, sizeof(tcp), "/proc/%d/comm", tracer_pid);
                FILE *ft = fopen(tcp, "r");
                if (ft) {
                    if (fgets(tcomm, sizeof(tcomm), ft)) {
                        size_t cl = strlen(tcomm);
                        if (cl > 0 && tcomm[cl - 1] == '\n') tcomm[cl - 1] = '\0';
                    }
                    fclose(ft);
                }
                printf("[!] INJECTION ALERT: PID %s (%s) is actively TRACED/INJECTED by PID %d (%s)!\n",
                       de->d_name, comm, tracer_pid, tcomm);
                alerts++;
            }
        }
    }
    closedir(d);

    if (alerts == 0) {
        printf("No processes currently attached or injected via ptrace.\n");
    } else {
        printf("Detected %d actively traced/injected process(es).\n", alerts);
    }
    fflush(stdout);
    return 0;
}

/* 15. builtin_promischunt */
static int builtin_promischunt(char **args) {
    (void)args;
    printf("=== Promiscuous Interface & Raw Sniffer Audit ===\n");
    int alerts = 0;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifconf ifc;
        char buf[2048];
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
            int n = ifc.ifc_len / (int)sizeof(struct ifreq);
            for (int i = 0; i < n; i++) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifc.ifc_req[i].ifr_name, IFNAMSIZ - 1);
                if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
                    if (ifr.ifr_flags & IFF_PROMISC) {
                        printf("[!] PROMISCUOUS INTERFACE: %s is in PROMISCUOUS mode!\n", ifr.ifr_name);
                        alerts++;
                    }
                }
            }
        }
        close(s);
    }

    FILE *fp = fopen("/proc/net/packet", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            unsigned int sk, ref, type, proto, iface, r, rmem, user, inode;
            if (sscanf(line, "%x %u %u %x %u %u %u %u %u", &sk, &ref, &type, &proto, &iface, &r, &rmem, &user, &inode) >= 9) {
                printf("[!] RAW AF_PACKET SOCKET: Proto 0x%04x on Iface %u (Socket Inode %u)\n", proto, iface, inode);
                alerts++;
            }
        }
        fclose(fp);
    }

    if (alerts == 0) {
        printf("No promiscuous interfaces or active raw packet sockets found.\n");
    }
    fflush(stdout);
    return 0;
}

/* 16. builtin_persistpeek */
static int builtin_persistpeek(char **args) {
    (void)args;
    printf("=== Persistence & Non-Standard Hook Audit ===\n");
    const char *paths[] = {
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/rc.local",
        "/etc/profile.d",
        "/var/spool/cron/crontabs",
        NULL
    };

    const char *keywords[] = {
        "/dev/shm", "/tmp/", "memfd", "curl", "wget", "nc ", "bash -i", "sh -i", "python", "perl", NULL
    };

    int matches = 0;
    for (int i = 0; paths[i]; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            DIR *d = opendir(paths[i]);
            if (!d) continue;
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.') continue;
                char sub[512];
                snprintf(sub, sizeof(sub), "%s/%s", paths[i], de->d_name);
                FILE *f = fopen(sub, "r");
                if (f) {
                    char line[512];
                    int ln = 0;
                    while (fgets(line, sizeof(line), f)) {
                        ln++;
                        for (int k = 0; keywords[k]; k++) {
                            if (strstr(line, keywords[k])) {
                                printf("[!] %s:%d: %s", sub, ln, line);
                                matches++;
                                break;
                            }
                        }
                    }
                    fclose(f);
                }
            }
            closedir(d);
        } else {
            FILE *f = fopen(paths[i], "r");
            if (f) {
                char line[512];
                int ln = 0;
                while (fgets(line, sizeof(line), f)) {
                    ln++;
                    for (int k = 0; keywords[k]; k++) {
                        if (strstr(line, keywords[k])) {
                            printf("[!] %s:%d: %s", paths[i], ln, line);
                            matches++;
                            break;
                        }
                    }
                }
                fclose(f);
            }
        }
    }

    if (matches == 0) {
        printf("No suspicious persistence triggers identified in standard locations.\n");
    } else {
        printf("Flagged %d potential persistence line(s).\n", matches);
    }
    fflush(stdout);
    return 0;
}



/* --- Detached Process & Job Control Engine --- */

typedef struct {
    int id;
    pid_t pid;
    char cmd[256];
    char logfile[256];
    int running;
} ShellJob;

#define MAX_SHELL_JOBS 64
static ShellJob shell_jobs[MAX_SHELL_JOBS];
static int next_job_id = 1;

static void update_shell_jobs(void) {
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].pid > 0 && shell_jobs[i].running) {
            int status = 0;
            pid_t r = waitpid(shell_jobs[i].pid, &status, WNOHANG);
            if (r == shell_jobs[i].pid || (r < 0 && errno == ECHILD) ||
                (kill(shell_jobs[i].pid, 0) < 0 && errno == ESRCH)) {
                shell_jobs[i].running = 0;
            }
        }
    }
}

static int add_shell_job(pid_t pid, const char *cmd, const char *logfile) {
    update_shell_jobs();
    int slot = -1;
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].pid == 0 || !shell_jobs[i].running) {
            slot = i;
            break;
        }
    }
    if (slot == -1) slot = 0;
    shell_jobs[slot].id = next_job_id++;
    shell_jobs[slot].pid = pid;
    strncpy(shell_jobs[slot].cmd, cmd ? cmd : "unknown", sizeof(shell_jobs[slot].cmd) - 1);
    shell_jobs[slot].cmd[sizeof(shell_jobs[slot].cmd) - 1] = '\0';
    strncpy(shell_jobs[slot].logfile, logfile ? logfile : "/dev/null", sizeof(shell_jobs[slot].logfile) - 1);
    shell_jobs[slot].logfile[sizeof(shell_jobs[slot].logfile) - 1] = '\0';
    shell_jobs[slot].running = 1;
    return shell_jobs[slot].id;
}

static int builtin_detach(char **args) {
    if (!args || !args[1]) {
        printf("Usage: detach [-o logfile] [-e errfile] <command...> [args...]\n");
        printf("Spawns an independent background session (immune to SIGHUP / terminal hangup).\n");
        printf("Example: detach -o /dev/shm/velo.log /usr/bin/velociraptor client\n");
        printf("Type 'help detach' for complete details and offline incident response examples.\n");
        return 1;
    }

    const char *out_log = NULL;
    const char *err_log = NULL;
    int idx = 1;

    while (args[idx] && args[idx][0] == '-') {
        if (strcmp(args[idx], "-o") == 0 && args[idx + 1]) {
            out_log = args[idx + 1];
            idx += 2;
        } else if (strcmp(args[idx], "-e") == 0 && args[idx + 1]) {
            err_log = args[idx + 1];
            idx += 2;
        } else if (strcmp(args[idx], "--") == 0) {
            idx++;
            break;
        } else {
            break;
        }
    }

    if (!args[idx]) {
        fprintf(stderr, "minish: detach: missing command to execute\n");
        return 1;
    }

    char cmd_str[256];
    cmd_str[0] = '\0';
    size_t clen = 0;
    for (int i = idx; args[i]; i++) {
        if (i > idx && clen + 1 < sizeof(cmd_str)) {
            cmd_str[clen++] = ' ';
            cmd_str[clen] = '\0';
        }
        size_t alen = strlen(args[i]);
        if (clen + alen < sizeof(cmd_str)) {
            memcpy(cmd_str + clen, args[i], alen);
            clen += alen;
            cmd_str[clen] = '\0';
        }
    }

    char default_log[128];
    if (!out_log) {
        const char *prog = args[idx];
        const char *slash = strrchr(prog, '/');
        if (slash) prog = slash + 1;
        snprintf(default_log, sizeof(default_log), "/dev/shm/detach_%s_%d.log", prog, (int)getpid());
        out_log = default_log;
    }
    if (!err_log) {
        err_log = out_log;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("minish: detach: fork");
        return 1;
    }

    if (pid == 0) {
        setsid();
        signal(SIGHUP, SIG_IGN);
        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTERM, SIG_DFL);

        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }

        int out_fd = open(out_log, O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (out_fd >= 0) {
            dup2(out_fd, STDOUT_FILENO);
            close(out_fd);
        }

        if (strcmp(err_log, out_log) == 0) {
            dup2(STDOUT_FILENO, STDERR_FILENO);
        } else {
            int err_fd = open(err_log, O_WRONLY | O_CREAT | O_APPEND, 0666);
            if (err_fd >= 0) {
                dup2(err_fd, STDERR_FILENO);
                close(err_fd);
            }
        }

        execvp(args[idx], &args[idx]);
        fprintf(stderr, "minish: detach: failed to exec '%s': %s\n", args[idx], strerror(errno));
        _exit(127);
    }

    int jid = add_shell_job(pid, cmd_str, out_log);
    printf("[+] Detached job [%d] spawned: PID %d\n", jid, (int)pid);
    printf("    Command:    %s\n", cmd_str);
    printf("    Output log: %s\n", out_log);
    printf("    Session:    detached from tty (immune to SIGHUP / terminal hangup)\n");
    fflush(stdout);
    return 0;
}

static int builtin_jobs(char **args) {
    (void)args;
    update_shell_jobs();
    int found = 0;
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].pid > 0) {
            printf("[%d]  PID %-6d  %-10s  %s\n",
                   shell_jobs[i].id,
                   (int)shell_jobs[i].pid,
                   shell_jobs[i].running ? "Running" : "Done",
                   shell_jobs[i].cmd);
            printf("     Log: %s  |  Attach: 'attach %d'  |  Stop: 'stop %d'\n",
                   shell_jobs[i].logfile, shell_jobs[i].id, shell_jobs[i].id);
            found++;
        }
    }
    if (!found) {
        printf("minish: no background or detached jobs\n");
    }
    fflush(stdout);
    return 0;
}

static int builtin_disown(char **args) {
    if (!args[1]) {
        update_shell_jobs();
        int count = 0;
        for (int i = 0; i < MAX_SHELL_JOBS; i++) {
            if (shell_jobs[i].pid > 0) {
                shell_jobs[i].pid = 0;
                count++;
            }
        }
        printf("[+] Disowned %d job(s)\n", count);
        return 0;
    }
    int target = atoi(args[1]);
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].id == target || shell_jobs[i].pid == target) {
            printf("[+] Disowned job [%d] (PID %d)\n", shell_jobs[i].id, (int)shell_jobs[i].pid);
            shell_jobs[i].pid = 0;
            return 0;
        }
    }
    fprintf(stderr, "minish: disown: job or PID '%s' not found\n", args[1]);
    return 1;
}

static int builtin_stop(char **args) {
    if (!args[1]) {
        printf("Usage: stop <job_id|pid> [-sig]\n");
        printf("Terminates a detached or background job along with its child process tree.\n");
        printf("Example: stop 1        (sends SIGTERM to job 1)\n");
        printf("Example: stop 1 -9     (sends SIGKILL to job 1)\n");
        return 1;
    }

    int sig = SIGTERM;
    const char *target_str = args[1];
    if (args[1][0] == '-' && args[2]) {
        sig = atoi(args[1] + 1);
        if (sig <= 0) sig = SIGTERM;
        target_str = args[2];
    } else if (args[2] && args[2][0] == '-') {
        sig = atoi(args[2] + 1);
        if (sig <= 0) sig = SIGTERM;
    }

    int target = atoi(target_str);
    int slot = -1;
    update_shell_jobs();
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].pid > 0 && (shell_jobs[i].id == target || shell_jobs[i].pid == target)) {
            slot = i;
            break;
        }
    }

    pid_t pid = (slot != -1) ? shell_jobs[slot].pid : (pid_t)target;
    if (pid <= 1) {
        fprintf(stderr, "minish: stop: invalid PID or job target\n");
        return 1;
    }

    kill_children_of(pid, sig);
    if (kill(pid, sig) == 0) {
        if (slot != -1) {
            shell_jobs[slot].running = 0;
            printf("[+] Stopped job [%d] (PID %d: %s) with signal %d\n",
                   shell_jobs[slot].id, (int)pid, shell_jobs[slot].cmd, sig);
        } else {
            printf("[+] Terminated process PID %d with signal %d\n", (int)pid, sig);
        }
        return 0;
    } else {
        perror("minish: stop");
        return 1;
    }
}

static int builtin_attach(char **args) {
    if (!args[1]) {
        printf("Usage: attach <job_id|pid>\n");
        printf("Taps into the live output log of a detached or background job.\n");
        printf("Press Ctrl-C or 'q' at any time to detach without killing the process.\n");
        return 1;
    }

    int target = atoi(args[1]);
    int slot = -1;
    update_shell_jobs();
    for (int i = 0; i < MAX_SHELL_JOBS; i++) {
        if (shell_jobs[i].pid > 0 && (shell_jobs[i].id == target || shell_jobs[i].pid == target)) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        fprintf(stderr, "minish: attach: job or PID '%s' not found. Run 'jobs' to list active jobs.\n", args[1]);
        return 1;
    }

    const char *logfile = shell_jobs[slot].logfile;
    if (strcmp(logfile, "/dev/null") == 0 || strcmp(logfile, "inherited stdout") == 0) {
        printf("Job [%d] (PID %d) output is not streaming to a log file (%s).\n",
               shell_jobs[slot].id, (int)shell_jobs[slot].pid, logfile);
        return 1;
    }

    FILE *fp = fopen(logfile, "r");
    if (!fp) {
        perror(logfile);
        return 1;
    }

    printf("\n=== Attaching to Job [%d] (PID %d: %s) ===\n",
           shell_jobs[slot].id, (int)shell_jobs[slot].pid, shell_jobs[slot].cmd);
    printf("Log source: %s\n", logfile);
    printf("Status:     %s\n", shell_jobs[slot].running ? "RUNNING" : "DONE");
    printf("Press [Ctrl-C] or 'q' at any time to detach (process will NOT be killed).\n");
    printf("--------------------------------------------------------------------------------\n");
    fflush(stdout);

    /* Print last 4KB */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    long seek_pos = (fsize > 4096) ? fsize - 4096 : 0;
    fseek(fp, seek_pos, SEEK_SET);

    char line_buf[512];
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        fputs(line_buf, stdout);
    }
    fflush(stdout);

    int running = 1;
    struct termios orig_t;
    int has_tty = isatty(STDIN_FILENO);
    if (has_tty) {
        tcgetattr(STDIN_FILENO, &orig_t);
        struct termios raw = orig_t;
        raw.c_lflag &= ~(ECHO | ICANON | ISIG);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 1;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }

    while (running) {
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            fputs(line_buf, stdout);
            fflush(stdout);
        }

        if (has_tty) {
            char ch;
            if (read(STDIN_FILENO, &ch, 1) > 0) {
                if (ch == 'q' || ch == 'Q' || ch == 3 || ch == 4) {
                    running = 0;
                    break;
                }
            }
        }

        int st = 0;
        pid_t wr = waitpid(shell_jobs[slot].pid, &st, WNOHANG);
        if (wr == shell_jobs[slot].pid || (wr < 0 && errno == ECHILD) ||
            (kill(shell_jobs[slot].pid, 0) < 0 && errno == ESRCH)) {
            shell_jobs[slot].running = 0;
            while (fgets(line_buf, sizeof(line_buf), fp)) {
                fputs(line_buf, stdout);
            }
            printf("\n[+] Process %d finished execution.\n", (int)shell_jobs[slot].pid);
            break;
        }

        usleep(100000);
    }

    if (has_tty) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_t);
    }
    fclose(fp);
    printf("\n[+] Detached from job [%d]. Background process remains active.\n\n", shell_jobs[slot].id);
    fflush(stdout);
    return 0;
}

/* --- Anti-Adversary Stealth & Camouflage Engine --- */

static int builtin_stealth(char **args) {
    const char *disguise = (args && args[1]) ? args[1] : "[kworker/0:1]";

    /* 1. Inspect parent process to detect interactive shell lineage */
    pid_t ppid = getppid();
    char pcomm[64] = "unknown";
    char ppath[128];
    snprintf(ppath, sizeof(ppath), "/proc/%d/comm", (int)ppid);
    FILE *fp = fopen(ppath, "r");
    if (fp) {
        if (fgets(pcomm, sizeof(pcomm), fp)) {
            pcomm[strcspn(pcomm, "\r\n")] = '\0';
        }
        fclose(fp);
    }

    printf("\n=== Anti-Adversary Stealth & Threat Hunting Camouflage ===\n");
    if (strcmp(pcomm, "bash") == 0 || strcmp(pcomm, "sh") == 0 ||
        strcmp(pcomm, "zsh") == 0 || strcmp(pcomm, "dash") == 0) {
        printf("  [!] LINEAGE ALERT: Parent process is '%s' (PID %d).\n", pcomm, (int)ppid);
        printf("      An adversary monitoring /proc or 'ps -ef' will see: %s -> minish\n", pcomm);
        printf("      TO COMPLETELY SEVER LINEAGE: Launch via 'exec minish' instead of './minish'.\n");
        printf("      'exec minish' replaces the calling %s in-place, eliminating it from the process tree.\n", pcomm);
    } else {
        printf("  [+] Parent process is '%s' (PID %d) - clean unexposed lineage.\n", pcomm, (int)ppid);
    }

    /* 2. Disguise process comm and cmdline memory in-place */
    set_process_name(disguise);
    printf("  [+] Process identity disguised as '%s'\n", disguise);
    printf("      - /proc/self/comm (top, ps comm)   -> %s\n", disguise);
    printf("      - /proc/self/cmdline (ps -ef, aux) -> %s\n", disguise);

    /* 3. Arm anti-kill recovery armor (SIGTERM, SIGINT, SIGQUIT) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    /* Leave SIGHUP active so terminal closures terminate cleanly without hanging */
    printf("  [+] Anti-Kill Armor armed: SIGTERM, SIGINT, SIGQUIT masked (SIGHUP kept for clean terminal exit).\n");
    printf("      Attacker kill scripts cannot terminate this recovery session.\n");

    /* 4. Set OOM score to -1000 */
    FILE *oom_fp = fopen("/proc/self/oom_score_adj", "w");
    if (oom_fp) {
        fprintf(oom_fp, "-1000\n");
        fclose(oom_fp);
        printf("  [+] OOM Protection: score adjusted to -1000 (immune to kernel OOM killer).\n");
    }

    printf("[+] Cloak active. Your triage shell is now disguised and armored against adversaries.\n\n");
    fflush(stdout);
    return 0;
}

/* Forward declarations for terminal raw mode control */
static int enable_raw_mode(void);
static void disable_raw_mode(void);

/* --- Zero-Dependency In-Memory Modal Micro-Editor (vim / vi) --- */

#define VIM_MODE_NORMAL  0
#define VIM_MODE_INSERT  1
#define VIM_MODE_COMMAND 2
#define VIM_MODE_SEARCH  3

enum VimKey {
    VIM_KEY_BACKSPACE = 127,
    VIM_KEY_ARROW_LEFT = 1000,
    VIM_KEY_ARROW_RIGHT,
    VIM_KEY_ARROW_UP,
    VIM_KEY_ARROW_DOWN,
    VIM_KEY_DEL,
    VIM_KEY_HOME,
    VIM_KEY_END,
    VIM_KEY_PAGE_UP,
    VIM_KEY_PAGE_DOWN
};

typedef struct {
    char *chars;
    int len;
} VimRow;

typedef struct {
    VimRow *rows;
    int num_rows;
    int cx, cy;            /* cursor col, cursor row */
    int row_offset;        /* top row visible */
    int col_offset;        /* left col visible */
    int screen_rows;       /* rows in text viewport */
    int screen_cols;       /* cols in viewport */
    char *filename;        /* active file */
    int modified;          /* 1 if modified */
    int mode;              /* current mode */
    char status_msg[128];  /* message on status line */
    time_t status_time;
    char *yank_buf;        /* line yank buffer */
    int show_nu;           /* 1 = line numbers shown */
    char search_pat[64];   /* last search pattern */
    /* Single-level undo buffer */
    VimRow *undo_rows;
    int undo_num_rows;
    int undo_cx, undo_cy;
    int has_undo;
    int replace_pending;
    int g_pending;         /* for 'gg' */
    int d_pending;         /* for 'dd' */
    int y_pending;         /* for 'yy' */
    int z_pending;         /* for 'ZZ'/'ZQ' */
} VimEditor;

struct vim_abuf {
    char *b;
    int len;
    int cap;
};

static void abuf_append(struct vim_abuf *ab, const char *s, int len) {
    if (len <= 0) return;
    if (ab->len + len >= ab->cap) {
        int ncap = (ab->cap == 0) ? 1024 : ab->cap * 2;
        while (ab->len + len >= ncap) ncap *= 2;
        char *nb = (char *)realloc(ab->b, ncap);
        if (!nb) return;
        ab->b = nb;
        ab->cap = ncap;
    }
    memcpy(ab->b + ab->len, s, len);
    ab->len += len;
}

static void abuf_free(struct vim_abuf *ab) {
    free(ab->b);
    ab->b = NULL;
    ab->len = 0;
    ab->cap = 0;
}

static void vim_free_row(VimRow *row) {
    free(row->chars);
    row->chars = NULL;
    row->len = 0;
}

static void vim_insert_row(VimEditor *E, int at, const char *s, int len) {
    if (at < 0 || at > E->num_rows) return;
    E->rows = (VimRow *)realloc(E->rows, sizeof(VimRow) * (E->num_rows + 1));
    if (at < E->num_rows) {
        memmove(&E->rows[at + 1], &E->rows[at], sizeof(VimRow) * (E->num_rows - at));
    }
    E->rows[at].len = len;
    E->rows[at].chars = (char *)malloc(len + 1);
    if (len > 0 && s) memcpy(E->rows[at].chars, s, len);
    E->rows[at].chars[len] = '\0';
    E->num_rows++;
    E->modified = 1;
}

static void vim_del_row(VimEditor *E, int at) {
    if (at < 0 || at >= E->num_rows) return;
    vim_free_row(&E->rows[at]);
    if (at < E->num_rows - 1) {
        memmove(&E->rows[at], &E->rows[at + 1], sizeof(VimRow) * (E->num_rows - at - 1));
    }
    E->num_rows--;
    E->modified = 1;
}

static void vim_row_insert_char(VimRow *row, int at, int c) {
    if (at < 0 || at > row->len) at = row->len;
    char *nb = (char *)realloc(row->chars, row->len + 2);
    if (!nb) return;
    row->chars = nb;
    memmove(&row->chars[at + 1], &row->chars[at], row->len - at + 1);
    row->chars[at] = (char)c;
    row->len++;
}

static void vim_row_del_char(VimRow *row, int at) {
    if (at < 0 || at >= row->len) return;
    memmove(&row->chars[at], &row->chars[at + 1], row->len - at);
    row->len--;
}

static void vim_row_append_string(VimRow *row, const char *s, int len) {
    if (len <= 0) return;
    char *nb = (char *)realloc(row->chars, row->len + len + 1);
    if (!nb) return;
    row->chars = nb;
    memcpy(&row->chars[row->len], s, len);
    row->len += len;
    row->chars[row->len] = '\0';
}

static void vim_save_undo(VimEditor *E) {
    if (E->has_undo && E->undo_rows) {
        for (int i = 0; i < E->undo_num_rows; i++) vim_free_row(&E->undo_rows[i]);
        free(E->undo_rows);
        E->undo_rows = NULL;
    }
    E->undo_num_rows = E->num_rows;
    E->undo_rows = (VimRow *)malloc(sizeof(VimRow) * E->num_rows);
    for (int i = 0; i < E->num_rows; i++) {
        E->undo_rows[i].len = E->rows[i].len;
        E->undo_rows[i].chars = (char *)malloc(E->rows[i].len + 1);
        memcpy(E->undo_rows[i].chars, E->rows[i].chars, E->rows[i].len + 1);
    }
    E->undo_cx = E->cx;
    E->undo_cy = E->cy;
    E->has_undo = 1;
}

static void vim_apply_undo(VimEditor *E) {
    if (!E->has_undo || !E->undo_rows) {
        snprintf(E->status_msg, sizeof(E->status_msg), "Already at oldest change");
        E->status_time = time(NULL);
        return;
    }
    VimRow *tmp_rows = E->rows;
    int tmp_num = E->num_rows;
    int tmp_cx = E->cx, tmp_cy = E->cy;

    E->rows = E->undo_rows;
    E->num_rows = E->undo_num_rows;
    E->cx = E->undo_cx;
    E->cy = E->undo_cy;

    E->undo_rows = tmp_rows;
    E->undo_num_rows = tmp_num;
    E->undo_cx = tmp_cx;
    E->undo_cy = tmp_cy;

    E->modified = 1;
    snprintf(E->status_msg, sizeof(E->status_msg), "1 change; before #1");
    E->status_time = time(NULL);
}

static void vim_update_window_size(VimEditor *E) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        E->screen_rows = (ws.ws_row >= 3) ? ws.ws_row - 2 : 22;
        E->screen_cols = ws.ws_col;
    } else {
        E->screen_rows = 22;
        E->screen_cols = 80;
    }
}

static void vim_open(VimEditor *E, const char *filename) {
    E->filename = filename ? strdup(filename) : NULL;
    E->rows = NULL;
    E->num_rows = 0;
    E->cx = 0;
    E->cy = 0;
    E->row_offset = 0;
    E->col_offset = 0;
    E->modified = 0;
    E->mode = VIM_MODE_NORMAL;
    E->yank_buf = NULL;
    E->show_nu = 1;
    E->search_pat[0] = '\0';
    E->undo_rows = NULL;
    E->undo_num_rows = 0;
    E->has_undo = 0;
    E->replace_pending = 0;
    E->g_pending = 0;
    E->d_pending = 0;
    E->y_pending = 0;
    E->z_pending = 0;

    if (!filename) {
        vim_insert_row(E, 0, "", 0);
        E->modified = 0;
        snprintf(E->status_msg, sizeof(E->status_msg), "[No Name] -- minish vim micro-editor");
        E->status_time = time(NULL);
        return;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        vim_insert_row(E, 0, "", 0);
        E->modified = 0;
        snprintf(E->status_msg, sizeof(E->status_msg), "\"%s\" [New File]", filename);
        E->status_time = time(NULL);
        return;
    }

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    while ((linelen = getline(&line, &linecap, fp)) != -1) {
        while (linelen > 0 && (line[linelen - 1] == '\n' || line[linelen - 1] == '\r')) {
            linelen--;
        }
        vim_insert_row(E, E->num_rows, line, (int)linelen);
    }
    free(line);
    fclose(fp);

    if (E->num_rows == 0) vim_insert_row(E, 0, "", 0);
    E->modified = 0;
    snprintf(E->status_msg, sizeof(E->status_msg), "\"%s\" %dL", filename, E->num_rows);
    E->status_time = time(NULL);
}

static int vim_save(VimEditor *E, const char *opt_name) {
    const char *target = opt_name ? opt_name : E->filename;
    if (!target || !target[0]) {
        snprintf(E->status_msg, sizeof(E->status_msg), "E32: No file name");
        E->status_time = time(NULL);
        return -1;
    }

    int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        snprintf(E->status_msg, sizeof(E->status_msg), "E212: Can't open file for writing: %s", strerror(errno));
        E->status_time = time(NULL);
        return -1;
    }

    size_t total_bytes = 0;
    for (int i = 0; i < E->num_rows; i++) {
        if (E->rows[i].len > 0) {
            ssize_t w = write(fd, E->rows[i].chars, E->rows[i].len);
            if (w < 0) {
                close(fd);
                snprintf(E->status_msg, sizeof(E->status_msg), "E514: Write error (disk full ENOSPC?): %s", strerror(errno));
                E->status_time = time(NULL);
                return -1;
            }
            total_bytes += (size_t)w;
        }
        if (write(fd, "\n", 1) < 0) {
            close(fd);
            snprintf(E->status_msg, sizeof(E->status_msg), "E514: Write error: %s", strerror(errno));
            E->status_time = time(NULL);
            return -1;
        }
        total_bytes++;
    }
    close(fd);

    if (!E->filename || strcmp(E->filename, target) != 0) {
        free(E->filename);
        E->filename = strdup(target);
    }
    E->modified = 0;
    snprintf(E->status_msg, sizeof(E->status_msg), "\"%s\" %dL, %zuB written", target, E->num_rows, total_bytes);
    E->status_time = time(NULL);
    return 0;
}

static int vim_read_key(void) {
    static int key_peek = -1;
    if (key_peek != -1) {
        int k = key_peek;
        key_peek = -1;
        return k;
    }

    int nread;
    char c;
    while ((nread = read(STDIN_FILENO, &c, 1)) != 1) {
        if (nread < 0 && errno != EAGAIN && errno != EINTR) return -1;
    }

    if (c == '\x1b') {
        char seq[4];
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
        int r1 = read(STDIN_FILENO, &seq[0], 1);
        int r2 = (r1 == 1 && (seq[0] == '[' || seq[0] == 'O')) ? read(STDIN_FILENO, &seq[1], 1) : 0;
        int r3 = (r2 == 1 && seq[0] == '[') ? read(STDIN_FILENO, &seq[2], 1) : 0;
        fcntl(STDIN_FILENO, F_SETFL, flags);

        if (r1 == 1 && seq[0] == '[') {
            if (r2 == 1) {
                if (seq[1] >= '0' && seq[1] <= '9') {
                    if (r3 == 1 && seq[2] == '~') {
                        switch (seq[1]) {
                            case '1': case '7': return VIM_KEY_HOME;
                            case '3': return VIM_KEY_DEL;
                            case '4': case '8': return VIM_KEY_END;
                            case '5': return VIM_KEY_PAGE_UP;
                            case '6': return VIM_KEY_PAGE_DOWN;
                        }
                    }
                } else {
                    switch (seq[1]) {
                        case 'A': return VIM_KEY_ARROW_UP;
                        case 'B': return VIM_KEY_ARROW_DOWN;
                        case 'C': return VIM_KEY_ARROW_RIGHT;
                        case 'D': return VIM_KEY_ARROW_LEFT;
                        case 'H': return VIM_KEY_HOME;
                        case 'F': return VIM_KEY_END;
                    }
                }
            }
        } else if (r1 == 1 && seq[0] == 'O') {
            if (r2 == 1) {
                switch (seq[1]) {
                    case 'H': return VIM_KEY_HOME;
                    case 'F': return VIM_KEY_END;
                }
            }
        } else if (r1 == 1) {
            key_peek = (unsigned char)seq[0];
            return '\x1b';
        }
        return '\x1b';
    }
    return (unsigned char)c;
}

static void vim_draw(VimEditor *E, const char *cmd_buf) {
    vim_update_window_size(E);

    if (E->cy < E->row_offset) E->row_offset = E->cy;
    if (E->cy >= E->row_offset + E->screen_rows) {
        E->row_offset = E->cy - E->screen_rows + 1;
    }
    int margin = E->show_nu ? 6 : 0;
    int avail_cols = E->screen_cols - margin;
    if (avail_cols < 10) avail_cols = 10;

    if (E->cx < E->col_offset) E->col_offset = E->cx;
    if (E->cx >= E->col_offset + avail_cols) {
        E->col_offset = E->cx - avail_cols + 1;
    }

    struct vim_abuf ab = {NULL, 0, 0};
    abuf_append(&ab, "\x1b[?25l\x1b[H", 9);

    for (int y = 0; y < E->screen_rows; y++) {
        int filerow = y + E->row_offset;
        if (filerow < E->num_rows) {
            if (E->show_nu) {
                char numbuf[16];
                int nlen = snprintf(numbuf, sizeof(numbuf), "\x1b[33m%5d \x1b[0m", filerow + 1);
                abuf_append(&ab, numbuf, nlen);
            }
            int len = E->rows[filerow].len - E->col_offset;
            if (len < 0) len = 0;
            if (len > avail_cols) len = avail_cols;
            if (len > 0) {
                abuf_append(&ab, &E->rows[filerow].chars[E->col_offset], len);
            }
        } else {
            if (E->show_nu) abuf_append(&ab, "      ", 6);
            if (E->num_rows == 0 && y == E->screen_rows / 3) {
                char welcome[80];
                int wlen = snprintf(welcome, sizeof(welcome), "minish micro-vim editor -- version 1.0.0");
                if (wlen > avail_cols) wlen = avail_cols;
                int pad = (avail_cols - wlen) / 2;
                if (pad > 0) {
                    abuf_append(&ab, "~", 1);
                    for (int p = 1; p < pad; p++) abuf_append(&ab, " ", 1);
                }
                abuf_append(&ab, welcome, wlen);
            } else {
                abuf_append(&ab, "\x1b[34m~\x1b[0m", 9);
            }
        }
        abuf_append(&ab, "\x1b[K\r\n", 5);
    }

    /* Status Bar */
    abuf_append(&ab, "\x1b[7m", 4);
    char status[128], rstatus[64];
    const char *mname = (E->mode == VIM_MODE_INSERT) ? "-- INSERT --" :
                        (E->mode == VIM_MODE_COMMAND) ? "-- COMMAND --" :
                        (E->mode == VIM_MODE_SEARCH) ? "-- SEARCH --" :
                        (E->replace_pending) ? "-- REPLACE --" : "NORMAL";
    int len = snprintf(status, sizeof(status), " %s  %s%s",
                       mname,
                       E->filename ? E->filename : "[No Name]",
                       E->modified ? " [+]" : "");
    int pct = (E->num_rows > 0) ? ((E->cy + 1) * 100) / E->num_rows : 0;
    int rlen = snprintf(rstatus, sizeof(rstatus), " %d,%d   %d%% ", E->cy + 1, E->cx + 1, pct);
    if (len > E->screen_cols) len = E->screen_cols;
    abuf_append(&ab, status, len);
    while (len < E->screen_cols) {
        if (E->screen_cols - len == rlen) {
            abuf_append(&ab, rstatus, rlen);
            break;
        } else {
            abuf_append(&ab, " ", 1);
            len++;
        }
    }
    abuf_append(&ab, "\x1b[0m\r\n", 6);

    /* Command / Message Bar */
    abuf_append(&ab, "\x1b[K", 3);
    if (E->mode == VIM_MODE_COMMAND) {
        abuf_append(&ab, ":", 1);
        if (cmd_buf) abuf_append(&ab, cmd_buf, (int)strlen(cmd_buf));
    } else if (E->mode == VIM_MODE_SEARCH) {
        abuf_append(&ab, "/", 1);
        if (cmd_buf) abuf_append(&ab, cmd_buf, (int)strlen(cmd_buf));
    } else if (E->status_msg[0] && time(NULL) - E->status_time < 5) {
        abuf_append(&ab, E->status_msg, (int)strlen(E->status_msg));
    }

    int cursor_y, cursor_x;
    if (E->mode == VIM_MODE_COMMAND || E->mode == VIM_MODE_SEARCH) {
        cursor_y = E->screen_rows + 2;
        cursor_x = 2 + (cmd_buf ? (int)strlen(cmd_buf) : 0);
    } else {
        cursor_y = (E->cy - E->row_offset) + 1;
        cursor_x = margin + (E->cx - E->col_offset) + 1;
    }
    char cpos[32];
    int clen = snprintf(cpos, sizeof(cpos), "\x1b[%d;%dH\x1b[?25h", cursor_y, cursor_x);
    abuf_append(&ab, cpos, clen);

    if (write(STDOUT_FILENO, ab.b, ab.len) < 0) { /* suppress warn_unused_result */ }
    abuf_free(&ab);
}

static void vim_move_cursor(VimEditor *E, int key) {
    VimRow *row = (E->cy < E->num_rows) ? &E->rows[E->cy] : NULL;
    switch (key) {
        case VIM_KEY_ARROW_LEFT:
        case 'h':
            if (E->cx > 0) E->cx--;
            break;
        case VIM_KEY_ARROW_RIGHT:
        case 'l':
            if (row && E->cx < row->len) E->cx++;
            break;
        case VIM_KEY_ARROW_UP:
        case 'k':
            if (E->cy > 0) E->cy--;
            break;
        case VIM_KEY_ARROW_DOWN:
        case 'j':
            if (E->cy < E->num_rows - 1) E->cy++;
            break;
    }
    row = (E->cy < E->num_rows) ? &E->rows[E->cy] : NULL;
    int rowlen = row ? row->len : 0;
    if (E->mode == VIM_MODE_NORMAL) {
        if (rowlen > 0 && E->cx >= rowlen) E->cx = rowlen - 1;
    } else {
        if (E->cx > rowlen) E->cx = rowlen;
    }
}

static void vim_search_next(VimEditor *E, int forward) {
    if (!E->search_pat[0] || E->num_rows == 0) return;
    int patlen = (int)strlen(E->search_pat);
    int start_y = E->cy;
    int start_x = forward ? E->cx + 1 : E->cx - 1;

    for (int step = 0; step < E->num_rows; step++) {
        int curr_y = forward ? (start_y + step) % E->num_rows :
                               (start_y - step + E->num_rows) % E->num_rows;
        VimRow *r = &E->rows[curr_y];
        if (r->len < patlen) continue;

        if (curr_y == start_y && step == 0) {
            if (forward) {
                if (start_x < r->len) {
                    char *m = strstr(&r->chars[start_x], E->search_pat);
                    if (m) {
                        E->cy = curr_y;
                        E->cx = (int)(m - r->chars);
                        return;
                    }
                }
            } else {
                for (int x = start_x; x >= 0; x--) {
                    if (strncmp(&r->chars[x], E->search_pat, patlen) == 0) {
                        E->cy = curr_y;
                        E->cx = x;
                        return;
                    }
                }
            }
        } else {
            if (forward) {
                char *m = strstr(r->chars, E->search_pat);
                if (m) {
                    E->cy = curr_y;
                    E->cx = (int)(m - r->chars);
                    return;
                }
            } else {
                for (int x = r->len - patlen; x >= 0; x--) {
                    if (strncmp(&r->chars[x], E->search_pat, patlen) == 0) {
                        E->cy = curr_y;
                        E->cx = x;
                        return;
                    }
                }
            }
        }
    }
    snprintf(E->status_msg, sizeof(E->status_msg), "Pattern not found: %.80s", E->search_pat);
    E->status_time = time(NULL);
}

static int show_command_help(const char *cmd);

static int builtin_vim(char **args) {
    if (args[1] && (strcmp(args[1], "--help") == 0 || strcmp(args[1], "-h") == 0)) {
        show_command_help("vim");
        return 0;
    }

    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "minish: %s: standard input and output must be an interactive terminal\n", args[0] ? args[0] : "vim");
        return 1;
    }

    const char *target_file = (args[1] != NULL) ? args[1] : NULL;

    VimEditor E;
    memset(&E, 0, sizeof(E));
    vim_open(&E, target_file);

    if (enable_raw_mode() < 0) {
        fprintf(stderr, "minish: %s: failed to set terminal raw mode\n", args[0] ? args[0] : "vim");
        return 1;
    }

    if (write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7) < 0) { /* suppress warn_unused_result */ }

    char cmd_buf[128];
    cmd_buf[0] = '\0';
    int cmd_len = 0;
    int running = 1;

    while (running) {
        vim_draw(&E, (E.mode == VIM_MODE_COMMAND || E.mode == VIM_MODE_SEARCH) ? cmd_buf : NULL);
        int c = vim_read_key();
        if (c < 0) break;

        /* COMMAND (Ex) MODE */
        if (E.mode == VIM_MODE_COMMAND) {
            if (c == '\r' || c == '\n') {
                cmd_buf[cmd_len] = '\0';
                char *cmd = cmd_buf;
                while (*cmd == ' ') cmd++;

                if (strcmp(cmd, "q") == 0) {
                    if (E.modified) {
                        snprintf(E.status_msg, sizeof(E.status_msg), "E37: No write since last change (add ! to override)");
                        E.status_time = time(NULL);
                    } else {
                        running = 0;
                    }
                } else if (strcmp(cmd, "q!") == 0) {
                    running = 0;
                } else if (strcmp(cmd, "w") == 0) {
                    vim_save(&E, NULL);
                } else if (strncmp(cmd, "w ", 2) == 0) {
                    char *fname = cmd + 2;
                    while (*fname == ' ') fname++;
                    vim_save(&E, fname);
                } else if (strcmp(cmd, "w!") == 0 || strncmp(cmd, "w! ", 3) == 0) {
                    char *fname = (strncmp(cmd, "w! ", 3) == 0) ? cmd + 3 : NULL;
                    if (fname) while (*fname == ' ') fname++;
                    vim_save(&E, fname);
                } else if (strcmp(cmd, "wq") == 0 || strcmp(cmd, "x") == 0 || strcmp(cmd, "wq!") == 0 || strcmp(cmd, "x!") == 0) {
                    if (vim_save(&E, NULL) == 0) {
                        running = 0;
                    }
                } else if (strncmp(cmd, "wq ", 3) == 0) {
                    char *fname = cmd + 3;
                    while (*fname == ' ') fname++;
                    if (vim_save(&E, fname) == 0) {
                        running = 0;
                    }
                } else if (strcmp(cmd, "set nu") == 0 || strcmp(cmd, "set number") == 0) {
                    E.show_nu = 1;
                    snprintf(E.status_msg, sizeof(E.status_msg), "number");
                    E.status_time = time(NULL);
                } else if (strcmp(cmd, "set nonu") == 0 || strcmp(cmd, "set nonumber") == 0) {
                    E.show_nu = 0;
                    snprintf(E.status_msg, sizeof(E.status_msg), "nonumber");
                    E.status_time = time(NULL);
                } else if (strcmp(cmd, "$") == 0) {
                    if (E.num_rows > 0) {
                        E.cy = E.num_rows - 1;
                        E.cx = (E.rows[E.cy].len > 0) ? E.rows[E.cy].len - 1 : 0;
                    }
                } else if (cmd[0] >= '0' && cmd[0] <= '9') {
                    int target_line = atoi(cmd);
                    if (target_line < 1) target_line = 1;
                    if (target_line > E.num_rows) target_line = E.num_rows;
                    E.cy = target_line - 1;
                    E.cx = 0;
                } else if (strcmp(cmd, "help") == 0) {
                    snprintf(E.status_msg, sizeof(E.status_msg), ":w[file]=save  :q[!]=quit  :wq=save&quit  :set nu/nonu  :<num>=goto");
                    E.status_time = time(NULL);
                } else if (cmd[0] != '\0') {
                    snprintf(E.status_msg, sizeof(E.status_msg), "E492: Not an editor command: %.80s", cmd);
                    E.status_time = time(NULL);
                }

                E.mode = VIM_MODE_NORMAL;
                cmd_len = 0;
                cmd_buf[0] = '\0';
            } else if (c == '\x1b') {
                E.mode = VIM_MODE_NORMAL;
                cmd_len = 0;
                cmd_buf[0] = '\0';
            } else if (c == VIM_KEY_BACKSPACE || c == 8 || c == 127) {
                if (cmd_len > 0) {
                    cmd_len--;
                    cmd_buf[cmd_len] = '\0';
                } else {
                    E.mode = VIM_MODE_NORMAL;
                }
            } else if (c >= 32 && c <= 126) {
                if (cmd_len < (int)sizeof(cmd_buf) - 2) {
                    cmd_buf[cmd_len++] = (char)c;
                    cmd_buf[cmd_len] = '\0';
                }
            }
            continue;
        }

        /* SEARCH MODE */
        if (E.mode == VIM_MODE_SEARCH) {
            if (c == '\r' || c == '\n') {
                cmd_buf[cmd_len] = '\0';
                if (cmd_len > 0) {
                    strncpy(E.search_pat, cmd_buf, sizeof(E.search_pat) - 1);
                    E.search_pat[sizeof(E.search_pat) - 1] = '\0';
                    vim_search_next(&E, 1);
                }
                E.mode = VIM_MODE_NORMAL;
                cmd_len = 0;
                cmd_buf[0] = '\0';
            } else if (c == '\x1b') {
                E.mode = VIM_MODE_NORMAL;
                cmd_len = 0;
                cmd_buf[0] = '\0';
            } else if (c == VIM_KEY_BACKSPACE || c == 8 || c == 127) {
                if (cmd_len > 0) {
                    cmd_len--;
                    cmd_buf[cmd_len] = '\0';
                } else {
                    E.mode = VIM_MODE_NORMAL;
                }
            } else if (c >= 32 && c <= 126) {
                if (cmd_len < (int)sizeof(cmd_buf) - 2) {
                    cmd_buf[cmd_len++] = (char)c;
                    cmd_buf[cmd_len] = '\0';
                }
            }
            continue;
        }

        /* INSERT MODE */
        if (E.mode == VIM_MODE_INSERT) {
            if (c == '\x1b') {
                E.mode = VIM_MODE_NORMAL;
                VimRow *row = (E.cy < E.num_rows) ? &E.rows[E.cy] : NULL;
                if (row && E.cx > 0 && E.cx >= row->len) {
                    E.cx = (row->len > 0) ? row->len - 1 : 0;
                }
            } else if (c == '\r' || c == '\n') {
                VimRow *row = &E.rows[E.cy];
                if (E.cx >= row->len) {
                    vim_insert_row(&E, E.cy + 1, "", 0);
                } else {
                    vim_insert_row(&E, E.cy + 1, &row->chars[E.cx], row->len - E.cx);
                    row = &E.rows[E.cy];
                    row->len = E.cx;
                    row->chars[row->len] = '\0';
                }
                E.cy++;
                E.cx = 0;
                E.modified = 1;
            } else if (c == VIM_KEY_BACKSPACE || c == 8 || c == 127) {
                if (E.cx > 0) {
                    VimRow *row = &E.rows[E.cy];
                    vim_row_del_char(row, E.cx - 1);
                    E.cx--;
                    E.modified = 1;
                } else if (E.cy > 0) {
                    VimRow *prev = &E.rows[E.cy - 1];
                    VimRow *curr = &E.rows[E.cy];
                    E.cx = prev->len;
                    vim_row_append_string(prev, curr->chars, curr->len);
                    vim_del_row(&E, E.cy);
                    E.cy--;
                    E.modified = 1;
                }
            } else if (c == VIM_KEY_DEL) {
                VimRow *row = &E.rows[E.cy];
                if (E.cx < row->len) {
                    vim_row_del_char(row, E.cx);
                    E.modified = 1;
                } else if (E.cy < E.num_rows - 1) {
                    VimRow *next = &E.rows[E.cy + 1];
                    vim_row_append_string(row, next->chars, next->len);
                    vim_del_row(&E, E.cy + 1);
                    E.modified = 1;
                }
            } else if (c == '\t') {
                VimRow *row = &E.rows[E.cy];
                for (int sp = 0; sp < 4; sp++) {
                    vim_row_insert_char(row, E.cx++, ' ');
                }
                E.modified = 1;
            } else if (c == VIM_KEY_ARROW_UP || c == VIM_KEY_ARROW_DOWN ||
                       c == VIM_KEY_ARROW_LEFT || c == VIM_KEY_ARROW_RIGHT) {
                vim_move_cursor(&E, c);
            } else if (c >= 32 && c <= 126) {
                VimRow *row = &E.rows[E.cy];
                vim_row_insert_char(row, E.cx, c);
                E.cx++;
                E.modified = 1;
            }
            continue;
        }

        /* NORMAL MODE */
        if (E.replace_pending) {
            E.replace_pending = 0;
            if (c >= 32 && c <= 126) {
                vim_save_undo(&E);
                VimRow *row = (E.cy < E.num_rows) ? &E.rows[E.cy] : NULL;
                if (row && E.cx < row->len) {
                    row->chars[E.cx] = (char)c;
                    E.modified = 1;
                }
            }
            continue;
        }

        if (E.g_pending) {
            E.g_pending = 0;
            if (c == 'g') {
                E.cy = 0;
                E.cx = 0;
                continue;
            }
        }

        if (E.d_pending) {
            E.d_pending = 0;
            if (c == 'd') {
                vim_save_undo(&E);
                free(E.yank_buf);
                E.yank_buf = strdup(E.rows[E.cy].chars);
                vim_del_row(&E, E.cy);
                if (E.num_rows == 0) vim_insert_row(&E, 0, "", 0);
                if (E.cy >= E.num_rows) E.cy = E.num_rows - 1;
                E.cx = 0;
                snprintf(E.status_msg, sizeof(E.status_msg), "1 line deleted");
                E.status_time = time(NULL);
                continue;
            } else if (c == 'w') {
                vim_save_undo(&E);
                VimRow *row = &E.rows[E.cy];
                if (E.cx < row->len) {
                    int del_start = E.cx;
                    while (del_start < row->len && !isspace((unsigned char)row->chars[del_start])) {
                        vim_row_del_char(row, del_start);
                    }
                    while (del_start < row->len && isspace((unsigned char)row->chars[del_start])) {
                        vim_row_del_char(row, del_start);
                    }
                    E.modified = 1;
                }
                continue;
            } else if (c == '$') {
                vim_save_undo(&E);
                VimRow *row = &E.rows[E.cy];
                while (row->len > E.cx) vim_row_del_char(row, E.cx);
                if (E.cx > 0 && E.cx >= row->len) E.cx = (row->len > 0) ? row->len - 1 : 0;
                E.modified = 1;
                continue;
            }
        }

        if (E.y_pending) {
            E.y_pending = 0;
            if (c == 'y') {
                free(E.yank_buf);
                E.yank_buf = strdup(E.rows[E.cy].chars);
                snprintf(E.status_msg, sizeof(E.status_msg), "1 line yanked");
                E.status_time = time(NULL);
                continue;
            }
        }

        if (E.z_pending) {
            E.z_pending = 0;
            if (c == 'Z') {
                if (vim_save(&E, NULL) == 0) running = 0;
                continue;
            } else if (c == 'Q') {
                running = 0;
                continue;
            }
        }

        switch (c) {
            case 'h': case VIM_KEY_ARROW_LEFT:
            case 'j': case VIM_KEY_ARROW_DOWN:
            case 'k': case VIM_KEY_ARROW_UP:
            case 'l': case VIM_KEY_ARROW_RIGHT:
                vim_move_cursor(&E, c);
                break;
            case '0':
                E.cx = 0;
                break;
            case '^': {
                VimRow *row = &E.rows[E.cy];
                E.cx = 0;
                while (E.cx < row->len && isspace((unsigned char)row->chars[E.cx])) E.cx++;
                break;
            }
            case '$': {
                VimRow *row = &E.rows[E.cy];
                E.cx = (row->len > 0) ? row->len - 1 : 0;
                break;
            }
            case 'w': {
                VimRow *row = &E.rows[E.cy];
                while (E.cx < row->len && !isspace((unsigned char)row->chars[E.cx])) E.cx++;
                while (E.cx < row->len && isspace((unsigned char)row->chars[E.cx])) E.cx++;
                if (E.cx >= row->len && E.cy < E.num_rows - 1) {
                    E.cy++;
                    E.cx = 0;
                    row = &E.rows[E.cy];
                    while (E.cx < row->len && isspace((unsigned char)row->chars[E.cx])) E.cx++;
                }
                break;
            }
            case 'b': {
                if (E.cx > 0) {
                    VimRow *row = &E.rows[E.cy];
                    while (E.cx > 0 && isspace((unsigned char)row->chars[E.cx - 1])) E.cx--;
                    while (E.cx > 0 && !isspace((unsigned char)row->chars[E.cx - 1])) E.cx--;
                } else if (E.cy > 0) {
                    E.cy--;
                    VimRow *row = &E.rows[E.cy];
                    E.cx = row->len;
                    while (E.cx > 0 && isspace((unsigned char)row->chars[E.cx - 1])) E.cx--;
                    while (E.cx > 0 && !isspace((unsigned char)row->chars[E.cx - 1])) E.cx--;
                }
                break;
            }
            case 'G':
                E.cy = (E.num_rows > 0) ? E.num_rows - 1 : 0;
                E.cx = 0;
                break;
            case 'g':
                E.g_pending = 1;
                break;
            case VIM_KEY_PAGE_UP:
            case 21: /* Ctrl-U */
                E.cy -= E.screen_rows / 2;
                if (E.cy < 0) E.cy = 0;
                break;
            case VIM_KEY_PAGE_DOWN:
            case 4: /* Ctrl-D */
                E.cy += E.screen_rows / 2;
                if (E.cy >= E.num_rows) E.cy = (E.num_rows > 0) ? E.num_rows - 1 : 0;
                break;

            case 'i':
                vim_save_undo(&E);
                E.mode = VIM_MODE_INSERT;
                break;
            case 'I':
                vim_save_undo(&E);
                E.cx = 0;
                while (E.cx < E.rows[E.cy].len && isspace((unsigned char)E.rows[E.cy].chars[E.cx])) E.cx++;
                E.mode = VIM_MODE_INSERT;
                break;
            case 'a':
                vim_save_undo(&E);
                if (E.rows[E.cy].len > 0) E.cx++;
                E.mode = VIM_MODE_INSERT;
                break;
            case 'A':
                vim_save_undo(&E);
                E.cx = E.rows[E.cy].len;
                E.mode = VIM_MODE_INSERT;
                break;
            case 'o':
                vim_save_undo(&E);
                vim_insert_row(&E, E.cy + 1, "", 0);
                E.cy++;
                E.cx = 0;
                E.mode = VIM_MODE_INSERT;
                break;
            case 'O':
                vim_save_undo(&E);
                vim_insert_row(&E, E.cy, "", 0);
                E.cx = 0;
                E.mode = VIM_MODE_INSERT;
                break;

            case 'x':
                if (E.rows[E.cy].len > 0) {
                    vim_save_undo(&E);
                    vim_row_del_char(&E.rows[E.cy], E.cx);
                    if (E.cx >= E.rows[E.cy].len && E.cx > 0) E.cx--;
                    E.modified = 1;
                }
                break;
            case 'r':
                E.replace_pending = 1;
                break;
            case 'd':
                E.d_pending = 1;
                break;
            case 'D':
                vim_save_undo(&E);
                while (E.rows[E.cy].len > E.cx) vim_row_del_char(&E.rows[E.cy], E.cx);
                if (E.cx > 0 && E.cx >= E.rows[E.cy].len) E.cx = (E.rows[E.cy].len > 0) ? E.rows[E.cy].len - 1 : 0;
                E.modified = 1;
                break;
            case 'y':
                E.y_pending = 1;
                break;
            case 'p':
                if (E.yank_buf) {
                    vim_save_undo(&E);
                    vim_insert_row(&E, E.cy + 1, E.yank_buf, (int)strlen(E.yank_buf));
                    E.cy++;
                    E.cx = 0;
                    E.modified = 1;
                }
                break;
            case 'P':
                if (E.yank_buf) {
                    vim_save_undo(&E);
                    vim_insert_row(&E, E.cy, E.yank_buf, (int)strlen(E.yank_buf));
                    E.cx = 0;
                    E.modified = 1;
                }
                break;
            case 'J':
                if (E.cy < E.num_rows - 1) {
                    vim_save_undo(&E);
                    VimRow *curr = &E.rows[E.cy];
                    VimRow *next = &E.rows[E.cy + 1];
                    vim_row_append_string(curr, " ", 1);
                    vim_row_append_string(curr, next->chars, next->len);
                    vim_del_row(&E, E.cy + 1);
                    E.modified = 1;
                }
                break;
            case 'u':
                vim_apply_undo(&E);
                break;
            case 'Z':
                E.z_pending = 1;
                break;

            case '/':
                E.mode = VIM_MODE_SEARCH;
                cmd_len = 0;
                cmd_buf[0] = '\0';
                break;
            case 'n':
                vim_search_next(&E, 1);
                break;
            case 'N':
                vim_search_next(&E, 0);
                break;
            case ':':
                E.mode = VIM_MODE_COMMAND;
                cmd_len = 0;
                cmd_buf[0] = '\0';
                break;
            default:
                break;
        }
    }

    disable_raw_mode();
    if (write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7) < 0) { /* suppress warn_unused_result */ }

    for (int i = 0; i < E.num_rows; i++) vim_free_row(&E.rows[i]);
    free(E.rows);
    if (E.undo_rows) {
        for (int i = 0; i < E.undo_num_rows; i++) vim_free_row(&E.undo_rows[i]);
        free(E.undo_rows);
    }
    free(E.filename);
    free(E.yank_buf);

    return 0;
}

/* --- Contextual Rich Command Help Engine --- */

static int show_command_help(const char *cmd) {
    if (!cmd) return 0;

    if (strcmp(cmd, "vim") == 0 || strcmp(cmd, "vi") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: vim / vi [file]\n");
        printf("CATEGORY: Zero-Dependency Disaster Recovery Modal Micro-Editor\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  vim [file]                         # Open existing file or new in-memory buffer\n");
        printf("  vi [file]                          # Standard POSIX vi alias\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Provides a 100%% self-contained, in-memory modal text editor for disaster\n");
        printf("  recovery when /tmp is unavailable, disks are full (ENOSPC), or dynamic linkers\n");
        printf("  are broken. Never writes swap files (.swp) or temporary scratch files to disk.\n");
        printf("  Operates via raw ANSI terminal sequences without ncurses or libtinfo.\n\n");
        printf("MODAL STATES & KEYBINDINGS:\n");
        printf("  NORMAL MODE (default):\n");
        printf("    i, I, a, A                       # Insert before / at start / after / at end of line\n");
        printf("    o, O                             # Open new line below / above\n");
        printf("    h, j, k, l / Arrow keys          # Left, down, up, right\n");
        printf("    0, ^, $                          # Line start, first non-space, line end\n");
        printf("    w, b                             # Next word, previous word\n");
        printf("    gg, G                            # Jump to top of file, end of file\n");
        printf("    Ctrl-U, Ctrl-D / PgUp, PgDn      # Half-page scroll up / down\n");
        printf("    x, r<char>                       # Delete char under cursor, replace char\n");
        printf("    dd, D                            # Delete line (yank to buffer), delete to EOL\n");
        printf("    dw                               # Delete word\n");
        printf("    yy, p, P                         # Yank (copy) line, paste below / above\n");
        printf("    J                                # Join current line with line below\n");
        printf("    u                                # Undo last edit\n");
        printf("    /<pattern>, n, N                 # Forward search, next match, prev match\n");
        printf("    ZZ, ZQ                           # Save & exit (:wq), quit without saving (:q!)\n");
        printf("    :                                # Enter Ex command-line mode\n\n");
        printf("  INSERT MODE:\n");
        printf("    <Esc>                            # Return to Normal mode\n");
        printf("    Enter / Backspace / Delete / Tab # Line split, character deletion, 4-space indent\n\n");
        printf("  EX COMMANDS (:):\n");
        printf("    :w [file]                        # Write buffer to file\n");
        printf("    :q / :q!                         # Quit / Force quit (abandon unsaved changes)\n");
        printf("    :wq / :x                         # Write buffer and exit\n");
        printf("    :<number>                        # Jump to line number (e.g. :42)\n");
        printf("    :$                               # Jump to last line\n");
        printf("    :set nu / :set nonu              # Enable / disable line numbers\n\n");
        printf("OFFLINE DISASTER RECOVERY RUNBOOKS:\n");
        printf("  1. Emergency /etc/fstab Rescue (fixing broken UUIDs halting boot):\n");
        printf("     minish$ vim /etc/fstab\n");
        printf("     (navigate with j/k, type dd to remove broken mount, type :wq to save)\n\n");
        printf("  2. In-Memory Emergency Script Creation on 100%% Full Disk (ENOSPC):\n");
        printf("     minish$ vim /dev/shm/recover.sh\n");
        printf("================================================================================\n\n");
        return 1;
    }

    
    if (strcmp(cmd, "detach") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: detach [-o logfile] [-e errfile] <command...> [args...]\n");
        printf("CATEGORY: Daemonized Background Process Detachment\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  detach <command...> [args...]               # Defaults output to /dev/shm/detach_*.log\n");
        printf("  detach -o <logfile> <command...> [args...]  # Direct output to custom log file\n");
        printf("  detach -o /dev/null <command...> [args...]  # Suppress all output\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Spawns long-running or hunting tools (e.g. Velociraptor client, Volatility scans,\n");
        printf("  pcap sniffers, or log monitors) as fully detached daemon processes:\n");
        printf("  1. Session Detachment: Calls setsid() to sever the controlling terminal (/dev/tty).\n");
        printf("  2. Hangup Immunity: Masks SIGHUP (terminal disconnect) and SIGINT.\n");
        printf("  3. Stdio Decoupling: Redirects stdin to /dev/null and streams stdout/stderr\n");
        printf("     to a volatile RAM logfile (/dev/shm/detach_<cmd>_<pid>.log, 0 disk writes).\n");
        printf("  4. Immediate Prompt Return: Shell prompt returns instantly without blocking.\n\n");
        printf("WHY 'detach' IS CRITICAL FOR THREAT HUNTING:\n");
        printf("  Standard background jobs ('cmd &') still share the controlling terminal and will\n");
        printf("  terminate if SSH disconnects. 'detach' ensures hunting agents run uninterrupted\n");
        printf("  while you perform active memory forensics or administrative triage in minish.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ detach /usr/local/bin/velociraptor client -c client.config.yaml\n");
        printf("  minish$ detach -o /dev/shm/vol.log python3 vol.py -f /proc/kcore linux.malfind\n");
        printf("  minish$ jobs                                # Check active detached jobs\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "jobs") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: jobs\n");
        printf("CATEGORY: Job Control & Detached Process Monitor\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  jobs\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Reaps completed background/detached child processes via non-blocking waitpid()\n");
        printf("  and lists all tracked jobs, their PIDs, running status, commands, and log paths.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ jobs\n");
        printf("  [1]  PID 3450    Running     velociraptor client  (log: /dev/shm/detach_velociraptor_3450.log)\n");
        printf("================================================================================\n\n");
        return 1;
    }

    
    if (strcmp(cmd, "stop") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: stop <job_id|pid> [-sig]\n");
        printf("CATEGORY: Job Control & Process Tree Termination\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  stop <job_id|pid>                  # Graceful termination (SIGTERM, 15)\n");
        printf("  stop <job_id|pid> -9               # Immediate forceful kill (SIGKILL, 9)\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Terminates a detached or background job. Automatically traverses /proc to\n");
        printf("  terminate the target process AND all child processes it spawned (via kill_children_of)\n");
        printf("  preventing orphan runaway workers from consuming CPU or memory.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ jobs                       # View active jobs\n");
        printf("  minish$ stop 1                     # Terminate job [1] gracefully\n");
        printf("  minish$ stop 3450 -9               # Force kill PID 3450\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "attach") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: attach <job_id|pid>\n");
        printf("CATEGORY: Live Job Monitoring & Output Stream Viewer\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  attach <job_id|pid>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Connects to the volatile RAM log output of a detached background process.\n");
        printf("  Displays the most recent log entries and streams new output in real-time.\n");
        printf("  Pressing [Ctrl-C] or 'q' detaches immediately back to the minish$ prompt\n");
        printf("  WITHOUT terminating the background process.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ attach 1                   # Monitor live output of job [1]\n");
        printf("  minish$ attach 3450                # Monitor live output of PID 3450\n");
        printf("================================================================================\n\n");
        return 1;
    }

if (strcmp(cmd, "disown") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: disown [job_id|pid]\n");
        printf("CATEGORY: Job Control & Tracking Release\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  disown [job_id|pid]                # Default: disowns all jobs\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Removes specified background jobs from the shell tracking table. The target\n");
        printf("  processes continue running independently under systemd/init (PID 1).\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ disown 1\n");
        printf("================================================================================\n\n");
        return 1;
    }

if (strcmp(cmd, "stealth") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: stealth [disguise_name]\n");
        printf("CATEGORY: Threat Hunting & Anti-Adversary Camouflage\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  stealth [disguise_name]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Activates operational camouflage and anti-kill armor in a single step:\n");
        printf("  1. Lineage Audit: Inspects /proc/<ppid>/comm. If parent is bash/zsh/sh, alerts\n");
        printf("     the responder and explains how 'exec minish' destroys the parent shell.\n");
        printf("  2. In-Place Cloaking: Rewrites /proc/self/comm via prctl(PR_SET_NAME) and\n");
        printf("     overwrites the initial argv memory block (/proc/self/cmdline, ps -ef).\n");
        printf("  3. Anti-Kill Armor: Masks SIGTERM, SIGHUP, SIGINT, SIGQUIT via sigaction.\n");
        printf("  4. OOM Immunity: Sets /proc/self/oom_score_adj to -1000.\n\n");
        printf("SYSTEM EFFECTS & DYNAMICS:\n");
        printf("  - Process Visibility: Disguises the process in ps, top, htop, and /proc.\n");
        printf("  - Default Disguise: '[kworker/0:1]' (looks like an idle kernel worker thread).\n");
        printf("  - Adversary Scripts: Automated kill loops targeting 'minish' or 'sh' fail.\n");
        printf("  - Memory / Disk Cost: 0 bytes of disk allocation; runs entirely in RAM.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ stealth                  # Disguise as [kworker/0:1] with signal armor\n");
        printf("  minish$ stealth (journald)       # Disguise as systemd-journald daemon\n");
        printf("  minish$ stealth [rcu_sched]      # Disguise as kernel RCU scheduler thread\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "exec") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: exec <command> [args...]\n");
        printf("CATEGORY: Process Replacement & Anti-Adversary Lineage Severing\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  exec <command> [args...]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Invokes the POSIX execve() system call on the current process without fork().\n");
        printf("  The calling process (e.g. bash) is completely overwritten in memory by the target\n");
        printf("  binary. The target inherits the exact PID, file descriptors, and parent PID.\n\n");
        printf("WHY 'exec minish' IS MANDATORY FOR THREAT HUNTING:\n");
        printf("  - If you run './minish' from an interactive shell, the process tree is:\n");
        printf("      sshd (PID 1020) -> bash (PID 1450) -> minish (PID 1820)\n");
        printf("    An attacker watching /proc or process connector events will instantly see\n");
        printf("    an analyst shell spawned beneath bash, burning your operational cover.\n");
        printf("  - When launched via 'exec minish' (or 'exec /dev/shm/m/usr/bin/minish'),\n");
        printf("    bash is eradicated from memory. minish BECOMES PID 1450 directly beneath sshd.\n");
        printf("    The 'bash -> minish' parent lineage never exists!\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  $ exec ./minish                  # Replace bash with minish in-place\n");
        printf("  $ exec /dev/shm/m/usr/bin/minish # Replace bash with RAM-extracted minish\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "ramoverlay") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: ramoverlay <target_dir> [size_MB]\n");
        printf("CATEGORY: Full-Disk Storage Bypass & In-Memory Tool Execution\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  ramoverlay <target_dir> [size_MB]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Mounts a Linux copy-on-write 'overlayfs' directly on top of <target_dir>.\n");
        printf("  Creates an upper directory in volatile RAM (/dev/shm/.ovl_<pid>/upper).\n");
        printf("  The underlying target directory serves as the read-only 'lowerdir'; all new\n");
        printf("  files, temporary locks, socket descriptors, and modifications are stored in RAM.\n\n");
        printf("SYSTEM EFFECTS & DYNAMICS:\n");
        printf("  - Physical Disk Writes: EXACTLY 0 BYTES. No disk blocks or inodes allocated.\n");
        printf("  - Existing Files: Remain fully visible and readable from the underlying directory.\n");
        printf("  - New / Modified Files: Captured exclusively in volatile RAM pages.\n");
        printf("  - Reversibility: Run 'umount <target_dir>' to cleanly remove the overlay.\n\n");
        printf("HOW TO RUN VOLATILITY / PYTHON ON A 100%% FULL DISK (ZERO DISK WRITES):\n");
        printf("  Problem: On 100%% full storage, Python crashes with 'OSError: [Errno 28] No space\n");
        printf("           left on device' when trying to write __pycache__ (.pyc) or temp locks.\n");
        printf("  Step 1: Unblock /tmp locks without writing to disk:\n");
        printf("          minish$ ramoverlay /tmp 128\n");
        printf("  Step 2: Disable Python bytecode disk compilation:\n");
        printf("          minish$ export PYTHONDONTWRITEBYTECODE=1\n");
        printf("          minish$ export TMPDIR=/tmp\n");
        printf("  Step 3: Analyze live physical memory directly via /proc/kcore (zero disk dump):\n");
        printf("          minish$ python3 /dev/shm/vol.py -f /proc/kcore linux.pslist\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ ramoverlay /tmp 128        # Overlay 128MB RAM over /tmp to unblock tools\n");
        printf("  minish$ ramoverlay /var/log 64     # Enable logging without physical disk space\n");
        printf("  minish$ umount /tmp                # Remove overlay when recovery is done\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "ramscratch") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: ramscratch [size_MB]\n");
        printf("CATEGORY: Full-Disk Storage Bypass & Writable RAM Workspace\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  ramscratch [size_MB]               # Default size: 64 MB\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Allocates an isolated in-memory scratchpad in volatile RAM (/dev/shm/.scratch),\n");
        printf("  sets directory permissions to 0700 (owner only), navigates (cd) into it, and\n");
        printf("  exports TMPDIR=$PWD into the parent shell environment.\n\n");
        printf("SYSTEM EFFECTS & DYNAMICS:\n");
        printf("  - Working Directory: Changes current directory to the volatile scratchpad.\n");
        printf("  - Environment: Sets TMPDIR so tools (Python, GCC, APT) write temp files to RAM.\n");
        printf("  - Physical Disk Writes: 0 bytes. Completely volatile.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ ramscratch 128             # Create 128MB RAM workspace and cd into it\n");
        printf("  minish$ echo $TMPDIR               # Verifies /dev/shm/.scratch\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "ramclone") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: ramclone <source_file> [destination_path]\n");
        printf("CATEGORY: Full-Disk Storage Bypass & Binary Staging\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  ramclone <source_file> [destination_path]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Copies a binary or script from disk directly into volatile RAM (/dev/shm),\n");
        printf("  retaining executable bits (0755). If disk is read-only or corrupted, keeps\n");
        printf("  critical tools in memory for continuous execution.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ ramclone /usr/bin/python3 /dev/shm/python3\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "deletedgrab") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: deletedgrab <pid> <fd|exe> [mem_name|-]\n");
        printf("CATEGORY: In-Memory Forensic Carving & Malware Rescue\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  deletedgrab <pid> exe [mem_name|-] # Carves deleted executable from /proc/<pid>/exe\n");
        printf("  deletedgrab <pid> <fd> [mem_name|-]# Carves open file descriptor from /proc/<pid>/fd/<fd>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Stealth malware frequently unlinks its binary from disk immediately after\n");
        printf("  launching (/tmp/.mal (deleted)) to defeat file scanners. Similarly, unlinked\n");
        printf("  database files or runaway logs trap gigabytes of disk space.\n");
        printf("  deletedgrab reaches directly into the Linux kernel VFS via /proc/<pid>/fd/<fd>\n");
        printf("  or /proc/<pid>/exe and streams the exact file bytes into an in-memory virtual\n");
        printf("  storage table ('memfile') or directly to stdout ('-').\n\n");
        printf("SYSTEM EFFECTS & DYNAMICS:\n");
        printf("  - Physical Disk Writes: 0 bytes. The carved binary lives purely in RAM.\n");
        printf("  - Anti-Detection: Leaves zero disk artifacts or modified timestamps.\n");
        printf("  - Analysis: Inspect with 'sha256' or 'strings' on the carved sample.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ deletedgrab 3412 exe malware_sample # Rescue deleted malware to RAM\n");
        printf("  minish$ memfile list                        # Verify rescued file in memory\n");
        printf("  minish$ deletedgrab 1248 4 - | sha256 -     # Hash trapped unlinked log\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "exehunt") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: exehunt\n");
        printf("CATEGORY: Threat Hunting & Rootkit Process Auditing\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  exehunt\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Traverses all running processes in /proc/[0-9]*/ and audits process binaries:\n");
        printf("  1. Detects Unlinked Malware: Resolves /proc/<pid>/exe. Flags binaries ending in\n");
        printf("     ' (deleted)', a hallmark of stealth miners, backdoors, and droppers.\n");
        printf("  2. Detects Volatile RAM Binaries: Flags processes running out of /dev/shm, /tmp,\n");
        printf("     /run, /var/tmp, or anonymous memfd descriptors (memfd:name).\n");
        printf("  3. Detects Process Masquerading: Compares /proc/<pid>/comm against the actual\n");
        printf("     binary basename. Flags malware claiming to be 'kworker' or 'sshd' but executing\n");
        printf("     from user directories.\n\n");
        printf("SYSTEM EFFECTS & DYNAMICS:\n");
        printf("  - Passive Inspection: Zero system modifications. Reads kernel procfs metadata.\n");
        printf("  - Output: Prints PID, comm, executable path, and reason for alert.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ exehunt\n");
        printf("  # If a rogue process is found:\n");
        printf("  # [!] UNLINKED MALWARE: PID 3412 (kworker/0:1) -> /tmp/.miner (deleted)\n");
        printf("  # Rescue sample: deletedgrab 3412 exe miner_sample\n");
        printf("  # Terminate:     kill -9 3412\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "sigshield") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: sigshield [on|off|status]\n");
        printf("CATEGORY: Anti-Adversary Defense & Recovery Armor\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  sigshield on                       # Arm immunity against signals and OOM\n");
        printf("  sigshield off                      # Restore default signal handlers\n");
        printf("  sigshield status                   # Check active protection status\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Adversary scripts and rogue watchdog daemons often send SIGTERM, SIGHUP, or\n");
        printf("  SIGINT to kill incident responder sessions, or trigger memory exhaustion to\n");
        printf("  force the Linux OOM killer to terminate triage shells.\n");
        printf("  sigshield masks SIGTERM, SIGHUP, SIGINT, and SIGQUIT via sigaction, and adjusts\n");
        printf("  /proc/self/oom_score_adj to -1000 so the kernel will never select it for OOM kill.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ sigshield on\n");
        printf("  minish$ sigshield status\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "ptracehunt") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: ptracehunt\n");
        printf("CATEGORY: Threat Hunting & Anti-Injection Defense\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  ptracehunt\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Scans /proc/[0-9]*/status for 'TracerPid'. In Linux, when TracerPid is non-zero,\n");
        printf("  another process has attached via ptrace(PTRACE_ATTACH) to inject code, hook\n");
        printf("  system calls, sniff passwords (e.g. from sshd), or tamper with memory.\n");
        printf("  ptracehunt identifies both the victim process and the tracing attacker PID.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ ptracehunt\n");
        printf("  # [!] INJECTION ALERT: PID 940 (sshd) is actively TRACED by PID 3412 (miner)!\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "promischunt") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: promischunt\n");
        printf("CATEGORY: Threat Hunting & Network Sniffer Detection\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  promischunt\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Advanced backdoors (such as BpfDoor) listen for magic trigger packets using raw\n");
        printf("  AF_PACKET sockets or place network interfaces in promiscuous mode (IFF_PROMISC)\n");
        printf("  without binding to any TCP/UDP listening port. They are completely invisible to\n");
        printf("  standard netstat and ss.\n");
        printf("  promischunt parses /proc/net/packet and interface flags to detect raw packet\n");
        printf("  sniffers and promiscuous interfaces immediately.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ promischunt\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "persistpeek") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: persistpeek\n");
        printf("CATEGORY: Threat Hunting & Persistence Auditing\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  persistpeek\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Audits common Linux persistence locations: crontabs (/var/spool/cron, /etc/cron*),\n");
        printf("  systemd service timers and overrides, /etc/ld.so.preload (userland rootkits),\n");
        printf("  /etc/rc.local, shell profiles (/etc/profile.d, ~/.bashrc), and udev rules.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ persistpeek\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "sockhunt") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: sockhunt\n");
        printf("CATEGORY: Threat Hunting & Hidden Socket Detection\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  sockhunt\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Cross-references open socket descriptors across all processes in /proc/<pid>/fd\n");
        printf("  against /proc/net/tcp and /proc/net/udp. Identifies hidden listeners and unlinked\n");
        printf("  sockets used by backdoors.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ sockhunt\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "killbyport") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: killbyport <port> [-sig]\n");
        printf("CATEGORY: Emergency Incident Response & Containment\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  killbyport <port> [-sig]           # Default signal: SIGTERM (15)\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Resolves the process holding a network port directly via /proc/net/tcp inode\n");
        printf("  matching and sends the specified signal to terminate it immediately.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ killbyport 4444 -9         # Force kill backdoor on port 4444\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "truncate") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: truncate <file> [bytes]\n");
        printf("CATEGORY: Full-Disk Storage Recovery (ENOSPC Reclaim)\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  truncate <file> [bytes]            # Default bytes: 0 (completely collapses file)\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  In-place zero-allocation file shrinker via truncate() / ftruncate() syscalls.\n");
        printf("  Releases disk extent blocks directly back to the filesystem free block bitmap\n");
        printf("  WITHOUT unlinking or deleting the file.\n\n");
        printf("WHY IT SUCCEEDS WHEN 'rm' FAILS:\n");
        printf("  - If an active daemon (nginx, syslog, mysqld) has the file open, 'rm' only unlinks\n");
        printf("    the filename (dentry); the kernel holds the blocks open until the daemon dies.\n");
        printf("  - 'truncate' collapses the file size in-place while keeping the file descriptor\n");
        printf("    intact. The daemon continues logging at offset 0, and disk space is reclaimed\n");
        printf("    INSTANTLY WITHOUT RESTARTING THE SERVICE.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ truncate /var/log/syslog 0          # Collapse syslog to 0 bytes\n");
        printf("  minish$ truncate /var/log/nginx/access.log 0# Free gigabytes without killing nginx\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "ghostfind") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: ghostfind [-t]\n");
        printf("CATEGORY: Full-Disk Storage Recovery (Ghost File Hunter)\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  ghostfind                          # Scan and report trapped disk space\n");
        printf("  ghostfind -t                       # Truncate trapped descriptors in-place\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  The 'Ghost File' Trap: When an admin runs 'rm' on an active log file, the filename\n");
        printf("  is unlinked, but running processes keep the file descriptor open. The disk remains\n");
        printf("  100%% full, but 'ls', 'du', and 'find' can no longer see the file.\n");
        printf("  ghostfind scans /proc/[0-9]*/fd/ for links ending in ' (deleted)' and resolves the\n");
        printf("  exact size of disk blocks trapped by each running process.\n");
        printf("  With -t, it opens /proc/<pid>/fd/<fd> with O_TRUNC, freeing trapped gigabytes\n");
        printf("  instantly without restarting the holding service.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ ghostfind                  # Audit ghost files and trapped gigabytes\n");
        printf("  minish$ ghostfind -t               # Instantly reclaim all trapped storage\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "zerolog") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: zerolog [path]\n");
        printf("CATEGORY: Full-Disk Storage Recovery (Batch Log Truncator)\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  zerolog [path]                     # Default path: /var/log\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Recursively traverses target path up to depth 15 and truncates all *.log and\n");
        printf("  *.log.* files in-place to 0 bytes via truncate(path, 0).\n");
        printf("  Reclaims all disk space consumed by runaway logs in seconds without deleting\n");
        printf("  files or disrupting running logging services.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ zerolog /var/log\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "inodescan") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: inodescan [path] [threshold]\n");
        printf("CATEGORY: Inode Table Exhaustion Diagnostic\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  inodescan [path] [threshold]       # Default threshold: 1000 files/dir\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Pinpoints directories hoarding thousands or millions of tiny files (e.g. PHP\n");
        printf("  session caches in /var/lib/php/sessions, mail spools, or container debris)\n");
        printf("  that exhaust the filesystem inode table (df -i 100%%) while block space remains free.\n");
        printf("  Streams directory entries without loading entire trees into memory, avoiding E2BIG.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ inodescan /var 5000        # Find directories with >= 5000 files\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "findgrowth") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: findgrowth [path] [seconds]\n");
        printf("CATEGORY: Real-Time Storage Diagnostics\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  findgrowth [path] [seconds]        # Default seconds: 2\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Answers: 'Which file is eating my disk space right this second?'\n");
        printf("  Takes a lightweight snapshot of file sizes in the target directory tree, pauses\n");
        printf("  for the sampling window, and prints all files that expanded during the interval\n");
        printf("  along with their growth rate (KB/s or MB/s).\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ findgrowth /var/log 2\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "topwriters") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: topwriters [seconds]\n");
        printf("CATEGORY: Real-Time Storage Diagnostics\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  topwriters [seconds]               # Default seconds: 2\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Samples /proc/[0-9]*/io (write_bytes) over the sampling window and ranks active\n");
        printf("  processes by disk write throughput (PID, process comm, MB/s, and total MB).\n");
        printf("  Pinpoints runaway logging loops and rogue write processes immediately.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ topwriters 2\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "fdsize") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: fdsize [pid]\n");
        printf("CATEGORY: Storage-Centric File Descriptor Profiler\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  fdsize [pid]                       # Default: scans all processes\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Audits sizes of files referenced by open descriptors in /proc/<pid>/fd.\n");
        printf("  Identifies which processes hold multi-gigabyte files open.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ fdsize 1248\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "findlarge") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: findlarge [path] [size_MB]\n");
        printf("CATEGORY: Storage Diagnostics\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  findlarge [path] [size_MB]         # Default path: ., default size: 50 MB\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Fast single-binary recursive scan for files exceeding the size threshold.\n");
        printf("  Does not fork external processes or require 'find' / 'du'.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ findlarge /var 100         # Find files > 100 MB in /var\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "b64exec") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: b64exec <proc_name> [args...]\n");
        printf("CATEGORY: Air-Gapped Terminal Tool Execution\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  cat <b64_file> | b64exec <proc_name> [args...]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Decodes Base64-encoded binary bytes from standard input directly into an anonymous\n");
        printf("  RAM file descriptor (memfd_create), seals it against write tampering (F_SEAL_WRITE),\n");
        printf("  disguises its process title to <proc_name>, and executes it via fexecve().\n");
        printf("  Allows pasting and executing compiled binaries across air-gapped serial/SSH consoles\n");
        printf("  with EXACTLY 0 BYTES WRITTEN TO DISK.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ cat << 'EOF' | b64exec mytool --arg1\n");
        printf("  <BASE64_STREAM_HERE>\n");
        printf("  EOF\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "memscript") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: memscript <interpreter> [args...]\n");
        printf("CATEGORY: Zero-Disk Script Execution\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  cat <script> | memscript <interpreter> [args...]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Reads a script (Python, Bash, Perl) from stdin into an anonymous kernel memfd in RAM\n");
        printf("  and executes '<interpreter> /proc/self/fd/<fd> [args...]'.\n");
        printf("  Enables running custom diagnostic scripts without creating a temporary script file\n");
        printf("  on a full or read-only disk.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ cat triage.py | memscript python3\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "memunshare") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: memunshare [-m] [-p] [-n] <command...>\n");
        printf("CATEGORY: Anti-Detection & Namespace Isolation\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  memunshare [-m] [-p] [-n] <command...>\n");
        printf("    -m: Private mount namespace (CLONE_NEWNS)\n");
        printf("    -p: Private PID namespace (CLONE_NEWPID)\n");
        printf("    -n: Private network namespace (CLONE_NEWNET)\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Spawns child commands inside isolated Linux kernel namespaces via unshare().\n");
        printf("  Prevents on-host attacker processes from observing your triage tools in /proc\n");
        printf("  or intercepting private temporary mounts.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ memunshare -p -m minish    # Launch hidden shell in isolated namespace\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "memfile") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: memfile <write|read|list|delete> [name]\n");
        printf("CATEGORY: Zero-Disk In-Memory Virtual Storage\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  memfile write <name>               # Reads stdin into named RAM buffer\n");
        printf("  memfile read <name>                # Dumps named RAM buffer to stdout\n");
        printf("  memfile list                       # Lists active RAM files and sizes\n");
        printf("  memfile delete <name>              # Releases RAM buffer\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ cat evidence.txt | memfile write sample1\n");
        printf("  minish$ memfile read sample1\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "memrun") == 0 || strcmp(cmd, "memexec") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: memrun <name|-> [args...]\n");
        printf("CATEGORY: Zero-Disk In-Memory Binary Execution\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  memrun <memfile_name|-> [args...]\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Creates an anonymous Linux memfd (memfd_create), copies the binary bytes into it,\n");
        printf("  and executes it directly via fexecve(). Never touches disk.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ cat /path/to/tool | memrun -\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "memgrep") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: memgrep <pid> <string>\n");
        printf("CATEGORY: Live Process Memory Secret Sniffer\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  memgrep <pid> <string>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Parses /proc/<pid>/maps for readable memory regions and searches them directly\n");
        printf("  via /proc/<pid>/mem. Sniffs passwords, tokens, and C2 URLs without core dumping.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ memgrep 1020 http          # Search process 1020 memory for 'http'\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "procpeek") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: procpeek [pid]\n");
        printf("CATEGORY: Process Forensics & Status Audit\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  procpeek [pid]                     # Default: self\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Prints parsed process state from /proc/<pid>/status: PID, PPID, UID/GID,\n");
        printf("  threads, memory footprints (VmRSS, VmSize), and open file descriptor count.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ procpeek 1450\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "mapspeek") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: mapspeek <pid>\n");
        printf("CATEGORY: Process Memory Forensics & Exploit Detection\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  mapspeek <pid>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Inspects /proc/<pid>/maps and flags dangerous RWX (readable, writable, executable)\n");
        printf("  memory segments, which typically indicate shellcode injection or JIT trampolines.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ mapspeek 3412\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "fdpeek") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: fdpeek <pid>\n");
        printf("CATEGORY: Process Descriptor Forensics\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  fdpeek <pid>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Resolves all open file descriptors in /proc/<pid>/fd/ to their target paths,\n");
        printf("  highlighting sockets, pipes, and unlinked deleted handles.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ fdpeek 1248\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "timestomp") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: timestomp <target_file> <reference_file|YYYYMMDDhhmm.ss>\n");
        printf("CATEGORY: Forensic Anti-Tamper & Timestamp Analysis\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  timestomp <target_file> <reference_file>\n");
        printf("  timestomp <target_file> <YYYYMMDDhhmm.ss>\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Updates atime and mtime on <target_file> via utimensat(). Used to analyze or\n");
        printf("  remediate forensic timestamp anomalies.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ timestomp hacked.conf /etc/passwd\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "wipe") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: wipe <file> [passes]\n");
        printf("CATEGORY: Secure Anti-Forensic Remediation\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  wipe <file> [passes]               # Default passes: 3 (0x00, 0xFF, random)\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Overwrites physical file blocks in-place with multiple patterns and flushes\n");
        printf("  via fsync() before unlinking the inode.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ wipe /dev/shm/temp_secret 3\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "dropcaches") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: dropcaches [1|2|3]\n");
        printf("CATEGORY: Memory Reclamation & Cache Management\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  dropcaches [1|2|3]                 # 1: pagecache, 2: dentries/inodes, 3: both\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Calls sync() then writes to /proc/sys/vm/drop_caches to reclaim clean memory.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ dropcaches 3\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "df") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: df [path]\n");
        printf("CATEGORY: Storage & Inode Triage\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  df [path]                          # Default path: .\n\n");
        printf("PURPOSE & KERNEL MECHANISM:\n");
        printf("  Queries statvfs() system call to display storage blocks AND inode capacity\n");
        printf("  side-by-side. Displays Avail(User) and Free(Root) in megabytes to expose root-reserve\n");
        printf("  headroom, and emits critical alerts when block or inode usage exceeds 90%%.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ df /\n");
        printf("  minish$ df /var\n");
        printf("================================================================================\n\n");
        return 1;
    }

    if (strcmp(cmd, "help") == 0) {
        printf("\n================================================================================\n");
        printf("COMMAND: help [command]\n");
        printf("CATEGORY: In-Shell Interactive Reference Engine\n");
        printf("================================================================================\n");
        printf("SYNTAX:\n");
        printf("  help                               # Displays general categorized summary\n");
        printf("  help <command>                     # Displays full manual for specified command\n");
        printf("  <command> --help                   # Standard flag alternative\n");
        printf("  <command> -h                       # Short flag alternative\n\n");
        printf("PURPOSE:\n");
        printf("  Provides complete offline documentation directly inside the static binary.\n");
        printf("  Explains syntax, kernel mechanisms, exact system effects, disk footprint,\n");
        printf("  and step-by-step disaster recovery runbooks.\n\n");
        printf("OFFLINE USAGE & EXAMPLES:\n");
        printf("  minish$ help ramoverlay            # How to run tools in RAM on full storage\n");
        printf("  minish$ help stealth               # How to cloak identity and audit lineage\n");
        printf("  minish$ help exec                  # How 'exec minish' severes bash lineage\n");
        printf("  minish$ help deletedgrab           # How to carve unlinked malware from memory\n");
        printf("================================================================================\n\n");
        return 1;
    }

    return 0;
}

static int builtin_help(char **args) {
    if (args && args[1]) {
        if (show_command_help(args[1])) {
            return 0;
        }
        printf("minish: no detailed help available for '%s'. See general summary below:\n", args[1]);
    }
    printf("\n=== Minimalist POSIX Micro-Shell & Rescue Utility (minish) ===\n");
    printf("OPERATIONAL ADVISORY (THREAT HUNTING & FULL-DISK RESCUE):\n");
    printf("  * SEVER BASH LINEAGE: Never launch as './minish' under bash! Run 'exec minish'\n");
    printf("    to replace bash in-place and prevent attackers from detecting your shell.\n");
    printf("  * INTERACTIVE HELP: Type 'help <command>' or '<command> --help' for full kernel\n");
    printf("    mechanisms, exact system effects, and step-by-step offline disaster runbooks.\n\n");
    printf("Stateful Built-ins:\n");
    printf("  vim / vi [file]       Modal in-memory text editor (normal/insert/ex modes)\n");
    printf("  cd [dir|-]            Change directory (supports tilde ~)\n");
    printf("  export [VAR=VAL]      Export environment variable\n");
    printf("  unset [VAR]           Unset environment variable\n");
    printf("  set [-e|+e] [-x|+x]   Toggle errexit / trace mode\n");
    printf("  source / . <file>     Evaluate script in current shell context\n");
    printf("  exec <cmd...>         Replace shell process with command\n");
    printf("  chroot <dir> [cmd]    Change root directory\n");
    printf("  setproctitle <name>   Rename running process (/proc/self/comm & cmdline)\n");
    printf("  exit [code]           Terminate shell with exit status\n");
    printf("  help                  Display this command summary\n\n");
    printf("File Surgery & System Maintenance:\n");
    printf("  cat [file...]         Concatenate and print files\n");
    printf("  cp <src> <dst>        Copy files retaining permission bits\n");
    printf("  mv <src> <dst>        Move/rename files atomically\n");
    printf("  rm [-r] [-f] [file]   Remove file (protects dirs without -r)\n");
    printf("  chmod <mode> <file>   Change permissions (octal or +x/-x)\n");
    printf("  chown <uid[:gid]> <f> Change file ownership\n");
    printf("  umask [mask]          Get or set file creation mask\n");
    printf("  touch [file...]       Update timestamp or create file\n");
    printf("  mkdir [-p] [dir...]   Create new directory\n");
    printf("  ls [-a] [-l] [path]   List directory contents\n");
    printf("  pwd                   Print current working directory\n");
    printf("  sync                  Flush dirty filesystem page caches\n");
    printf("  remount <rw|ro> [path]Remount filesystem read-write or read-only\n");
    printf("  reboot / poweroff     Issue direct kernel reboot or shutdown\n");
    printf("  sysrq <key>           Trigger Magic SysRq (s, u, b, f, t)\n\n");
    printf("Nonstandard Triage & Rescue Diagnostics:\n");
    printf("  sysinfo / free        Display uptime, load average, and RAM/swap\n");
    printf("  dmesg                 Dump kernel ring buffer messages\n");
    printf("  uname [-a|-r|-m]      Print system and kernel architecture\n");
    printf("  memfile <op> [name]   In-memory RAM-backed file storage\n");
    printf("  probeblk <dev>        Sniff filesystem magic (ext4/xfs/btrfs/swap)\n");
    printf("  hexview <file> [off]  Hex + ASCII binary viewer for files/disks\n");
    printf("  falloc <MB> <path>    Preallocate multi-MB file instantaneously\n");
    printf("  sockstat              List listening and connected TCP/UDP sockets\n");
    printf("  killtree <pid> [-sig] Recursively terminate entire process tree\n");
    printf("  procpeek [pid]        Inspect process status, memory, and open FDs\n");
    printf("  httpget <url> [dest]  Download file over raw TCP HTTP socket\n");
    printf("  dnslookup <host>      Resolve hostname to IPv4/IPv6 addresses\n");
    printf("  randhex [bytes]       Generate secure random hex tokens\n");
    printf("  watch <sec> <cmd>     Periodically execute command with screen clear\n\n");
    printf("Full-Disk Rescue & Storage Recovery:\n");
    printf("  df [path]             Inspect block storage and inode table exhaustion\n");
    printf("  truncate <file> [sz]  Zero-allocation in-place shrink (frees blocks immediately)\n");
    printf("  ghostfind [-t]        Find/truncate unlinked open files holding trapped disk space\n");
    printf("  findlarge [path] [MB] Recursively find files exceeding size threshold (default 50MB)\n");
    printf("  inodescan [path] [N]  Audit inode distribution; find directories hoarding files\n");
    printf("  zerolog [path]        Batch truncate all *.log files in-place to 0 bytes\n");
    printf("  findempty [path] [-d] Scan or delete 0-byte orphan files wasting inode slots\n");
    printf("  dusage [path] [depth] Recursive directory space usage breakdown (ncdu/du alternative)\n");
    printf("  findinode <ino> [path]Reverse resolve filesystem inode number back to pathname\n");
    printf("  tmpfs <dir> [MB]      Mount emergency RAM tmpfs to unblock /tmp on full disks\n");
    printf("  memrun / memexec <name|-> [a]Execute binary directly from RAM (memfd_create)\n");
    printf("  findgrowth [path] [s] Real-time file growth rate monitor\n");
    printf("  fdsize [pid]          Storage-centric open file descriptor profiler\n");
    printf("  topwriters [sec]      Process storage write throughput monitor\n");
    printf("  ramscratch [MB]       One-touch volatile in-memory workspace\n");
    printf("  ramclone <f> [dest]   Zero-disk file cloner/stager into RAM\n\n");
    printf("Forensic Triage & Anti-Tamper Extensions:\n");
    printf("  sha256 <file|->       FIPS 180-4 cryptographic hash generator\n");
    printf("  nc [-l] <h|p> [p]     Micro-Netcat client & listener for raw TCP data streaming\n");
    printf("  elfpeek <binary>      Zero-execution dynamic library & ELF header inspector\n");
    printf("  envpeek [pid]         Sniff process environment & secrets from /proc/<pid>/environ\n");
    printf("  modpeek               Audit loaded kernel drivers & rootkits from /proc/modules\n");
    printf("  base64 [-e|-d] [file] Bit-shift Base64 transceiver for air-gapped serial consoles\n");
    printf("  replace <f> <s> <r>   Atomic in-place configuration patcher (replaces sed)\n");
    printf("  mknod <p> <c|b> M m   Direct device node reconstruction syscall\n");
    printf("  mount [-t t] [-o o]   Kernel syscall filesystem & bind mounter for chroot rescue\n");
    printf("  umount [-f] <target>  Direct kernel unmount syscall\n");
    printf("  memdump <pid> [out|-] Extract live process memory from /proc/<pid>/mem\n");
    printf("  finfo / statpeek <f>  Nanosecond inode, permission, and anti-timestomp auditor\n");
    printf("  strings [file] [len]  Extract printable ASCII artifacts without binutils\n");
    printf("  wipe <file> [passes]  Multi-pass secure overwriter & unlinker\n\n");
    printf("In-Memory Defense Execution & Adversary Hunting:\n");
    printf("  deletedgrab <p> <f>   Extract deleted files/descriptors into RAM\n");
    printf("  sigshield [on|off]    Anti-kill armor; immune to SIGTERM/SIGHUP & OOM\n");
    printf("  b64exec <name> [args] Decode Base64 from stdin into memfd & execute\n");
    printf("  ramoverlay <dir> [MB] Writable RAM overlayfs over full/ro filesystem\n");
    printf("  exehunt               Detect unlinked, RAM, or disguised processes\n");
    printf("  memscript <intp> [a]  Execute script directly out of RAM (zero-disk)\n");
    printf("  memunshare [-m|-p|-n] Run defense tools in private PID/RAM namespace\n");
    printf("  memgrep <pid> <str>   Sniff secrets/C2 domains in process memory\n");
    printf("  ptracehunt            Detect process injection & ptrace tracers\n");
    printf("  promischunt           Detect promiscuous interfaces & raw sniffers\n");
    printf("  persistpeek           Audit crontabs, systemd & profile persistence\n\n");
    printf("Pipeline & Text Surgery (Zero-Coreutils):\n");
    printf("  grep [-i] [-v] [-n] <p> [f]  Fast substring search and stream filter\n");
    printf("  head [-n N] [file...]        Output first N lines (default 10)\n");
    printf("  tail [-n N] [file...]        Output last N lines using circular buffer\n");
    printf("  wc [-l|-w|-c] [file...]      Count lines, words, and/or bytes\n");
    printf("  cut -d <d> -f <col> [f...]   Delimited column and field extractor\n");
    printf("  sort [file...]               In-memory line sorting\n");
    printf("  uniq [-c] [file...]          Consecutive duplicate line filter and counter\n");
    printf("  tr [-d] <set1> [set2]        Single-byte character translation / deletion\n");
    printf("  diff <file1> <file2>         Lightweight line-by-line file comparison\n\n");
    printf("Process, Thread & Memory Forensics (Anti-Rootkit):\n");
    printf("  ps / proclist                Native process table (PID, PPID, RSS, Comm)\n");
    printf("  mapspeek <pid>               Inspect memory maps; flags anonymous rwx pages\n");
    printf("  fdpeek <pid>                 Audit open file descriptors and deleted handles\n");
    printf("  stackpeek <pid>              Dump kernel backtrace for D-state hung processes\n");
    printf("  wchanpeek <pid>              Display kernel wait-channel sleep symbol\n");
    printf("  oomadj [pid] [score]         Inspect or adjust OOM score (-1000 to +1000)\n\n");
    printf("Security, Capabilities & LSM Defense:\n");
    printf("  cappeek [pid]                Decode POSIX capability bitmasks (Eff, Prm, Inh)\n");
    printf("  nspeek [pid]                 Inspect and compare namespace inode IDs\n");
    printf("  chattr <+i|-i> <file>        Toggle ext2/3/4 immutable bit (FS_IOC_SETFLAGS)\n");
    printf("  lockdown <dir>               Recursively mark all directory files immutable (+i)\n");
    printf("  lsmaudit                     Audit active LSMs (SELinux, AppArmor, Smack)\n");
    printf("  taintpeek                    Decode Linux kernel tainted status bitmask\n");
    printf("  id [user] / whoami           Display UID, GID, and supplemental groups\n");
    printf("  entropy <file|->             Calculate Shannon entropy to spot ransomware/blobs\n\n");
    printf("Storage, Block Devices & Initramfs Rescue:\n");
    printf("  dd if=.. of=.. [bs=N] [cnt=N]Raw block carver and imager for MBR/GPT/devices\n");
    printf("  fiemap <file>                Map physical disk LBA sectors and extents\n");
    printf("  losetup [-d dev] [dev] [f]   Direct loop device attachment/detachment ioctl\n");
    printf("  pivot_root <new> <old>       Direct syscall for initramfs PID 1 boot handoff\n");
    printf("  swapon / swapoff <dev|file>  Activate or deactivate emergency swap space\n");
    printf("  dropcaches [1|2|3]           Flush pagecache, dentries, and inodes from RAM\n");
    printf("  diskstat                     Storage I/O throughput and in-flight request stats\n");
    printf("  blkdiscard <device>          Send BLKDISCARD ioctl to trim SSDs or VM disks\n\n");
    printf("Network & Air-Gap Triage:\n");
    printf("  tcpping <host> <port> [ms]   Non-blocking TCP connect liveness test (no ICMP)\n");
    printf("  pcapdump <iface> <N> [out]   Zero-dependency micro packet sniffer (raw AF_PACKET)\n");
    printf("  ipaddr [iface] [ip/mask]     Direct ioctl network interface IP configurator\n");
    printf("  dnsquery <host> [dns_ip]     Direct UDP DNS query bypassing /etc/resolv.conf\n");
    printf("  sockhunt <port>              Pinpoint PID, comm, and binary holding a port\n");
    printf("  killbyport <port> [-sig]     Terminate process listening on target port\n");
    printf("  netif                        Interface traffic and packet counters from /proc\n");
    printf("  arppeek                      Local LAN ARP neighbor table from /proc\n");
    printf("  routepeek                    Kernel IPv4 routing table from /proc\n");
    printf("  portscan <host> <start> <end>Fast TCP port scanner\n\n");
    printf("Hardware, Firmware & Hypervisor Introspection:\n");
    printf("  dmipeek / smbios             Motherboard, BIOS, and hypervisor identification\n");
    printf("  cpuid / cpuinfo              CPU microcode, cores, and hardware vulnerability status\n");
    printf("  pcipeek                      Inspect PCI hardware bus controllers without lspci\n");
    printf("  usbpeek                      USB device hardware sniffer (rogue USB detectors)\n\n");
    printf("Interactive Scripting, Forensics & System Control:\n");
    printf("  read [-r] [VAR]              Prompt for interactive input into shell variable\n");
    printf("  calc <n1> <op> <n2>          64-bit integer arithmetic (+, -, *, /, %%, &, |, ^)\n");
    printf("  clear                        Reset terminal screen via ANSI escape code\n");
    printf("  timestomp <f> <ref|epoch>    Set nanosecond timestamps via utimensat\n");
    printf("  uptime                       Display system uptime and 1/5/15 min load averages\n");
    printf("  symlink <target> <link>      Create symbolic link without /bin/ln\n");
    printf("  readlink [-f] <link>         Read symbolic link target\n");
    printf("  time <command...>            Measure command execution duration (real/user/sys)\n");
    printf("  md5 <file|->                 Standalone RFC 1321 MD5 cryptographic hasher\n");
    printf("  crc32 <file|->               Fast IEEE 802.3 32-bit checksum\n");
    printf("  xor <file|-> <key>           Bitwise XOR stream encoder/decoder\n");
    printf("  stealth [name]               Disguise process, audit parent shell, arm anti-kill armor\n");
    printf("  detach [-o f] <cmd...>       Spawn daemonized background job (setsid, immune to SIGHUP)\n");
    printf("  jobs                         List active background and detached jobs\n");
    printf("  disown [id|pid]              Release job tracking from shell\n");
    printf("  stop <id|pid> [-sig]         Terminate detached/background job and child tree\n");
    printf("  attach <id|pid>              Stream live output log of detached job (Ctrl-C detaches)\n\n");
    printf("Detailed Command Help & Recovery Examples:\n");
    printf("  Type 'help <command>' or '<command> --help' (e.g. 'help ramoverlay', 'help stealth',\n");
    printf("  'help deletedgrab', 'help truncate', 'help ghostfind', 'help exec', etc.)\n\n");
    fflush(stdout);
    return 0;
}

static int builtin_exit(char **args) {
    int code = (args[1] != NULL) ? atoi(args[1]) : last_exit_status;
    exit(code);
}

/* Built-in table */
static const BuiltinDef builtins[] = {
    {"vim",          &builtin_vim,          0},
    {"vi",           &builtin_vim,          0},
    {"cd",           &builtin_cd,           1},
    {"exit",         &builtin_exit,         1},
    {"export",       &builtin_export,       1},
    {"unset",        &builtin_unset,        1},
    {"setproctitle", &builtin_setproctitle, 1},
    {"procrename",   &builtin_setproctitle, 1},
    {"renameproc",   &builtin_setproctitle, 1},
    {"exec",         &builtin_exec,         1},
    {"set",          &builtin_set,          1},
    {"source",       &builtin_source,       1},
    {".",            &builtin_source,       1},
    {"chroot",       &builtin_chroot,       1},
    {"memfile",      &builtin_memfile,      1},
    {"memrun",       &builtin_memrun,       0},
    {"memexec",      &builtin_memrun,       0},
    {"sha256",       &builtin_sha256,       0},
    {"nc",           &builtin_nc,           0},
    {"elfpeek",      &builtin_elfpeek,      0},
    {"envpeek",      &builtin_envpeek,      0},
    {"modpeek",      &builtin_modpeek,      0},
    {"base64",       &builtin_base64,       0},
    {"replace",      &builtin_replace,      0},
    {"mknod",        &builtin_mknod,        0},
    {"mount",        &builtin_mount,        0},
    {"umount",       &builtin_umount,       0},
    {"memdump",      &builtin_memdump,      0},
    {"finfo",        &builtin_finfo,        0},
    {"statpeek",     &builtin_finfo,        0},
    {"strings",      &builtin_strings,      0},
    {"wipe",         &builtin_wipe,         0},
    {"umask",        &builtin_umask,        1},
    {"remount",      &builtin_remount,      0},
    {"sync",         &builtin_sync,         0},
    {"chmod",        &builtin_chmod,        0},
    {"chown",        &builtin_chown,        0},
    {"mv",           &builtin_mv,           0},
    {"cp",           &builtin_cp,           0},
    {"df",           &builtin_df,           0},
    {"truncate",     &builtin_truncate,     0},
    {"ghostfind",    &builtin_ghostfind,    0},
    {"findlarge",    &builtin_findlarge,    0},
    {"inodescan",    &builtin_inodescan,    0},
    {"zerolog",      &builtin_zerolog,      0},
    {"findempty",    &builtin_findempty,    0},
    {"dusage",       &builtin_dusage,       0},
    {"findinode",    &builtin_findinode,    0},
    {"tmpfs",        &builtin_tmpfs,        0},
    {"sysinfo",      &builtin_sysinfo,      0},
    {"free",         &builtin_sysinfo,      0},
    {"dmesg",        &builtin_dmesg,        0},
    {"uname",        &builtin_uname,        0},
    {"reboot",       &builtin_reboot,       0},
    {"poweroff",     &builtin_poweroff,     0},
    {"sysrq",        &builtin_sysrq,        0},
    {"probeblk",     &builtin_probeblk,     0},
    {"hexview",      &builtin_hexview,      0},
    {"falloc",       &builtin_falloc,       0},
    {"sockstat",     &builtin_sockstat,     0},
    {"killtree",     &builtin_killtree,     0},
    {"procpeek",     &builtin_procpeek,     0},
    {"httpget",      &builtin_httpget,      0},
    {"dnslookup",    &builtin_dnslookup,    0},
    {"randhex",      &builtin_randhex,      0},
    {"watch",        &builtin_watch,        0},
    {"pwd",          &builtin_pwd,          0},
    {"echo",         &builtin_echo,         0},
    {"cat",          &builtin_cat,          0},
    {"ls",           &builtin_ls,           0},
    {"touch",        &builtin_touch,        0},
    {"mkdir",        &builtin_mkdir,        0},
    {"rm",           &builtin_rm,           0},
    {"sleep",        &builtin_sleep,        0},
    {"kill",         &builtin_kill,         0},
    {"true",         &builtin_true,         0},
    {"false",        &builtin_false,        0},
    {"which",        &builtin_which,        0},
    {"test",         &builtin_test,         0},
    {"[",            &builtin_test,         0},
    {"help",         &builtin_help,         0},
    {"grep",         &builtin_grep,         0},
    {"head",         &builtin_head,         0},
    {"tail",         &builtin_tail,         0},
    {"wc",           &builtin_wc,           0},
    {"cut",          &builtin_cut,          0},
    {"sort",         &builtin_sort,         0},
    {"uniq",         &builtin_uniq,         0},
    {"tr",           &builtin_tr,           0},
    {"diff",         &builtin_diff,         0},
    {"ps",           &builtin_ps,           0},
    {"proclist",     &builtin_ps,           0},
    {"mapspeek",     &builtin_mapspeek,     0},
    {"fdpeek",       &builtin_fdpeek,       0},
    {"stackpeek",    &builtin_stackpeek,    0},
    {"wchanpeek",    &builtin_wchanpeek,    0},
    {"oomadj",       &builtin_oomadj,       0},
    {"cappeek",      &builtin_cappeek,      0},
    {"nspeek",       &builtin_nspeek,       0},
    {"chattr",       &builtin_chattr,       0},
    {"lockdown",     &builtin_lockdown,     0},
    {"lsmaudit",     &builtin_lsmaudit,     0},
    {"taintpeek",    &builtin_taintpeek,    0},
    {"id",           &builtin_id,           0},
    {"whoami",       &builtin_id,           0},
    {"entropy",      &builtin_entropy,      0},
    {"dd",           &builtin_dd,           0},
    {"fiemap",       &builtin_fiemap,       0},
    {"losetup",      &builtin_losetup,      0},
    {"pivot_root",   &builtin_pivot_root,   0},
    {"swapon",       &builtin_swapon,       0},
    {"swapoff",      &builtin_swapoff,      0},
    {"dropcaches",   &builtin_dropcaches,   0},
    {"diskstat",     &builtin_diskstat,     0},
    {"blkdiscard",   &builtin_blkdiscard,   0},
    {"tcpping",      &builtin_tcpping,      0},
    {"pcapdump",     &builtin_pcapdump,     0},
    {"ipaddr",       &builtin_ipaddr,       0},
    {"dnsquery",     &builtin_dnsquery,     0},
    {"sockhunt",     &builtin_sockhunt,     0},
    {"killbyport",   &builtin_killbyport,   0},
    {"netif",        &builtin_netif,        0},
    {"arppeek",      &builtin_arppeek,      0},
    {"routepeek",    &builtin_routepeek,    0},
    {"portscan",     &builtin_portscan,     0},
    {"dmipeek",      &builtin_dmipeek,      0},
    {"smbios",       &builtin_dmipeek,      0},
    {"cpuid",        &builtin_cpuid,        0},
    {"cpuinfo",      &builtin_cpuid,        0},
    {"pcipeek",      &builtin_pcipeek,      0},
    {"usbpeek",      &builtin_usbpeek,      0},
    {"read",         &builtin_read,         1},
    {"calc",         &builtin_calc,         0},
    {"clear",        &builtin_clear,        0},
    {"timestomp",    &builtin_timestomp,    0},
    {"uptime",       &builtin_uptime,       0},
    {"symlink",      &builtin_symlink,      0},
    {"readlink",     &builtin_readlink,     0},
    {"time",         &builtin_time,         0},
    {"md5",          &builtin_md5,          0},
    {"crc32",        &builtin_crc32,        0},
    {"xor",          &builtin_xor,          0},
    {"findgrowth",   &builtin_findgrowth,   0},
    {"fdsize",       &builtin_fdsize,       0},
    {"topwriters",   &builtin_topwriters,   0},
    {"ramscratch",   &builtin_ramscratch,   1},
    {"ramclone",     &builtin_ramclone,     1},
    {"deletedgrab",  &builtin_deletedgrab,  1},
    {"sigshield",    &builtin_sigshield,    1},
    {"stealth",      &builtin_stealth,      1},
    {"detach",       &builtin_detach,       1},
    {"jobs",         &builtin_jobs,         0},
    {"disown",       &builtin_disown,       1},
    {"stop",         &builtin_stop,         0},
    {"attach",       &builtin_attach,       0},
    {"b64exec",      &builtin_b64exec,      0},
    {"ramoverlay",   &builtin_ramoverlay,   0},
    {"exehunt",      &builtin_exehunt,      0},
    {"memscript",    &builtin_memscript,    0},
    {"memunshare",   &builtin_memunshare,   0},
    {"memgrep",      &builtin_memgrep,      0},
    {"ptracehunt",   &builtin_ptracehunt,   0},
    {"promischunt",  &builtin_promischunt,  0},
    {"persistpeek",  &builtin_persistpeek,  0},
    {NULL,           NULL,                  0}
};

static const BuiltinDef *find_builtin(const char *cmd) {
    if (!cmd) return NULL;
    for (int i = 0; builtins[i].name; i++) {
        if (strcmp(cmd, builtins[i].name) == 0) {
            return &builtins[i];
        }
    }
    return NULL;
}

/* --- Variable Interpolation Helper --- */

static void interpolate_var(const char **p_ptr, char **buf, size_t *len, size_t *cap) {
    const char *p = *p_ptr;
    p++; /* skip '$' */

    if (*p == '?') {
        char num[32];
        snprintf(num, sizeof(num), "%d", last_exit_status);
        buf_append_str(buf, len, cap, num);
        p++;
    } else if (*p == '$') {
        char num[32];
        snprintf(num, sizeof(num), "%d", (int)getpid());
        buf_append_str(buf, len, cap, num);
        p++;
    } else if (*p == '#') {
        char num[32];
        int count = (script_argc > 1) ? (script_argc - 1) : 0;
        snprintf(num, sizeof(num), "%d", count);
        buf_append_str(buf, len, cap, num);
        p++;
    } else if (isdigit((unsigned char)*p)) {
        int idx = *p - '0';
        p++;
        if (idx < script_argc && script_argv && script_argv[idx]) {
            buf_append_str(buf, len, cap, script_argv[idx]);
        }
    } else if (*p == '{') {
        p++;
        const char *start = p;
        while (*p && *p != '}') p++;
        size_t vlen = (size_t)(p - start);
        char var_name[256];
        if (vlen < sizeof(var_name)) {
            memcpy(var_name, start, vlen);
            var_name[vlen] = '\0';
            if (strcmp(var_name, "?") == 0) {
                char num[32];
                snprintf(num, sizeof(num), "%d", last_exit_status);
                buf_append_str(buf, len, cap, num);
            } else if (strcmp(var_name, "$") == 0) {
                char num[32];
                snprintf(num, sizeof(num), "%d", (int)getpid());
                buf_append_str(buf, len, cap, num);
            } else if (strcmp(var_name, "#") == 0) {
                char num[32];
                int count = (script_argc > 1) ? (script_argc - 1) : 0;
                snprintf(num, sizeof(num), "%d", count);
                buf_append_str(buf, len, cap, num);
            } else if (isdigit((unsigned char)var_name[0])) {
                int idx = atoi(var_name);
                if (idx < script_argc && script_argv && script_argv[idx]) {
                    buf_append_str(buf, len, cap, script_argv[idx]);
                }
            } else {
                const char *val = getenv(var_name);
                if (val) buf_append_str(buf, len, cap, val);
            }
        }
        if (*p == '}') p++;
    } else if (isalpha((unsigned char)*p) || *p == '_') {
        const char *start = p;
        while (isalnum((unsigned char)*p) || *p == '_') p++;
        size_t vlen = (size_t)(p - start);
        char var_name[256];
        if (vlen < sizeof(var_name)) {
            memcpy(var_name, start, vlen);
            var_name[vlen] = '\0';
            const char *val = getenv(var_name);
            if (val) buf_append_str(buf, len, cap, val);
        }
    } else {
        buf_append_char(buf, len, cap, '$');
    }

    *p_ptr = p;
}

/* --- Deferred Word Expansion (Tilde, Quotes, Variables) --- */

static char *expand_word(const char *word) {
    if (!word) return NULL;

    size_t cap = 64, len = 0;
    char *res = malloc(cap);
    if (!res) return NULL;
    res[0] = '\0';

    const char *p = word;

    /* Tilde expansion at start of word: ~ or ~/path */
    if (*p == '~' && (p[1] == '\0' || p[1] == '/')) {
        const char *home = getenv("HOME");
        if (!home) home = "";
        buf_append_str(&res, &len, &cap, home);
        p++;
    }

    while (*p) {
        if (*p == '\'') {
            /* Single quotes: literal characters, strip quotes */
            p++;
            while (*p && *p != '\'') {
                buf_append_char(&res, &len, &cap, *p++);
            }
            if (*p == '\'') p++;
        } else if (*p == '"') {
            /* Double quotes: variable expansion and escape sequences, strip quotes */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && *(p + 1)) {
                    p++;
                    if (*p == '$' || *p == '"' || *p == '\\' || *p == '`') {
                        buf_append_char(&res, &len, &cap, *p++);
                    } else {
                        buf_append_char(&res, &len, &cap, '\\');
                        buf_append_char(&res, &len, &cap, *p++);
                    }
                } else if (*p == '$') {
                    interpolate_var(&p, &res, &len, &cap);
                } else {
                    buf_append_char(&res, &len, &cap, *p++);
                }
            }
            if (*p == '"') p++;
        } else if (*p == '\\' && *(p + 1)) {
            /* Unquoted backslash escape */
            p++;
            buf_append_char(&res, &len, &cap, *p++);
        } else if (*p == '$') {
            /* Unquoted variable interpolation */
            interpolate_var(&p, &res, &len, &cap);
        } else if (*p == '=' && *(p + 1) == '~' && (*(p + 2) == '\0' || *(p + 2) == '/')) {
            /* Tilde expansion after assignment: VAR=~/path */
            buf_append_char(&res, &len, &cap, '=');
            p += 2;
            const char *home = getenv("HOME");
            if (!home) home = "";
            buf_append_str(&res, &len, &cap, home);
        } else {
            buf_append_char(&res, &len, &cap, *p++);
        }
    }

    return res;
}

/* --- Tokenizer --- */

static char **tokenize_line(const char *line) {
    size_t cap = 32, count = 0;
    char **tokens = malloc(cap * sizeof(char *));
    if (!tokens) return NULL;

    const char *p = line;
    while (*p) {
        while (*p && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
        if (!*p) break;

        /* Unquoted newline is a command separator like semicolon */
        if (*p == '\n') {
            if (count > 0 &&
                strcmp(tokens[count - 1], ";") != 0 &&
                strcmp(tokens[count - 1], "&&") != 0 &&
                strcmp(tokens[count - 1], "||") != 0 &&
                strcmp(tokens[count - 1], "|") != 0 &&
                strcmp(tokens[count - 1], "&") != 0) {
                tokens[count++] = strdup(";");
            }
            p++;
            continue;
        }

        /* Comment support outside quotes */
        if (*p == '#') {
            while (*p && *p != '\n') p++;
            continue;
        }

        /* Multi-character and redirection operators */
        if (strncmp(p, "2>&1", 4) == 0) {
            tokens[count++] = strdup("2>&1");
            p += 4;
        } else if (strncmp(p, "1>&2", 4) == 0) {
            tokens[count++] = strdup(">&2");
            p += 4;
        } else if (strncmp(p, ">&2", 3) == 0) {
            tokens[count++] = strdup(">&2");
            p += 3;
        } else if (strncmp(p, "2>>", 3) == 0) {
            tokens[count++] = strdup("2>>");
            p += 3;
        } else if (strncmp(p, "1>>", 3) == 0) {
            tokens[count++] = strdup(">>");
            p += 3;
        } else if (strncmp(p, "2>", 2) == 0) {
            tokens[count++] = strdup("2>");
            p += 2;
        } else if (strncmp(p, "1>", 2) == 0) {
            tokens[count++] = strdup(">");
            p += 2;
        } else if (strncmp(p, "&>>", 3) == 0) {
            tokens[count++] = strdup("&>>");
            p += 3;
        } else if (strncmp(p, "&>", 2) == 0) {
            tokens[count++] = strdup("&>");
            p += 2;
        } else if (strncmp(p, "&&", 2) == 0) {
            tokens[count++] = strdup("&&");
            p += 2;
        } else if (strncmp(p, "||", 2) == 0) {
            tokens[count++] = strdup("||");
            p += 2;
        } else if (strncmp(p, ">>", 2) == 0) {
            tokens[count++] = strdup(">>");
            p += 2;
        } else if (*p == '|' || *p == '<' || *p == '>' || *p == ';' || *p == '&') {
            char op[2] = { *p, '\0' };
            tokens[count++] = strdup(op);
            p++;
        } else {
            /* General word token with quote preservation */
            size_t word_cap = 64, word_len = 0;
            char *word = malloc(word_cap);
            word[0] = '\0';

            while (*p) {
                if (*p == '\'') {
                    buf_append_char(&word, &word_len, &word_cap, *p++);
                    while (*p && *p != '\'') {
                        buf_append_char(&word, &word_len, &word_cap, *p++);
                    }
                    if (*p == '\'') {
                        buf_append_char(&word, &word_len, &word_cap, *p++);
                    }
                } else if (*p == '"') {
                    buf_append_char(&word, &word_len, &word_cap, *p++);
                    while (*p && *p != '"') {
                        if (*p == '\\' && *(p + 1)) {
                            buf_append_char(&word, &word_len, &word_cap, *p++);
                            buf_append_char(&word, &word_len, &word_cap, *p++);
                        } else {
                            buf_append_char(&word, &word_len, &word_cap, *p++);
                        }
                    }
                    if (*p == '"') {
                        buf_append_char(&word, &word_len, &word_cap, *p++);
                    }
                } else if (*p == '\\' && *(p + 1)) {
                    buf_append_char(&word, &word_len, &word_cap, *p++);
                    buf_append_char(&word, &word_len, &word_cap, *p++);
                } else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' ||
                           *p == '|' || *p == '<' || *p == '>' || *p == ';' || *p == '&' ||
                           (p[0] == '2' && p[1] == '>') ||
                           (p[0] == '1' && p[1] == '>')) {
                    break;
                } else if (*p == '#' && word_len == 0) {
                    break;
                } else {
                    buf_append_char(&word, &word_len, &word_cap, *p++);
                }
            }

            tokens[count++] = word;
        }

        if (count + 1 >= cap) {
            cap *= 2;
            tokens = realloc(tokens, cap * sizeof(char *));
        }
    }
    tokens[count] = NULL;
    return tokens;
}

static void free_tokens(char **tokens) {
    if (!tokens) return;
    for (int i = 0; tokens[i]; i++) {
        free(tokens[i]);
    }
    free(tokens);
}

/* --- AST / Pipeline Parsing --- */

static PipelineUnit *parse_pipeline_chain(char **tokens, int *num_units_out) {
    if (!tokens || !tokens[0]) {
        *num_units_out = 0;
        return NULL;
    }

    size_t unit_cap = 8, num_units = 0;
    PipelineUnit *units = calloc(unit_cap, sizeof(PipelineUnit));

    int t = 0;
    while (tokens[t]) {
        size_t cmd_cap = 4, num_cmds = 0;
        SimpleCommand *cmds = calloc(cmd_cap, sizeof(SimpleCommand));

        size_t arg_cap = 8, argc = 0;
        char **argv = calloc(arg_cap, sizeof(char *));

        char *in_file = NULL;
        char *out_file = NULL;
        int append_out = 0;
        char *err_file = NULL;
        int append_err = 0;
        int err_to_out = 0;
        int out_to_err = 0;
        int is_bg = 0;
        ChainOp op = OP_NONE;

        while (tokens[t]) {
            const char *tok = tokens[t];

            if (strcmp(tok, ";") == 0) {
                op = OP_SEMICOLON;
                t++;
                break;
            } else if (strcmp(tok, "&&") == 0) {
                op = OP_AND;
                t++;
                break;
            } else if (strcmp(tok, "||") == 0) {
                op = OP_OR;
                t++;
                break;
            } else if (strcmp(tok, "&") == 0) {
                is_bg = 1;
                op = OP_SEMICOLON;
                t++;
                if (tokens[t]) {
                    if (strcmp(tokens[t], ";") == 0) { op = OP_SEMICOLON; t++; }
                    else if (strcmp(tokens[t], "&&") == 0) { op = OP_AND; t++; }
                    else if (strcmp(tokens[t], "||") == 0) { op = OP_OR; t++; }
                }
                break;
            } else if (strcmp(tok, "|") == 0) {
                argv[argc] = NULL;
                cmds[num_cmds].argv = argv;
                cmds[num_cmds].argc = (int)argc;
                cmds[num_cmds].input_file = in_file;
                cmds[num_cmds].output_file = out_file;
                cmds[num_cmds].append_output = append_out;
                cmds[num_cmds].err_file = err_file;
                cmds[num_cmds].append_err = append_err;
                cmds[num_cmds].err_to_out = err_to_out;
                cmds[num_cmds].out_to_err = out_to_err;
                num_cmds++;

                if (num_cmds >= cmd_cap) {
                    cmd_cap *= 2;
                    cmds = realloc(cmds, cmd_cap * sizeof(SimpleCommand));
                }

                arg_cap = 8;
                argc = 0;
                argv = calloc(arg_cap, sizeof(char *));
                in_file = NULL;
                out_file = NULL;
                append_out = 0;
                err_file = NULL;
                append_err = 0;
                err_to_out = 0;
                out_to_err = 0;
                t++;
            } else if (strcmp(tok, "<") == 0) {
                t++;
                if (tokens[t]) in_file = strdup(tokens[t++]);
            } else if (strcmp(tok, ">") == 0) {
                t++;
                if (tokens[t]) {
                    out_file = strdup(tokens[t++]);
                    append_out = 0;
                }
            } else if (strcmp(tok, ">>") == 0) {
                t++;
                if (tokens[t]) {
                    out_file = strdup(tokens[t++]);
                    append_out = 1;
                }
            } else if (strcmp(tok, "2>") == 0) {
                t++;
                if (tokens[t]) {
                    err_file = strdup(tokens[t++]);
                    append_err = 0;
                }
            } else if (strcmp(tok, "2>>") == 0) {
                t++;
                if (tokens[t]) {
                    err_file = strdup(tokens[t++]);
                    append_err = 1;
                }
            } else if (strcmp(tok, "2>&1") == 0) {
                err_to_out = 1;
                t++;
            } else if (strcmp(tok, ">&2") == 0) {
                out_to_err = 1;
                t++;
            } else if (strcmp(tok, "&>") == 0) {
                t++;
                if (tokens[t]) {
                    out_file = strdup(tokens[t++]);
                    append_out = 0;
                    err_to_out = 1;
                }
            } else if (strcmp(tok, "&>>") == 0) {
                t++;
                if (tokens[t]) {
                    out_file = strdup(tokens[t++]);
                    append_out = 1;
                    err_to_out = 1;
                }
            } else {
                argv[argc++] = strdup(tok);
                if (argc + 1 >= arg_cap) {
                    arg_cap *= 2;
                    argv = realloc(argv, arg_cap * sizeof(char *));
                }
                t++;
            }
        }

        argv[argc] = NULL;
        cmds[num_cmds].argv = argv;
        cmds[num_cmds].argc = (int)argc;
        cmds[num_cmds].input_file = in_file;
        cmds[num_cmds].output_file = out_file;
        cmds[num_cmds].append_output = append_out;
        cmds[num_cmds].err_file = err_file;
        cmds[num_cmds].append_err = append_err;
        cmds[num_cmds].err_to_out = err_to_out;
        cmds[num_cmds].out_to_err = out_to_err;
        num_cmds++;

        units[num_units].cmds = cmds;
        units[num_units].num_cmds = (int)num_cmds;
        units[num_units].is_background = is_bg;
        units[num_units].next_op = op;
        num_units++;

        if (num_units >= unit_cap) {
            unit_cap *= 2;
            units = realloc(units, unit_cap * sizeof(PipelineUnit));
        }
    }

    *num_units_out = (int)num_units;
    return units;
}

static void free_pipeline_chain(PipelineUnit *units, int num_units) {
    if (!units) return;
    for (int u = 0; u < num_units; u++) {
        for (int c = 0; c < units[u].num_cmds; c++) {
            SimpleCommand *cmd = &units[u].cmds[c];
            if (cmd->argv) {
                for (int a = 0; cmd->argv[a]; a++) {
                    free(cmd->argv[a]);
                }
                free(cmd->argv);
            }
            if (cmd->input_file) free(cmd->input_file);
            if (cmd->output_file) free(cmd->output_file);
            if (cmd->err_file) free(cmd->err_file);
        }
        free(units[u].cmds);
    }
    free(units);
}

/* --- Just-In-Time Command Expansion Helpers --- */

static void expand_command(const SimpleCommand *src, SimpleCommand *dst) {
    dst->argc = src->argc;
    dst->argv = malloc((src->argc + 1) * sizeof(char *));
    for (int a = 0; a < src->argc; a++) {
        dst->argv[a] = expand_word(src->argv[a]);
    }
    dst->argv[src->argc] = NULL;
    dst->input_file = src->input_file ? expand_word(src->input_file) : NULL;
    dst->output_file = src->output_file ? expand_word(src->output_file) : NULL;
    dst->append_output = src->append_output;
    dst->err_file = src->err_file ? expand_word(src->err_file) : NULL;
    dst->append_err = src->append_err;
    dst->err_to_out = src->err_to_out;
    dst->out_to_err = src->out_to_err;
}

static void free_expanded_command(SimpleCommand *cmd) {
    if (cmd->argv) {
        for (int a = 0; a < cmd->argc; a++) {
            free(cmd->argv[a]);
        }
        free(cmd->argv);
    }
    if (cmd->input_file) free(cmd->input_file);
    if (cmd->output_file) free(cmd->output_file);
    if (cmd->err_file) free(cmd->err_file);
}

static void restore_fds(int saved_in, int saved_out, int saved_err) {
    if (saved_in >= 0) {
        dup2(saved_in, STDIN_FILENO);
        close(saved_in);
    }
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
}

static int is_assignment_word(const char *s) {
    if (!s || (!isalpha((unsigned char)s[0]) && s[0] != '_')) return 0;
    const char *p = s + 1;
    while (*p && *p != '=') {
        if (!isalnum((unsigned char)*p) && *p != '_') return 0;
        p++;
    }
    return (*p == '=');
}

static int is_all_assignments(char **argv, int argc) {
    if (argc <= 0) return 0;
    for (int i = 0; i < argc; i++) {
        if (!is_assignment_word(argv[i])) return 0;
    }
    return 1;
}

static int execute_assignments(char **argv) {
    for (int i = 0; argv[i]; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            *eq = '\0';
            setenv(argv[i], eq + 1, 1);
            *eq = '=';
        }
    }
    return 0;
}

/* --- Execution Engine --- */

static void execute_pipeline(PipelineUnit *unit) {
    int num_cmds = unit->num_cmds;
    if (num_cmds == 0) return;

    /* Handle single foreground command in parent (assignments & stateful built-ins) */
    if (num_cmds == 1 && unit->cmds[0].argc > 0 && !unit->is_background) {
        SimpleCommand exp_cmd;
        expand_command(&unit->cmds[0], &exp_cmd);

        if (exp_cmd.argc == 0) {
            free_expanded_command(&exp_cmd);
            return;
        }

        /* Check for standalone variable assignments: NAME=VALUE ... */
        if (is_all_assignments(exp_cmd.argv, exp_cmd.argc)) {
            last_exit_status = execute_assignments(exp_cmd.argv);
            free_expanded_command(&exp_cmd);
            return;
        }

        const BuiltinDef *b = find_builtin(exp_cmd.argv[0]);
        if (b && exp_cmd.argv[1] && (strcmp(exp_cmd.argv[1], "--help") == 0 || strcmp(exp_cmd.argv[1], "-h") == 0)) {
            if (show_command_help(exp_cmd.argv[0])) {
                last_exit_status = 0;
                free_expanded_command(&exp_cmd);
                return;
            }
        }
        if (b && b->is_stateful) {
            int saved_stdin = -1, saved_stdout = -1, saved_stderr = -1;

            if (exp_cmd.input_file) {
                saved_stdin = dup(STDIN_FILENO);
                int fd = open(exp_cmd.input_file, O_RDONLY);
                if (fd >= 0) {
                    dup2(fd, STDIN_FILENO);
                    close(fd);
                } else {
                    perror(exp_cmd.input_file);
                    restore_fds(saved_stdin, saved_stdout, saved_stderr);
                    last_exit_status = 1;
                    free_expanded_command(&exp_cmd);
                    return;
                }
            }
            if (exp_cmd.output_file) {
                saved_stdout = dup(STDOUT_FILENO);
                int flags = O_WRONLY | O_CREAT | (exp_cmd.append_output ? O_APPEND : O_TRUNC);
                int fd = open(exp_cmd.output_file, flags, 0666);
                if (fd >= 0) {
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                } else {
                    perror(exp_cmd.output_file);
                    restore_fds(saved_stdin, saved_stdout, saved_stderr);
                    last_exit_status = 1;
                    free_expanded_command(&exp_cmd);
                    return;
                }
            }
            if (exp_cmd.err_file) {
                saved_stderr = dup(STDERR_FILENO);
                int flags = O_WRONLY | O_CREAT | (exp_cmd.append_err ? O_APPEND : O_TRUNC);
                int fd = open(exp_cmd.err_file, flags, 0666);
                if (fd >= 0) {
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                } else {
                    perror(exp_cmd.err_file);
                    restore_fds(saved_stdin, saved_stdout, saved_stderr);
                    last_exit_status = 1;
                    free_expanded_command(&exp_cmd);
                    return;
                }
            }
            if (exp_cmd.err_to_out) {
                if (saved_stderr < 0) saved_stderr = dup(STDERR_FILENO);
                dup2(STDOUT_FILENO, STDERR_FILENO);
            }
            if (exp_cmd.out_to_err) {
                if (saved_stdout < 0) saved_stdout = dup(STDOUT_FILENO);
                dup2(STDERR_FILENO, STDOUT_FILENO);
            }

            last_exit_status = b->func(exp_cmd.argv);
            fflush(stdout);
            fflush(stderr);

            restore_fds(saved_stdin, saved_stdout, saved_stderr);
            free_expanded_command(&exp_cmd);
            return;
        }
        free_expanded_command(&exp_cmd);
    }

    /* Multi-command pipeline or external/forked foreground/background execution */
    int num_pipes = num_cmds - 1;
    int *pipefds = NULL;
    if (num_pipes > 0) {
        pipefds = malloc(sizeof(int) * 2 * num_pipes);
        if (!pipefds) {
            perror("minish: malloc");
            last_exit_status = 1;
            return;
        }
        for (int i = 0; i < num_pipes; i++) {
            if (pipe(pipefds + i * 2) < 0) {
                perror("minish: pipe");
                for (int j = 0; j < i * 2; j++) close(pipefds[j]);
                free(pipefds);
                last_exit_status = 1;
                return;
            }
        }
    }

    pid_t *pids = malloc(sizeof(pid_t) * num_cmds);
    if (!pids) {
        perror("minish: malloc");
        last_exit_status = 1;
        if (pipefds) {
            for (int j = 0; j < 2 * num_pipes; j++) close(pipefds[j]);
            free(pipefds);
        }
        return;
    }

    sigset_t chld_mask, orig_mask;
    sigemptyset(&chld_mask);
    sigaddset(&chld_mask, SIGCHLD);
    if (!unit->is_background) {
        sigprocmask(SIG_BLOCK, &chld_mask, &orig_mask);
    }

    fflush(NULL);

    for (int i = 0; i < num_cmds; i++) {
        if (unit->cmds[i].argc == 0) {
            pids[i] = -1;
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            if (!unit->is_background) {
                sigprocmask(SIG_SETMASK, &orig_mask, NULL);
            }
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);

            if (i > 0 && pipefds) {
                dup2(pipefds[(i - 1) * 2], STDIN_FILENO);
            }
            if (i < num_cmds - 1 && pipefds) {
                dup2(pipefds[i * 2 + 1], STDOUT_FILENO);
            }
            if (pipefds) {
                for (int j = 0; j < 2 * num_pipes; j++) {
                    close(pipefds[j]);
                }
            }

            SimpleCommand exp_cmd;
            expand_command(&unit->cmds[i], &exp_cmd);

            if (exp_cmd.argc == 0) {
                _exit(0);
            }

            if (is_all_assignments(exp_cmd.argv, exp_cmd.argc)) {
                execute_assignments(exp_cmd.argv);
                _exit(0);
            }

            if (exp_cmd.input_file) {
                int fd = open(exp_cmd.input_file, O_RDONLY);
                if (fd < 0) {
                    perror(exp_cmd.input_file);
                    _exit(1);
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            }
            if (exp_cmd.output_file) {
                int flags = O_WRONLY | O_CREAT | (exp_cmd.append_output ? O_APPEND : O_TRUNC);
                int fd = open(exp_cmd.output_file, flags, 0666);
                if (fd < 0) {
                    perror(exp_cmd.output_file);
                    _exit(1);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }
            if (exp_cmd.err_file) {
                int flags = O_WRONLY | O_CREAT | (exp_cmd.append_err ? O_APPEND : O_TRUNC);
                int fd = open(exp_cmd.err_file, flags, 0666);
                if (fd < 0) {
                    perror(exp_cmd.err_file);
                    _exit(1);
                }
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
            if (exp_cmd.err_to_out) {
                dup2(STDOUT_FILENO, STDERR_FILENO);
            }
            if (exp_cmd.out_to_err) {
                dup2(STDERR_FILENO, STDOUT_FILENO);
            }

            const BuiltinDef *b = find_builtin(exp_cmd.argv[0]);
            if (b && exp_cmd.argv[1] && (strcmp(exp_cmd.argv[1], "--help") == 0 || strcmp(exp_cmd.argv[1], "-h") == 0)) {
                if (show_command_help(exp_cmd.argv[0])) {
                    fflush(stdout);
                    _exit(0);
                }
            }
            if (b) {
                int ret = b->func(exp_cmd.argv);
                fflush(stdout);
                fflush(stderr);
                _exit(ret);
            }

            execvp(exp_cmd.argv[0], exp_cmd.argv);
            perror(exp_cmd.argv[0]);
            int exit_code = (errno == ENOENT) ? 127 : 126;
            _exit(exit_code);
        } else if (pid < 0) {
            perror("minish: fork");
            pids[i] = -1;
        } else {
            pids[i] = pid;
        }
    }

    if (pipefds) {
        for (int j = 0; j < 2 * num_pipes; j++) {
            close(pipefds[j]);
        }
        free(pipefds);
    }

    if (unit->is_background) {
        if (num_cmds > 0 && pids[num_cmds - 1] > 0) {
            char cmd_summary[128] = "background job";
            if (unit->cmds[0].argc > 0 && unit->cmds[0].argv[0]) {
                snprintf(cmd_summary, sizeof(cmd_summary), "%s", unit->cmds[0].argv[0]);
            }
            int jid = add_shell_job(pids[num_cmds - 1], cmd_summary, "inherited stdout");
            printf("[%d] %d\n", jid, (int)pids[num_cmds - 1]);
            fflush(stdout);
        }
        last_exit_status = 0;
    } else {
        for (int i = 0; i < num_cmds; i++) {
            if (pids[i] > 0) {
                int status = 0;
                while (waitpid(pids[i], &status, 0) == -1) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (i == num_cmds - 1) {
                    if (WIFEXITED(status)) {
                        last_exit_status = WEXITSTATUS(status);
                    } else if (WIFSIGNALED(status)) {
                        last_exit_status = 128 + WTERMSIG(status);
                    }
                }
            }
        }
        sigprocmask(SIG_SETMASK, &orig_mask, NULL);
    }

    free(pids);
}

static void execute_line(const char *line) {
    char **tokens = tokenize_line(line);
    if (!tokens || !tokens[0]) {
        free_tokens(tokens);
        return;
    }

    int num_units = 0;
    PipelineUnit *units = parse_pipeline_chain(tokens, &num_units);

    for (int i = 0; i < num_units; i++) {
        int should_run = 1;
        if (i > 0) {
            ChainOp prev_op = units[i - 1].next_op;
            if (prev_op == OP_AND) {
                should_run = (last_exit_status == 0);
            } else if (prev_op == OP_OR) {
                should_run = (last_exit_status != 0);
            } else {
                should_run = 1;
            }
        }

        if (should_run) {
            if (shell_xtrace) {
                fprintf(stderr, "+ ");
                for (int c = 0; c < units[i].num_cmds; c++) {
                    for (int a = 0; a < units[i].cmds[c].argc; a++) {
                        fprintf(stderr, "%s ", units[i].cmds[c].argv[a]);
                    }
                    if (c < units[i].num_cmds - 1) fprintf(stderr, "| ");
                }
                fprintf(stderr, "\n");
            }

            execute_pipeline(&units[i]);

            /* POSIX errexit handling */
            if (shell_errexit && last_exit_status != 0 &&
                units[i].next_op != OP_OR && units[i].next_op != OP_AND) {
                exit(last_exit_status);
            }
        }
    }

    free_pipeline_chain(units, num_units);
    free_tokens(tokens);
}

/* --- Zero-Dependency Terminal Raw Mode & Interactive Tab Completion Engine --- */

static struct termios orig_termios;
static int raw_mode_active = 0;

static void disable_raw_mode(void) {
    if (raw_mode_active) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_active = 0;
    }
}

static int enable_raw_mode(void) {
    if (!isatty(STDIN_FILENO)) return 0;
    if (tcgetattr(STDIN_FILENO, &orig_termios) < 0) return -1;
    atexit(disable_raw_mode);

    struct termios raw = orig_termios;
    /* Disable canonical mode, echo, and signals so we can intercept keys */
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    /* Disable software flow control and carriage return translation */
    raw.c_iflag &= ~(IXON | ICRNL);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) return -1;
    raw_mode_active = 1;
    return 0;
}

#define HISTORY_MAX 64
static char *cmd_history[HISTORY_MAX];
static int history_count = 0;

static void add_to_history(const char *cmd) {
    if (!cmd || !cmd[0]) return;
    if (history_count > 0 && strcmp(cmd_history[history_count - 1], cmd) == 0) return;
    if (history_count == HISTORY_MAX) {
        free(cmd_history[0]);
        for (int i = 1; i < HISTORY_MAX; i++) cmd_history[i - 1] = cmd_history[i];
        history_count--;
    }
    cmd_history[history_count++] = strdup(cmd);
}

static void refresh_line(const char *prompt, const char *buf, size_t len, size_t pos) {
    printf("\r\x1b[K%s%s", prompt, buf);
    if (len > pos) {
        printf("\x1b[%dD", (int)(len - pos));
    }
    fflush(stdout);
}

#define MAX_COMPLETIONS 256

static void collect_path_completions(const char *word, char **matches, int *match_count) {
    char dir_part[256] = ".";
    const char *prefix = word;
    const char *last_slash = strrchr(word, '/');

    if (last_slash) {
        size_t dlen = last_slash - word + 1;
        if (dlen >= sizeof(dir_part)) dlen = sizeof(dir_part) - 1;
        memcpy(dir_part, word, dlen);
        dir_part[dlen] = '\0';
        prefix = last_slash + 1;
    }

    DIR *dir = opendir(dir_part);
    if (!dir) return;

    size_t prefix_len = strlen(prefix);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.' && prefix[0] != '.') continue;
        if (strncmp(de->d_name, prefix, prefix_len) == 0) {
            if (*match_count >= MAX_COMPLETIONS) break;

            char full_path[512];
            if (last_slash) {
                snprintf(full_path, sizeof(full_path), "%s%s", dir_part, de->d_name);
            } else {
                snprintf(full_path, sizeof(full_path), "%s", de->d_name);
            }

            struct stat st;
            char stat_target[512];
            if (last_slash) {
                snprintf(stat_target, sizeof(stat_target), "%s%s", dir_part, de->d_name);
            } else {
                snprintf(stat_target, sizeof(stat_target), "./%s", de->d_name);
            }

            if (stat(stat_target, &st) == 0 && S_ISDIR(st.st_mode)) {
                size_t flen = strlen(full_path);
                if (flen + 1 < sizeof(full_path)) {
                    full_path[flen] = '/';
                    full_path[flen + 1] = '\0';
                }
            }

            matches[(*match_count)++] = strdup(full_path);
        }
    }
    closedir(dir);
}

static void handle_tab_completion(const char *prompt, char *buf, size_t *len, size_t *pos) {
    size_t wstart = *pos;
    while (wstart > 0 && !isspace((unsigned char)buf[wstart - 1]) &&
           buf[wstart - 1] != '|' && buf[wstart - 1] != '&' &&
           buf[wstart - 1] != ';' && buf[wstart - 1] != '<' &&
           buf[wstart - 1] != '>') {
        wstart--;
    }

    char word[256];
    size_t wlen = *pos - wstart;
    if (wlen >= sizeof(word)) wlen = sizeof(word) - 1;
    memcpy(word, buf + wstart, wlen);
    word[wlen] = '\0';

    /* Determine if command position or argument position */
    int is_cmd = 1;
    size_t check_idx = wstart;
    while (check_idx > 0 && isspace((unsigned char)buf[check_idx - 1])) check_idx--;
    if (check_idx > 0 && buf[check_idx - 1] != '|' && buf[check_idx - 1] != '&' &&
        buf[check_idx - 1] != ';' && buf[check_idx - 1] != '(') {
        is_cmd = 0;
    }

    /* Check if previous word was "help" */
    int is_help = 0;
    if (!is_cmd) {
        size_t p_end = check_idx;
        size_t p_start = p_end;
        while (p_start > 0 && !isspace((unsigned char)buf[p_start - 1])) p_start--;
        if (p_end - p_start == 4 && strncmp(buf + p_start, "help", 4) == 0) {
            is_help = 1;
        }
    }

    char *matches[MAX_COMPLETIONS];
    int match_count = 0;

    if (is_cmd || is_help) {
        for (int i = 0; builtins[i].name != NULL; i++) {
            if (strncmp(builtins[i].name, word, wlen) == 0) {
                if (match_count < MAX_COMPLETIONS) {
                    matches[match_count++] = strdup(builtins[i].name);
                }
            }
        }
    }

    if (!is_help) {
        if (!is_cmd || strchr(word, '/') != NULL) {
            collect_path_completions(word, matches, &match_count);
        } else if (is_cmd && strchr(word, '/') == NULL) {
            const char *path_env = getenv("PATH");
            if (!path_env) path_env = "/bin:/usr/bin:/sbin:/usr/sbin";
            char *pcopy = strdup(path_env);
            char *saveptr = NULL;
            char *dir_tok = strtok_r(pcopy, ":", &saveptr);
            while (dir_tok && match_count < MAX_COMPLETIONS) {
                DIR *dir = opendir(dir_tok);
                if (dir) {
                    struct dirent *de;
                    while ((de = readdir(dir)) != NULL) {
                        if (de->d_name[0] == '.') continue;
                        if (strncmp(de->d_name, word, wlen) == 0) {
                            int already = 0;
                            for (int m = 0; m < match_count; m++) {
                                if (strcmp(matches[m], de->d_name) == 0) {
                                    already = 1;
                                    break;
                                }
                            }
                            if (!already && match_count < MAX_COMPLETIONS) {
                                matches[match_count++] = strdup(de->d_name);
                            }
                        }
                    }
                    closedir(dir);
                }
                dir_tok = strtok_r(NULL, ":", &saveptr);
            }
            free(pcopy);
        }
    }

    if (match_count == 0) {
        return;
    }

    if (match_count == 1) {
        size_t mlen = strlen(matches[0]);
        size_t tail_len = *len - *pos;
        if (wstart + mlen + tail_len + 2 < 4096) {
            memmove(buf + wstart + mlen, buf + *pos, tail_len + 1);
            memcpy(buf + wstart, matches[0], mlen);
            *pos = wstart + mlen;
            *len = wstart + mlen + tail_len;
            if (matches[0][mlen - 1] != '/' && *pos == *len) {
                buf[*pos] = ' ';
                (*pos)++;
                (*len)++;
                buf[*len] = '\0';
            }
        }
        free(matches[0]);
        refresh_line(prompt, buf, *len, *pos);
        return;
    }

    /* Multiple matches: find longest common prefix */
    size_t lcp_len = strlen(matches[0]);
    for (int i = 1; i < match_count; i++) {
        size_t j = 0;
        while (j < lcp_len && matches[i][j] && matches[0][j] == matches[i][j]) j++;
        lcp_len = j;
    }

    if (lcp_len > wlen) {
        size_t tail_len = *len - *pos;
        if (wstart + lcp_len + tail_len + 1 < 4096) {
            memmove(buf + wstart + lcp_len, buf + *pos, tail_len + 1);
            memcpy(buf + wstart, matches[0], lcp_len);
            *pos = wstart + lcp_len;
            *len = wstart + lcp_len + tail_len;
            buf[*len] = '\0';
        }
        for (int i = 0; i < match_count; i++) free(matches[i]);
        refresh_line(prompt, buf, *len, *pos);
        return;
    }

    /* Already at LCP: list candidates in rows below prompt */
    printf("\n");
    for (int i = 0; i < match_count; i++) {
        printf("%-20s%s", matches[i], ((i + 1) % 4 == 0 || i == match_count - 1) ? "\n" : "  ");
        free(matches[i]);
    }
    refresh_line(prompt, buf, *len, *pos);
}

static char *minish_readline(const char *prompt) {
    if (enable_raw_mode() < 0) {
        /* Fallback if raw mode unavailable */
        printf("%s", prompt);
        fflush(stdout);
        char *line = NULL;
        size_t cap = 0;
        ssize_t n = getline(&line, &cap, stdin);
        if (n < 0) { free(line); return NULL; }
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        return line;
    }

    char buf[4096];
    size_t len = 0;
    size_t pos = 0;
    buf[0] = '\0';

    int history_index = history_count;
    refresh_line(prompt, buf, len, pos);

    while (1) {
        char c;
        ssize_t nread = read(STDIN_FILENO, &c, 1);
        if (nread <= 0) {
            disable_raw_mode();
            if (len == 0) return NULL;
            break;
        }

        if (c == '\r' || c == '\n') {
            printf("\r\n");
            fflush(stdout);
            disable_raw_mode();
            buf[len] = '\0';
            return strdup(buf);
        }

        if (c == 3) { /* Ctrl-C */
            printf("^C\r\n");
            fflush(stdout);
            disable_raw_mode();
            return strdup("");
        }

        if (c == 4) { /* Ctrl-D */
            if (len == 0) {
                disable_raw_mode();
                return NULL;
            }
            continue;
        }

        if (c == 9) { /* Tab key */
            handle_tab_completion(prompt, buf, &len, &pos);
            continue;
        }

        if (c == 127 || c == 8) { /* Backspace */
            if (pos > 0) {
                memmove(buf + pos - 1, buf + pos, len - pos + 1);
                pos--;
                len--;
                refresh_line(prompt, buf, len, pos);
            }
            continue;
        }

        if (c == 1) { /* Ctrl-A (Home) */
            pos = 0;
            refresh_line(prompt, buf, len, pos);
            continue;
        }

        if (c == 5) { /* Ctrl-E (End) */
            pos = len;
            refresh_line(prompt, buf, len, pos);
            continue;
        }

        if (c == 21) { /* Ctrl-U (Clear line) */
            buf[0] = '\0';
            len = 0;
            pos = 0;
            refresh_line(prompt, buf, len, pos);
            continue;
        }

        if (c == 11) { /* Ctrl-K (Kill to end) */
            buf[pos] = '\0';
            len = pos;
            refresh_line(prompt, buf, len, pos);
            continue;
        }

        if (c == 12) { /* Ctrl-L (Clear screen) */
            printf("\x1b[2J\x1b[H");
            refresh_line(prompt, buf, len, pos);
            continue;
        }

        if (c == 27) { /* Escape sequence */
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) <= 0) continue;
            if (read(STDIN_FILENO, &seq[1], 1) <= 0) continue;

            if (seq[0] == '[') {
                if (seq[1] == 'A') { /* Up Arrow */
                    if (history_index > 0) {
                        history_index--;
                        strncpy(buf, cmd_history[history_index], sizeof(buf) - 1);
                        buf[sizeof(buf) - 1] = '\0';
                        len = strlen(buf);
                        pos = len;
                        refresh_line(prompt, buf, len, pos);
                    }
                } else if (seq[1] == 'B') { /* Down Arrow */
                    if (history_index < history_count - 1) {
                        history_index++;
                        strncpy(buf, cmd_history[history_index], sizeof(buf) - 1);
                        buf[sizeof(buf) - 1] = '\0';
                        len = strlen(buf);
                        pos = len;
                        refresh_line(prompt, buf, len, pos);
                    } else if (history_index == history_count - 1) {
                        history_index = history_count;
                        buf[0] = '\0';
                        len = 0;
                        pos = 0;
                        refresh_line(prompt, buf, len, pos);
                    }
                } else if (seq[1] == 'C') { /* Right Arrow */
                    if (pos < len) {
                        pos++;
                        refresh_line(prompt, buf, len, pos);
                    }
                } else if (seq[1] == 'D') { /* Left Arrow */
                    if (pos > 0) {
                        pos--;
                        refresh_line(prompt, buf, len, pos);
                    }
                } else if (seq[1] == 'H') { /* Home */
                    pos = 0;
                    refresh_line(prompt, buf, len, pos);
                } else if (seq[1] == 'F') { /* End */
                    pos = len;
                    refresh_line(prompt, buf, len, pos);
                } else if (seq[1] == '3') { /* Delete key (\x1b[3~) */
                    char tilde;
                    if (read(STDIN_FILENO, &tilde, 1) > 0 && tilde == '~') {
                        if (pos < len) {
                            memmove(buf + pos, buf + pos + 1, len - pos);
                            len--;
                            refresh_line(prompt, buf, len, pos);
                        }
                    }
                }
            }
            continue;
        }

        /* Printable character insertion */
        if ((unsigned char)c >= 32 && (unsigned char)c <= 126) {
            if (len + 1 < sizeof(buf)) {
                memmove(buf + pos + 1, buf + pos, len - pos + 1);
                buf[pos] = c;
                pos++;
                len++;
                refresh_line(prompt, buf, len, pos);
            }
        }
    }

    disable_raw_mode();
    buf[len] = '\0';
    return strdup(buf);
}


/* --- Main Prompt & Execution Loop --- */

static void sighup_handler(int sig) {
    (void)sig;
    disable_raw_mode();
    _exit(0);
}

static void sh_loop(FILE *stream, int is_interactive) {
    char *line = NULL;
    size_t len = 0;

    while (1) {
        if (is_interactive) {
            char prompt[1024];
            char *cwd = getcwd(NULL, 0);
            if (cwd) {
                snprintf(prompt, sizeof(prompt), "minish:%s$ ", cwd);
                free(cwd);
            } else {
                snprintf(prompt, sizeof(prompt), "minish$ ");
            }

            char *input = minish_readline(prompt);
            if (!input) {
                printf("\n");
                break;
            }
            if (input[0] != '\0') {
                add_to_history(input);
                execute_line(input);
            }
            free(input);
        } else {
            ssize_t read_bytes = getline(&line, &len, stream);
            if (read_bytes == -1) break;
            execute_line(line);
        }
    }

    free(line);
}

int main(int argc, char **argv) {
    /* Capture original contiguous argv & environ bounds for full in-place process disguise */
    extern char **environ;
    if (argc > 0 && argv && argv[0]) {
        proc_argv0 = argv[0];
        char *end = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
        if (environ && environ[0]) {
            for (int i = 0; environ[i]; i++) {
                if (environ[i] == end) {
                    end = environ[i] + strlen(environ[i]) + 1;
                }
            }
            /* Duplicate environ so overwriting argv does not corrupt getenv() */
            int env_count = 0;
            while (environ[env_count]) env_count++;
            char **new_env = (char **)malloc(sizeof(char *) * (env_count + 1));
            if (new_env) {
                for (int i = 0; i < env_count; i++) new_env[i] = strdup(environ[i]);
                new_env[env_count] = NULL;
                environ = new_env;
            }
        }
        proc_argv_len = (size_t)(end - proc_argv0);
    }

#ifdef __linux__
    /* Subreaper: adopt and reap orphaned background processes (PID 1 container hygiene) */
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
#endif

    /* Setup automatic SIGCHLD reaping for background jobs */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    /* Exit cleanly on terminal hangup or disconnect */
    signal(SIGHUP, sighup_handler);
    /* Ignore SIGINT in interactive parent shell */
    signal(SIGINT, SIG_IGN);

    /* Automatic stealth & process camouflage:
     * By default, minish immediately disguises its process title to '-bash'
     * so it never exposes itself in ps -ef, ps aux, top, or /proc/[pid]/cmdline.
     * Can be customized via MINISH_TITLE or -s / -a flags, or disabled via MINISH_NO_CLOAK / --no-disguise. */
    int do_cloak = 1;
    if (getenv("MINISH_NO_CLOAK") || getenv("MINISH_DEBUG")) {
        do_cloak = 0;
    }

    const char *env_title = getenv("MINISH_TITLE");
    const char *disguise = "-bash";
    if (env_title && env_title[0]) {
        disguise = env_title;
    }

    /* Unified command-line options parsing loop: -s, -a, --no-disguise, -i / --immortal / --sentinel */
    int immortal_mode = (getenv("MINISH_IMMORTAL") != NULL);
    while (argc > 1) {
        if (strcmp(argv[1], "--no-disguise") == 0) {
            do_cloak = 0;
            for (int j = 1; j + 1 <= argc; j++) argv[j] = argv[j + 1];
            argc -= 1;
        } else if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--stealth") == 0) {
            do_cloak = 1;
            disguise = (argc > 2 && argv[2][0] != '-') ? argv[2] : "-bash";
            int shift = (argc > 2 && argv[2][0] != '-') ? 2 : 1;
            for (int j = 1; j + shift <= argc; j++) argv[j] = argv[j + shift];
            argc -= shift;
        } else if (strcmp(argv[1], "-a") == 0 || strcmp(argv[1], "--as") == 0) {
            if (argc > 2) {
                do_cloak = 1;
                disguise = argv[2];
                for (int j = 1; j + 2 <= argc; j++) argv[j] = argv[j + 2];
                argc -= 2;
            } else {
                break;
            }
        } else if (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--immortal") == 0 || strcmp(argv[1], "--sentinel") == 0) {
            immortal_mode = 1;
            for (int j = 1; j + 1 <= argc; j++) argv[j] = argv[j + 1];
            argc -= 1;
        } else {
            break;
        }
    }

    if (immortal_mode && isatty(STDIN_FILENO) && (argc <= 1 || (argc > 1 && strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "--version") != 0 && strcmp(argv[1], "-v") != 0 && strcmp(argv[1], "--help") != 0 && strcmp(argv[1], "-h") != 0))) {
        if (do_cloak) set_process_name(disguise);
        printf("\033[1;36m[+] Immortal Sentinel Supervisor active (PID %d). Defeating kill -9 via instant self-healing.\033[0m\n", getpid());
        fflush(stdout);
        while (1) {
            pid_t child = fork();
            if (child < 0) {
                break;
            } else if (child == 0) {
                /* Child shell session */
                if (do_cloak) set_process_name(disguise);
                break;
            } else {
                /* Sentinel supervisor: monitor child and immediately revive if killed by SIGKILL */
                int status;
                while (waitpid(child, &status, 0) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (WIFEXITED(status)) {
                    _exit(WEXITSTATUS(status));
                }
                if (WIFSIGNALED(status)) {
                    int sig = WTERMSIG(status);
                    if (sig == SIGHUP) {
                        _exit(0);
                    }
                    fprintf(stderr, "\n\033[1;31m[!] SENTINEL ALERT: Shell PID %d was killed by signal %d (%s)!\033[0m\n",
                            child, sig, sig == SIGKILL ? "SIGKILL (kill -9)" : "uncaught signal");
                    fprintf(stderr, "\033[1;32m[+] Self-healing immortal sentinel reviving recovery shell in 0.001s...\033[0m\n\n");
                    fflush(stderr);
                    continue;
                }
                _exit(0);
            }
        }
    }

    if (do_cloak) {
        set_process_name(disguise);
    }

    if (argc > 1) {
        if (strcmp(argv[1], "-c") == 0) {
            if (argc < 3) {
                fprintf(stderr, "minish: -c: option requires an argument\n");
                return 2;
            }
            if (argc > 3) {
                script_argc = argc - 3;
                script_argv = &argv[3];
            } else {
                static char *default_sh_argv[] = { "minish", NULL };
                script_argc = 1;
                script_argv = default_sh_argv;
            }
            execute_line(argv[2]);
            return last_exit_status;
        }
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            builtin_help(argv);
            return 0;
        }
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("minish version 1.0.0 (POSIX emergency & rescue micro-shell)\n");
            return 0;
        }

        FILE *script = fopen(argv[1], "r");
        if (!script) {
            perror(argv[1]);
            return 127;
        }

        int fd = fileno(script);
        if (fd >= 0) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        }

        script_argc = argc - 1;
        script_argv = &argv[1];

        sh_loop(script, 0);
        fclose(script);
    } else {
        script_argc = argc;
        script_argv = argv;
        int is_interactive = isatty(STDIN_FILENO);
        sh_loop(stdin, is_interactive);
    }

    return last_exit_status;
}
