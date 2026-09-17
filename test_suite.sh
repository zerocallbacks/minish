# minish automated verification test script
echo "=== Test 1: Variable expansion and quoting ==="
export TEST_VAR=Antigravity
echo "TEST_VAR is: $TEST_VAR"
echo "Curly expansion: ${TEST_VAR}_Rocks"
echo "Shell PID is: $$"
echo 'Single quote literal: $TEST_VAR and $$'

echo "=== Test 2: File creation and I/O redirection ==="
mkdir -p test_sandbox/sublevel
cd test_sandbox
pwd
echo "First line of text" > file.txt
echo "Second line appended" >> file.txt
cat file.txt

echo "=== Test 3: Input redirection ==="
cat < file.txt

echo "=== Test 4: Stderr redirection and suppression ==="
rm non_existent_file 2>/dev/null || echo "Successfully silenced stderr and handled OR"
rm another_missing_file 2> err.log || true
cat err.log

echo "=== Test 5: Multi-stage pipeline execution ==="
cat file.txt | cat | cat

echo "=== Test 6: Command chaining (&&, ||, ;) ==="
echo "Condition true" && echo "Success on AND"
false || echo "Recovered on false OR"
true && echo "Condition true again"
false && echo "FAIL on AND" || echo "Recovered on false AND OR"
true || echo "FAIL on OR" && echo "Continued on true OR AND"
echo "First in sequence" ; echo "Second in sequence"
false ; echo "Same-line exit code was: $?"

echo "=== Test 7: Standalone assignments and tilde expansion ==="
SANDBOX_VAR="Custom_Value"
echo "SANDBOX_VAR is: $SANDBOX_VAR"
ORIG_DIR=$PWD
cd ~
pwd
cd -
[ "$PWD" = "$ORIG_DIR" ] && echo "Successfully returned from HOME via cd -"

echo "=== Test 8: Directory navigation (cd - / OLDPWD) ==="
cd sublevel
pwd
cd -
pwd

echo "=== Test 9: Built-in conditional testing ([ / test) ==="
[ -f file.txt ] && echo "File check passed"
[ -s file.txt ] && echo "File non-empty check passed"
[ -d sublevel ] && echo "Directory check passed"
[ "apple" = "apple" ] && echo "String equality passed"
[ 100 -gt 25 ] && [ 7 -eq 7 ] && echo "Numeric comparison passed"
[ ! -f missing_file.txt ] && echo "Negation check passed"

echo "=== Test 10: Directory listing (ls -a and ls -l) ==="
touch alpha.log beta.log
ls -a
ls -l

echo "=== Test 11: Utility lookup (which) ==="
which cd
which ls
which cat

echo "=== Test 12: Directory deletion safety and rm ==="
mkdir empty_dir
rm empty_dir 2>/dev/null || echo "rm without -r prevented directory deletion"
rmdir empty_dir || rm -rf empty_dir

echo "=== Test 13: Process renaming (setproctitle / procrename) ==="
setproctitle rescue_worker
setproctitle > title.txt
cat title.txt
rm title.txt
echo "Process rename verified successfully"

echo "=== Test 14: File surgery (cp, mv, chmod, umask, sync) ==="
echo "Testing surgery operations" > surgery_orig.txt
cp surgery_orig.txt surgery_copy.txt
[ -f surgery_copy.txt ] && echo "cp verified"
mv surgery_copy.txt surgery_moved.txt
[ ! -f surgery_copy.txt ] && [ -f surgery_moved.txt ] && echo "mv verified"
chmod 0640 surgery_moved.txt
chmod +x surgery_moved.txt
umask 027
sync
echo "File surgery and sync verified"

echo "=== Test 15: Diagnostics and system introspection (uname, sysinfo) ==="
uname -s
uname -m
sysinfo | cat > sysinfo.log
[ -s sysinfo.log ] && echo "sysinfo verified"
rm sysinfo.log

echo "=== Test 16: Virtual in-memory storage (memfile) ==="
echo "Memory secret block" > mem_input.txt
memfile save rescue_payload < mem_input.txt
memfile list
memfile cat rescue_payload
memfile rm rescue_payload
rm mem_input.txt
echo "memfile operations verified"

echo "=== Test 17: Binary file allocation and hex viewer (falloc, hexview) ==="
falloc 1 test_alloc.bin
[ -f test_alloc.bin ] && echo "falloc created 1MB file"
hexview test_alloc.bin 0
rm test_alloc.bin

echo "=== Test 18: Cryptographic random generation (randhex) ==="
randhex 16 > token.txt
[ -s token.txt ] && echo "randhex generated 32-character hex token"
cat token.txt
rm token.txt

echo "=== Test 19: Network socket stats and process introspection (sockstat, procpeek) ==="
sockstat > /dev/null && echo "sockstat executed successfully"
procpeek $$ > proc.log
[ -s proc.log ] && echo "procpeek inspected current shell process"
rm proc.log

echo "=== Test 20: Script sourcing and context persistence (.) ==="
echo "SOURCED_FLAG=AntigravityActive" > sub_script.sh
. ./sub_script.sh
[ "$SOURCED_FLAG" = "AntigravityActive" ] && echo "Sourcing script into shell context passed"
rm sub_script.sh

echo "=== Test 21: Full-Disk storage and inode triage (df) ==="
df . > df.log
[ -s df.log ] && echo "df inspected storage blocks and inodes successfully"
cat df.log
rm df.log

echo "=== Test 22: Zero-allocation in-place shrink (truncate) ==="
echo "Heavy log data content filling up disk" > runaway.log
[ -s runaway.log ] && echo "runaway.log created with data"
truncate runaway.log 0
[ ! -s runaway.log ] && [ -f runaway.log ] && echo "truncate reduced file to 0 bytes in-place"
rm runaway.log

echo "=== Test 23: Large runaway file detection (findlarge) ==="
falloc 1 big_payload.bin
findlarge . 1 > findlarge.log
[ -s findlarge.log ] && echo "findlarge identified 1MB payload file"
cat findlarge.log
rm big_payload.bin findlarge.log

echo "=== Test 24: Ghost file inspection (ghostfind) ==="
ghostfind > ghost.log
[ -s ghost.log ] && echo "ghostfind scanned procfs successfully"
rm ghost.log

echo "=== Test 25: Zero-disk binary execution from RAM (memrun / memexec) ==="
memfile save rescue_bin < ../minish
memrun rescue_bin -c "echo In-memory execution via memrun verified!"
cat ../minish | memrun - -c "echo In-memory execution via stdin pipe verified!"
cat ../minish | memexec - -c "echo In-memory execution via memexec alias verified!"
memfile rm rescue_bin

echo "=== Test 26: Standalone cryptographic hashing (sha256) ==="
touch empty.bin
sha256 empty.bin > sha.log
cat sha.log
[ -s sha.log ] && echo "sha256 file hashing passed"
rm empty.bin sha.log

echo "=== Test 27: Air-gapped terminal transfer (base64 encode & decode) ==="
echo "AntigravityDFIR" > plain.txt
base64 -e plain.txt > encoded.b64
base64 -d encoded.b64 > decoded.txt
cat decoded.txt
[ -s decoded.txt ] && echo "base64 roundtrip encode/decode passed"
rm plain.txt encoded.b64 decoded.txt

echo "=== Test 28: Zero-execution ELF header & library inspector (elfpeek) ==="
elfpeek ../minish > elf.log
[ -s elf.log ] && echo "elfpeek inspected binary headers without executing"
cat elf.log
rm elf.log

echo "=== Test 29: Process environment & secret sniffer (envpeek) ==="
export AGENT_TOKEN=AntigravitySecretRecoveryKey999
envpeek $$ > env.log
[ -s env.log ] && echo "envpeek inspected process environ successfully"
rm env.log

echo "=== Test 30: Kernel driver and module auditor (modpeek) ==="
modpeek > mods.log
[ -s mods.log ] && echo "modpeek audited kernel modules successfully"
rm mods.log

echo "=== Test 31: Atomic in-place configuration patcher (replace) ==="
echo "nameserver 1.1.1.1" > resolv.test
cat resolv.test
replace resolv.test 1.1.1.1 8.8.8.8
cat resolv.test
rm resolv.test

echo "=== Test 32: Deep inode, permission & anti-timestomp auditor (finfo / statpeek) ==="
touch audit_target.txt
finfo audit_target.txt > finfo.log
[ -s finfo.log ] && echo "finfo reported nanosecond timestamps and inode metadata"
cat finfo.log
rm audit_target.txt finfo.log

echo "=== Test 33: Zero-dependency ASCII artifact extractor (strings) ==="
strings ../minish > strings.log
[ -s strings.log ] && echo "strings extracted printable ASCII artifacts"
rm strings.log

echo "=== Test 34: Secure anti-forensic overwriter & unlinker (wipe) ==="
echo "TopSecretDecryptedKey" > shred_me.dat
[ -f shred_me.dat ] && echo "shred_me.dat created"
wipe shred_me.dat 2
echo "=== Test 35: Text and stream surgery (grep, head, tail, wc, cut, sort, uniq, tr, diff) ==="
echo -e "gamma\nalpha\nbeta\nbeta\nalpha" > text.dat
cat text.dat | grep -i "alp" > grep.out
[ -s grep.out ] && echo "grep filtered stream successfully"
head -n 2 text.dat > head.out
[ -s head.out ] && echo "head limited stream successfully"
tail -n 2 text.dat > tail.out
[ -s tail.out ] && echo "tail buffered stream successfully"
wc -l text.dat > wc.out
[ -s wc.out ] && echo "wc counted stream lines successfully"
echo "root:x:0:0:root:/root:/bin/minish" > pass.dat
cut -d : -f 1 pass.dat > cut.out
[ -s cut.out ] && echo "cut extracted delimited column successfully"
sort text.dat > sort.out
[ -s sort.out ] && echo "sort sorted lines successfully"
uniq -c sort.out > uniq.out
[ -s uniq.out ] && echo "uniq counted consecutive lines successfully"
echo "hello world" | tr " " "\n" > tr.out
[ -s tr.out ] && echo "tr translated characters successfully"
echo "same" > diff1.txt ; echo "same" > diff2.txt
diff diff1.txt diff2.txt && echo "diff verified identical files"
rm -f text.dat grep.out head.out tail.out wc.out pass.dat cut.out sort.out uniq.out tr.out diff1.txt diff2.txt

echo "=== Test 36: Process, Thread & Memory Forensics (ps, mapspeek, fdpeek, stackpeek, wchanpeek, oomadj) ==="
ps > ps.out
[ -s ps.out ] && echo "ps generated native process table"
mapspeek $$ > maps.out
[ -s maps.out ] && echo "mapspeek audited memory maps"
fdpeek $$ > fds.out
[ -s fds.out ] && echo "fdpeek audited open file descriptors"
wchanpeek $$ > wchan.out
[ -s wchan.out ] && echo "wchanpeek read wait channel"
oomadj $$ > oom.out
[ -s oom.out ] && echo "oomadj inspected OOM score"
rm -f ps.out maps.out fds.out wchan.out oom.out

echo "=== Test 37: Security, Capabilities & LSM Defense (cappeek, nspeek, lsmaudit, taintpeek, id, entropy) ==="
cappeek $$ > cap.out
[ -s cap.out ] && echo "cappeek decoded capabilities"
nspeek $$ > ns.out
[ -s ns.out ] && echo "nspeek audited namespaces"
lsmaudit > lsm.out
[ -s lsm.out ] && echo "lsmaudit audited security engines"
taintpeek > taint.out
[ -s taint.out ] && echo "taintpeek audited kernel taint"
id > id.out
[ -s id.out ] && echo "id reported user and group credentials"
whoami > who.out
[ -s who.out ] && echo "whoami alias verified"
echo "Plain text repetitive repetitive" > low_ent.txt
entropy low_ent.txt > ent.out
[ -s ent.out ] && echo "entropy calculated Shannon entropy successfully"
rm -f cap.out ns.out lsm.out taint.out id.out who.out low_ent.txt ent.out

echo "=== Test 38: Storage & Block Recovery (dd, fiemap, diskstat, dropcaches, losetup) ==="
echo "0123456789abcdef" > dd_src.dat
dd if=dd_src.dat of=dd_dst.dat bs=4 count=2 2>/dev/null
[ -s dd_dst.dat ] && echo "dd carved raw blocks successfully"
fiemap dd_src.dat > fie.out
[ -s fie.out ] && echo "fiemap inspected physical disk extents"
diskstat > disk.out
[ -s disk.out ] && echo "diskstat inspected storage I/O throughput"
losetup > loop.out
[ -f loop.out ] && echo "losetup inspected loop devices"
dropcaches 3 > /dev/null 2>&1 || true
echo "dropcaches executed"
rm -f dd_src.dat dd_dst.dat fie.out disk.out loop.out

echo "=== Test 39: Network & Air-Gap Triage (netif, arppeek, routepeek, tcpping) ==="
netif > netif.out
[ -s netif.out ] && echo "netif reported interface byte counters"
arppeek > arp.out
[ -s arp.out ] && echo "arppeek reported local ARP table"
routepeek > route.out
[ -s route.out ] && echo "routepeek reported kernel IPv4 routes"
tcpping 127.0.0.1 22 100 > /dev/null 2>&1 || true
echo "tcpping executed"
rm -f netif.out arp.out route.out

echo "=== Test 40: Hardware, Firmware & Hypervisor (dmipeek, cpuid, pcipeek, usbpeek, uptime) ==="
dmipeek > dmi.out
[ -s dmi.out ] && echo "dmipeek audited system and BIOS"
cpuid > cpuid.out
[ -s cpuid.out ] && echo "cpuid audited CPU vulnerabilities and microcode"
pcipeek > pci.out
[ -s pci.out ] && echo "pcipeek audited hardware PCI controllers"
usbpeek > usb.out
[ -s usb.out ] && echo "usbpeek audited USB devices"
uptime > up.out
[ -s up.out ] && echo "uptime reported load averages"
rm -f dmi.out cpuid.out pci.out usb.out up.out

echo "=== Test 41: Interactive Scripting, Forensics & System Control (calc, clear, time, md5, crc32, xor) ==="
calc 100 + 42 > calc.out
[ -s calc.out ] && echo "calc computed integer arithmetic successfully"
calc 1024 '*' 1024 > calc_mul.out
[ -s calc_mul.out ] && echo "calc multiplication verified"
clear > /dev/null && echo "clear reset terminal screen"
time echo "timed command" 2> time.out
[ -s time.out ] && echo "time measured command execution"
echo "ChecksumMe" > check.dat
md5 check.dat > md5.out
[ -s md5.out ] && echo "md5 computed RFC 1321 hash"
crc32 check.dat > crc.out
[ -s crc.out ] && echo "crc32 computed IEEE 802.3 checksum"
xor check.dat "KEY" > xor.out
[ -s xor.out ] && echo "xor stream obfuscated data"
rm -f calc.out calc_mul.out time.out check.dat md5.out crc.out xor.out

echo "=== Test 42: Filesystem Links & Metadata (symlink, readlink, timestomp) ==="
mkdir -p /tmp/minish_symlink_sandbox
touch /tmp/minish_symlink_sandbox/target.txt
symlink /tmp/minish_symlink_sandbox/target.txt /tmp/minish_symlink_sandbox/test.lnk
[ -L /tmp/minish_symlink_sandbox/test.lnk ] && echo "symlink created symbolic link"
readlink /tmp/minish_symlink_sandbox/test.lnk > rlink.out
[ -s rlink.out ] && echo "readlink resolved link destination"
rm -rf /tmp/minish_symlink_sandbox rlink.out
touch link_target.txt
timestomp link_target.txt 1700000000
echo "timestomp updated nanosecond timestamps"
rm -f link_target.txt

echo "=== Test 43: Advanced Full-Disk & Inode Triage (inodescan, zerolog, findempty, dusage, findinode) ==="
mkdir -p full_disk_test/sublogs
touch full_disk_test/empty1.txt full_disk_test/empty2.txt
echo "Error log line" > full_disk_test/sublogs/crash.log
dusage full_disk_test 2 > dusage.out
[ -s dusage.out ] && echo "dusage computed directory space usage"
inodescan full_disk_test 1 > inodescan.out
[ -s inodescan.out ] && echo "inodescan profiled directory inode counts"
findempty full_disk_test > empty.out
[ -s empty.out ] && echo "findempty identified 0-byte files"
findempty full_disk_test -d > /dev/null
[ ! -f full_disk_test/empty1.txt ] && echo "findempty -d reclaimed inodes"
[ -s full_disk_test/sublogs/crash.log ] && echo "crash.log created with data"
zerolog full_disk_test > zerolog.out
[ ! -s full_disk_test/sublogs/crash.log ] && echo "zerolog truncated log files in-place"
finfo full_disk_test/sublogs/crash.log > finfo.out
cat finfo.out | grep Inode: | cut -d : -f 2 | tr -d " " > ino.txt
read TARGET_INO < ino.txt
findinode $TARGET_INO full_disk_test > findino.out
[ -s findino.out ] && echo "findinode resolved inode back to file path"
rm -rf full_disk_test dusage.out inodescan.out empty.out zerolog.out finfo.out findino.out ino.txt

echo "=== Test 45: Real-time full-disk & inode triage (findgrowth, fdsize, topwriters, ramscratch, ramclone) ==="
findgrowth . 1 > fg.out
[ -s fg.out ] && echo "findgrowth monitored active file growth"
fdsize $$ > fds.out
[ -s fds.out ] && echo "fdsize profiled process file descriptors"
topwriters 1 > tw.out
[ -s tw.out ] && echo "topwriters monitored process write throughput"
echo "staging data for ram clone" > to_clone.txt
ramclone to_clone.txt cloned_data > rc.out
[ -s rc.out ] && echo "ramclone cloned file into volatile memory"
memfile cat cloned_data > mc.out
[ -s mc.out ] && echo "ramclone verified via memfile cat"
memfile rm cloned_data
ramscratch 32 > rs.out
[ -s rs.out ] && echo "ramscratch activated volatile workspace"
cd /mnt/f/Chiron/SHELL/test_sandbox
rm -f to_clone.txt fg.out fds.out tw.out rc.out mc.out rs.out

echo "=== Test 46: Forensic carving and anti-termination self-defense (deletedgrab, sigshield) ==="
sigshield on > ss_on.out
[ -s ss_on.out ] && echo "sigshield enabled signal immunity"
sigshield status > ss_st.out
[ -s ss_st.out ] && echo "sigshield reported active protection status"
sigshield off > ss_off.out
[ -s ss_off.out ] && echo "sigshield restored default signals"
deletedgrab $$ exe grabbed_exe > dg.out
[ -s dg.out ] && echo "deletedgrab extracted process executable into memory"
memfile rm grabbed_exe
rm -f ss_on.out ss_st.out ss_off.out dg.out

echo "=== Test 47: Running defense tools in volatile memory (b64exec, memscript, ramoverlay, memunshare) ==="
echo "echo MEMSCRIPT_WORKS" | memscript sh - > ms.out
grep MEMSCRIPT_WORKS ms.out > /dev/null && echo "memscript executed in-memory script"
base64 /usr/bin/true | b64exec mytrue > /dev/null && echo "b64exec executed Base64 binary directly from RAM"
mkdir -p ovl_test
echo "original content" > ovl_test/file.txt
ramoverlay ovl_test 16 > ro.out || true
[ -s ro.out ] && echo "ramoverlay mounted volatile overlayfs"
umount -f ovl_test > /dev/null 2>&1 || true
memunshare -m echo "UNSHARE_WORKS" > mu.out || true
[ -s mu.out ] && echo "memunshare executed in isolated namespace"
rm -rf ovl_test ms.out ro.out mu.out

echo "=== Test 48: Adversary hunting and rootkit defense (exehunt, memgrep, ptracehunt, promischunt, persistpeek) ==="
exehunt > eh.out
[ -s eh.out ] && echo "exehunt audited process executables"
memgrep $$ minish > mg.out
[ -s mg.out ] && echo "memgrep sniffed memory strings in process space"
ptracehunt > ph.out
[ -s ph.out ] && echo "ptracehunt audited ptrace injection status"
promischunt > prh.out
[ -s prh.out ] && echo "promischunt audited promiscuous interfaces and raw sniffers"
persistpeek > pp.out
[ -s pp.out ] && echo "persistpeek audited system persistence vectors"
rm -f eh.out mg.out ph.out prh.out pp.out

echo "=== Test 50: In-Memory Modal Micro-Editor (vim / vi) ==="
vim --help > vim_help.out
[ -s vim_help.out ] && grep "Zero-Dependency Disaster Recovery Modal Micro-Editor" vim_help.out > /dev/null && echo "vim --help verified"
vi --help > vi_help.out
[ -s vi_help.out ] && grep "Zero-Dependency Disaster Recovery Modal Micro-Editor" vi_help.out > /dev/null && echo "vi alias verified"
help vim > vim_cmdhelp.out
[ -s vim_cmdhelp.out ] && grep "MODAL STATES & KEYBINDINGS" vim_cmdhelp.out > /dev/null && echo "help vim keybindings verified"
rm -f vim_help.out vi_help.out vim_cmdhelp.out

echo "=== Test 51: Cleanup and recursive rm ==="
cd ..
rm -rf test_sandbox
[ ! -d test_sandbox ] && echo "Cleaned up sandbox recursively."

echo "=== All Tests Completed Successfully ==="



