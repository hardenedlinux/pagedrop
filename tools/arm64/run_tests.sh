#!/bin/bash
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
fail=0

say() { printf '\n===== %s =====\n' "$1"; }
mark() {
	if [ "$1" -eq 0 ]; then
		echo "PASS $2"
	else
		echo "FAIL $2"
		fail=1
	fi
}

# Every test needs a fresh module with its own parameters. A pinned module
# makes rmmod fail for a moment, and an unchecked insmod would then fail with
# EEXIST and leave the previous module, with the previous path= and data=,
# under the test. Retry the unload and stop the suite if either step fails.
unload() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		grep -q '^pagedrop ' /proc/modules || return 0
		sudo rmmod pagedrop 2>/dev/null && return 0
		sleep 1
	done
	echo "rmmod pagedrop: still loaded after 10 tries"
	exit 1
}
load() {
	sudo insmod ./pagedrop.ko "$@" && return 0
	echo "insmod pagedrop.ko $*: failed"
	exit 1
}

unload
make clean >/dev/null
make
gcc -O0 -Wall -o userland/c/capture userland/c/capture.c -pthread
gcc -O0 -o userland/c/sigsegv.out userland/c/sigsegv.c
gcc -O0 -o userland/c/simple userland/c/simple.c
gcc -O0 -Wall -o userland/c/extra userland/c/extra.c
gcc -static -no-pie -O0 -o /tmp/upxtest.orig userland/c/upxtest.c
rm -f /tmp/upxtest
upx -q -o /tmp/upxtest /tmp/upxtest.orig
gcc -O0 -o /tmp/pb_check tools/x86/pb_check.c
gcc -O0 -o /tmp/pb_addr tools/x86/pb_addr.c
python3 tools/test_pb_rank.py
mark $? pb_rank

say "hooks"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=simple
hooks=$(sudo dmesg | grep 'pagedrop: hooked' | tail -13)
	echo "$hooks"
	missing=0
	for n in mprotect pkey_mprotect mremap munmap vm_mmap_pgoff execve execveat fork vfork clone clone3 exit_files force_sig_fault; do
	echo "$hooks" | grep -q "$n" || { echo "missing hook $n"; missing=1; }
done
mark "$missing" "hooks"

say "simple"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
text=$(python3 - << 'PY'
import struct
data=open("userland/c/simple","rb").read()
e_shoff,=struct.unpack_from("<Q", data, 40)
entsize,shnum,shstr=struct.unpack_from("<HHH", data, 58)
def sh(i):
    return struct.unpack_from("<IIQQQQIIQQ", data, e_shoff+i*entsize)
soff=sh(shstr)[4]
for i in range(shnum):
    s=sh(i)
    name=data[soff+s[0]:].split(b"\0",1)[0]
    if name==b".text":
        print(data[s[4]:s[4]+16].hex())
        break
PY
)
sudo /tmp/pb_check "$text" ./userland/c/simple
mark "$?" "simple"

say "sigsegv"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=sigsegv
sudo PB_WANT_ADDR=100000000 /tmp/pb_check 204284d26086a8f2a0caccf2e00ef1f2c0035fd6 ./userland/c/sigsegv.out
mark "$?" "sigsegv live"
python3 - << 'PY'
import glob
sc=bytes.fromhex("204284d26086a8f2a0caccf2e00ef1f2c0035fd6")
nop=bytes.fromhex("1f2003d5") * 4
ok=any(sc in open(f,"rb").read() and open(f,"rb").read(16)==nop for f in glob.glob("/tmp/100000000_*"))
print("sigsegv file", "ok" if ok else "BAD")
raise SystemExit(0 if ok else 1)
PY
mark "$?" "sigsegv file"

say "capture"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=capture
./userland/c/capture
mark "$?" "capture"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo /tmp/pb_addr ./userland/c/capture
mark "$?" "capture mremap"

say "epoch"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra epoch
mark "$?" "epoch"

say "exact"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extr exact=1
./userland/c/extra epoch
if [ $? -eq 0 ]; then
	mark 1 "exact"
else
	unload
	sudo rm -f /tmp/[0-9a-f]*_[0-9]*
	load path=extra exact=1
	./userland/c/extra epoch
	mark $? "exact"
fi

say "flip"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra flip
mark "$?" "flip"

say "regs"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra regs
mark "$?" "regs"

say "commname"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra
./userland/c/extra commname
mark "$?" "commname"
python3 - << 'PY'
ok = False
for line in open("/tmp/pagedrop.index"):
    p = line.split()
    if len(p) != 5:
        raise SystemExit("bad index line %r" % line)
    if p[1] == "ex_tra_x" and p[4] == "mprotect":
        ok = True
raise SystemExit(0 if ok else 1)
PY
mark "$?" "index commname"

say "read"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra read
mark "$?" "read"
python3 - << 'PY'
ok = False
for line in open("/tmp/pagedrop.index"):
    p = line.split()
    if len(p) == 5 and p[1] == "extra" and p[2] == "260000000" and p[4] == "read":
        int(p[0])
        int(p[3])
        ok = True
        break
raise SystemExit(0 if ok else 1)
PY
mark "$?" "index read"

say "forkread"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra forkread
mark "$?" "forkread"

say "forkrace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra forkrace
mark "$?" "forkrace"

say "dumprace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra dumprace
mark "$?" "dumprace"

say "armrace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra armrace
mark "$?" "armrace"

say "mremaprace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260010000
./userland/c/extra mremaprace
mark "$?" "mremaprace"

say "datarace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra datarace
mark "$?" "datarace"

say "munmaprace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra munmaprace
mark "$?" "munmaprace"

say "clonevm"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra clonevm
mark "$?" "clonevm"

say "maymove"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260010000
./userland/c/extra maymove
mark "$?" "maymove"

say "execrace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
cp -f userland/c/extra /tmp/stalehelper
load path=extra data=260000000-260001000
./userland/c/extra execrace
if [ $? -eq 139 ]; then
	mark 0 "execrace"
else
	mark 1 "execrace"
fi

say "rankload"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=capture
./userland/c/capture
capture_rc=$?
./userland/c/extra datarace
python3 tools/pb_rank.py --file ./userland/c/extra --tgid "$(awk 'NR==1{print $1}' /tmp/pagedrop.index)" --top 5
mark "$?" "rankload"
mark "$capture_rc" "rankload capture"


say "pin"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace /tmp/pbpin.fifo
mkfifo /tmp/pbpin.fifo
load path=extra data=260000000-260001000
./userland/c/extra pin > /tmp/pbpin.fifo &
pinpid=$!
exec 3< /tmp/pbpin.fifo
ready=
ref=
read -r -t 5 -u 3 ready
# Builtins only from here to the refcount read: any process that exits runs
# the exit_files hook, which updates the pin, and would hide a pin that the
# arming itself did not take.
read -r ref < /sys/module/pagedrop/refcnt
echo "pin: extra said '$ready', refcnt $ref"
pin=1
if [ "$ready" = armed ] && [ "${ref:-0}" -ge 1 ] && ! sudo rmmod pagedrop 2>/dev/null; then
	pin=0
fi
mark "$pin" "pin"
kill "$pinpid" 2>/dev/null
wait "$pinpid" 2>/dev/null
exec 3<&-
rm -f /tmp/pbpin.fifo
unload

say "pinmove"
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace /tmp/pbpin.fifo
mkfifo /tmp/pbpin.fifo
load path=extra data=260000000-280000000
./userland/c/extra pinmove > /tmp/pbpin.fifo &
pinpid=$!
exec 3< /tmp/pbpin.fifo
ready=
ref=
read -r -t 5 -u 3 ready
# The release is asynchronous. Poll for a second with builtins only, while
# extra is still alive and nothing exits, so only the move can release it.
for _ in 1 2 3 4 5 6 7 8 9 10; do
	read -r ref < /sys/module/pagedrop/refcnt
	[ "$ref" = 0 ] && break
	read -r -t 0.1 -u 3 _ || true
done
echo "pinmove: extra said '$ready', refcnt $ref"
if [ "$ready" = moved ] && [ "$ref" = 0 ]; then
	mark 0 "pinmove"
else
	mark 1 "pinmove"
fi
kill "$pinpid" 2>/dev/null
wait "$pinpid" 2>/dev/null
exec 3<&-
rm -f /tmp/pbpin.fifo

say "pinoff"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra read
mark $? "pinoff read"
pinoff=1
for _ in 1 2 3 4 5 6 7 8 9 10; do
	if sudo rmmod pagedrop 2>/dev/null; then
		pinoff=0
		break
	fi
	sleep 1
done
mark "$pinoff" "pinoff rmmod"

say "roarm"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra roarm
mark "$?" "roarm"

say "moveread"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra moveread
mark "$?" "moveread"

say "movein"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-280000000
./userland/c/extra moveread
mark "$?" "movein"

say "dontunmap"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra dontunmap
mark "$?" "dontunmap"

say "fixeddontunmap"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-280000000
./userland/c/extra fixeddontunmap
mark "$?" "fixeddontunmap"

say "execguard"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra execguard
mark "$?" "execguard"

say "rowrite"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra
./userland/c/extra rowrite
mark "$?" "rowrite"

say "vforkwrite"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra
./userland/c/extra vforkwrite
mark "$?" "vforkwrite"

say "badprot"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra
./userland/c/extra badprot
mark "$?" "badprot"

say "partial"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra
./userland/c/extra partial
mark "$?" "partial"

say "fixedwx"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra fixedwx
mark "$?" "fixedwx"

say "fixedover"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-280000000
./userland/c/extra fixedover
mark "$?" "fixedover"

say "rearm"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra rearm
mark "$?" "rearm"

say "fixed"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra fixed
mark "$?" "fixed"

say "pair"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra pair
mark "$?" "pair"

say "vfork"
unload
load path=extra
./userland/c/extra vfork
mark "$?" "vfork"

say "outside"
unload
sudo rm -f /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra outside
mark "$?" "outside"

say "baddata"
unload
sudo insmod ./pagedrop.ko path=extra data=zz
if [ $? -eq 0 ]; then
	sudo rmmod pagedrop 2>/dev/null || true
	mark 1 "baddata"
else
	mark 0 "baddata"
fi

say "wrarm"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra wrarm
mark "$?" "wrarm"

say "noneexec"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra noneexec
mark "$?" "noneexec"

say "disarm"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
load path=extra data=260000000-260001000
./userland/c/extra disarm
mark "$?" "disarm"

say "stale"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
cp -f userland/c/extra /tmp/stalehelper
load path=extra
timeout 3 ./userland/c/extra stale
if [ $? -eq 139 ]; then
	mark 0 "stale"
else
	mark 1 "stale"
fi

say "execfail"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
cp -f userland/c/extra /tmp/exectest
load path=exectest
/tmp/exectest fail
mark "$?" "execfail"

say "execve"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
mkdir -p /tmp/pbmatch
cp -f userland/c/extra /tmp/pbmatch/notme
load path=pbmatch
./userland/c/extra execve
mark "$?" "execve"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
./userland/c/extra execveat
mark "$?" "execveat"

say "tag"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra tag
mark "$?" "tag"

say "tagrace"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=extra
./userland/c/extra tagrace
mark "$?" "tagrace"

say "upx"
unload
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
load path=upxtest
/tmp/upxtest
sudo /tmp/pb_check 204284d26086a8f2a0caccf2e00ef1f2c0035fd6 /tmp/upxtest
mark "$?" "upx"

oops=$(sudo dmesg | grep -E 'Oops|BUG:' | tail -3 || true)
if [ -n "$oops" ]; then
	echo "$oops"
	mark 1 "no oops"
else
	mark 0 "no oops"
fi
( unload ) || mark 1 "rmmod"
if [ "$fail" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "SOME FAILED"
fi
exit "$fail"
