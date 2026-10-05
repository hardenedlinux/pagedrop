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

sudo rmmod pagedrop 2>/dev/null || true
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
sudo insmod ./pagedrop.ko path=simple
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
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=sigsegv
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
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=capture
./userland/c/capture
mark "$?" "capture"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo /tmp/pb_addr ./userland/c/capture
mark "$?" "capture mremap"

say "epoch"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra epoch
mark "$?" "epoch"

say "exact"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extr exact=1
./userland/c/extra epoch
if [ $? -eq 0 ]; then
	mark 1 "exact"
else
	sudo rmmod pagedrop 2>/dev/null || true
	sudo rm -f /tmp/[0-9a-f]*_[0-9]*
	sudo insmod ./pagedrop.ko path=extra exact=1
	./userland/c/extra epoch
	mark $? "exact"
fi

say "flip"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra flip
mark "$?" "flip"

say "regs"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra regs
mark "$?" "regs"

say "commname"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra
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
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
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
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra forkread
mark "$?" "forkread"

say "forkrace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra forkrace
mark "$?" "forkrace"

say "dumprace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra dumprace
mark "$?" "dumprace"

say "armrace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra armrace
mark "$?" "armrace"

say "mremaprace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260010000
./userland/c/extra mremaprace
mark "$?" "mremaprace"

say "datarace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra datarace
mark "$?" "datarace"

say "munmaprace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra munmaprace
mark "$?" "munmaprace"

say "clonevm"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra clonevm
mark "$?" "clonevm"

say "maymove"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260010000
./userland/c/extra maymove
mark "$?" "maymove"

say "execrace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
cp -f userland/c/extra /tmp/stalehelper
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra execrace
if [ $? -eq 139 ]; then
	mark 0 "execrace"
else
	mark 1 "execrace"
fi

say "rankload"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=capture
./userland/c/capture
capture_rc=$?
./userland/c/extra datarace
python3 tools/pb_rank.py --file ./userland/c/extra --tgid "$(awk 'NR==1{print $1}' /tmp/pagedrop.index)" --top 5
mark "$?" "rankload"
mark "$capture_rc" "rankload capture"


say "pin"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra pin &
pinpid=$!
sleep 1
if sudo rmmod pagedrop 2>/dev/null; then
	mark 1 "pin"
else
	mark 0 "pin"
fi
kill "$pinpid" 2>/dev/null
wait "$pinpid" 2>/dev/null
# The unpin is asynchronous, so rmmod can fail for a moment after the last
# armed page goes away. Poll rather than assume it has already happened.
for _ in 1 2 3 4 5 6 7 8 9 10; do
	sudo rmmod pagedrop 2>/dev/null && break
	sleep 1
done

say "pinoff"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
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
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra roarm
mark "$?" "roarm"

say "moveread"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra moveread
mark "$?" "moveread"

say "movein"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-280000000
./userland/c/extra moveread
mark "$?" "movein"

say "dontunmap"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra dontunmap
mark "$?" "dontunmap"

say "execguard"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra execguard
mark "$?" "execguard"

say "rowrite"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra rowrite
mark "$?" "rowrite"

say "vforkwrite"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra vforkwrite
mark "$?" "vforkwrite"

say "badprot"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra badprot
mark "$?" "badprot"

say "partial"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra partial
mark "$?" "partial"

say "fixedwx"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra fixedwx
mark "$?" "fixedwx"

say "fixedover"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-280000000
./userland/c/extra fixedover
mark "$?" "fixedover"

say "rearm"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra rearm
mark "$?" "rearm"

say "fixed"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra fixed
mark "$?" "fixed"

say "pair"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra pair
mark "$?" "pair"

say "vfork"
sudo rmmod pagedrop 2>/dev/null || true
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra vfork
mark "$?" "vfork"

say "outside"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra outside
mark "$?" "outside"

say "baddata"
sudo rmmod pagedrop 2>/dev/null || true
sudo insmod ./pagedrop.ko path=extra data=zz
if [ $? -eq 0 ]; then
	sudo rmmod pagedrop 2>/dev/null || true
	mark 1 "baddata"
else
	mark 0 "baddata"
fi

say "wrarm"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra wrarm
mark "$?" "wrarm"

say "noneexec"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra noneexec
mark "$?" "noneexec"

say "disarm"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]* /tmp/pagedrop.index /tmp/pagedrop.trace
sudo insmod ./pagedrop.ko path=extra data=260000000-260001000
./userland/c/extra disarm
mark "$?" "disarm"

say "stale"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
cp -f userland/c/extra /tmp/stalehelper
sudo insmod ./pagedrop.ko path=extra
timeout 3 ./userland/c/extra stale
if [ $? -eq 139 ]; then
	mark 0 "stale"
else
	mark 1 "stale"
fi

say "execfail"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
cp -f userland/c/extra /tmp/exectest
sudo insmod ./pagedrop.ko path=exectest
/tmp/exectest fail
mark "$?" "execfail"

say "execve"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
mkdir -p /tmp/pbmatch
cp -f userland/c/extra /tmp/pbmatch/notme
sudo insmod ./pagedrop.ko path=pbmatch
./userland/c/extra execve
mark "$?" "execve"
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
./userland/c/extra execveat
mark "$?" "execveat"

say "tag"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra tag
mark "$?" "tag"

say "tagrace"
sudo rmmod pagedrop 2>/dev/null || true
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=extra
./userland/c/extra tagrace
mark "$?" "tagrace"

say "upx"
sudo rmmod pagedrop
sudo rm -f /tmp/[0-9a-f]*_[0-9]*
sudo insmod ./pagedrop.ko path=upxtest
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
sudo rmmod pagedrop || mark 1 "rmmod"
if [ "$fail" -eq 0 ]; then
	echo "ALL PASS"
else
	echo "SOME FAILED"
fi
exit "$fail"
