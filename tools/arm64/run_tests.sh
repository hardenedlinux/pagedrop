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

# Unload, and insist it worked.
#
# A pinned module refuses rmmod for a moment after the last armed page is
# released, because the release is a work item. Retry that, and if the module
# is still loaded after ten seconds the rest of the suite would be measuring
# the previous build with the previous path= and data=, so stop instead.
#
# This is the false pass AGENTS.md warns about: rmmod was allowed to fail and
# insmod's EEXIST was ignored, so a case could print PASS while measuring the
# module that was already loaded.
# Remove dump files and the index and trace, bounded so a large dump count
# cannot overflow the argument list. A glob here dies with "Argument list too
# long" and the cleanup then silently stops, so every later case measures the
# previous run's dumps instead of its own.
clean_dumps() {
	sudo find /tmp -maxdepth 1 -name '[0-9a-f]*_[0-9]*' -type f -delete 2>/dev/null
	sudo rm -f /tmp/pagedrop.index /tmp/pagedrop.trace "$@"
}

unload() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		grep -q '^pagedrop ' /proc/modules || return 0
		sudo rmmod pagedrop 2>/dev/null && return 0
		sleep 1
	done
	echo "rmmod pagedrop: still loaded after 10 tries"
	echo "the suite would measure the previous build, so stopping"
	exit 1
}

# Load, and insist it worked.
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
clean_dumps
load path=simple
hooks=$(sudo dmesg | grep 'pagedrop: hooked' | tail -13)
	echo "$hooks"
	missing=0
	# exit_files replaced do_exit: testing live on entry to do_exit raced with
	# exit_group, so two threads could each judge the other still alive and
	# both skip the cleanup. See the comment on fh_exit_files.
	for n in mprotect pkey_mprotect mremap munmap vm_mmap_pgoff execve execveat fork vfork clone clone3 exit_files force_sig_fault; do
	echo "$hooks" | grep -q "$n" || { echo "missing hook $n"; missing=1; }
done
mark "$missing" "hooks"

say "simple"
clean_dumps
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
clean_dumps
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
clean_dumps
load path=capture
./userland/c/capture
mark "$?" "capture"
clean_dumps
sudo /tmp/pb_addr ./userland/c/capture
mark "$?" "capture mremap"

say "epoch"
unload
clean_dumps
load path=extra
./userland/c/extra epoch
mark "$?" "epoch"

say "exact"
unload
clean_dumps
load path=extr exact=1
./userland/c/extra epoch
if [ $? -eq 0 ]; then
	mark 1 "exact"
else
	unload
	clean_dumps
	load path=extra exact=1
	./userland/c/extra epoch
	mark $? "exact"
fi

say "flip"
unload
clean_dumps
load path=extra
./userland/c/extra flip
mark "$?" "flip"

say "rowrite"
unload
clean_dumps
load path=extra
./userland/c/extra rowrite
mark "$?" "rowrite"

say "faultstore"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra faultstore
mark "$?" "faultstore"
unload
clean_dumps
load path=extra
./userland/c/extra faultstore
mark "$?" "faultstore no-data"

say "commname"
unload
clean_dumps
load path=extra
./userland/c/extra commname
mark "$?" "commname"
# A comm containing a space or a newline must not be able to forge an index
# row: every line has to keep exactly five fields, and the name has to come
# through sanitised.
python3 - << 'PYEOF'
ok = False
for line in open("/tmp/pagedrop.index"):
    p = line.split()
    if len(p) != 5:
        raise SystemExit("bad index line %r" % line)
    if p[1] == "ex_tra_x" and p[4] == "mprotect":
        ok = True
raise SystemExit(0 if ok else 1)
PYEOF
mark "$?" "index commname"

say "dontunmap"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra dontunmap
mark "$?" "dontunmap"

say "epochread"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra epochread
mark "$?" "epochread"

say "read"
unload
clean_dumps
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

say "armexec"
unload
clean_dumps
load path=extra data=260000000-260002000
./userland/c/extra armexec
mark "$?" "armexec"

say "forkread"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra forkread
mark "$?" "forkread"

say "forkrace"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra forkrace
mark "$?" "forkrace"

say "dumprace"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra dumprace
mark "$?" "dumprace"

say "armrace"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra armrace
mark "$?" "armrace"

say "mremaprace"
unload
clean_dumps
load path=extra data=260000000-260010000
./userland/c/extra mremaprace
mark "$?" "mremaprace"

say "datarace"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra datarace
mark "$?" "datarace"

say "munmaprace"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra munmaprace
mark "$?" "munmaprace"

say "clonevm"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra clonevm
mark "$?" "clonevm"

say "maymove"
unload
clean_dumps
load path=extra data=260000000-260010000
./userland/c/extra maymove
mark "$?" "maymove"

say "execrace"
unload
clean_dumps
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
clean_dumps
load path=capture
./userland/c/capture
capture_rc=$?
./userland/c/extra datarace
python3 tools/pb_rank.py --file ./userland/c/extra --tgid "$(awk 'NR==1{print $1}' /tmp/pagedrop.index)" --top 5
mark "$?" "rankload"
mark "$capture_rc" "rankload capture"


say "pin"
unload
clean_dumps
load path=extra data=260000000-260001000
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
unload
clean_dumps
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
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra roarm
mark "$?" "roarm"

say "moveread"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra moveread
mark "$?" "moveread"

say "movein"
unload
clean_dumps
load path=extra data=260000000-280000000
./userland/c/extra moveread
mark "$?" "movein"

say "moveout"
unload
clean_dumps
load path=extra data=260000000-270001000
./userland/c/extra moveout
mark "$?" "moveout"

say "movespan"
unload
clean_dumps
load path=extra data=260000000-270001000
./userland/c/extra movespan
mark "$?" "movespan"

say "mppart"
unload
clean_dumps
load path=extra data=260000000-260003000
./userland/c/extra mppart
mark "$?" "mppart"

say "rearm"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra rearm
mark "$?" "rearm"

say "fixed"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra fixed
mark "$?" "fixed"

say "pair"
unload
clean_dumps
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
# Deliberately NOT load(): this case asserts that insmod REJECTS a bad
# data= range, so a nonzero exit is the pass condition. load() treats a
# nonzero exit as fatal and would end the run before the test could judge it.
sudo insmod ./pagedrop.ko path=extra data=zz
if [ $? -eq 0 ]; then
	unload
	mark 1 "baddata"
else
	mark 0 "baddata"
fi

say "wrarm"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra wrarm
mark "$?" "wrarm"

say "noneexec"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra noneexec
mark "$?" "noneexec"

say "disarm"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra disarm
mark "$?" "disarm"

say "stale"
unload
clean_dumps
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
clean_dumps
cp -f userland/c/extra /tmp/exectest
load path=exectest
/tmp/exectest fail
mark "$?" "execfail"

say "execve"
unload
clean_dumps
mkdir -p /tmp/pbmatch
cp -f userland/c/extra /tmp/pbmatch/notme
load path=pbmatch
./userland/c/extra execve
mark "$?" "execve"
clean_dumps
./userland/c/extra execveat
mark "$?" "execveat"

say "tag"
unload
clean_dumps
load path=extra
./userland/c/extra tag
mark "$?" "tag"

say "tagrace"
unload
clean_dumps
load path=extra
./userland/c/extra tagrace
mark "$?" "tagrace"

say "upx"
unload
clean_dumps
load path=upxtest
/tmp/upxtest
sudo /tmp/pb_check 204284d26086a8f2a0caccf2e00ef1f2c0035fd6 /tmp/upxtest
mark "$?" "upx"

say "badprot"
unload
clean_dumps
load path=extra
./userland/c/extra badprot
mark "$?" "badprot"
say "execguard"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra execguard
mark "$?" "execguard"
say "fixeddontunmap"
unload
clean_dumps
load path=extra data=260000000-280000000
./userland/c/extra fixeddontunmap
mark "$?" "fixeddontunmap"
say "fixedover"
unload
clean_dumps
load path=extra data=260000000-280000000
./userland/c/extra fixedover
mark "$?" "fixedover"
say "fixedwx"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra fixedwx
mark "$?" "fixedwx"
say "partial"
unload
clean_dumps
load path=extra
./userland/c/extra partial
mark "$?" "partial"
unload
say "pinmove"
clean_dumps /tmp/pbpin.fifo
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
say "regs"
unload
clean_dumps
load path=extra
./userland/c/extra regs
mark "$?" "regs"
say "vforkfork"
unload
clean_dumps
load path=extra data=260000000-260001000
./userland/c/extra vforkfork
mark "$?" "vforkfork"
say "vforkwrite"
unload
clean_dumps
load path=extra
./userland/c/extra vforkwrite
mark "$?" "vforkwrite"

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
