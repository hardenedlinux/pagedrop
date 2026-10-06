#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096
#define EPOCH_ADDR 0x250000000UL
#define FAIL_ADDR 0x230000000UL
#define TAG_ADDR 0x240000000UL
#define READ_DATA 0x260000000UL
#define READ_CODE 0x261000000UL
#define MOVED_ADDR 0x270000000UL
#define WX_ADDR 0x220000000UL
#define TAG_BYTE 0x5aUL

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

static sigjmp_buf fault_env;
static volatile int faulted;

static void on_fault(int sig)
{
	(void)sig;
	faulted = 1;
	siglongjmp(fault_env, 1);
}

static void arm_fault(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_fault;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	alarm(10);
}

static void plant(void *p, const char *mark)
{
	memcpy((unsigned char *)p + 16, mark, 8);
#if defined(__aarch64__)
	*(uint32_t *)p = 0xd65f03c0;
#else
	*(unsigned char *)p = 0xc3;
#endif
}

static int file_has(const char *path, const char *mark, int n)
{
	unsigned char buf[64];
	int fd;
	int got;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	got = read(fd, buf, sizeof(buf));
	close(fd);
	if (got < 16 + n)
		return 0;
	return memcmp(buf + 16, mark, n) == 0;
}

static int dump_exact(unsigned long want, const char *mark)
{
	DIR *d;
	struct dirent *de;
	int n = strlen(mark);
	int found = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (want && addr != want)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		if (file_has(path, mark, n)) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
}

static int count_mark(const char *mark)
{
	DIR *d;
	struct dirent *de;
	int n = strlen(mark);
	int count = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		if (file_has(path, mark, n))
			count++;
	}
	closedir(d);
	return count;
}

static void *map_fixed(unsigned long addr, int prot)
{
	void *p;

	p = mmap((void *)addr, PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED)
		return NULL;
	return p;
}

static int call_ok(void *p)
{
	faulted = 0;
	if (sigsetjmp(fault_env, 1) != 0)
		return 0;
	((void (*)(void))p)();
	return !faulted;
}

static int do_epoch(void)
{
	void *p;

	arm_fault();
	p = map_fixed(EPOCH_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("epoch mmap");
		return 1;
	}
	plant(p, "EPOCH-A!");
	if (!call_ok(p) || !dump_exact(EPOCH_ADDR, "EPOCH-A!")) {
		fprintf(stderr, "epoch: first dump missing\n");
		return 1;
	}
	plant(p, "EPOCH-B!");
	if (!call_ok(p) || !dump_exact(EPOCH_ADDR, "EPOCH-B!")) {
		fprintf(stderr, "epoch: second dump missing\n");
		return 1;
	}
	if (count_mark("EPOCH-A!") < 1 || count_mark("EPOCH-B!") < 1) {
		fprintf(stderr, "epoch: old dump was replaced\n");
		return 1;
	}
	printf("epoch ok\n");
	return 0;
}

static int do_flip(void)
{
	unsigned char *p;

	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("flip mmap");
		return 1;
	}
	memcpy(p + 16, "FLIP-OLD", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("flip rx");
		return 1;
	}
	if (!dump_exact(0, "FLIP-OLD")) {
		fprintf(stderr, "flip: old marker not dumped\n");
		return 1;
	}
	if (mprotect(p, PAGE, PROT_READ | PROT_WRITE) != 0) {
		perror("flip rw");
		return 1;
	}
	memcpy(p + 16, "FLIP-NEW", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("flip rx2");
		return 1;
	}
	if (!dump_exact(0, "FLIP-NEW") || !dump_exact(0, "FLIP-OLD")) {
		fprintf(stderr, "flip: expected both markers\n");
		return 1;
	}
	printf("flip ok\n");
	return 0;
}

/*
 * A raw mprotect(RWX) must hand back the prot register unchanged. The
 * module clears PROT_WRITE in the request, and once did it in the
 * caller's saved registers, which the syscall ABI preserves.
 */
static int do_regs(void)
{
	unsigned long prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	unsigned long after;
	long ret;
	void *p;

	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("regs mmap");
		return 1;
	}
#if defined(__x86_64__)
	{
		register unsigned long rdx asm("rdx") = prot;
		long rax = SYS_mprotect;

		asm volatile("syscall"
			     : "+a"(rax), "+r"(rdx)
			     : "D"(p), "S"((unsigned long)PAGE)
			     : "rcx", "r11", "memory");
		ret = rax;
		after = rdx;
	}
#elif defined(__aarch64__)
	{
		register unsigned long x0 asm("x0") = (unsigned long)p;
		register unsigned long x1 asm("x1") = PAGE;
		register unsigned long x2 asm("x2") = prot;
		register unsigned long x8 asm("x8") = SYS_mprotect;

		asm volatile("svc #0"
			     : "+r"(x0), "+r"(x2)
			     : "r"(x1), "r"(x8)
			     : "memory");
		ret = (long)x0;
		after = x2;
	}
#endif
	if (ret != 0) {
		fprintf(stderr, "regs: mprotect returned %ld\n", ret);
		return 1;
	}
	if (after != prot) {
		fprintf(stderr, "regs: prot register %#lx, want %#lx\n", after, prot);
		return 1;
	}
	printf("regs ok\n");
	return 0;
}

static int do_fail(void)
{
	void *p;
	char *argv[] = {"missing", NULL};
	char *envp[] = {NULL};

	arm_fault();
	p = map_fixed(FAIL_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("fail mmap");
		return 1;
	}
	plant(p, "KEEPME!!");
	execve("/tmp/missing-exectest", argv, envp);
	execve("/tmp/missing-other", argv, envp);
	if (!call_ok(p) || !dump_exact(FAIL_ADDR, "KEEPME!!")) {
		fprintf(stderr, "execfail: tracking dropped\n");
		return 1;
	}
	printf("execfail ok\n");
	return 0;
}

static int do_payload(void)
{
	const char *mark = getenv("PB_MARK");
	unsigned char *p;

	if (!mark || strlen(mark) != 8)
		mark = "PBPAYLD!";
	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 1;
	memcpy(p + 16, mark, 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	if (!dump_exact(0, mark)) {
		fprintf(stderr, "payload: %s not dumped\n", mark);
		return 1;
	}
	printf("payload %s\n", mark);
	return 0;
}

static int trace_has(unsigned long va)
{
	FILE *f;
	char line[128];
	int found = 0;

	f = fopen("/tmp/pagedrop.trace", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		unsigned long ip, data;
		unsigned long epoch;

		if (sscanf(line, "%lx %lx %lu", &ip, &data, &epoch) != 3)
			continue;
		if (data == va) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int do_read(void)
{
	unsigned char *data;
	unsigned char *code;
	unsigned char buf[16];
	int fd;
	DIR *d;
	struct dirent *de;
	int dumped = 0;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("read mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
#if defined(__aarch64__)
	{
		uint32_t *w = (uint32_t *)code;

		w[0] = 0xd2800001;
		w[1] = 0xf2ac0001;
		w[2] = 0xf2c00041;
		w[3] = 0xf9400020;
		w[4] = 0xd65f03c0;
	}
#else
	{
		unsigned char stub[] = {
			0x48, 0xb8, 0x00, 0x00, 0x00, 0x60, 0x02, 0x00, 0x00, 0x00,
			0x48, 0x8b, 0x00,
			0xc3
		};
		memcpy(code, stub, sizeof(stub));
	}
#endif
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("read rx");
		return 1;
	}
	arm_fault();
	if (!call_ok(code)) {
		fprintf(stderr, "read: load fault was not swallowed\n");
		return 1;
	}
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "read: trace missing\n");
		return 1;
	}
	d = opendir("/tmp");
	if (!d)
		return 1;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (addr != READ_DATA)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, buf, 8) == 8 && memcmp(buf, "BYTECODE", 8) == 0)
			dumped = 1;
		close(fd);
	}
	closedir(d);
	if (!dumped) {
		fprintf(stderr, "read: data page not dumped\n");
		return 1;
	}
	printf("read ok\n");
	return 0;
}

#if defined(__aarch64__)
static unsigned char *tagrace_ptr;
static volatile int tagrace_stop;
static volatile int tagrace_bad;

static void *tagrace_worker(void *arg)
{
	unsigned long tag = (unsigned long)arg;
	unsigned char *p = (unsigned char *)(READ_DATA | (tag << 56));
	int i;

	for (i = 0; i < 4000 && !tagrace_stop; i++) {
		if (sigsetjmp(fault_env, 1) == 0) {
			volatile unsigned char x = *p;

			(void)x;
		} else {
			tagrace_bad++;
		}
	}
	return NULL;
}

static int do_tagrace(void)
{
	pthread_t th[4];
	unsigned char *code;
	int i;

	arm_fault();
	tagrace_ptr = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!tagrace_ptr || !code) {
		perror("tagrace mmap");
		return 1;
	}
	/* A code page mprotected to execute is what arms the data range. */
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("tagrace rx");
		return 1;
	}
	tagrace_stop = 0;
	for (i = 0; i < 4; i++)
		if (pthread_create(&th[i], NULL, tagrace_worker,
				   (void *)(unsigned long)(TAG_BYTE + i)) != 0)
			return 1;
	for (i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	/*
	 * The threads must have read the right byte. Without the module the
	 * page is never made inaccessible, so a read fault here is the
	 * module failing to restore a tagged access, which is the whole
	 * point of the case.
	 */
	if (tagrace_bad) {
		fprintf(stderr, "tagrace: %d tagged reads faulted\n", tagrace_bad);
		return 1;
	}
	printf("tagrace ok\n");
	return 0;
}
#endif

static unsigned char *forkread_ptr;
static volatile int forkread_stop;

static void *forkread_reader(void *arg)
{
	int i;

	(void)arg;
	/* Keep touching the armed page while the main thread forks, so a
	 * child can be born and fault on the same page the parent is using. */
	for (i = 0; i < 20000 && !forkread_stop; i++) {
		if (sigsetjmp(fault_env, 1) == 0) {
			volatile unsigned char x = *forkread_ptr;

			(void)x;
		}
	}
	return NULL;
}

static int do_forkread(void)
{
	unsigned char *data;
	unsigned char *code;
	pthread_t reader;
	pid_t pid;
	int st;
	int i;
	int bad = 0;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("forkread mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("forkread rx");
		return 1;
	}
	arm_fault();
	forkread_ptr = data;
	forkread_stop = 0;
	if (pthread_create(&reader, NULL, forkread_reader, NULL) != 0)
		return 1;
	/* Fork repeatedly while the reader is walking the armed page. Every
	 * child shares those page tables, so each one can fault on a page the
	 * module armed for the parent. */
	for (i = 0; i < 200; i++) {
		pid = fork();
		if (pid < 0) {
			bad++;
			break;
		}
		if (pid == 0) {
			volatile unsigned char x = data[0];

			_exit(x == 'B' ? 0 : 1);
		}
		if (waitpid(pid, &st, 0) < 0) {
			bad++;
			break;
		}
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad++;
	}
	forkread_stop = 1;
	pthread_join(reader, NULL);
	if (bad) {
		fprintf(stderr, "forkread: %d of 200 children failed\n", bad);
		return 1;
	}
	printf("forkread ok\n");
	return 0;
}

static unsigned char *dumprace_ptr;

static void *dumprace_worker(void *arg)
{
	pthread_barrier_t *bar = arg;
	volatile unsigned char x;

	pthread_barrier_wait(bar);
	x = *dumprace_ptr;
	(void)x;
	return NULL;
}

static int do_dumprace(void)
{
	unsigned char *data;
	unsigned char *code;
	pthread_t th[8];
	pthread_barrier_t bar;
	FILE *f;
	char line[128];
	int i;
	int n = 0;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("dumprace mmap");
		return 1;
	}
	memset(data, 0x42, PAGE);
	dumprace_ptr = data;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	pthread_barrier_init(&bar, NULL, 8);
	for (i = 0; i < 8; i++)
		pthread_create(&th[i], NULL, dumprace_worker, &bar);
	for (i = 0; i < 8; i++)
		pthread_join(th[i], NULL);
	pthread_barrier_destroy(&bar);
	f = fopen("/tmp/pagedrop.trace", "r");
	if (!f) {
		fprintf(stderr, "dumprace: no trace file\n");
		return 1;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned long ip, va, epoch;

		if (sscanf(line, "%lx %lx %lu", &ip, &va, &epoch) == 3 && va == READ_DATA)
			n++;
	}
	fclose(f);
	if (n != 1) {
		fprintf(stderr, "dumprace: %d trace lines, want 1\n", n);
		return 1;
	}
	printf("dumprace ok\n");
	return 0;
}

static unsigned char *armrace_ptr;
static unsigned char *armrace_code;
static volatile int armrace_stop;

static void *armrace_reloader(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < 2000 && !armrace_stop; i++) {
		mprotect(armrace_ptr, PAGE, PROT_READ | PROT_WRITE);
		mprotect(armrace_code, PAGE, PROT_READ | PROT_EXEC);
	}
	armrace_stop = 1;
	return NULL;
}

static void *armrace_reader(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < 2000 && !armrace_stop; i++) {
		volatile unsigned char x = *armrace_ptr;

		(void)x;
	}
	return NULL;
}

static int do_armrace(void)
{
	pthread_t r, w;

	armrace_ptr = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	armrace_code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!armrace_ptr || !armrace_code) {
		perror("armrace mmap");
		return 1;
	}
	memset(armrace_ptr, 0x42, PAGE);
	if (mprotect(armrace_code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	armrace_stop = 0;
	if (pthread_create(&r, NULL, armrace_reader, NULL) != 0)
		return 1;
	if (pthread_create(&w, NULL, armrace_reloader, NULL) != 0)
		return 1;
	pthread_join(w, NULL);
	pthread_join(r, NULL);
	printf("armrace ok\n");
	return 0;
}

static volatile int mremap_stop;
#define MOVE_N 64
#define MOVE_FIRST 0x260000000UL
#define MOVE_ALT 0x260010000UL

static void *mremap_reader(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < MOVE_N * 200 && !mremap_stop; i++) {
		volatile unsigned char x = *(volatile unsigned char *)MOVE_ALT;

		(void)x;
	}
	return NULL;
}

static int do_mremaprace(void)
{
	unsigned char *code;
	pthread_t r;
	int i;
	int moved = 0;

	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("mremaprace mmap");
		return 1;
	}
	for (i = 0; i < MOVE_N; i++)
		if (!map_fixed(MOVE_FIRST + (unsigned long)i * PAGE,
			       PROT_READ | PROT_WRITE))
			return 1;
	/* ALT starts as a plain mapping and is never unmapped afterwards. */
	if (!map_fixed(MOVE_ALT, PROT_READ | PROT_WRITE))
		return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	pthread_create(&r, NULL, mremap_reader, NULL);
	for (i = 0; i < MOVE_N; i++) {
		if (mremap((void *)(MOVE_FIRST + (unsigned long)i * PAGE), PAGE, PAGE,
			   MREMAP_MAYMOVE | MREMAP_FIXED, (void *)MOVE_ALT) == MAP_FAILED)
			break;
		moved++;
	}
	mremap_stop = 1;
	pthread_join(r, NULL);
	if (!moved) {
		fprintf(stderr, "mremaprace: no moves\n");
		return 1;
	}
	printf("mremaprace ok\n");
	return 0;
}

static unsigned char *datarace_ptr;
static volatile int datarace_stop;

static void *datarace_storm(void *arg)
{
	int i;

	(void)arg;
	/* Both of these are x-only or plain, so each one arms and each one
	 * disarms the data range while the reader is walking over it. */
	for (i = 0; i < 3000 && !datarace_stop; i++) {
		mprotect(datarace_ptr, PAGE, PROT_READ | PROT_EXEC);
		mprotect(datarace_ptr, PAGE, PROT_READ | PROT_WRITE);
	}
	datarace_stop = 1;
	return NULL;
}

static void *datarace_reader(void *arg)
{
	int i;

	(void)arg;
	/* No signal handler on purpose: the page is only ever RW or RX here,
	 * so the only faults available are the ones the module invented. */
	for (i = 0; i < 8000 && !datarace_stop; i++) {
		volatile unsigned char x = *datarace_ptr;

		(void)x;
	}
	return NULL;
}

static int do_datarace(void)
{
	pthread_t storm, reader;
	unsigned char *code;

	datarace_ptr = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!datarace_ptr || !code) {
		perror("datarace mmap");
		return 1;
	}
	memset(datarace_ptr, 0x42, PAGE);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	datarace_stop = 0;
	if (pthread_create(&storm, NULL, datarace_storm, NULL) != 0)
		return 1;
	if (pthread_create(&reader, NULL, datarace_reader, NULL) != 0)
		return 1;
	pthread_join(storm, NULL);
	pthread_join(reader, NULL);
	printf("datarace ok\n");
	return 0;
}

static unsigned char *munmaprace_ptr;
static volatile int munmaprace_stop;
static volatile sig_atomic_t munmaprace_faults;

static void munmaprace_fault(int sig)
{
	(void)sig;
	munmaprace_faults++;
}

static void *munmaprace_reader(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < 8000 && !munmaprace_stop; i++) {
		if (sigsetjmp(fault_env, 1) == 0) {
			volatile unsigned char x = *munmaprace_ptr;

			(void)x;
		}
	}
	return NULL;
}

static int do_munmaprace(void)
{
	pthread_t r;
	struct sigaction sa;
	unsigned char *code;

	munmaprace_ptr = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!munmaprace_ptr || !code) {
		perror("munmaprace mmap");
		return 1;
	}
	memset(munmaprace_ptr, 0x42, PAGE);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = munmaprace_fault;
	sigaction(SIGSEGV, &sa, NULL);
	arm_fault();
	munmaprace_stop = 0;
	munmaprace_faults = 0;
	if (pthread_create(&r, NULL, munmaprace_reader, NULL) != 0)
		return 1;
	/* Drop the page out from under the reader. The fault it takes is the
	 * program's own doing, so a handler is installed and the test only
	 * requires that the module neither wedges nor panics. */
	if (munmap(munmaprace_ptr, PAGE) != 0) {
		pthread_join(r, NULL);
		perror("munmaprace munmap");
		return 1;
	}
	usleep(20000);
	munmaprace_stop = 1;
	pthread_join(r, NULL);
	printf("munmaprace ok faults %d\n", (int)munmaprace_faults);
	return 0;
}

static unsigned char *clonevm_ptr;

static void *clonevm_reader(void *arg)
{
	volatile unsigned char x;

	(void)arg;
	x = *clonevm_ptr;
	return (void *)(long)(x == 'B');
}

static int do_clonevm(void)
{
	unsigned char *data;
	unsigned char *code;
	pthread_t a;
	pthread_t b;
	void *ra = NULL;
	void *rb = NULL;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("clonevm mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("clonevm rx");
		return 1;
	}
	/*
	 * Two threads of one tgid racing the same armed page. This is the
	 * shape a raw CLONE_VM without CLONE_THREAD would give: a second
	 * execution context over the same page tables, with the module
	 * restoring the page underneath both of them.
	 */
	clonevm_ptr = data;
	if (pthread_create(&a, NULL, clonevm_reader, NULL) != 0)
		return 1;
	if (pthread_create(&b, NULL, clonevm_reader, NULL) != 0)
		return 1;
	pthread_join(a, &ra);
	pthread_join(b, &rb);
	if (ra != (void *)(long)1 || rb != (void *)(long)1) {
		fprintf(stderr, "clonevm: a thread read the wrong byte\n");
		return 1;
	}
	printf("clonevm ok\n");
	return 0;
}

static unsigned char *execrace_ptr;

static void *execrace_reader(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < 20000; i++) {
		if (sigsetjmp(fault_env, 1) == 0) {
			volatile unsigned char x = *execrace_ptr;

			(void)x;
		}
	}
	return NULL;
}

static int do_execrace(void)
{
	pthread_t r[4];
	unsigned char *data;
	unsigned char *code;
	char *argv[] = {"stalehelper", NULL};
	char *envp[] = {NULL};
	int i;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("execrace mmap");
		return 1;
	}
	memset(data, 0x42, PAGE);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	execrace_ptr = data;
	arm_fault();
	for (i = 0; i < 4; i++)
		if (pthread_create(&r[i], NULL, execrace_reader, NULL) != 0)
			return 1;
	/* Exec while the readers are inside the page. The readers are killed
	 * with the old image, which is the point: pb_do_exec drops the data
	 * state for this tgid while faults are in flight. */
	execve("/tmp/stalehelper", argv, envp);
	perror("execrace execve");
	return 1;
}

/*
 * The module must refuse to unload while a page is still inaccessible, and
 * must not pin once the page has been read. Leaves the page armed on exit so
 * the runner's rmmod is the thing under test.
 */
static int do_pin(void)
{
	unsigned char *data;
	unsigned char *code;
	volatile unsigned char x;
	unsigned char *probe;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	probe = map_fixed(0x266000000UL, PROT_READ | PROT_WRITE);
	if (!data || !code || !probe) {
		perror("pin mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	(void)probe;
	(void)x;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	/*
	 * The data page is armed now. Tell the suite, which reads the module
	 * refcount before any process exits: every exit runs the exit_files
	 * hook, which also updates the pin and would hide a pin not taken here.
	 */
	printf("armed\n");
	fflush(stdout);
	/* Hold the page inaccessible. Reading it here would restore the
	 * protection and release the pin, which is the other case. */
	usleep(1500000);
	printf("pin ok\n");
	return 0;
}

/*
 * Run with data=260000000-280000000. Two armed pages, the first read so it
 * is restored, the second still PROT_NONE. An MREMAP_FIXED move into the
 * range that also shrinks to one page drops the second page's record after
 * the move, in pb_armed_after_move. No page is PROT_NONE after that, so the
 * pin must go. The process stays alive and the suite starts nothing that
 * exits while it watches the refcount, so only that path can release it.
 */
static int do_pinmove(void)
{
	unsigned char *src;
	unsigned char *code;
	unsigned char *moved;

	src = mmap((void *)READ_DATA, 2 * PAGE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src == MAP_FAILED || code == MAP_FAILED) {
		perror("pinmove mmap");
		return 1;
	}
	memcpy(src, "BYTECODE", 8);
	memcpy(src + PAGE, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("pinmove rx");
		return 1;
	}
	if (*(volatile unsigned char *)src != 'B') {
		fprintf(stderr, "pinmove: first page lost its bytes\n");
		return 1;
	}
	moved = mremap(src, 2 * PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED,
		       (void *)MOVED_ADDR);
	if (moved == MAP_FAILED) {
		perror("pinmove mremap");
		return 1;
	}
	if (moved[0] != 'B') {
		fprintf(stderr, "pinmove: moved page lost its bytes\n");
		return 1;
	}
	printf("moved\n");
	fflush(stdout);
	usleep(3000000);
	printf("pinmove ok\n");
	return 0;
}

static int do_maymove(void)
{
	unsigned char *code;
	void *p;
	unsigned long a;
	int i;
	int moved = 0;
	int relocated = 0;

	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("maymove mmap");
		return 1;
	}
	for (i = 0; i < 32; i++)
		if (!map_fixed(0x260000000UL + (unsigned long)i * PAGE,
			       PROT_READ | PROT_WRITE))
			return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;

	/*
	 * The premise the module's guard rests on. Measured on 6.8, a
	 * same-size MREMAP_MAYMOVE keeps the address, so fh_sys_mremap only
	 * has to release armed pages when the size changes. If a kernel ever
	 * relocates a same-size move, that guard is incomplete and there is
	 * an arming window with no way to place a record ahead of the move.
	 * Say so rather than let the hardening pass silently.
	 */
	a = 0x260000000UL;
	p = mremap((void *)a, PAGE, PAGE, MREMAP_MAYMOVE, (void *)0);
	if (p == MAP_FAILED) {
		perror("maymove same size");
		return 1;
	}
	if ((unsigned long)p != a) {
		relocated = 1;
		printf("maymove: same-size move relocated %lx to %lx\n", a,
		       (unsigned long)p);
	} else {
		/* Put the page back where the loop below expects it. */
		if (mremap(p, PAGE, PAGE, MREMAP_MAYMOVE, (void *)a) == MAP_FAILED) {
			perror("maymove restore");
			return 1;
		}
	}

	/* Now the size-changing case the hardening does cover. */
	for (i = 0; i < 32; i++) {
		unsigned long s = 0x260000000UL + (unsigned long)i * PAGE;

		if (!map_fixed(s + PAGE, PROT_READ | PROT_WRITE))
			break;
		if (mremap((void *)s, PAGE, 2 * PAGE, MREMAP_MAYMOVE,
			   (void *)0) == MAP_FAILED)
			break;
		moved++;
	}
	if (!moved) {
		fprintf(stderr, "maymove: no size-changing moves\n");
		return 1;
	}
	if (relocated)
		return 1;
	printf("maymove ok %d\n", moved);
	return 0;
}

static int do_forkrace(void)
{
	unsigned char *data;
	unsigned char *code;
	int i;
	int bad = 0;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("forkrace mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	for (i = 0; i < 200; i++) {
		pid_t pid = fork();
		int st;

		if (pid < 0)
			return 1;
		if (pid == 0) {
			volatile unsigned char x = data[0];

			_exit(x == 'B' ? 0 : 1);
		}
		if (waitpid(pid, &st, 0) < 0)
			return 1;
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad++;
	}
	if (bad) {
		fprintf(stderr, "forkrace: %d of 200 children failed\n", bad);
		return 1;
	}
	printf("forkrace ok\n");
	return 0;
}

static int do_roarm(void)
{
	unsigned char *data;
	unsigned char *code;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("roarm mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(data, PAGE, PROT_READ) != 0) {
		perror("roarm ro");
		return 1;
	}
#if defined(__aarch64__)
	{
		uint32_t *w = (uint32_t *)code;

		w[0] = 0xd2800001;
		w[1] = 0xf2ac0001;
		w[2] = 0xf2c00041;
		w[3] = 0xf9400020;
		w[4] = 0xd65f03c0;
	}
#else
	{
		unsigned char stub[] = {
			0x48, 0xb8, 0x00, 0x00, 0x00, 0x60, 0x02, 0x00, 0x00, 0x00,
			0x48, 0x8b, 0x00,
			0xc3
		};
		memcpy(code, stub, sizeof(stub));
	}
#endif
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("roarm rx");
		return 1;
	}
	arm_fault();
	if (!call_ok(code)) {
		fprintf(stderr, "roarm: load fault was not swallowed\n");
		return 1;
	}
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		data[0] = 0x41;
	if (!faulted) {
		fprintf(stderr, "roarm: write was allowed\n");
		return 1;
	}
	printf("roarm ok\n");
	return 0;
}

static int do_moveread(void)
{
	unsigned char *data;
	unsigned char *code;
	unsigned char *moved;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("moveread mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("moveread rx");
		return 1;
	}
	moved = mremap(data, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED,
		       (void *)MOVED_ADDR);
	if (moved == MAP_FAILED) {
		perror("moveread mremap");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = moved[0];

		(void)x;
	}
	if (faulted) {
		fprintf(stderr, "moveread: fault after mremap\n");
		return 1;
	}
	printf("moveread ok\n");
	return 0;
}

static int do_rearm(void)
{
	unsigned char *data;
	unsigned char *code;
	volatile unsigned char x;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("rearm mmap");
		return 1;
	}
	memcpy(data, "OLDDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "rearm: first trace missing\n");
		return 1;
	}
	if (truncate("/tmp/pagedrop.trace", 0) != 0)
		return 1;
	if (munmap(data, PAGE) != 0)
		return 1;
	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	if (!data)
		return 1;
	memcpy(data, "NEWDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_WRITE) != 0)
		return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	(void)x;
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "rearm: second trace missing\n");
		return 1;
	}
	printf("rearm ok\n");
	return 0;
}

static int do_fixed(void)
{
	unsigned char *data;
	unsigned char *code;
	volatile unsigned char x;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("fixed mmap");
		return 1;
	}
	memcpy(data, "OLDDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "fixed: first trace missing\n");
		return 1;
	}
	if (truncate("/tmp/pagedrop.trace", 0) != 0)
		return 1;
	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	if (!data)
		return 1;
	memcpy(data, "NEWDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_WRITE) != 0)
		return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	(void)x;
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "fixed: second trace missing\n");
		return 1;
	}
	printf("fixed ok\n");
	return 0;
}

static int do_pair(void)
{
	void *mine;
	void *after;
	pid_t pid;
	int st;

	mine = map_fixed(EPOCH_ADDR, PROT_READ | PROT_WRITE);
	if (!mine) {
		perror("pair mmap");
		return 1;
	}
	plant(mine, "PARENT!!");
	if (mprotect(mine, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		void *p = map_fixed(0x251000000UL, PROT_READ | PROT_WRITE);

		if (!p)
			_exit(1);
		plant(p, "CHILD!!!");
		if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0)
			_exit(1);
		if (!dump_exact(0x251000000UL, "CHILD!!!"))
			_exit(1);
		_exit(0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return 1;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		fprintf(stderr, "pair: child failed\n");
		return 1;
	}
	after = map_fixed(0x252000000UL, PROT_READ | PROT_WRITE);
	if (!after)
		return 1;
	plant(after, "AFTER!!!");
	if (mprotect(after, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	if (!dump_exact(0x252000000UL, "AFTER!!!")) {
		fprintf(stderr, "pair: parent lost tracking\n");
		return 1;
	}
	printf("pair ok\n");
	return 0;
}

static int do_vfork(void)
{
	pid_t pid;
	int st;

	pid = vfork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		execl("/bin/true", "true", (char *)NULL);
		_exit(1);
	}
	if (waitpid(pid, &st, 0) < 0)
		return 1;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		fprintf(stderr, "vfork: child failed\n");
		return 1;
	}
	printf("vfork ok\n");
	return 0;
}

static int do_outside(void)
{
	unsigned char *p;
	volatile unsigned char x;

	p = map_fixed(0x262000000UL, PROT_READ | PROT_WRITE);
	if (!p) {
		perror("outside mmap");
		return 1;
	}
	memcpy(p, "OUTSIDE!", 8);
	x = p[0];
	(void)x;
	if (trace_has(0x262000000UL)) {
		fprintf(stderr, "outside: traced\n");
		return 1;
	}
	printf("outside ok\n");
	return 0;
}

static int do_wrarm(void)
{
	unsigned char *data;
	unsigned char *code;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("wrarm mmap");
		return 1;
	}
	data[0] = 'A';
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("wrarm rx");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		data[0] = 'B';
	if (faulted) {
		fprintf(stderr, "wrarm: write fault was not swallowed\n");
		return 1;
	}
	if (data[0] != 'B')
		return 1;
	printf("wrarm ok\n");
	return 0;
}

static int do_noneexec(void)
{
	unsigned char *data;
	unsigned char *code;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("noneexec mmap");
		return 1;
	}
	plant(data, "MARKER!!");
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	if (mprotect(data, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("noneexec rx");
		return 1;
	}
	if (!dump_exact(READ_DATA, "MARKER!!")) {
		fprintf(stderr, "noneexec: marker not dumped\n");
		return 1;
	}
	printf("noneexec ok\n");
	return 0;
}

static int do_disarm(void)
{
	unsigned char *data;
	unsigned char *code;
	volatile unsigned char x;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("disarm mmap");
		return 1;
	}
	memcpy(data, "OLDDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "disarm: first trace missing\n");
		return 1;
	}
	if (truncate("/tmp/pagedrop.trace", 0) != 0)
		return 1;
	if (mprotect(data, PAGE, PROT_READ | PROT_WRITE) != 0)
		return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_WRITE) != 0)
		return 1;
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 1;
	x = data[0];
	(void)x;
	if (!trace_has(READ_DATA)) {
		fprintf(stderr, "disarm: second trace missing\n");
		return 1;
	}
	printf("disarm ok\n");
	return 0;
}

static int do_execve(void)
{
	char *argv[] = {"notme", NULL};
	char *envp[] = {"PB_MARK=PBEXECVE", NULL};

	execve("/tmp/pbmatch/notme", argv, envp);
	perror("execve");
	return 1;
}

static int do_execveat(void)
{
	char *argv[] = {"notme", NULL};
	char *envp[] = {"PB_MARK=PBEXECAT", NULL};
	int fd;

	fd = open("/tmp/pbmatch/notme", O_RDONLY);
	if (fd < 0) {
		perror("open payload");
		return 1;
	}
	syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
	perror("execveat");
	return 1;
}

#if defined(__aarch64__)
static int do_tag(void)
{
	unsigned char *p;
	unsigned char *tagged;

	arm_fault();
	p = map_fixed(TAG_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("tag mmap");
		return 1;
	}
	tagged = (unsigned char *)(TAG_ADDR | (TAG_BYTE << 56));
	if (sigsetjmp(fault_env, 1) != 0) {
		fprintf(stderr, "tag: fault was not swallowed\n");
		return 1;
	}
	plant(tagged, "TAGGED!!");
	if (!call_ok(p) || !dump_exact(TAG_ADDR, "TAGGED!!")) {
		fprintf(stderr, "tag: untagged dump missing\n");
		return 1;
	}
	if (dump_exact(TAG_ADDR | (TAG_BYTE << 56), "TAGGED!!")) {
		fprintf(stderr, "tag: dumped under the tagged address\n");
		return 1;
	}
	printf("tag ok\n");
	return 0;
}
#endif

/*
 * MREMAP_DONTUNMAP moves the page and leaves the source mapped, with its
 * protection. An armed source must not be left PROT_NONE with its record
 * gone to the destination: both ends have to read without a fault.
 */
/*
 * Run with data=260000000-280000000, so the source and the destination are
 * both armed. MREMAP_FIXED|MREMAP_DONTUNMAP is valid on 5.10 and 7.0 when
 * the size does not change: the page moves to the fixed address and the
 * source stays mapped. Both ends must then read without a fault, and the
 * moved page must keep its bytes.
 */
static int do_fixeddontunmap(void)
{
	unsigned char *data;
	unsigned char *dst;
	unsigned char *code;
	unsigned char *moved;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	dst = map_fixed(MOVED_ADDR, PROT_READ | PROT_WRITE);
	code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!data || !dst || code == MAP_FAILED) {
		perror("fixeddontunmap mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("fixeddontunmap rx");
		return 1;
	}
	moved = mremap(data, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
		       dst);
	if (moved == MAP_FAILED) {
		perror("fixeddontunmap mremap");
		return 1;
	}
	if (moved != dst) {
		fprintf(stderr, "fixeddontunmap: page not at the fixed address\n");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = moved[0];

		if (x != 'B') {
			fprintf(stderr, "fixeddontunmap: moved page lost its bytes\n");
			return 1;
		}
	}
	if (faulted) {
		fprintf(stderr, "fixeddontunmap: fault on the moved page\n");
		return 1;
	}
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = data[0];

		(void)x;
	}
	if (faulted) {
		fprintf(stderr, "fixeddontunmap: fault on the source\n");
		return 1;
	}
	printf("fixeddontunmap ok\n");
	return 0;
}

static int do_dontunmap(void)
{
	unsigned char *data;
	unsigned char *code;
	unsigned char *moved;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("dontunmap mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("dontunmap rx");
		return 1;
	}
	moved = mremap(data, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, NULL);
	if (moved == MAP_FAILED) {
		perror("dontunmap mremap");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = moved[0];

		if (x != 'B') {
			fprintf(stderr, "dontunmap: moved page lost its bytes\n");
			return 1;
		}
	}
	if (faulted) {
		fprintf(stderr, "dontunmap: fault on the moved page\n");
		return 1;
	}
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = data[0];

		(void)x;
	}
	if (faulted) {
		fprintf(stderr, "dontunmap: fault on the source\n");
		return 1;
	}
	printf("dontunmap ok\n");
	return 0;
}

/*
 * Run after vfork and exec by do_execguard. The new image makes its own
 * PROT_NONE page at the address the parent armed, and its own handler must
 * see the fault. The module must not restore the page from the parent's
 * record, nor from a copy of it. The sleep lets the parent's fork
 * bookkeeping finish first.
 */
static int do_guard_child(void)
{
	unsigned char *p;

	usleep(100000);
	p = map_fixed(READ_DATA, PROT_NONE);
	if (!p) {
		perror("guardchild mmap");
		return 2;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = p[0];

		(void)x;
	}
	if (!faulted) {
		fprintf(stderr, "execguard: the child's guard page was readable\n");
		return 1;
	}
	return 0;
}

static int do_execguard(void)
{
	unsigned char *data;
	unsigned char *code;
	pid_t pid;
	int st;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("execguard mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("execguard rx");
		return 1;
	}
	pid = vfork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		execl("/proc/self/exe", "guardchild", (char *)NULL);
		_exit(3);
	}
	if (waitpid(pid, &st, 0) < 0)
		return 1;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		fprintf(stderr, "execguard: child status %#x\n", st);
		return 1;
	}
	printf("execguard ok\n");
	return 0;
}

/*
 * A comm with a space and a newline, then a dump. The index line must
 * still be one line of five fields; run_tests.sh checks it.
 */
static int do_commname(void)
{
	unsigned char *p;

	if (prctl(PR_SET_NAME, "ex tra\nx", 0, 0, 0) != 0) {
		perror("commname prctl");
		return 1;
	}
	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("commname mmap");
		return 1;
	}
	memcpy(p + 16, "COMMNAME", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("commname rx");
		return 1;
	}
	if (!dump_exact(0, "COMMNAME")) {
		fprintf(stderr, "commname: marker not dumped\n");
		return 1;
	}
	printf("commname ok\n");
	return 0;
}

/*
 * A store to code that was only ever read-execute is the program's own
 * fault and must reach its handler. The module once stripped exec from
 * the page, left it read-only, and swallowed the fault, so the store
 * faulted again forever. alarm() turns that into a failure.
 */
static int do_rowrite(void)
{
	unsigned char *p;

	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("rowrite mmap");
		return 1;
	}
	memcpy(p + 16, "ROWRITE!", 8);
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("rowrite rx");
		return 1;
	}
	arm_fault();
	alarm(3);
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)p = 1;
	alarm(0);
	if (!faulted) {
		fprintf(stderr, "rowrite: store to read-execute page succeeded\n");
		return 1;
	}
	printf("rowrite ok\n");
	return 0;
}

/*
 * The window before the parent copies its records into a fork child,
 * made deterministic: after vfork the parent only runs pb_note_child once
 * the child has exited. The child stores to the parent's RWX page, which
 * the module keeps read-execute. That fault is the module's, so the child
 * must not get a SIGSEGV. vfork shares the memory, so the parent sees the
 * store.
 */
/*
 * Run with data=260000000-260001000. A vfork child stays in its copy window
 * for its whole life: the parent runs pb_note_child only once the child has
 * exited. A child forked inside that window must get the records of the
 * nearest ancestor that owns them, here the vfork parent, not the empty set
 * of its own parent. The grandchild reads the armed page, and without those
 * records the read is a real SIGSEGV.
 */
static int do_vforkfork(void)
{
	unsigned char *data;
	unsigned char *code;
	pid_t pid;
	int st;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("vforkfork mmap");
		return 1;
	}
	memcpy(data, "BYTECODE", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("vforkfork rx");
		return 1;
	}
	pid = vfork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		long c;
		int cst;

		/*
		 * Any hooked call lists this child, as a child of a tracked
		 * process that does not own its records yet. munmap of an
		 * unmapped range changes nothing in the shared mm.
		 */
		munmap((void *)0x2b0000000UL, PAGE);
		c = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
		if (c == 0)
			_exit(*(volatile unsigned char *)data == 'B' ? 0 : 2);
		if (c < 0)
			_exit(3);
		if (waitpid(c, &cst, 0) < 0)
			_exit(4);
		if (WIFSIGNALED(cst))
			_exit(100 + WTERMSIG(cst));
		_exit(WIFEXITED(cst) ? WEXITSTATUS(cst) : 5);
	}
	if (waitpid(pid, &st, 0) < 0)
		return 1;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		if (WIFEXITED(st) && WEXITSTATUS(st) > 100)
			fprintf(stderr, "vforkfork: grandchild killed by signal %d\n",
				WEXITSTATUS(st) - 100);
		else
			fprintf(stderr, "vforkfork: status %#x\n", st);
		return 1;
	}
	printf("vforkfork ok\n");
	return 0;
}

static int do_vforkwrite(void)
{
	unsigned char *p;
	pid_t pid;
	int st;

	p = map_fixed(WX_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!p) {
		perror("vforkwrite mmap");
		return 1;
	}
	pid = vfork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		*(volatile unsigned char *)p = 0x42;
		_exit(0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return 1;
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
		fprintf(stderr, "vforkwrite: child status %#x\n", st);
		return 1;
	}
	if (p[0] != 0x42) {
		fprintf(stderr, "vforkwrite: store not visible\n");
		return 1;
	}
	printf("vforkwrite ok\n");
	return 0;
}

/*
 * MAP_FIXED with RWX over an armed data page. The armed record belongs to
 * the old mapping. If it survives, a store to the new page is taken for a
 * read of armed data: its old protection is restored and a trace line is
 * written. The store must be handled as a W^X write, with no trace line.
 */
static int do_fixedwx(void)
{
	unsigned char *data;
	unsigned char *code;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("fixedwx mmap");
		return 1;
	}
	memcpy(data, "OLDDATA!", 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("fixedwx rx");
		return 1;
	}
	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (!data) {
		perror("fixedwx remap");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)data = 1;
	if (faulted) {
		fprintf(stderr, "fixedwx: store to the new RWX page faulted\n");
		return 1;
	}
	if (trace_has(READ_DATA)) {
		fprintf(stderr, "fixedwx: the old armed record handled the store\n");
		return 1;
	}
	printf("fixedwx ok\n");
	return 0;
}

/*
 * Make wx an RWX page again. The module keeps it read-execute, with a
 * record that allows the next store, as right after mmap.
 */
static int badprot_rearm(unsigned char *wx)
{
	if (mprotect(wx, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		perror("badprot rwx");
		return 1;
	}
	return 0;
}

static int badprot_store(unsigned char *wx, const char *what)
{
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)wx = 1;
	if (faulted) {
		fprintf(stderr, "badprot: store to the RWX page faulted after %s\n", what);
		return 1;
	}
	return 0;
}

/*
 * A failed mprotect must leave the module's records as they were. The
 * prot bit 0x8000 is invalid on x86_64 and arm64, and pkey 15 is never
 * allocated here, so these calls fail with EINVAL before any VMA is
 * touched. arm64 before 6.12 has no pkeys, and pkey_mprotect fails with
 * ENOSYS instead. A W^X page the module keeps read-execute must still take a
 * store after each of them, including the ones that ask for exactly the
 * read-execute protection the page already has. And a failed
 * mprotect(RWX) of a read-write page must not let the module make it
 * executable.
 */
static int do_badprot(void)
{
	unsigned char *wx;
	unsigned char *rw;

	wx = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	rw = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (wx == MAP_FAILED || rw == MAP_FAILED) {
		perror("badprot mmap");
		return 1;
	}
	if (mprotect(wx, PAGE, PROT_READ | 0x8000) == 0 || errno != EINVAL) {
		fprintf(stderr, "badprot: mprotect did not fail with EINVAL\n");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)wx = 1;
	if (faulted) {
		fprintf(stderr, "badprot: store to the RWX page faulted\n");
		return 1;
	}
	if (badprot_rearm(wx))
		return 1;
	if (mprotect(wx, PAGE, PROT_READ | PROT_EXEC | 0x8000) == 0 || errno != EINVAL) {
		fprintf(stderr, "badprot: mprotect(RX|0x8000) did not fail with EINVAL\n");
		return 1;
	}
	if (badprot_store(wx, "a failed mprotect(RX)"))
		return 1;
	if (badprot_rearm(wx))
		return 1;
	if (syscall(SYS_pkey_mprotect, wx, PAGE, PROT_READ | PROT_EXEC, 15) == 0) {
		fprintf(stderr, "badprot: pkey_mprotect with pkey 15 succeeded\n");
		return 1;
	}
	if (badprot_store(wx, "a failed pkey_mprotect(RX)"))
		return 1;
	plant(rw, "BADPROT!");
	if (mprotect(rw, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC | 0x8000) == 0 ||
	    errno != EINVAL) {
		fprintf(stderr, "badprot: mprotect(RWX) did not fail with EINVAL\n");
		return 1;
	}
	if (call_ok(rw)) {
		fprintf(stderr, "badprot: a read-write page ran\n");
		return 1;
	}
	printf("badprot ok\n");
	return 0;
}

/*
 * Run with data=260000000-280000000, so the source and the destination
 * are both armed. The source is read-only, the destination read-write.
 * After MREMAP_FIXED moves the source over the destination, only the
 * source's record may describe that address: a read must work and a store
 * must fault. A surviving destination record would restore read-write.
 */
static int do_fixedover(void)
{
	unsigned char *src;
	unsigned char *dst;
	unsigned char *code;
	unsigned char *moved;

	src = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	dst = map_fixed(MOVED_ADDR, PROT_READ | PROT_WRITE);
	code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!src || !dst || code == MAP_FAILED) {
		perror("fixedover mmap");
		return 1;
	}
	memcpy(src, "BYTECODE", 8);
	if (mprotect(src, PAGE, PROT_READ) != 0) {
		perror("fixedover ro");
		return 1;
	}
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("fixedover rx");
		return 1;
	}
	moved = mremap(src, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
	if (moved == MAP_FAILED) {
		perror("fixedover mremap");
		return 1;
	}
	arm_fault();
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0) {
		volatile unsigned char x = moved[0];

		if (x != 'B') {
			fprintf(stderr, "fixedover: moved page lost its bytes\n");
			return 1;
		}
	}
	if (faulted) {
		fprintf(stderr, "fixedover: read of the moved page faulted\n");
		return 1;
	}
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)moved = 1;
	if (!faulted) {
		fprintf(stderr, "fixedover: store to the read-only page succeeded\n");
		return 1;
	}
	printf("fixedover ok\n");
	return 0;
}

/*
 * An mprotect that fails part way still applies what came before the
 * failure. Here an RWX page, which the module keeps read-execute, is
 * followed by a hole. mprotect(RX) over both applies RX to the page, a
 * no-op for its VMA, then fails on the hole with ENOMEM. The program has
 * forbidden writes to the page, so a store must fault. The module must not
 * put back the RWX record it had before the call.
 */
static int do_partial(void)
{
	unsigned char *p;

	p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("partial mmap");
		return 1;
	}
	if (munmap(p + PAGE, PAGE) != 0) {
		perror("partial munmap");
		return 1;
	}
	if (mprotect(p, 2 * PAGE, PROT_READ | PROT_EXEC) == 0 || errno != ENOMEM) {
		fprintf(stderr, "partial: mprotect did not fail with ENOMEM\n");
		return 1;
	}
	arm_fault();
	alarm(3);
	faulted = 0;
	if (sigsetjmp(fault_env, 1) == 0)
		*(volatile unsigned char *)p = 1;
	alarm(0);
	if (!faulted) {
		fprintf(stderr, "partial: store allowed after RX was applied\n");
		return 1;
	}
	printf("partial ok\n");
	return 0;
}

static int is_named(const char *argv0, const char *name)
{
	const char *base = strrchr(argv0, '/');

	base = base ? base + 1 : argv0;
	return strcmp(base, name) == 0;
}

static int is_payload(const char *argv0)
{
	return is_named(argv0, "notme");
}

static int do_stale_helper(void)
{
	void (*f)(void) = (void (*)(void))EPOCH_ADDR;

	alarm(2);
	f();
	printf("stale helper returned\n");
	return 0;
}

static int do_stale(void)
{
	void *p;
	char *argv[] = {"stalehelper", NULL};
	char *envp[] = {NULL};

	p = map_fixed(EPOCH_ADDR, PROT_READ | PROT_WRITE);
	if (!p) {
		perror("stale mmap");
		return 1;
	}
	if (mprotect(p, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("stale rx");
		return 1;
	}
	execve("/tmp/stalehelper", argv, envp);
	perror("stale exec");
	return 1;
}

int main(int argc, char **argv)
{
	if (argc < 1)
		return 2;
	if (is_payload(argv[0]))
		return do_payload();
	if (is_named(argv[0], "stalehelper"))
		return do_stale_helper();
	if (is_named(argv[0], "guardchild"))
		return do_guard_child();
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "epoch"))
		return do_epoch();
	if (!strcmp(argv[1], "flip"))
		return do_flip();
	if (!strcmp(argv[1], "regs"))
		return do_regs();
	if (!strcmp(argv[1], "fail"))
		return do_fail();
	if (!strcmp(argv[1], "read"))
		return do_read();
	if (!strcmp(argv[1], "forkread"))
		return do_forkread();
	if (!strcmp(argv[1], "forkrace"))
		return do_forkrace();
	if (!strcmp(argv[1], "dumprace"))
		return do_dumprace();
	if (!strcmp(argv[1], "armrace"))
		return do_armrace();
	if (!strcmp(argv[1], "mremaprace"))
		return do_mremaprace();
	if (!strcmp(argv[1], "datarace"))
		return do_datarace();
	if (!strcmp(argv[1], "munmaprace"))
		return do_munmaprace();
	if (!strcmp(argv[1], "clonevm"))
		return do_clonevm();
	if (!strcmp(argv[1], "execrace"))
		return do_execrace();
	if (!strcmp(argv[1], "maymove"))
		return do_maymove();
	if (!strcmp(argv[1], "pin"))
		return do_pin();
	if (!strcmp(argv[1], "pinmove"))
		return do_pinmove();
	if (!strcmp(argv[1], "roarm"))
		return do_roarm();
	if (!strcmp(argv[1], "moveread"))
		return do_moveread();
	if (!strcmp(argv[1], "rearm"))
		return do_rearm();
	if (!strcmp(argv[1], "fixed"))
		return do_fixed();
	if (!strcmp(argv[1], "pair"))
		return do_pair();
	if (!strcmp(argv[1], "vfork"))
		return do_vfork();
	if (!strcmp(argv[1], "outside"))
		return do_outside();
	if (!strcmp(argv[1], "wrarm"))
		return do_wrarm();
	if (!strcmp(argv[1], "noneexec"))
		return do_noneexec();
	if (!strcmp(argv[1], "disarm"))
		return do_disarm();
	if (!strcmp(argv[1], "vforkwrite"))
		return do_vforkwrite();
	if (!strcmp(argv[1], "vforkfork"))
		return do_vforkfork();
	if (!strcmp(argv[1], "fixedover"))
		return do_fixedover();
	if (!strcmp(argv[1], "partial"))
		return do_partial();
	if (!strcmp(argv[1], "badprot"))
		return do_badprot();
	if (!strcmp(argv[1], "fixedwx"))
		return do_fixedwx();
	if (!strcmp(argv[1], "rowrite"))
		return do_rowrite();
	if (!strcmp(argv[1], "commname"))
		return do_commname();
	if (!strcmp(argv[1], "dontunmap"))
		return do_dontunmap();
	if (!strcmp(argv[1], "fixeddontunmap"))
		return do_fixeddontunmap();
	if (!strcmp(argv[1], "execguard"))
		return do_execguard();
	if (!strcmp(argv[1], "stale"))
		return do_stale();
	if (!strcmp(argv[1], "execve"))
		return do_execve();
	if (!strcmp(argv[1], "execveat"))
		return do_execveat();
#if defined(__aarch64__)
	if (!strcmp(argv[1], "tag"))
		return do_tag();
	if (!strcmp(argv[1], "tagrace"))
		return do_tagrace();
#endif
	fprintf(stderr, "usage: extra epoch|flip|regs|fail|read|forkread|forkrace|pin|pinmove|dumprace|armrace|mremaprace|datarace|munmaprace|clonevm|execrace|maymove|roarm|moveread|rearm|fixed|pair|vfork|outside|wrarm|noneexec|disarm|rowrite|vforkwrite|vforkfork|fixedwx|badprot|partial|fixedover|commname|dontunmap|fixeddontunmap|execguard|stale|execve|execveat|tag|tagrace\n");
	return 2;
}
