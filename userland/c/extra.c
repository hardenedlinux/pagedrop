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
/* glibc does not expose MREMAP_DONTUNMAP; the value has been 4 since 5.7. */
/* A tracked W+X page, used by the failed-mprotect cases. */
#define WX_ADDR 0x220000000UL

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#define READ_DATA 0x260000000UL
#define READ_CODE 0x261000000UL
/*
 * How many index rows the second phase may add. Measured as a delta, not an
 * absolute: a plain run of this case already writes about 450 rows for the
 * process's own executable pages (libc, ld, the binary), so an absolute bound
 * has to be set above the baseline and stops being a check. An earlier attempt
 * keyed the re-arm on the global epoch counter and produced 177,256 read rows
 * in one dumprace run; this bound is what would have caught it.
 */
#define EPOCHREAD_MAX_ROWS 16
#define MOVED_ADDR 0x270000000UL
/*
 * Destinations for our own move cases. These must not collide with an
 * address any other case uses: OUT_TWO was 0x270000000, the same address as
 * MOVED_ADDR, so a case that maps its destination at MOVED_ADDR and a case
 * that maps a page at OUT_TWO interfere through the module's records and the
 * failure looks like a module bug in whichever ran second.
 */
#define OUT_ONE 0x2a0000000UL
#define OUT_TWO 0x2c0000000UL
/*
 * do_vforkfork hard-codes 0x2b0000000 for its munmap probe, taken from
 * upstream. OUT_TWO must stay clear of it, which is why these moved once
 * already: a destination address shared with a case that arms pages makes
 * the two interfere through the module's records and the failure looks
 * like a module bug.
 */
#define VFORK_PROBE 0x2b0000000UL
#define TAG_BYTE 0x5aUL

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

static int dump_head(unsigned long want, const char *mark, int n)
{
	DIR *d;
	struct dirent *de;
	unsigned char buf[32];
	int found = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d)) && !found) {
		unsigned long addr, epoch;
		char path[320];
		int fd;

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (addr != want)
			continue;
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, buf, n) == n && memcmp(buf, mark, n) == 0)
			found = 1;
		close(fd);
	}
	closedir(d);
	return found;
}

static int badprot_rearm(unsigned char *wx);
static int do_guard_child(void);
static int badprot_store(unsigned char *wx, const char *what);

static void show_range(const char *tag, unsigned long lo, unsigned long hi)
{
	unsigned char vec[PAGE];
	unsigned long a, end;
	FILE *f;
	char line[256];

	printf("%s maps:\n", tag);
	f = fopen("/proc/self/maps", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &a, &end) != 2)
			continue;
		if (end <= lo || a >= hi)
			continue;
		printf("  %s", line);
	}
	fclose(f);
	for (a = lo; a < hi; a += PAGE) {
		int rc = mincore((void *)a, PAGE, vec);

		printf("%s mincore %lx rc=%d %s\n", tag, a, rc,
		       rc == 0 ? (vec[0] & 1 ? "resident" : "not-resident")
			       : "unmapped");
	}
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

static int read_ok(unsigned long addr, unsigned char *out, int n)
{
	faulted = 0;
	if (sigsetjmp(fault_env, 1) != 0)
		return 0;
	memcpy(out, (const void *)addr, (size_t)n);
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

static int trace_count(unsigned long va)
{
	FILE *f;
	char line[128];
	int n = 0;

	f = fopen("/tmp/pagedrop.trace", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof line, f)) {
		unsigned long ip, data, epoch;

		if (sscanf(line, "%lx %lx %lu", &ip, &data, &epoch) != 3)
			continue;
		if (data == va)
			n++;
	}
	fclose(f);
	return n;
}

static int index_rows(void)
{
	FILE *f = fopen("/tmp/pagedrop.index", "r");
	char line[256];
	int n = 0;

	if (!f)
		return 0;
	while (fgets(line, sizeof line, f))
		n++;
	fclose(f);
	return n;
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

/*
 * One data page read through two handler versions must be traced twice.
 *
 * A read fault restores the page and keeps its record, so the page never
 * faults again and the address would be observed once for the life of the
 * process. Re-mprotect the handler page so its epoch advances, read the same
 * data address again, and the second read must be traced at the new epoch.
 *
 * The row ceiling is load-bearing and is the reason this case can be trusted.
 * An earlier attempt keyed the re-arm on the global epoch counter, which
 * advances on every dump of any page, so each re-arm bought another fault and
 * another dump: one dumprace run produced 177,256 read rows. Asserting the
 * trace count alone would not have caught that, because the first two lines
 * still appear in the right order. Bound the total work instead.
 */
static int do_epochread(void)
{
	unsigned char *data;
	unsigned char *code;
	int first, second, rows_before, rows_after;

	data = map_fixed(READ_DATA, PROT_READ | PROT_WRITE);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!data || !code) {
		perror("epochread mmap");
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
		perror("epochread rx");
		return 1;
	}
	arm_fault();
	if (!call_ok(code)) {
		fprintf(stderr, "epochread: first load fault not swallowed\n");
		return 1;
	}
	first = trace_count(READ_DATA);
	rows_before = index_rows();
	if (first != 1) {
		fprintf(stderr, "epochread: first read traced %d times, want 1\n",
			first);
		return 1;
	}
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("epochread re-rx");
		return 1;
	}
	if (!call_ok(code)) {
		fprintf(stderr, "epochread: second load fault not swallowed\n");
		return 1;
	}
	second = trace_count(READ_DATA);
	if (second != 2) {
		fprintf(stderr, "epochread: after a new handler epoch traced %d "
			"times, want 2\n", second);
		return 1;
	}
	rows_after = index_rows();
	if (rows_after - rows_before > EPOCHREAD_MAX_ROWS) {
		fprintf(stderr, "epochread: the second handler version added %d "
			"index rows, want at most %d; the re-arm is feeding "
			"itself\n", rows_after - rows_before, EPOCHREAD_MAX_ROWS);
		return 1;
	}
	printf("epochread ok\n");
	return 0;
}

/*
 * One mprotect makes a two page range inside data= executable, and the
 * handler that runs out of the first page reads a byte of the second. The
 * code page and the armed range are the same address, which is what read
 * is not: there the mprotect range is entirely outside data=. If the arming
 * does not survive the real mprotect the whole range is left readable, the
 * read never faults, and there is no trace line and no data dump.
 */
static int do_armexec(void)
{
	unsigned long lo = READ_DATA;
	unsigned long hi = READ_DATA + 2 * PAGE;
	unsigned long data_va = READ_DATA + PAGE;
	unsigned char *p;

	p = mmap((void *)lo, 2 * PAGE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		perror("armexec mmap");
		return 1;
	}
	memcpy(p + PAGE, "BYTECODE", 8);
#if defined(__aarch64__)
	{
		uint32_t *w = (uint32_t *)p;
		unsigned long v = data_va;

		/*
		 * Build the stub from data_va at run time. The old arm64 stub
		 * hard-coded mov x1,#0x100 and therefore never read data_va, so
		 * the case could not pass on this arch in either direction and
		 * the suite's only red case was the module's fault on paper
		 * only. Materialise the address into x0 with movz plus three
		 * movk, load the byte the same way the x86 stub does, return.
		 */
		w[0] = 0xd2800000u | (uint32_t)((v & 0xffffu) << 5);
		w[1] = 0xf2a00000u | (1u << 21) |
			(uint32_t)(((v >> 16) & 0xffffu) << 5);
		w[2] = 0xf2c00000u | (2u << 21) |
			(uint32_t)(((v >> 32) & 0xffffu) << 5);
		w[3] = 0xf2e00000u | (3u << 21) |
			(uint32_t)(((v >> 48) & 0xffffu) << 5);
		w[4] = 0xf9400000;	/* ldr x0, [x0] */
		w[5] = 0xd65f03c0;	/* ret */
	}
#else
	{
		unsigned long src = data_va;
		unsigned char stub[] = {
			0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
			0x48, 0x8b, 0x00,
			0xc3
		};

		memcpy(stub + 2, &src, sizeof(src));
		memcpy(p, stub, sizeof(stub));
	}
#endif
	arm_fault();
	if (mprotect(p, 2 * PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("armexec rx");
		return 1;
	}
	show_range("after-mprotect", lo, hi);
	if (!call_ok(p)) {
		fprintf(stderr, "armexec: load fault was not swallowed\n");
		return 1;
	}
	show_range("after-call", lo, hi);
	if (!trace_has(data_va)) {
		fprintf(stderr, "armexec: trace missing for %lx\n", data_va);
		return 1;
	}
	if (!dump_head(data_va, "BYTECODE", 8)) {
		fprintf(stderr, "armexec: data page not dumped\n");
		return 1;
	}
	printf("armexec ok\n");
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
	/* Hold the page inaccessible. Reading it here would restore the
	 * protection and release the pin, which is the other case. */
	usleep(1500000);
	printf("pin ok\n");
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

/*
 * MREMAP_FIXED out of the armed range. The first move is one armed page to a
 * destination outside data=, the shape cycle 1 covered. The second moves two
 * armed pages at once, with the first destination page inside data= and the
 * second outside it. A page that leaves the armed range must not be settled
 * with an mprotect before the move: that splits the source VMA, mremap needs
 * one mapping, and the kernel refuses the whole move with EFAULT.
 */
static int do_moveout(void)
{
	static const char marks[3][9] = { "MOVEAAA!", "MOVEBBB!", "MOVECCC!" };
	unsigned char vec[2 * PAGE];
	unsigned char buf[9];
	unsigned long one;
	unsigned long two;
	unsigned char *data;
	unsigned char *code;
	int i;

	data = mmap((void *)READ_DATA, 3 * PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (data == MAP_FAILED) {
		perror("moveout mmap");
		return 1;
	}
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("moveout code");
		return 1;
	}
	for (i = 0; i < 3; i++)
		memcpy(data + (unsigned long)i * PAGE + 16, marks[i], 8);
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("moveout rx");
		return 1;
	}
	arm_fault();

	one = (unsigned long)mremap(data + 2 * PAGE, PAGE, PAGE,
				    MREMAP_MAYMOVE | MREMAP_FIXED,
				    (void *)OUT_ONE);
	if (one != OUT_ONE) {
		fprintf(stderr, "moveout: one page ret=%lx errno=%d (%s)\n",
			one, errno, strerror(errno));
		return 1;
	}
	if (!read_ok(one + 16, buf, 8) || memcmp(buf, marks[2], 8)) {
		fprintf(stderr, "moveout: one page not readable at %lx\n", one);
		return 1;
	}

	two = (unsigned long)mremap(data, 2 * PAGE, 2 * PAGE,
				    MREMAP_MAYMOVE | MREMAP_FIXED,
				    (void *)OUT_TWO);
	if (two != OUT_TWO) {
		fprintf(stderr, "moveout: two page ret=%lx errno=%d (%s)\n",
			two, errno, strerror(errno));
		return 1;
	}
	if (mincore((void *)READ_DATA, PAGE, vec) == 0) {
		fprintf(stderr, "moveout: source still mapped\n");
		return 1;
	}
	if (mincore((void *)OUT_TWO, 2 * PAGE, vec) != 0) {
		perror("moveout mincore dst");
		return 1;
	}
	for (i = 0; i < 2; i++) {
		unsigned long at = two + (unsigned long)i * PAGE;

		if (!read_ok(at + 16, buf, 8) || memcmp(buf, marks[i], 8)) {
			fprintf(stderr, "moveout: page %d not readable at %lx\n",
				i, at);
			return 1;
		}
	}
	printf("moveout ok\n");
	return 0;
}

/*
 * Two armed pages moved so the destination straddles the end of data=, and
 * then the target's own MREMAP_FIXED over that span. 6.8 mremap needs
 * uniform protection across the old range, and a restore that walks the
 * destination one page at a time leaves the page inside data= PROT_NONE and
 * gives the page outside it its recorded protection back, which is a split
 * the module made itself: the second move returns EFAULT and the
 * destination is unmapped, where the same program with the module unloaded
 * gets the address back. Nothing touches the destination between the two
 * moves, so the split is the module's alone. do_moveout stops where this
 * starts and its three data pages are one mapping, so both records save the
 * same protection and the destination stays uniform.
 *
 * The two data pages are deliberately the same protection. Adjacent armed
 * pages with different recorded protections cannot be the geometry here:
 * 6.8 refuses a non-uniform source whatever the module does, so the program
 * with the module unloaded never gets past the first move and there is no
 * artifact A to compare against.
 */
static int do_movespan(void)
{
	static const char marks[2][9] = { "SPANAAA!", "SPANBBB!" };
	unsigned char vec[2 * PAGE];
	unsigned char buf[9];
	unsigned long one, two;
	unsigned char *code;
	int i;

	if (!map_fixed(READ_DATA, PROT_READ | PROT_WRITE) ||
	    !map_fixed(READ_DATA + PAGE, PROT_READ | PROT_WRITE)) {
		perror("movespan mmap");
		return 1;
	}
	for (i = 0; i < 2; i++)
		memcpy((void *)(READ_DATA + (unsigned long)i * PAGE + 16),
		       marks[i], 8);
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("movespan code");
		return 1;
	}
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("movespan rx");
		return 1;
	}
	arm_fault();
	if (!map_fixed(OUT_ONE, PROT_READ | PROT_WRITE)) {
		perror("movespan guard");
		return 1;
	}
	plant((void *)OUT_ONE, "GUARD!!!");

	one = (unsigned long)mremap((void *)READ_DATA, 2 * PAGE, 2 * PAGE,
				    MREMAP_MAYMOVE | MREMAP_FIXED,
				    (void *)OUT_TWO);
	if (one != OUT_TWO) {
		fprintf(stderr, "movespan: first ret=%lx errno=%d (%s)\n",
			one, errno, strerror(errno));
		return 1;
	}
	show_range("movespan straddle", OUT_TWO, OUT_TWO + 2 * PAGE);

	two = (unsigned long)mremap((void *)OUT_TWO, 2 * PAGE, 2 * PAGE,
				    MREMAP_MAYMOVE | MREMAP_FIXED,
				    (void *)OUT_ONE);
	if (two != OUT_ONE) {
		fprintf(stderr, "movespan: second ret=%lx errno=%d (%s)\n",
			two, errno, strerror(errno));
		return 1;
	}
	if (mincore((void *)OUT_ONE, 2 * PAGE, vec) != 0) {
		perror("movespan mincore dst");
		return 1;
	}
	if (mincore((void *)OUT_TWO, PAGE, vec) == 0) {
		fprintf(stderr, "movespan: straddle still mapped\n");
		return 1;
	}
	for (i = 0; i < 2; i++) {
		unsigned long at = two + (unsigned long)i * PAGE;

		if (!read_ok(at + 16, buf, 8) || memcmp(buf, marks[i], 8)) {
			fprintf(stderr, "movespan: page %d not live at %lx\n",
				i, at);
			return 1;
		}
	}
	printf("movespan ok\n");
	return 0;
}

/*
 * One page of a three page armed run is mprotect'ed back to the protection it
 * already had, and the target then moves the whole run with MREMAP_FIXED to a
 * destination outside data=. 6.8 mremap needs uniform protection across the old
 * range. A disarm that settles one armed page at a time with its own protection,
 * before the syscall, leaves the pages the call did not name still PROT_NONE,
 * and the kernel rewrites only the named page, so the split survives the
 * mprotect. The target's own move is then refused with EFAULT and the
 * destination is unmapped, where the same program with the module unloaded gets
 * the destination address and its own markers back.
 *
 * The control can run the whole program here, which is what separates this from
 * the differing protection destination case: the target chose the subset
 * itself, so nothing is split when the module is out. The destination is a
 * marked page, so a refused move is visible as the marker being gone and not
 * only as a return value.
 */
static int do_mppart(void)
{
	static const char marks[3][9] = { "MPPTAAA!", "MPPTBBB!", "MPPTCCC!" };
	unsigned char vec[3 * PAGE];
	unsigned char buf[9];
	unsigned long one;
	unsigned char *code;
	int i;

	for (i = 0; i < 3; i++) {
		if (!map_fixed(READ_DATA + (unsigned long)i * PAGE,
			       PROT_READ | PROT_WRITE)) {
			perror("mppart mmap");
			return 1;
		}
		memcpy((void *)(READ_DATA + (unsigned long)i * PAGE + 16),
		       marks[i], 8);
	}
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("mppart code");
		return 1;
	}
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("mppart rx");
		return 1;
	}
	arm_fault();
	show_range("armed", READ_DATA, READ_DATA + 3 * PAGE);
	if (!map_fixed(OUT_ONE, PROT_READ | PROT_WRITE)) {
		perror("mppart dest");
		return 1;
	}
	plant((void *)OUT_ONE, "MPPTDEST");
	show_range("dest-before", OUT_ONE, OUT_ONE + PAGE);

	/* a strict subset: one page of the three, and the protection it had */
	if (mprotect((void *)READ_DATA, PAGE, PROT_READ | PROT_WRITE) != 0) {
		perror("mppart subset");
		return 1;
	}
	show_range("after-subset", READ_DATA, READ_DATA + 3 * PAGE);

	one = (unsigned long)mremap((void *)READ_DATA, 3 * PAGE, 3 * PAGE,
				    MREMAP_MAYMOVE | MREMAP_FIXED,
				    (void *)OUT_ONE);
	if (one != OUT_ONE) {
		fprintf(stderr, "mppart: ret=%lx errno=%d (%s) REFUSED\n",
			one, errno, strerror(errno));
		show_range("dest-after", OUT_ONE, OUT_ONE + PAGE);
		return 1;
	}
	show_range("dest-after", OUT_ONE, OUT_ONE + 3 * PAGE);
	if (mincore((void *)READ_DATA, PAGE, vec) == 0) {
		fprintf(stderr, "mppart: source still mapped\n");
		return 1;
	}
	if (mincore((void *)OUT_ONE, 3 * PAGE, vec) != 0) {
		perror("mppart mincore dst");
		return 1;
	}
	for (i = 0; i < 3; i++) {
		unsigned long at = one + (unsigned long)i * PAGE;

		if (!read_ok(at + 16, buf, 8) || memcmp(buf, marks[i], 8)) {
			fprintf(stderr, "mppart: page %d not live at %lx\n",
				i, at);
			return 1;
		}
	}
	printf("mppart ok\n");
	return 0;
}

/*
 * mppart with an unaligned start. Same three page armed run, same target
 * chosen strict subset, but the subset mprotect starts half a page in, so the
 * kernel rewrites two pages of the run and not one. The re-arm after the
 * syscall walks pb_page_count(len) pages from addr & PAGE_MASK, which is one
 * page here, so the second rewritten page is left readable with a record that
 * still claims PROT_NONE. The run is split again and the target's own move
 * is refused, which is the class mppart exists to catch.
 */
static int do_mpunalign(void)
{
	static const char marks[3][9] = { "MPUNAAA!", "MPUNBBB!", "MPUNCCC!" };
	unsigned char vec[3 * PAGE];
	unsigned char buf[9];
	unsigned long one;
	unsigned char *code;
	int i;

	for (i = 0; i < 3; i++) {
		if (!map_fixed(READ_DATA + (unsigned long)i * PAGE,
			       PROT_READ | PROT_WRITE)) {
			perror("mpunalign mmap");
			return 1;
		}
		memcpy((void *)(READ_DATA + (unsigned long)i * PAGE + 16),
		       marks[i], 8);
	}
	code = map_fixed(READ_CODE, PROT_READ | PROT_WRITE);
	if (!code) {
		perror("mpunalign code");
		return 1;
	}
	if (mprotect(code, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("mpunalign rx");
		return 1;
	}
	arm_fault();
	show_range("armed", READ_DATA, READ_DATA + 3 * PAGE);
	if (!map_fixed(OUT_ONE, PROT_READ | PROT_WRITE)) {
		perror("mpunalign dest");
		return 1;
	}
	plant((void *)OUT_ONE, "MPUNDEST");
	show_range("dest-before", OUT_ONE, OUT_ONE + PAGE);

	/* a strict subset starting half a page in: two pages are rewritten */
	if (mprotect((void *)(READ_DATA + PAGE / 2), PAGE,
		     PROT_READ | PROT_WRITE) != 0) {
		perror("mpunalign subset");
		return 1;
	}
	show_range("after-subset", READ_DATA, READ_DATA + 3 * PAGE);

	one = (long)mremap((void *)READ_DATA, 3 * PAGE, 3 * PAGE,
			   MREMAP_MAYMOVE | MREMAP_FIXED, (void *)OUT_ONE);
	if (one != (long)OUT_ONE) {
		fprintf(stderr, "mpunalign: ret=%lx errno=%d (%s) REFUSED\n",
			one, errno, strerror(errno));
		show_range("dest-after", OUT_ONE, OUT_ONE + PAGE);
		return 1;
	}
	show_range("dest-after", OUT_ONE, OUT_ONE + 3 * PAGE);
	if (mincore((void *)READ_DATA, PAGE, vec) == 0) {
		fprintf(stderr, "mpunalign: source still mapped\n");
		return 1;
	}
	if (mincore((void *)OUT_ONE, 3 * PAGE, vec) != 0) {
		perror("mpunalign mincore dst");
		return 1;
	}
	for (i = 0; i < 3; i++) {
		unsigned long at = one + (unsigned long)i * PAGE;

		if (!read_ok(at + 16, buf, 8) || memcmp(buf, marks[i], 8)) {
			fprintf(stderr, "mpunalign: page %d not live at %lx\n",
				i, at);
			return 1;
		}
	}
	printf("mpunalign ok\n");
	return 0;
}

/*
 * mppart with two changes the fix introduced rather than removed. The subset
 * page is mprotect'ed to a protection its neighbours do not have, and the
 * target then reads that page, which is the read the re-arm exists to serve.
 * The re-arm records the protection the kernel installed for the named page
 * only, so the three records now differ. pb_armed_run restores the run of
 * pages that record the same protection, so the read puts one r-- page next
 * to two PROT_NONE pages again and the target's own move is refused.
 */
static int do_mpmix(void)
{
	static const char marks[3][9] = { "MPMXAAA!", "MPMXBBB!", "MPMXCCC!" };
	unsigned char vec[3 * PAGE];
	unsigned char buf[9];
	unsigned long one;
	unsigned char *p;
	int i;

	p = mmap((void *)READ_DATA, 3 * PAGE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		perror("mpmix mmap");
		return 1;
	}
	for (i = 0; i < 3; i++)
		memcpy((void *)(READ_DATA + (unsigned long)i * PAGE + 16),
		       marks[i], 8);
	if (!map_fixed(READ_CODE, PROT_READ | PROT_WRITE)) {
		perror("mpmix code");
		return 1;
	}
	if (mprotect((void *)READ_CODE, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("mpmix rx");
		return 1;
	}
	arm_fault();
	show_range("armed", READ_DATA, READ_DATA + 3 * PAGE);
	if (!map_fixed(OUT_ONE, PROT_READ | PROT_WRITE)) {
		perror("mpmix dest");
		return 1;
	}
	plant((void *)OUT_ONE, "MPMXDEST");

	/* a strict subset, and a protection the other two pages do not have */
	if (mprotect((void *)READ_DATA, PAGE, PROT_READ) != 0) {
		perror("mpmix subset");
		return 1;
	}
	show_range("after-subset", READ_DATA, READ_DATA + 3 * PAGE);
	if (!read_ok(READ_DATA + 16, buf, 8) || memcmp(buf, marks[0], 8)) {
		fprintf(stderr, "mpmix: read of the re-armed page failed\n");
		return 1;
	}
	show_range("after-read", READ_DATA, READ_DATA + 3 * PAGE);

	one = (long)mremap((void *)READ_DATA, 3 * PAGE, 3 * PAGE,
			   MREMAP_MAYMOVE | MREMAP_FIXED, (void *)OUT_ONE);
	if (one != (long)OUT_ONE) {
		fprintf(stderr, "mpmix: ret=%lx errno=%d (%s) REFUSED\n",
			one, errno, strerror(errno));
		show_range("dest-after", OUT_ONE, OUT_ONE + PAGE);
		return 1;
	}
	show_range("dest-after", OUT_ONE, OUT_ONE + 3 * PAGE);
	if (mincore((void *)READ_DATA, PAGE, vec) == 0) {
		fprintf(stderr, "mpmix: source still mapped\n");
		return 1;
	}
	if (mincore((void *)OUT_ONE, 3 * PAGE, vec) != 0) {
		perror("mpmix mincore dst");
		return 1;
	}
	for (i = 0; i < 3; i++) {
		unsigned long at = one + (unsigned long)i * PAGE;

		if (!read_ok(at + 16, buf, 8) || memcmp(buf, marks[i], 8)) {
			fprintf(stderr, "mpmix: page %d not live at %lx\n",
				i, at);
			return 1;
		}
	}
	printf("mpmix ok\n");
	return 0;
}

/*
 * A page that has been read once is restored and its record says restored,
 * so nothing needs the module pinned. A successful mprotect naming that page
 * re-arms it and the record says not restored again, so something needs the
 * pin again. Whether anything took it is the question: the process is still
 * alive and the page is PROT_NONE. A reader in the same process then faults
 * into a module that may be gone.
 */
static int do_pinrearm(void)
{
	unsigned char vec[PAGE];
	unsigned char buf[8];
	FILE *f;

	if (!map_fixed(READ_DATA, PROT_READ | PROT_WRITE) ||
	    !map_fixed(READ_CODE, PROT_READ | PROT_WRITE)) {
		perror("pinrearm mmap");
		return 1;
	}
	memcpy((void *)(READ_DATA + 16), "PINREARM", 8);
	if (mprotect((void *)READ_CODE, PAGE, PROT_READ | PROT_EXEC) != 0) {
		perror("pinrearm rx");
		return 1;
	}
	arm_fault();
	if (!read_ok(READ_DATA + 16, buf, 8) || memcmp(buf, "PINREARM", 8)) {
		fprintf(stderr, "pinrearm: first read failed\n");
		return 1;
	}
	show_range("after-read", READ_DATA, READ_DATA + PAGE);
	/* the re-arm under test: one successful mprotect naming the page */
	if (mprotect((void *)READ_DATA, PAGE, PROT_READ | PROT_WRITE) != 0) {
		perror("pinrearm subset");
		return 1;
	}
	show_range("after-mprotect", READ_DATA, READ_DATA + PAGE);
	f = fopen("/tmp/pinrearm.ready", "w");
	if (f) {
		fprintf(f, "ready\n");
		fclose(f);
	}
	for (;;) {
		if (mincore((void *)READ_DATA, PAGE, vec) != 0) {
			fprintf(stderr, "pinrearm: page gone while mapped\n");
			return 1;
		}
		usleep(20000);
		if (access("/tmp/pinrearm.go", F_OK) == 0)
			break;
	}
	fprintf(stderr, "pinrearm: reading after the go file\n");
	if (!read_ok(READ_DATA + 16, buf, 8) || memcmp(buf, "PINREARM", 8)) {
		fprintf(stderr, "pinrearm: read after rmmod took a signal\n");
		return 1;
	}
	show_range("after-go", READ_DATA, READ_DATA + PAGE);
	printf("pinrearm ok\n");
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
 * A data fault the module cannot attribute, on a page whose VMA forbids the
 * access. Unloaded that is a SIGSEGV, every time; the case exists to pin that
 * the loaded run delivers it too, and never livelocks. The stack depth is
 * varied per iteration because the decision on that path reads two locals that
 * pb_take_page leaves untouched when it finds no record, so one fixed depth
 * would measure one value of that leftover.
 */
static unsigned long fs_sink;

static void fs_sink_to(unsigned int depth)
{
	volatile unsigned long v = fs_sink;

	if (depth)
		fs_sink_to(depth - 1);
	else
		fs_sink = v;
}

static int fs_store(unsigned char *p, unsigned int depth)
{
	fs_sink_to(depth);
	faulted = 0;
	if (sigsetjmp(fault_env, 1) != 0)
		return 1;
	*(volatile unsigned char *)p = 1;
	return 0;
}

static void fs_show(const char *what, unsigned long addr)
{
	char line[512], path[64];
	unsigned long lo, hi;
	FILE *f;

	printf("%s at %lx: ", what, addr);
	snprintf(path, sizeof(path), "/proc/%d/maps", getpid());
	f = fopen(path, "r");
	if (!f) {
		printf("maps unavailable\n");
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi) {
			fputs(line, stdout);
			fclose(f);
			return;
		}
	}
	printf("not mapped\n");
	fclose(f);
}

static int fs_leg(const char *what, unsigned char *p, int prot, int n)
{
	int i, faulted_ok = 0, missed = -1;

	if (prot >= 0 && mprotect(p, PAGE, prot) != 0) {
		perror("faultstore mprotect");
		return 1;
	}
	fs_show(what, (unsigned long)p);
	for (i = 0; i < n; i++) {
		if (fs_store(p, (unsigned int)(i & 7)))
			faulted_ok++;
		else {
			missed = i;
			break;
		}
	}
	if (missed >= 0)
		fprintf(stderr, "faultstore: %s store %d did not fault\n", what, missed);
	printf("%s: %d/%d stores delivered a signal\n", what, faulted_ok, n);
	return missed >= 0 ? 1 : 0;
}

static int do_faultstore(void)
{
	unsigned char *ro, *none, *gone;
	int rc = 0;

	if (!map_fixed(READ_DATA, PROT_READ | PROT_WRITE)) {
		perror("faultstore data mmap");
		return 1;
	}
	ro = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	none = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	gone = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ro == MAP_FAILED || none == MAP_FAILED || gone == MAP_FAILED) {
		perror("faultstore mmap");
		return 1;
	}
	*(volatile unsigned char *)READ_DATA = 1;
	arm_fault();
	if (fs_leg("ro-page", ro, PROT_READ, 200))
		rc = 1;
	if (fs_leg("none-page", none, PROT_NONE, 200))
		rc = 1;
	if (munmap(gone, PAGE) != 0) {
		perror("faultstore munmap");
		return 1;
	}
	if (fs_leg("unmapped", gone, -1, 200))
		rc = 1;
	if (fs_leg("data-range", (unsigned char *)READ_DATA, PROT_READ, 200))
		rc = 1;
	alarm(0);
	if (rc)
		return 1;
	printf("faultstore ok\n");
	return 0;
}

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
#else
	/* The module and this check cover x86_64 and arm64 only. */
	(void)prot;
	fprintf(stderr, "regs: no raw syscall for this arch\n");
	return 1;
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
		munmap((void *)VFORK_PROBE, PAGE);
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

int main(int argc, char **argv)
{
	if (argc < 1)
		return 2;
	if (is_payload(argv[0]))
		return do_payload();
	if (is_named(argv[0], "stalehelper"))
		return do_stale_helper();
	/* Re-exec'd by do_execguard after a vfork; see do_guard_child. */
	if (is_named(argv[0], "guardchild"))
		return do_guard_child();
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "epoch"))
		return do_epoch();
	if (!strcmp(argv[1], "flip"))
		return do_flip();
	if (!strcmp(argv[1], "fail"))
		return do_fail();
	if (!strcmp(argv[1], "epochread"))
		return do_epochread();
	if (!strcmp(argv[1], "read"))
		return do_read();
	if (!strcmp(argv[1], "armexec"))
		return do_armexec();
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
	if (!strcmp(argv[1], "roarm"))
		return do_roarm();
	if (!strcmp(argv[1], "moveread"))
		return do_moveread();
	if (!strcmp(argv[1], "moveout"))
		return do_moveout();
	if (!strcmp(argv[1], "movespan"))
		return do_movespan();
	if (!strcmp(argv[1], "mppart"))
		return do_mppart();
	if (!strcmp(argv[1], "mpunalign"))
		return do_mpunalign();
	if (!strcmp(argv[1], "mpmix"))
		return do_mpmix();
	if (!strcmp(argv[1], "pinrearm"))
		return do_pinrearm();
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
	if (!strcmp(argv[1], "rowrite"))
		return do_rowrite();
	if (!strcmp(argv[1], "faultstore"))
		return do_faultstore();
	if (!strcmp(argv[1], "commname"))
		return do_commname();
	if (!strcmp(argv[1], "dontunmap"))
		return do_dontunmap();
	if (!strcmp(argv[1], "badprot"))
		return do_badprot();
	if (!strcmp(argv[1], "execguard"))
		return do_execguard();
	if (!strcmp(argv[1], "fixeddontunmap"))
		return do_fixeddontunmap();
	if (!strcmp(argv[1], "fixedover"))
		return do_fixedover();
	if (!strcmp(argv[1], "fixedwx"))
		return do_fixedwx();
	if (!strcmp(argv[1], "partial"))
		return do_partial();
	if (!strcmp(argv[1], "pinmove"))
		return do_pinmove();
	if (!strcmp(argv[1], "regs"))
		return do_regs();
	if (!strcmp(argv[1], "vforkfork"))
		return do_vforkfork();
	if (!strcmp(argv[1], "vforkwrite"))
		return do_vforkwrite();
	if (!strcmp(argv[1], "disarm"))
		return do_disarm();
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
	fprintf(stderr, "usage: extra epoch|flip|fail|read|armexec|forkread|forkrace|pin|dumprace|armrace|mremaprace|datarace|munmaprace|clonevm|execrace|maymove|roarm|moveread|moveout|movespan|mppart|rearm|fixed|pair|vfork|outside|wrarm|noneexec|rowrite|faultstore commname dontunmap disarm|stale|execve|execveat|tag|tagrace\n");
	return 2;
}
