#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int check_dump(pid_t pid, const unsigned char *needle, size_t nlen)
{
	DIR *d;
	struct dirent *de;
	int found = 0;

	d = opendir("/tmp");
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		unsigned long addr, epoch;
		char path[320];
		unsigned char *buf;
		unsigned char *hit;
		int fd;
		uint64_t ent = 0;
		unsigned char live[64];
		struct iovec loc, rem;
		unsigned long va;
		ssize_t n;
		size_t cmp = nlen;

		if (sscanf(de->d_name, "%lx_%lu", &addr, &epoch) != 2)
			continue;
		if (getenv("PB_WANT_ADDR")) {
			unsigned long want = strtoul(getenv("PB_WANT_ADDR"), NULL, 16);

			if ((addr & ~(unsigned long)0xfff) != (want & ~(unsigned long)0xfff))
				continue;
		}
		snprintf(path, sizeof(path), "/tmp/%s", de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		buf = malloc(4096);
		if (!buf) {
			close(fd);
			continue;
		}
		if (read(fd, buf, 4096) != 4096) {
			free(buf);
			close(fd);
			continue;
		}
		close(fd);
		hit = memmem(buf, 4096, needle, nlen);
		if (!hit) {
			free(buf);
			continue;
		}
		va = addr + (unsigned long)(hit - buf);
		snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			pread(fd, &ent, sizeof(ent), (va / 4096) * 8);
			close(fd);
		}
		if (cmp > sizeof(live))
			cmp = sizeof(live);
		loc.iov_base = live;
		loc.iov_len = cmp;
		rem.iov_base = (void *)va;
		rem.iov_len = cmp;
		n = process_vm_readv(pid, &loc, 1, &rem, 1, 0);
		printf("va=%lx dump=%s off=%ld present=%d pfn=%lx live=%s\n",
		       va, de->d_name, (long)(hit - buf),
		       (int)((ent >> 63) & 1),
		       (unsigned long)(ent & ((1ULL << 55) - 1)),
		       (n == (ssize_t)cmp && memcmp(live, needle, cmp) == 0) ? "match" : "MISMATCH");
		found = (n == (ssize_t)cmp && memcmp(live, needle, cmp) == 0 &&
			 ((ent >> 63) & 1));
		free(buf);
		/*
		 * Keep looking unless this candidate verified. The live check is
		 * time-varying: a page dumped at one epoch and then written,
		 * unmapped or swapped out before the stop that inspects it no
		 * longer matches, and readdir order over a flat /tmp decides
		 * which candidate is seen first. Breaking unconditionally turns
		 * that into a false negative, and the caller cannot tell it from
		 * a module that never captured the page at all. Continuing can
		 * only turn a fail into a pass, never the reverse.
		 */
		if (found)
			break;
	}
	closedir(d);
	return found;
}

int main(int argc, char **argv)
{
	unsigned char needle[64];
	size_t nlen = 0;
	pid_t pid;
	int status, found = 0;
	char *hex;

	if (argc < 3) {
		fprintf(stderr, "usage: pb_check <hex-needle> prog [args...]\n");
		return 2;
	}
	hex = argv[1];
	if (strlen(hex) % 2 || strlen(hex) / 2 > sizeof(needle))
		return 2;
	while (hex[0] && hex[1]) {
		unsigned int b;
		if (sscanf(hex, "%2x", &b) != 1)
			return 2;
		needle[nlen++] = (unsigned char)b;
		hex += 2;
	}

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGSTOP);
		execvp(argv[2], argv + 2);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	while (waitpid(pid, &status, 0) > 0 && !WIFEXITED(status) && !WIFSIGNALED(status)) {
		int sig;

		if (!WIFSTOPPED(status))
			continue;
		sig = WSTOPSIG(status);
		if (sig == (SIGTRAP | 0x80) && check_dump(pid, needle, nlen)) {
			found = 1;
			break;
		}
		if (sig == SIGTRAP || sig == SIGSTOP || sig == (SIGTRAP | 0x80))
			sig = 0;
		ptrace(PTRACE_SYSCALL, pid, 0, sig);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	if (!found)
		printf("needle not seen in a live dumped page\n");
	return found ? 0 : 1;
}
