/*
 * Not UPX. A tiny decompress-then-mprotect stub.
 *
 * The file holds an RLE of the instruction bytes, not the bytes themselves.
 * upx -d cannot undo it. pagedrop should dump the plaintext page at mprotect.
 * Not built by the Makefile. Not a kernel-suite case.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 4096

typedef int (*pagefn)(void);

int main(void)
{
	unsigned char *page;
	unsigned char plain[16];
	int n = 0;
	int i;
	int v;
#if defined(__aarch64__)
	/* movz w0, #0x5a87; ret  -> e0 50 8b 52 c0 03 5f d6, run-length encoded */
	static const unsigned char packed[] = {
		1, 0xe0, 1, 0x50, 1, 0x8b, 1, 0x52,
		1, 0xc0, 1, 0x03, 1, 0x5f, 1, 0xd6
	};
#else
	/* mov eax, 0x5a87; ret -> b8 87 5a 00 00 c3 */
	static const unsigned char packed[] = {
		1, 0xb8, 1, 0x87, 1, 0x5a, 2, 0x00, 1, 0xc3
	};
#endif

	for (i = 0; i + 1 < (int)sizeof(packed) && n < (int)sizeof(plain); i += 2) {
		int count = packed[i];
		unsigned char byte = packed[i + 1];
		int k;

		for (k = 0; k < count && n < (int)sizeof(plain); k++)
			plain[n++] = byte;
	}
	page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return 1;
	memcpy(page, plain, (size_t)n);
	if (mprotect(page, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 2;
	v = ((pagefn)page)();
	fprintf(stderr, "nzpack %p\n", (void *)page);
	printf("nz-ok %d\n", v);
	return v == 23175 ? 0 : 3;
}
