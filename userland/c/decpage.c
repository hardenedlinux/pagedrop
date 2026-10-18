/*
 * Not UPX. Stock UPX compresses; it does not encrypt.
 * This file holds ciphertext, decrypts it into an anonymous page, then
 * calls mprotect. It is not built by the Makefile and it is not a stitcher case.
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096
#define KEY 0x5a

typedef int (*pagefn)(void);

int main(void)
{
	unsigned char *page;
	int i;
	int v;
#if defined(__aarch64__)
	static const unsigned char cipher[] = {
		0xba, 0x0a, 0xd1, 0x08,
		0x9a, 0x59, 0x05, 0x8c
	};
#else
	static const unsigned char cipher[] = {
		0xe2, 0xdd, 0x00, 0x5a, 0x5a,
		0x99
	};
#endif

	page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return 1;
	for (i = 0; i < (int)sizeof(cipher); i++)
		page[i] = cipher[i] ^ KEY;
	if (mprotect(page, PAGE, PROT_READ | PROT_EXEC) != 0)
		return 2;
	v = ((pagefn)page)();
	fprintf(stderr, "decpage %p\n", (void *)page);
	printf("dec-ok %d\n", v);
	return v == 23175 ? 0 : 3;
}
