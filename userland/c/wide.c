#include <stdio.h>
#include <string.h>

static char pad[48 * 1024] = {1, 2, 3, 4};
static const char phrase[] = "pagebuster-wide-table";

__attribute__((noinline, used, aligned(4096)))
int mix(int x)
{
	return (x * 17) ^ 0x5a5a;
}

__attribute__((noinline, used, aligned(4096)))
int weigh(int x)
{
	return ((x << 3) - x) + 0x1234;
}

__attribute__((noinline, used, aligned(4096)))
int fold(const unsigned char *p, int n)
{
	int s = 0x21;
	int i;

	for (i = 0; i < n; i++)
		s = (s * 33 + p[i]) ^ 0x11;
	return s;
}

__attribute__((noinline, used, aligned(4096)))
int scramble(int x)
{
	return mix(x) ^ weigh(x + 1) ^ 0x1020;
}

__attribute__((noinline, used, aligned(4096)))
int accumulate(int n)
{
	int s = 0;
	int i;

	for (i = 0; i < n; i++)
		s = mix(s + i);
	return s;
}

__attribute__((noinline, used, aligned(4096)))
int pick(int n)
{
	unsigned char tmp[32];
	int ncopy;

	ncopy = (int)strlen(phrase);
	if (ncopy > (int)sizeof(tmp))
		ncopy = (int)sizeof(tmp);
	memcpy(tmp, phrase, (size_t)ncopy);
	return fold(tmp, ncopy) ^ mix(n);
}

__attribute__((noinline, used, aligned(4096)))
int dispatch(int n)
{
	int a = scramble(n);
	int b = accumulate(n & 7);
	int c = pick(n);
	int d = weigh(n);

	return a ^ b ^ c ^ d;
}

__attribute__((noinline, used, aligned(4096)))
int main(void)
{
	int m = mix(13);
	int v = dispatch(13);

	fprintf(stderr, "mix %p weigh %p fold %p scramble %p accumulate %p pick %p dispatch %p main %p\n",
		(void *)mix, (void *)weigh, (void *)fold, (void *)scramble,
		(void *)accumulate, (void *)pick, (void *)dispatch, (void *)main);
	printf("wide-ok %d %d %d\n", pad[0], m, v);
	return m == 23175 && v != 0 ? 0 : 1;
}
