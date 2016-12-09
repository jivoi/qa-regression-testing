/* based on http://cygwin.com/ml/libc-alpha/2012-01/msg00026.html */

#include <stdio.h>
#include <stdlib.h>

void *realloc (void *p, size_t new_size)
{
	fprintf(stderr, "FAIL, realloc called\n");
	abort();
}

int main()
{
	const char *buf = "123";
	int i;

	sscanf(buf, "%d", &i);
	return 123 - i;
}

