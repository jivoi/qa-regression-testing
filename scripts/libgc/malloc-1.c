#include <gc.h>
#include <assert.h>
#include <stdio.h>

/* Based on
 * http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/
 * malloc(-1) case.
 *
 * part of CVE-2012-2673
 */

int main(void)
{
	int *foo = NULL;

	foo = (int*) GC_MALLOC((long) 1000);
	printf("foo = 0x%.8lx\n", (long) foo);
	printf("Heap size = %zd\n", GC_get_heap_size());

	foo = (int*) GC_MALLOC(-1);
	if (!foo) {
		printf("ok\n");
		return 0;
	}

	printf("FAIL!\n");
	printf("GC_MALLOC(-1) succeeded instead of returning NULL\n");
	printf("foo = 0x%.8lx\n", (long) foo);
	printf("Heap size = %zd\n", GC_get_heap_size());
	return 1;
}
	
