/* Check VM memory growth directions
 *
 * Compile: gcc -fPIC -pie mmap-growth-direction.c -o mmap-growth-direction
 * Run: ./mmap-growth-direction [--maps]
 *
 * Check heap/stack gap...
 * MAP=$(./mmap-growth-direction --maps | egrep 'heap|stack' | tail -n2); stack=$(echo "$MAP" | grep stack | cut -d" " -f1 | cut -d- -f2 | tr a-f A-F); heap=$(echo "$MAP" | grep heap | cut -d" " -f1 | cut -d- -f1 | tr a-f A-F); (echo "ibase=16"; echo "obase=10"; echo "$stack - $heap") | bc
 *
 * Note that with "ulimit -s unlimited", "[heap]" is no longer shown, so the
 * above heap/stack gap can't be measured using the above recipe.
 *
 * Copyright 2007, Canonical Ltd
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define do_malloc(ptr,size)	{ \
	unsigned int i; \
	if (!((ptr)=malloc(size))) { \
		perror("malloc"); \
		return 1; \
	} \
	/* do work on the allocation just to be sure we don't get reordered */ \
	for (i =0; i < (size); i++) { ptr[i]=0x01; } \
}

char buf[1024];

int main(int argc, char *argv[])
{
	char * mmap1 = NULL;
	char * mmap2 = NULL;

	char * brk1 = NULL;
	char * brk2 = NULL;

	if (argc>1) {
		sprintf(buf,"cat /proc/%u/maps",getpid());
		if (system(buf)<0) return 1;
	}

	// perform > 128K allocations to force glibc to perform mmap alloc
	do_malloc(mmap1,1024*1024);
	do_malloc(mmap2,1024*1024);

	if (mmap2>mmap1) {
		printf("mmap allocations grow down (%p > %p)\n", mmap2, mmap1);
	}
	else {
		printf("mmap allocations grow up (%p <= %p)\n", mmap2, mmap1);
	}

	// perform < 128K allocations to force glibc to perform brk alloc
	do_malloc(brk1,1024);
	do_malloc(brk2,1024);
	
	if (brk2>brk1) {
		printf("brk allocations grow down (%p > %p)\n", brk2, brk1);
	}
	else {
		printf("brk allocations grow up (%p <= %p)\n", brk2, brk1);
	}

	if (argc>1) {
		if (system(buf)<0) return 1;
	}

	return 0;
}
