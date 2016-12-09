/*
 * Tests lower 64k userspace mmap availability, which should be enforced via
 * /proc/sys/vm/mmap_min_addr.
 *
 * Copyright (C) 2008 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int page;
    void *memory;
    int bad_mem_failed = 0, good_mem_failed = 0;
    long pagesize = sysconf(_SC_PAGE_SIZE);
    int need_nl = 1;
    int testsize = 0;
    if (argc>1) testsize=atoi(argv[1]);
    if (!testsize) testsize=65536;

    // drop setuidness (for MMAP_PAGE_ZERO testing)
    if (geteuid() != getuid()) {
	if (setresuid(getuid(),getuid(),getuid())) {
	    fprintf(stderr, "Failed to call setresuid: %s\n", strerror(errno));
	    exit(errno);
        }
    }	

    // verify we cannot map any pages within the lower "testsize" bytes of memory.
    printf("Testing lower %d bytes in %ld byte chunks: ", testsize, pagesize);
    fflush(stdout);
    for (page = 0; page < testsize/pagesize; page++) {
        memory = mmap((void*)(page*pagesize), pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (memory != MAP_FAILED) {
            bad_mem_failed = 1;
            if (need_nl) {
                need_nl = 0;
                fprintf(stderr,"\n");
            }
            fprintf(stderr,"\tUnexpectedly allocated %ld bytes at 0x%08lx\n",
                pagesize, (unsigned long)memory);
        }
    }
    printf("%s\n", bad_mem_failed ? "FAIL (able to allocate memory)"
                                  : "pass (could not allocate memory)");

    // verify we can map space just above the blocked area (i.e. mmap
    // itself isn't broken).
    printf("Testing %ld byte chunk above %d: ", pagesize, testsize-1);
    fflush(stdout);
    if ((long)main > ((long)page*pagesize) && (long)main < ((long)page*pagesize + pagesize)) {
        printf("skipped, main is mapped very low! (ARM?)\n");
    }
    else {
        memory = mmap((void*)(page*pagesize), pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (memory == MAP_FAILED) {
            good_mem_failed = 1;
            fprintf(stderr,"\n\tUnexpectedly unable to allocate %ld bytes at 0x%08lx\n",
                pagesize, page*pagesize);
        }
        printf("%s\n", good_mem_failed ? "FAIL (cannot allocate memory)"
                                       : "pass (able to allocate memory)");
    }

    return (bad_mem_failed | good_mem_failed);
}
