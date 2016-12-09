/*
 * Allocates memory and attempts to corrupt the heap table if requested
 *
 * Copyright (C) 2009 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

void usage(char *argv[])
{
    fprintf(stderr,"Usage: %s [safe|unsafe]\n", argv[0]);
    exit(1);
}

int main(int argc, char * argv[])
{
    char *buf1, *buf2;
    long pagesize = sysconf(_SC_PAGE_SIZE);
    /* keep allocations small, within brk range */
    int size = pagesize * 8;

    if (argc<2) {
        usage(argv);
    }

    setenv("LIBC_FATAL_STDERR_","1",0);

    buf1 = malloc(size);
    buf2 = malloc(size);

    if (!strcmp(argv[1],"unsafe")) {
        // blast past memory allocated by buf1
        size *= 2;
    }
    else if (!strcmp(argv[1],"safe")) {
        /* do nothing */
    }
    else {
        usage(argv);
    }
    memset(buf1,0xfe,size);

    free(buf1);
    free(buf2);
    return 0;
}
