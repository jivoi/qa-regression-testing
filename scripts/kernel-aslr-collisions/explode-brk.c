/*
 * Demonstrates brk area crashing into other segments when run under
 * NX-emulation kernel patch. (Run about 1000 times to trigger it.)
 *
 * Copyright (C) 2010, Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 * gcc explode.c -fPIE -pie -o explode
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

// The larger this size, the faster a collision can be found.
#define SIZE (32*1024)
//#define SIZE (1)

int main(int argc, char * argv[])
{
    char cmd[80];
    int i;

    void * start = sbrk(0);
    void * end = (void*)((uintptr_t)start + SIZE);

    snprintf(cmd,sizeof(cmd),"cat /proc/%d/maps", getpid());

    if ((uintptr_t)sbrk(SIZE) == -1) {
        printf("FAIL: unable to use brk area at %p - %p\n", start, end);
        system(cmd);
        return 1;
    }
    printf("ok: %p\n", start);
    return 0;
}
