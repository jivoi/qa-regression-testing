/*
 * Set MMAP_PAGE_ZERO to call a setuid mmap tester.
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
#include <sys/personality.h>
#include <assert.h>

int main(int argc, char *argv[])
{
    unsigned long curr, want;
    curr = want = personality(0xffffffff);
    want |= MMAP_PAGE_ZERO;
    personality(want);
    curr = want = personality(0xffffffff);
    assert(curr == want);

    execl("./low-mmap-setuid","low-mmap-setuid",argv[1],NULL);
    perror("execl");
    return 1;
}
