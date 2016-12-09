/* Copyright 2010, Canonical, Ltd.
   Author: Kees Cook <kees@ubuntu.com>
   License: GPLv3

   This attempts to crash the stack into the new stack guard page. The
   expected behavior is to get a bus error. Exiting 0 should be considered
   a failure.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

long getstack(FILE *maps, char *buf, int size)
{
    unsigned long stack = 0;
    rewind(maps);
    while (!stack && fgets(buf, size, maps)) {
        if (strstr(buf,"[stack]")) {
            printf("%s", buf);
            stack = strtoul(buf, NULL, 16);
        }
    }
    return stack;
}

int region_empty(unsigned char *target, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        if (target[i] != '\0') return 0;
    }
    return 1;
}

void bigfunc(FILE *maps, unsigned long target, int size)
{
    char buf[2048];

    if (getstack(maps, buf, 2048) != target &&
        region_empty((unsigned char*)target, size)) {
        bigfunc(maps, target, size);
    }
}

int main(int argc, char * argv[])
{
    char buf[128];
    FILE *maps;
    void *memory;
    unsigned long stack = 0;
    long pagesize = sysconf(_SC_PAGE_SIZE);
    int size = pagesize;

    sprintf(buf, "/proc/%d/maps", getpid());
    if (!(maps = fopen(buf,"r"))) {
        perror(buf);
        return 1;
    }

    stack = getstack(maps, buf, 128);

    if (!stack) {
        fprintf(stderr, "Could not locate stack address\n");
        return 2;
    }

    size = pagesize;
    stack -= size;

    printf("Target: %p\n", (void*)stack);
    memory = mmap((void*)stack, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (memory == MAP_FAILED) {
        perror("mmap");
        return 3;
    }
    memset(memory, 0, pagesize);

    bigfunc(maps, (unsigned long)memory, size);

    fflush(NULL);
    fprintf(stderr,"Unexpectedly survived stack crash into mapped segment\n");

    return 0;
}
