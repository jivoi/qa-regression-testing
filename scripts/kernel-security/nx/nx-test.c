/*
 * Tests NX in various memory regions.
 *
 * Copyright (C) 2008-2009 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#if defined(__i386__) || defined(__x86_64__)
/* ret; ret; ret; ret; */
# define RET_OPCODES 0xc3c3c3c3;
#elif defined(__ARMEL__)
/* bx lr */
# define RET_OPCODES 0xe12fff1e;
void alarm_handler(int signum)
{
    int *boom = NULL;
    printf("Pretending to segfault when ARM spins instead of crashing on NX...\n");
    fflush(NULL);
    *boom = 1;
}
#elif defined(__powerpc__) || defined(__powerpc64__)
/* blr */
# define RET_OPCODES 0x4e800020;
#elif defined(__aarch64__)
/* ret */
# define RET_OPCODES 0xd65f03c0;
#elif defined(__s390x__) || (__s390__)
/* br %14 ; br %14 */
# define RET_OPCODES 0x07f407f4;
# error "Unknown opcode for function return"
#else
# error "Unknown opcode for function return"
#endif

/* Earlier versions of gcc don't define this correctly? */
#ifndef __clear_cache
extern void __clear_cache (void *begin, void *end);
#endif

static const unsigned int ret_rodata = RET_OPCODES;

#define STATIC_PAGE_SIZE_MAX (64 * 1024)
unsigned int ret_data = RET_OPCODES;
/* push ret_bss for sure into a separate page, instead of landing in
   the .data segment.  Thanks to pipacs for pointing this out. */
struct {
    unsigned char page_bump[STATIC_PAGE_SIZE_MAX];
    unsigned int opcode;
} ret_bss;

void usage(char *argv[])
{
    fprintf(stderr,"Usage: %s [data|rodata|bss|stack|brk|mmap|mmap-exec]\n",
                   argv[0]);
    exit(1);
}

int main(int argc, char * argv[])
{
    char *report = "Unexpected: returned from function that was marked non-executable.\nNX segment markings are not being enforced.";
    unsigned int ret_stack = RET_OPCODES;
    FILE *maps;
    char buf[128];
    void (*region_func)(void);
    long pagesize = sysconf(_SC_PAGE_SIZE);

    /* since we need to know the minimum page size for bss/data split,
       we should verify that the system doesn't have some as-yet-never-seen
       giant page sizes. */
    assert(pagesize<=STATIC_PAGE_SIZE_MAX);

    if (argc<2) {
        usage(argv);
    }

    if (!strcmp(argv[1],"bss")) {
        region_func = (void*)&(ret_bss.opcode);
    }
    else if (!strcmp(argv[1],"data")) {
        region_func = (void*)&ret_data;
    }
    else if (!strcmp(argv[1],"stack")) {
        region_func = (void*)&ret_stack;
    }
    else if (!strcmp(argv[1],"rodata")) {
        region_func = (void*)&ret_rodata;
    }
    else if (!strcmp(argv[1],"mmap") || !strcmp(argv[1],"mmap-exec")) {
        int prot = PROT_READ | PROT_WRITE;
        if (!strcmp(argv[1],"mmap-exec")) {
            prot |= PROT_EXEC;
            report = "Expected: returned from function that was marked executable.";
        }

        region_func = mmap(NULL, pagesize, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region_func == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
    }
    else if (!strcmp(argv[1],"brk")) {
        region_func = malloc(pagesize);
        if (!region_func) {
            perror("malloc");
            return 1;
        }
    }
    else {
        usage(argv);
    }

    /* Report memory regions, for clarification in NX-emu layouts */
    printf("rodata:%p\n", &ret_rodata);
    printf("data:  %p\n", &ret_data);
    printf("bss:   %p\n", &(ret_bss.opcode));
    printf("brk:   %p\n", malloc(pagesize));
    printf("rw:    %p\n", mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    printf("rwx:   %p\n", mmap(NULL, pagesize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    printf("stack: %p\n", &pagesize);

    /* Set "RET" opcode for allocated regions. */
    if (region_func != (void*)&ret_data &&
        region_func != (void*)&ret_rodata) {
        *(unsigned int *)region_func = RET_OPCODES;
    }

    printf("Dump of /proc/self/maps:\n");
    maps = fopen("/proc/self/maps","r");
    while (fgets(buf,sizeof(buf),maps)) {
        printf("%s",buf);
    }
    fclose(maps);
    printf("Attempting to execute function at %p\n",region_func);
    printf("If this program seg-faults, the region was enforced as non-executable...\n");
    fflush(NULL);
    __clear_cache(region_func, region_func + sizeof(int));

#if defined(__ARMEL__)
    signal(SIGALRM, alarm_handler);
    alarm(1); /* ARM seems to spin instead of crash in some kernels */
#endif
    region_func();
    alarm(0);

    puts(report);
    return 0;
}
