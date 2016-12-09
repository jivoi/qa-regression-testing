// Copyright 2008 Canonical, Ltd
// Author: Kees Cook <kees@ubuntu.com>
// License: GPLv3
//
// Display stack protector guard value
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <dlfcn.h>

void guard(char * argv0)
{
    // trigger protector (large stack)
#define BUF_SIZE 128
    char buf[BUF_SIZE];
    uintptr_t ptr;
    int i=0;
    unsigned char *val;

    memset(buf,0,BUF_SIZE);

    // FIXME: why is this needed?  What is x86_64 shoving in here extra?
    if (sizeof(ptr)==8) i=1;

    ptr = *(uintptr_t*)&buf[BUF_SIZE+(sizeof(ptr))*i];
    val = (unsigned char*)&ptr;
    for (i=0; i<sizeof(ptr); i++) {
        printf("%02x ",*val++);
    }
    printf("\n");
}

int main(int argc, char * argv[])
{
    void * stack_chk_fail = dlsym(RTLD_DEFAULT, "__stack_chk_fail");
    if (!stack_chk_fail) {
        fprintf(stderr, "Failed to locate symbol __stack_chk_fail\n");
        return 1;
    }
    guard(argv[0]);

    return 0;
}
