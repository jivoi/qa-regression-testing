/*
 * Attempts to validate that glibc-stored function pointers are not visible
 * in the clear.
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
#include <setjmp.h>

jmp_buf jump_point;

void lower_function(void)
{
    printf("In called function.\n");
    longjmp(jump_point,1);
}

/* older glibc leaked this */
#if defined(JB_PC)
# undef JB_PC
#endif

int main(int argc, char * argv[])
{
    int JB_PC, JB_UNENC;
    int code = 1;

    if (argc < 3) {
        fprintf(stderr,"Usage: %s JB_PC JB_UNENC\n", argv[0]);
        fprintf(stderr," JB_PC: setjmp jump buffer offset to encrypted Program Counter (-1 to skip)\n");
        fprintf(stderr," JB_UNENC: setjmp jump buffer offset to unencrypted register close to PC\n");
        return 3;
    }
    JB_PC = atoi(argv[1]);
    JB_UNENC = atoi(argv[2]);

    if (JB_PC == -1) {
        printf("glibc pointer obfuscation offset tests not known for this architecture\n");
        return 2;
    }

    printf("Setting jump point...\n");
    if (setjmp(jump_point) == 0) {
        /* first time through */
        unsigned long *ptr = (unsigned long *)jump_point;
        unsigned long mask = 0xfff;
        unsigned long target = (unsigned long)main & ~mask;
        int i;
        int size = sizeof(jump_point) / sizeof(ptr);

        printf("JB_PC   : %d\n",JB_PC);
        printf("JB_UNENC: %d\n",JB_UNENC);
        printf("main    : %p\n",main);
        printf("mask    : %p\n",(void*)~mask);
        printf("target  : %p\n",(void*)target);

        /* report all the values */
        for (i = 0; i < size; i++) {
            printf("%d %p: %p\n", i, (void*)&(ptr[i]), (void*)ptr[i]);
        }

        /* verify that the PC has been obfuscated */
        if ((ptr[JB_PC] & ~mask) == target) {
                printf("Yikes, JB_PC (offset %d) contains %p (close to %p)!\n", JB_PC, (void*)ptr[JB_PC], main);
                exit(100);
        }
        else {
            printf("JB_PC obfuscated: %p\n",(void*)ptr[JB_PC]);
        }

        if (JB_UNENC != -1) {
            if ((ptr[JB_UNENC] & ~mask) != target) {
                    printf("Yikes, offset %d (%p) does not contain value close to %p!\n", JB_UNENC, (void*)ptr[JB_UNENC], main);
                    exit(200);
            }
            else {
                printf("Simple register correctly not obfuscated: %p\n",(void*)ptr[JB_UNENC]);
            }
        }

        lower_function();
    }
    else {
        /* after longjmp */
        printf("Returned\n");
        code = 0;
    }
    if (code != 0) {
        printf("Error: did not return correctly\n");
    }
    printf("Exiting\n");
    return code;
}
