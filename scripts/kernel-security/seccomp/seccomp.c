/*
 * Copyright 2009-2010, Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 * This program should be SIGKILL'd after doing continued reads,
 * if SECCOMP is working in the kernel.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/prctl.h>

int main(int argc, char * argv[])
{
    FILE *passwd;
    FILE *zero;
    FILE *null;
    char buf[80];

    if (!(zero=fopen("/dev/zero","r"))) {
        perror("/dev/zero");
        return 2;
    }
    printf("open /dev/zero ok\n");
    if (!(fgets(buf, 80, zero))) {
        perror("/dev/zero");
        return 3;
    }
    printf("read /dev/zero ok\n");

    if (!(passwd=fopen("/etc/passwd","r"))) {
        perror("/etc/passwd");
        return 4;
    }
    printf("open /etc/passwd ok\n");
    if (!(fgets(buf, 80, passwd))) {
        perror("/etc/passwd");
        return 5;
    }
    printf("read /etc/passwd ok\n");

#ifdef PR_SET_SECCOMP
    if (prctl(PR_SET_SECCOMP,1,0,0,0)<0) {
	perror("prctl");
    }
    else {
        printf("set PR_SET_SECCOMP ok\n");
    }
#else
    printf("PR_SET_SECCOMP not available\n");
#endif

    if (!(fgets(buf, 80, zero))) {
        perror("/dev/zero");
        return 6;
    }
    printf("continued reading /dev/zero ok\n");

    if (!(fgets(buf, 80, passwd))) {
        perror("/etc/passwd");
        return 7;
    }
    printf("continued reading /etc/passwd ok\n");

    printf("expecting SIGKILL next ...\n");
    fflush(NULL);

    if (!(null=fopen("/dev/null","r"))) {
        /* should have gotten SIGKILL here */
        perror("/dev/null");
        return 8;
    }
    if (!(fgets(buf, 80, passwd))) {
        perror("/etc/passwd");
        return 9;
    }

    fprintf(stderr,"No errors after PR_SET_SECCOMP!?\n");
    return 10;
}
