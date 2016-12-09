/*
 * Verifies that glibc is catching misuse of select macros.
 * https://sourceware.org/bugzilla/show_bug.cgi?id=10352
 *
 * Copyright (C) 2014, Kees Cook
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 * Requires '-O2 -D_FORTIFY_SOURCE=2' to show the protection, if present.
 *
 */
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int fd;
    fd_set buffer1;
    fd_set readable;
    fd_set buffer2;

    if (argc < 2) {
        fprintf(stderr, "Simulate which fd number?\n");
        return 1;
    }

    /* Clear memory of fdsets surrounding our test. */
    memset(&buffer1, 0, sizeof(buffer1));
    memset(&readable, 0xFF, sizeof(readable));
    memset(&buffer2, 0, sizeof(buffer2));

    fd = atoi(argv[1]);

    /* Clear the entire fdset. */
    FD_ZERO(&readable);

    FD_SET(fd, &readable);
    if (!FD_ISSET(fd, &readable)) {
        fprintf(stderr, "FD_SET didn't work\n");
        return 2;
    }

    FD_CLR(fd, &readable);
    if (FD_ISSET(fd, &readable)) {
        fprintf(stderr, "FD_CLR didn't work\n");
        return 3;
    }

    /*
     * If we're with 1024 bits of the end of "readable", we should
     * fail here, since we're checking within buffer2.
     */
    memset(&readable, 0xFF, sizeof(readable));
    if (!FD_ISSET(fd, &readable)) {
        fprintf(stderr, "FD_ISSET didn't work\n");
        return 4;
    }

    FD_ZERO(&readable);
    if (FD_ISSET(fd, &readable)) {
        fprintf(stderr, "FD_ZERO didn't work\n");
        return 5;
    }

    printf("ok\n");

    return 0;
}
