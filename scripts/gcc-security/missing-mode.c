/* Copyright 2008-2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    FILE *outfile;
    int outfd;
    char buf[32];


    // write
    outfd = open("bogus-modes", O_WRONLY | O_CREAT | O_EXCL);
    if (outfd<0) {
        perror("open");
        return 1;
    }
    printf("ok\n");
    fflush(NULL);

    close(outfd);
    unlink("bogus-modes");

    // nonsense compile-time tests
    memcpy(buf, argv, 4096);
    snprintf(buf, 4096, "%s", argv[1]);
    read(outfd, buf, 4096);

    return 0;
}
