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

    // write
    outfd = open("/dev/null", O_WRONLY | O_APPEND);
    if (outfd<0) {
        perror("open");
        return 1;
    }
    int expected = strlen(argv[1]);
    write(outfd, argv[1], expected);
    close(outfd);

    // frwite
    if (!(outfile = fopen("/dev/null", "w"))) {
        perror("fopen");
        return 2;
    }
    fwrite(argv[1], strlen(argv[1]), 1, outfile);
    fclose(outfile);

    // system
    system("cat /dev/null");

    printf("ok\n");
    return 0;
}
