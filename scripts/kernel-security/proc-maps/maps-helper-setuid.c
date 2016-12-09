/*
 * Drops privs, and writes given filename contents to stdout.
 * Think of it as a priv-dropping "cat".
 *
 * Copyright (C) 2008 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
    int fd;
    ssize_t saw;
    unsigned char buf[1024];

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (argc < 2) {
        fprintf(stderr,"Usage: %s FILENAME\n", argv[0]);
        return 1;
    }

    if ((argc == 3) && (strcmp(argv[2], "sleep") == 0)) {
	usleep(100000);
    }

    if (gid < 1 || uid < 1) {
        fprintf(stderr,"UID and GID must be greater than 0.\n");
        return 1;
    }

    // drop privs
    if (setresgid(gid,gid,gid)<0 || getegid() != gid) {
        fprintf(stderr,"setresgid failed\n");
        return 1;
    }
    if (setresuid(uid,uid,uid)<0 || geteuid() != uid) {
        fprintf(stderr,"setresuid failed\n");
        return 1;
    }

    if ((fd = open(argv[1],O_RDONLY))<0) {
        perror(argv[1]);
        return 1;
    }
    while ( (saw = read(fd, buf, 1024)) > 0) {
        ssize_t sent, wrote;
        for (sent = 0; sent < saw; sent += wrote ) {
            wrote = write(STDOUT_FILENO,buf,saw);
            if (wrote <= 0) {
                perror(argv[1]);
                return 1;
            }
        }
    }
    close(fd);

    return 0;
}
