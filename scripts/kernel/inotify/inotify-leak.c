/* Copyright 2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
#include <sys/inotify.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

void remove_watch(int master, int fd)
{
    int s;

    s = inotify_rm_watch (master, fd);
    if (s != 0) {
        fprintf(stderr, "failed to rm_watch %d: %s\n", fd, strerror (errno));
        exit(1);
    }
}

int
main (void)
{
    int master;
    struct rlimit rlim;

    if (getrlimit(RLIMIT_NOFILE, &rlim)) {
        perror("getrlimit");
        exit(2);
    }
    printf("RLIMIT_NOFILE: %zd\n", rlim.rlim_max);

    master = inotify_init ();

    while (1) {
        int one = inotify_add_watch (master, ".", IN_MODIFY);
        printf("%d ...\n", one);
        int two = inotify_add_watch (master, "..", IN_MODIFY);
        printf("%d ...\n", two);

        remove_watch(master, one);
        remove_watch(master, two);

        if (one > 4097 || two > 4097) {
            printf("ok\n");
            return 0;
        }
    }

    return 1;
}
