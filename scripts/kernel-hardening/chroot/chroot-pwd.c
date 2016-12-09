/* Copyright 2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
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
#include <fcntl.h>

int main(int argc, char * argv[])
{
    if (argc<2) {
        fprintf(stderr,"Usage: %s DIRECTORY-TO-CHROOT-INTO\n", argv[0]);
        return 1;
    }
    if (chroot(argv[1])) {
        perror("chroot");
        return 2;
    }
    puts(get_current_dir_name());

    return 0;
}
