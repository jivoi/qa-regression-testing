/* Copyright 2007-2014 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees@ubuntu.com>
	Steve Beattie <steve.beattie@canonical.com>
*/
// stack protector strong example
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    unsigned short buf[20];

    if (argc<3) {
        fprintf(stderr,"Usage: %s [memcpy] text...(copied into 32 character buffer)\n", argv[0]);
        return 1;
    }
    else if (!strcmp(argv[1],"memcpy")) {
        memcpy(buf, argv[2], strlen(argv[2])+1);
    }
    else {
        fprintf(stderr,"Unknown mode '%s'\n",argv[1]);
        return 2;
    }
    printf("Hello!  You typed: %s\n", (char *) buf);
    return 0;
}
