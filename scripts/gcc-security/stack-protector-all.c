/* Copyright 2007-2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
// stack protector example, only without an explicit buffer, to test -all
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

char buf[32];

int main(int argc, char *argv[]) {

    if (argc<3) {
        fprintf(stderr,"Usage: %s [strcpy/memcpy/sprintf/getcwd/read] text...(copied into 32 character buffer)\n", argv[0]);
        return 1;
    }
    if (!strcmp(argv[1],"strcpy")) {
        strcpy(buf, argv[2]);
    }
    else if (!strcmp(argv[1],"memcpy")) {
        memcpy(buf, argv[2], strlen(argv[2])+1);
    }
    else if (!strcmp(argv[1],"sprintf")) {
        /* add []'s to avoid built-in reduction to a memcpy */
        sprintf(buf, "[%s]", argv[2]);
    }
    else if (!strcmp(argv[1],"getcwd")) {
        int len = strlen(argv[2]);
        char *dir = (char*)malloc(len+1);
        char *base = "/tmp/getcwd-test-directory-";
        char *xs = "-XXXXXX";
        len -= strlen(base) + strlen(xs);
        if (len<1) {
            fprintf(stderr,"arg1 must be longer\n");
            return 5;
        }
        *dir='\0';
        strcat(dir, base);
        while (len--) {
            strcat(dir, "A");
        }
        strcat(dir, xs);
        if (!(mkdtemp(dir))) {
            perror("mkdtemp");
            return 3;
        }
        printf("%s\n",dir);
        fflush(NULL);
        if (chdir(dir)<0) {
            perror(dir);
            return 4;
        }
        getwd(buf);
        rmdir(dir);
    }
    else if (!strcmp(argv[1],"read")) {
        /* read from /dev/zero instead of argv[2] */
        int fd;

        fd = open("/dev/zero", O_RDONLY);
        if (fd<0) {
            perror("open");
            return 1;
        }
        read(fd, buf, strlen(argv[2])+1);
        close(fd);
    }
    else {
        fprintf(stderr,"Unknown mode '%s'\n",argv[1]);
        return 2;
    }
    printf("Hello!  You typed: %s\n", buf);
    return 0;
}
