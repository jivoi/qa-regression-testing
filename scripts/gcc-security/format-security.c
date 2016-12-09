/* Copyright 2008-2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
// format-security.c
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc<2) {
        fprintf(stderr,"Usage: %s text...(handled as format string)\n", argv[0]);
        return 1;
    }
    printf("Hello!  You typed: ");
    printf(argv[1]);
    printf("\n");
    return 0;
}
