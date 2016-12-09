/* Copyright 2008-2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("Check me with 'readelf -l %s | grep GNU_RELRO'\n", argv[0]);
    return 0;
}
