/*
 * Verifies that glibc is not pre-terminating sprintf output.
 * https://launchpad.net/bugs/305901
 *
 * Copyright (C) 2009 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 * Requires '-O2 -D_FORTIFY_SOURCE=2' to show the bug, if present.
 *
 */
#include <stdio.h>
#include <string.h>

#define PREFIX "this prefix should exist"
#define SUFFIX "appended text"

int main()
{
    char buf[80];
    char expected[80];

    sprintf(expected, "%s: " SUFFIX, PREFIX);
    sprintf(buf, "%s: ", PREFIX);
    sprintf(buf, "%s" SUFFIX, buf);

    printf("expected: '%s'\n", expected);
    printf("buf:      '%s'\n", buf);

    if (strcmp(buf, expected)) {
        fprintf(stderr,"Oops: '%s' != '%s'\n", buf, expected);
        return 1;
    }
    printf("ok\n");

    return 0;
}
