/*
 * Just pauses to read stdin and exits.
 *
 * Copyright (C) 2008 Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    char buf[80];

    if (!fgets(buf, 79, stdin)) {
        return 1;
    }

    return 0;
}
