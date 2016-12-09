// Author: Kees Cook <kees@ubuntu.com>, License: GPLv3, Copyright 2010 Canonical Ltd.
#include <gnutls/openssl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    unsigned char buf[4096];
    while (RAND_bytes(buf, sizeof(buf))) {
        write(STDOUT_FILENO, buf, sizeof(buf));
    }
    return 0;
}
