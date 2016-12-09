// Author: Kees Cook <kees@ubuntu.com>, License: GPLv3, Copyright 2010 Canonical Ltd.
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <values.h>
#include <assert.h>

int main()
{
    unsigned int i, j, value;
    unsigned char buf[4096];
    unsigned char *ptr;

    unsigned int bytes_per_chunk = 3;
    unsigned int chunks = sizeof(buf) / bytes_per_chunk;
    unsigned int size;

    // Use bottom 3 bytes of rand result, since it is signed, leaving
    // the top bits unused.
    assert(RAND_MAX>=INT_MAX);

    for (;;) {
        ptr = buf;
        size = 0;
        for (i = 0; i < chunks; i++) {
            value = rand();
            for (j = 0; j < bytes_per_chunk; j++) {
                *ptr++ = (unsigned char)((value >> (8*j)) & 0xFF);
                size++;
            }
        }
        write(STDOUT_FILENO, buf, size);
    }
    return 0;
}
