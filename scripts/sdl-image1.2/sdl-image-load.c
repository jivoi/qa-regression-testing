/*
 * Copyright (C) 2008 Canonical Ltd
 * Author: Kees Cook <kees@canonical.com>
 * License: GPLv3
 *
 * gcc -o sdl-image-load -lSDL_image sdl-image-load.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <SDL/SDL_image.h>

int main(int argc, char * argv[])
{
    if (argc<2) {
        fprintf(stderr,"Usage: %s IMAGE\n",argv[0]);
        return 1;
    }
    SDL_Surface *surface = IMG_Load_RW(SDL_RWFromFile(argv[1], "rb"), 1);
    if (!surface) {
        fprintf(stderr,"Failed to load image: %s\n", IMG_GetError());
        return 1;
    }

    return 0;
}
