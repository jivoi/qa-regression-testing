/*
 * Regression test for https://launchpad.net/bugs/418135
 *
 * Copyright (C) 2009, Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 *
 * gcc -Wall -O2 $(pkg-config --cflags --libs glib-2.0 gio-2.0) -o symlink-copying symlink-copying.c
 */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define ORIG "original"
#define SYMLINK "symlink"
#define COPY "symlink.copy"


int main()
{
    FILE *f;
    struct stat info_before, info_after;
    GFile *src, *dest;

    /* create temp directory */
    char *dir = strdup("/tmp/symlink-copying-XXXXXX");
    if ( !(mkdtemp(dir)) ) {
        perror(dir);
        return 1;
    }
    if ( chdir(dir)<0 ) {
        perror(dir);
        return 2;
    }

    /* create test file */
    if ( !(f = fopen(ORIG,"w")) ) {
        perror(ORIG);
        return 3;
    }
    fclose(f);

    if (lstat(ORIG, &info_before)) {
        perror(ORIG);
        return 4;
    }

    /* verify we can write to it */
    if ( access(ORIG, W_OK)<0 ) {
        perror(ORIG);
        return 5;
    }

    /* create symlink */
    if ( symlink(ORIG, SYMLINK)<0 ) {
        perror(SYMLINK);
        return 6;
    }

/*
    printf("Before:\n");
    if (system("ls -l")) {
        perror("system");
        return 255;
    }
*/

    g_type_init();

    src = g_file_new_for_path(SYMLINK);
    dest = g_file_new_for_path(COPY);

    if ( !g_file_copy(src, dest, G_FILE_COPY_NOFOLLOW_SYMLINKS, NULL, NULL, NULL, NULL)) {
        perror("g_file_copy");
        return 7;
    }

/*
    printf("After:\n");
    if (system("ls -l")) {
        perror("system");
        return 255;
    }
*/

    if (lstat(ORIG, &info_after)) {
        perror(ORIG);
        return 8;
    }

    unlink(COPY);
    unlink(SYMLINK);
    unlink(ORIG);
    rmdir(dir);

    if (info_before.st_mode != info_after.st_mode) {
        fprintf(stderr, "FAIL: mode changed on original file (0%03o -> 0%03o)\n", info_before.st_mode, info_after.st_mode);
        return 10;
    }
    else {
        printf("ok\n");
    }

    return 0;
}
