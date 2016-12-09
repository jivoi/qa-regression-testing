/* Copyright 2009-2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
*/
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <assert.h>

void func(const char*path) {
    unsigned int stack_overflow = -1;
    struct dirent entry;
    struct dirent *result = NULL;
    int ret;

    DIR *dir = opendir(path);
    if(!dir) abort();

    printf("sizeof portable dirent: %lu (from 'man readdir_r', seems to be clearly wrong)\n", offsetof(struct dirent, d_name) + pathconf(path, _PC_NAME_MAX) + 1);

    printf("sizeof(struct dirent): %" PRIuFAST32 "\n", sizeof(entry));
    printf("\tsizeof(dirent.d_ino@%" PRIuFAST32 "): %" PRIuFAST32 "\n", offsetof(struct dirent, d_ino), sizeof(entry.d_ino));
    printf("\tsizeof(dirent.d_off@%" PRIuFAST32 "): %" PRIuFAST32 "\n", offsetof(struct dirent, d_off), sizeof(entry.d_off));
    printf("\tsizeof(dirent.d_reclen@%" PRIuFAST32 "): %" PRIuFAST32 "\n", offsetof(struct dirent, d_reclen), sizeof(entry.d_reclen));
    printf("\tsizeof(dirent.d_type@%" PRIuFAST32 "): %" PRIuFAST32 "\n", offsetof(struct dirent, d_type), sizeof(entry.d_type));
    printf("\tsizeof(dirent.d_name@%" PRIuFAST32 "): %" PRIuFAST32 "\n", offsetof(struct dirent, d_name), sizeof(entry.d_name));

    while (!(ret = readdir_r(dir, &entry, &result)) && result) {
        printf("\t\td_reclen == %d\n", result->d_reclen);
    }

    assert(stack_overflow == -1);
}

int main(int argc, const char** argv) {
    if(argc < 2) abort();
    func(argv[1]);
    return 0;
}
