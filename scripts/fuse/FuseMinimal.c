/** Minimal userspace file system demo, compile using
 *  gcc -D_FILE_OFFSET_BITS=64 -lfuse -Wall FuseMinimal.c -o FuseMinimal
 *
 *  Copyright (c) halfdog <me@halfdog.net>
 *  
 *  This software is provided by the copyright owner "as is" to
 *  study it but without any expressed or implied warranties, that
 *  this software is fit for any other purpose. If you try to compile
 *  or run it, you do it solely on your own risk and the copyright
 *  owner shall not be liable for any direct or indirect damage
 *  caused by this software.
 */

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fuse.h>
#include <string.h>

static int io_getattr(const char *path, struct stat *stbuf) {
  int res=-1;
  memset(stbuf, 0, sizeof(struct stat));
  if (strcmp(path, "/") == 0) {
    stbuf->st_mode=S_IFDIR|0755;
    stbuf->st_nlink=2;
    res=0;
  }
  return(res);
}


static int io_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi) {
  (void) offset;
  (void) fi;
  if(strcmp(path, "/")!=0) return -ENOENT;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);
  return 0;
}

static struct fuse_operations hello_oper = {
  .getattr	= io_getattr,
  .readdir	= io_readdir,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &hello_oper, NULL);
}
