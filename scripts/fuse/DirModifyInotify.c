/** This program waits for notify of file/directory to replace
 *  given directory with symlink.
 *  Parameters:
 *  * --LinkTarget: If set, the MovePath is replaced with link to
 *    this path
 *  Usage: DirModifyInotify.c --Watch [watchfile0] --WatchCount [num]
 *      --MovePath [path] --LinkTarget [path]
 *  gcc -o DirModifyInotify DirModifyInotify.c
 *
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
  char	*movePath=NULL;
  char	*newDirName;
  char	*symlinkTarget=NULL;

  int	argPos;
  int	handle;
  int	inotifyHandle;
  int	inotifyDataSize=sizeof(struct inotify_event);
  struct inotify_event *inotifyData;
  int	randomVal;
  int	callCount;
  int	targetCallCount=0;
  int	debugFlag=0;
  int	ret;

  if(argc<4) return(1);
  inotifyHandle=inotify_init();

  for(argPos=1; argPos<argc; argPos++) {
    if(!strcmp(argv[argPos], "--Debug")) {
      debugFlag=1;
      continue;
    }

    if(!strcmp(argv[argPos], "--LinkTarget")) {
      argPos++;
      if(argPos==argc) exit(1);
      symlinkTarget=argv[argPos];
      continue;
    }

    if(!strcmp(argv[argPos], "--MovePath")) {
      argPos++;
      if(argPos==argc) exit(1);
      movePath=argv[argPos];
      continue;
    }

    if(!strcmp(argv[argPos], "--Watch")) {
      argPos++;
      if(argPos==argc) exit(1);
//IN_ALL_EVENTS, IN_CLOSE_WRITE|IN_CLOSE_NOWRITE, IN_OPEN|IN_ACCESS
      ret=inotify_add_watch(inotifyHandle, argv[argPos], IN_ALL_EVENTS);
      if(ret==-1) {
        fprintf(stderr, "Failed to add watch path %s, error %d\n",
            argv[argPos], errno);
        return(1);
      }
      continue;
    }

    if(!strcmp(argv[argPos], "--WatchCount")) {
      argPos++;
      if(argPos==argc) exit(1);
      targetCallCount=atoi(argv[argPos]);
      continue;
    }

    fprintf(stderr, "Unknown option %s\n", argv[argPos]);
    return(1);
  }

  if(!movePath) {
    fprintf(stderr, "No move path specified!\n" \
        "Usage: DirModifyInotify.c --Watch [watchfile0] --MovePath [path]\n" \
        "    --LinkTarget [path]\n");
    return(1);
  }

  fprintf(stderr, "Using target call count %d\n", targetCallCount);

// Init name of new directory
  newDirName=(char*)malloc(strlen(movePath)+256);
  sprintf(newDirName, "%s-moved", movePath);
  inotifyData=(struct inotify_event*)malloc(inotifyDataSize);

  for(callCount=0; ; callCount++) {
    ret=read(inotifyHandle, inotifyData, inotifyDataSize);
    if(callCount==targetCallCount) {
/*
      ret=rmdir("tmp/tmp");
      if(!ret) fprintf(stderr, "rmdir failed, error %d\n", errno);
*/
      rename(movePath, newDirName);
      if(symlinkTarget) symlink(symlinkTarget, movePath);
      fprintf(stderr, "Move triggered at count %d\n", callCount);
    }
    if(debugFlag) {
      fprintf(stderr, "Received notify %d, ret %d\n", callCount, ret);
    }
    if(ret<0) {
      break;
    }
  }
  return(0);
}
