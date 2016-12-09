# This is the output of $(shell getconf LFS_CFLAGS) on 32bit...
LFS_CFLAGS=-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS=-Wall -Werror $(LFS_CFLAGS)
CC=gcc

EXES=test-native test-m32
all: $(EXES)

test:
	mkdir -p bug-dir
	touch bug-dir/111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
	./test-native bug-dir
	./test-m32 bug-dir

clean:
	rm -f $(EXES)
	rm -rf bug-dir

test-native: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test-m32: test.c
	$(CC) $(CFLAGS) -m32 $(LDFLAGS) -o $@ $<

#/usr/bin/c++   -D_THREAD_SAFE -D_PTHREADS -D_REENTRANT -pipe -g -Wall -W -Wno-parentheses -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -DGNU -Woverloaded-virtual  -m32 -msse -DUSE_INTERNAL_STL -DNATIVE_INCLUDE_PATH="/usr/include/c++/4.3" -Wno-deprecated -Wno-invalid-offsetof -DUSE_INTERNAL_STL  -o test.o -c test.cpp
#/usr/bin/c++    -pipe -g -Wall -W -Wno-parentheses -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -DGNU -Woverloaded-virtual  -m32 -msse -DUSE_INTERNAL_STL -DNATIVE_INCLUDE_PATH="/usr/include/c++/4.3" -Wno-deprecated -Wno-invalid-offsetof -DUSE_INTERNAL_STL   -fPIC      -ldl  test.o  -o test -Wl,--start-group -rdynamic -lpthread  -Wl,--end-group
