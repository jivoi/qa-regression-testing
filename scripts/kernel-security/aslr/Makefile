override CFLAGS+=-Wall -Wformat-security -D_FORTIFY_SOURCE=2 -O2

EXECS=aslr mmap-growth-direction
ARCH=$(shell dpkg --print-architecture)

# ppc64el/s390x breaks when compiling -m32
ifneq ($(ARCH),ppc64el)
EXECS+=aslr32
endif

all: $(EXECS)

aslr: aslr.c
	$(CC) $(CFLAGS) -fPIC -pie -o $@ $< -ldl

# ppc64el breaks when compiling -m32
ifneq ($(ARCH),ppc64el)
# s390x needs -m31 for building compat mode bins
  ifeq ($(ARCH),s390x)
  COMPAT_FLAG=-m31
  else
  COMPAT_FLAG=-m32
  endif

aslr32: aslr.c
	$(CC) $(CFLAGS) $(COMPAT_FLAG) -fPIC -pie -o $@ $< -ldl
endif

mmap-growth-direction: mmap-growth-direction.c
	$(CC) $(CFLAGS) -fPIC -pie -o $@ $<

clean:
	rm -f $(EXECS)
