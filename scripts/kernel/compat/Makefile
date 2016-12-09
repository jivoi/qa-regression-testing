CFLAGS=-Wall

EXECS=CVE-2010-3301 CVE-2010-3081
ARCH=$(shell dpkg --print-architecture)

ifeq ($(ARCH),amd64)
EXTRA_FLAGS=-m32
endif

all: $(EXECS)

CVE-2010-3081: CVE-2010-3081.c
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ $<

clean:
	rm -f $(EXECS)
