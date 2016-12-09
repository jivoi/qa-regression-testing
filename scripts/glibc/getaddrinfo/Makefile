CFLAGS=-O2 -g -Wall

all: pagesize-abort pagesize-abort-static CVE-2013-4357

pagesize-abort-static: pagesize-abort.c
	cc ${CFLAGS} -static -o $@ $<

clean:
	rm -f pagesize-abort pagesize-abort-static CVE-2013-4357
