CFLAGS=-O2 -g -Wall

all: test test-static

test-static: test.c
	cc ${CFLAGS} -static -o $@ $<

clean:
	rm -f test test-static
