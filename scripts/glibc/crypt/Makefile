CFLAGS=-O2 -g -Wall

test-crypt: test.c
	cc ${CFLAGS} -o $@ $< -lcrypt

clean:
	rm -f test-crypt
