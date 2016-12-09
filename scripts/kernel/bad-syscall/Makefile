CFLAGS=-Wall -Wformat-security -D_FORTIFY_SOURCE=2 -O2

EXECS=bad-syscall

all: $(EXECS)

bad-syscall: bad-syscall-test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXECS)
