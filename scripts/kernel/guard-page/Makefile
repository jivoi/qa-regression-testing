CFLAGS=-Wall -Wformat-security -D_FORTIFY_SOURCE=2 -O2

EXECS=split-stack

all: $(EXECS)

split-stack: split-stack.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXECS)
