# Add -O2 causes it segv on karmic/amd64
CFLAGS=-Wall -Wformat-security -D_FORTIFY_SOURCE=2

EXECS=signal-stack

all: $(EXECS)

signal-stack: signal-stack.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXECS)
