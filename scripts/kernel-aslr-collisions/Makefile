CFLAGS=-fPIE
LDFLAGS=-pie

EXES=explode-brk aslr-crash

all: $(EXES)

%: %.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f $(EXES)
