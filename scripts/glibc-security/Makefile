CFLAGS=-Wall -Werror -Wformat -Wformat-security -D_FORTIFY_SOURCE=2
NOOPT=-O0 -g3
OPT=-O2
LDLIBS=-ldl

EXECS=guard heap ptr-enc sprintf select

all: $(EXECS)

guard: guard.c
	STACK=""; \
	if [ `lsb_release -rs` != '6.06' ]; then STACK=-fstack-protector; fi; \
	$(CC) $(CFLAGS) $(NOOPT) $$STACK -o $@ $< $(LDLIBS)

heap: heap.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

ptr-enc: ptr-enc.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

sprintf: sprintf.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

select: select.c
	$(CC) $(CFLAGS) $(OPT) -o $@ $< $(LDLIBS)

clean:
	rm -f $(EXECS)
