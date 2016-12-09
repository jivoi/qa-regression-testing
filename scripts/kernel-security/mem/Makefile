CFLAGS=-Wall -Werror -O2

EXECS=readmem

all: $(EXECS)
	make -C signpost

clean:
	rm -f $(EXECS)
	make -C signpost clean

readmem: readmem.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< -o $@ -lcap
