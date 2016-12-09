CFLAGS=-g -Wall -Werror -Wformat -Wformat-security -O0

EXECS=nx-test nx-test-pie nx-test-rie

all: $(EXECS)

nx-test-pie: nx-test.c
	$(CC) $(CFLAGS) -fPIE -pie -o $@ $<

nx-test-rie: nx-test.c
	$(CC) $(CFLAGS) -Wl,-z,execstack -o $@ $<

clean:
	rm -f $(EXECS) nx-test-rie.tmp
