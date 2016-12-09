CFLAGS=-Wall -Werror -g3

EXECS=sleeper thread-prctl

all: $(EXECS)

clean:
	rm -f $(EXECS)

thread-%: thread-%.c
	$(CC) $(CFLAGS) -pthread -o $@ $<
