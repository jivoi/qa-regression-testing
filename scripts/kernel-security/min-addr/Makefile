CFLAGS=-Wall -Werror -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2

EXECS=low-mmap mappage0 low-mmap-setuid

all: $(EXECS)

clean:
	rm -f $(EXECS)

low-mmap-setuid: low-mmap.c
	$(CC) $(CFLAGS) -o $@-notsetuid $<
	#sudo chown root $@-notsetuid && sudo chmod u+s $@-notsetuid
	chmod u+s $@-notsetuid
	mv $@-notsetuid $@
