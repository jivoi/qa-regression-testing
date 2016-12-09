CFLAGS=-Wall -Werror -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2

EXECS=maps-helper-normal maps-helper-setuid

all: $(EXECS)

maps-helper-setuid: maps-helper-setuid.c
	$(CC) $(CFLAGS) -o maps-helper-notsetuid $<
	#sudo chown root maps-helper-notsetuid && sudo chmod u+s maps-helper-notsetuid
	chmod u+s maps-helper-notsetuid
	mv -f maps-helper-notsetuid $@

clean:
	rm -f $(EXECS) maps-helper-notsetuid
