EXES=openssl-rand glibc-rand gnutls-rand

all: $(EXES)

openssl-rand: openssl-rand.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -lcrypto

glibc-rand: glibc-rand.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

gnutls-rand: gnutls-rand.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -lgnutls-openssl

clean:
	rm -rf $(EXES)
