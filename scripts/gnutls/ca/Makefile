GENERATED = \
	x509-ca-key.pem \
	x509-ca.pem \
	x509-server-key.pem \
	x509-server.pem

all: $(GENERATED)

x509-ca-key.pem:
	certtool -p --outfile x509-ca-key.pem

x509-ca.pem:
	certtool --generate-self-signed \
		--load-privkey x509-ca-key.pem \
		--outfile x509-ca.pem \
		--template ca.cfg

x509-server-key.pem:
	certtool -p --outfile x509-server-key.pem

x509-server.pem:
	certtool --generate-certificate \
		--load-privkey x509-server-key.pem \
		--load-ca-privkey x509-ca-key.pem \
		--load-ca-certificate x509-ca.pem \
		--outfile x509-server.pem \
		--template server.cfg

test:
	gnutls-cli expired.demo.gnutls.org --x509cafile x509-ca.pem 

clean:
	rm -f $(GENERATED) *~

