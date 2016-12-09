.SUFFIXES: .der .pem

.der.pem:
	openssl x509 -inform DER -in $< -outform PEM -out $@

all: $(subst .der,.pem,$(wildcard *.der)) canonical-master-signing-public-chain.pem

canonical-master-signing-public-chain.pem: canonical-master-public.pem canonical-signing-public.pem
	cat $? >> $@

clean:
	rm -f *.pem
