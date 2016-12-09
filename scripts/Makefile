export TMPDIR=.
TESTS:=$(wildcard test-*.py)
TGZS:=$(patsubst %.py,qrt-%.tar.gz,$(TESTS))

all: $(TGZS)
clean:
	rm -f $(TGZS)

qrt-test-%.tar.gz: test-%.py
	./make-test-tarball $<

.PHONY: all clean
