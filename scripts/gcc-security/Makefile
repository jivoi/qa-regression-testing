export LIBC_FATAL_STDERR_=1
export LANG=C
export LC_CTYPE=C
export LC_MESSAGES=C
export LC_ALL=C

CC=gcc
CFLAGS=-O2

STACK_PROTECTOR=stack-protector-on stack-protector-off stack-protector-default stack-protector-all
STACK_PROTECTOR_STRONG=stack-protector-strong-on stack-protector-strong-off stack-protector-strong-default
FORMAT_SECURITY=format-security-on format-security-off format-security-equal2 format-security-default
FORMAT=format-on format-off format-equal0 format-equal1 format-equal2 format-extra-args-on format-default
WARN_UNCHECKED=warn-unchecked-on warn-unchecked-off warn-unchecked-default
BUFFER_OVERFLOW=buffer-overflow-on buffer-overflow-off buffer-overflow-default
MISSING_MODE=missing-mode-on missing-mode-off missing-mode-default
RELRO=relro-on relro-off relro-default

EXE=$(STACK_PROTECTOR) $(STACK_PROTECTOR_STRONG) $(FORMAT_SECURITY) $(FORMAT) $(WARN_UNCHECKED) $(BUFFER_OVERFLOW) $(MISSING_MODE) $(RELRO)

all: $(EXE)

# Test ONLY stack protector, so disable FORTIFY
stack-protector-on: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector

stack-protector-off: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fno-stack-protector

stack-protector-default: stack-protector.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $<

stack-protector-all: stack-protector-all.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector-all


# stack-protector-strong
stack-protector-strong-on: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fstack-protector-strong

stack-protector-strong-off: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $< -fno-stack-protector

stack-protector-strong-default: stack-protector-strong.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -o $@ $<


# Test FORTIFY, but re-use stack-protector since it's basically the same test
buffer-overflow-on: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $< -D_FORTIFY_SOURCE=2

buffer-overflow-off: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $< -U_FORTIFY_SOURCE

buffer-overflow-default: stack-protector.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $<


format-security-on: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security

format-security-off: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -U_FORTIFY_SOURCE -Wno-format

# -Wformat=2 should also enable -Wformat-security
format-security-equal2: format-security.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2 -Wformat=2

format-security-default: format-security.c
	$(CC) $(CFLAGS) -o $@ $<


# test -Wformat/-Wformat-extra-args
format-on: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat

format-off: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wno-format

format-equal0: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=0

format-equal1: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=1

format-equal2: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat=2

format-extra-args-on: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $< -Wformat-extra-args

format-default: format-extra-args.c
	$(CC) $(CFLAGS) -o $@ $<


warn-unchecked-on: warn-unchecked.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2

warn-unchecked-off: warn-unchecked.c
	$(CC) $(CFLAGS) -o $@ $< -U_FORTIFY_SOURCE

warn-unchecked-default: warn-unchecked.c
	$(CC) $(CFLAGS) -o $@ $<


# Since this one can fail to build, put other fortify checks in here too
missing-mode-on: missing-mode.c
	$(CC) $(CFLAGS) -o $@ $< -D_FORTIFY_SOURCE=2

missing-mode-off: missing-mode.c
	$(CC) $(CFLAGS) -o $@ $< -U_FORTIFY_SOURCE

missing-mode-default: missing-mode.c
	$(CC) $(CFLAGS) -o $@ $<


relro-on: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,relro

relro-off: hello.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-z,norelro

relro-default: hello.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(EXE) bogus-modes

.PHONY: clean
