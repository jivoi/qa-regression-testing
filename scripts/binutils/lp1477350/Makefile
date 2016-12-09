OBJCOPY ?= /usr/bin/objcopy
OBJECTS = test-x86_64.o test-x86_64.elf test-i386.o test-i386.elf
TESTS=test-x86_64.pecoff test-i386.pecoff

all: $(TESTS)
clean:
	rm -f ${OBJECTS} $(TESTS)


test-x86_64.o: test.S
	gcc -m64 -D_FORTIFY_SOURCE=2  -c -o $@ $<

test-i386.o: test.S
	gcc -m32 -D_FORTIFY_SOURCE=2  -c -o $@ $<

%.elf: %.o
	gcc  -g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Wformat-security -Werror=format-security  -nostdlib -T ./$*.lds -o $@ $<

test-x86_64.pecoff: test-x86_64.elf
	$(OBJCOPY) -j .text  -j .sdata -j .data \
	        -j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc --target=efi-app-x86-64 $< test-x86_64.pecoff

test-i386.pecoff: test-i386.elf
	$(OBJCOPY) -j .text  -j .sdata -j .data \
	        -j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc --target=efi-app-i386 $< test-i386.pecoff
