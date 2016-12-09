obj-m += execuser.o

all:
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$$PWD modules

clean:
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$$PWD clean
