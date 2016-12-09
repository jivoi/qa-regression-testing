SUBDIRS=memmove signalstack guard-page

all:
	set -e && for dir in $(SUBDIRS) ; do \
		make -C $${dir} ; \
	done
	-make -C bad-syscall
	-make -C inotify
	-make -C compat

clean:
	for dir in $(SUBDIRS) ; do \
		make -C $${dir} clean ; \
	done
	make -C inotify clean
	make -C bad-syscall clean
	make -C compat clean
