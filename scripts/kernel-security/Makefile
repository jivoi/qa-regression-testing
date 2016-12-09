SUBDIRS=aslr guard-page mem min-addr nx proc-maps ptrace seccomp seccomp_filter userns

all:
	set -e && for dir in $(SUBDIRS) ; do \
		make -C $${dir} ; \
	done

clean:
	for dir in $(SUBDIRS) ; do \
		make -C $${dir} clean ; \
	done
