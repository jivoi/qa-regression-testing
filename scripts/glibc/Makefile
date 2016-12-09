SUBDIRS=crypt getaddrinfo getdents strstr strspn strtod sscanf vfprintf \
	strcoll regex malloc

all:
	set -e && for dir in $(SUBDIRS) ; do \
		make -C $${dir} ; \
	done

clean:
	for dir in $(SUBDIRS) ; do \
		make -C $${dir} clean ; \
	done
