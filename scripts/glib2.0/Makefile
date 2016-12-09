CC=gcc
CFLAGS=-Wall -O2 $(shell pkg-config --cflags glib-2.0 gio-2.0)
LDLIBS=$(shell pkg-config --libs glib-2.0 gio-2.0)

EXE=symlink-copying

all: $(EXE)
clean:
	rm -f $(EXE)

$(EXE): symlink-copying.c
