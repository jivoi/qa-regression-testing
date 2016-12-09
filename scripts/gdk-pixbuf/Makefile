
test-gdk-pixbuf: test-gdk-pixbuf.c
	$(CC) -o $@ $< $(shell pkg-config --libs --cflags gdk-pixbuf-2.0)

clean:
	rm -f test-gdk-pixbuf
