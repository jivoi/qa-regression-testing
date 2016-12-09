LIBS=-lgc
# Include path needed for versions of libgc <= 6.8
INCLUDE_PATH=/usr/include/gc/
CFLAGS=-O2 -g -Wall

all: malloc-1 calloc-mult-overflow

malloc-1: malloc-1.c
	$(CC) -I$(INCLUDE_PATH) $(CFLAGS) $< -o $@ $(LIBS)

calloc-mult-overflow: calloc-mult-overflow.c
	$(CC) -I$(INCLUDE_PATH) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f malloc-1 calloc-mult-overflow
