all: relro-bt

librelro-bt.so: relro-bt-lib.c
	gcc -ggdb3 -fPIC -shared relro-bt-lib.c -o librelro-bt.so

relro-bt: relro-bt.c librelro-bt.so
	gcc -ggdb3 -L`pwd` -Wall -o relro-bt relro-bt.c -lrelro-bt

clean:
	rm -f relro-bt librelro-bt.so core.*
