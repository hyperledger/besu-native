CC=gcc
CFLAGS=-O2 -Wall -Wextra -pedantic -Wno-long-long -fpic

all:		libblake2bf.so libblake2bf.dylib

compile:    blake2b.c
	$(CC) blake2b.c -c $(CFLAGS)

libblake2bf.so: blake2b.o
		$(CC) -o $@ -shared $(CFLAGS) blake2b.o

libblake2bf.dylib: blake2b.o
		$(CC) -o $@ -dynamiclib $(CFLAGS) blake2b.o

clean:
		rm -rf *.o *.dylib *.so
