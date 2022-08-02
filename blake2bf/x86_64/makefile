CC=gcc
CFLAGS=-O2 -Wall -Wextra -pedantic -Wno-long-long -fpic

all:		libblake2bf

compile:    blake2b.c
	$(CC) blake2b.c -c $(CFLAGS)

libblake2bf: blake2b.o
		$(CC) -shared -o $@.so $(CFLAGS) blake2b.o

clean:
		rm -rf *.o *.so
