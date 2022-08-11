CC=gcc
CFLAGS=-march=armv8-a -O2 -Wall -Wextra -pedantic -Wno-long-long

all:		libblake2bf

compile:    blake2b.c blake2b-round.h blake2b-load-neon.h
	$(CC) blake2b.c -c $(CFLAGS)

libblake2bf: blake2b.o
		$(CC) -shared -o $@.so $(CFLAGS) blake2b.o

clean:
		rm -rf *.o *.so
