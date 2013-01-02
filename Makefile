CC = gcc
CFLAGS = -pedantic -Wall -Wextra -g -DDEBUG

all:	libsegfault.so

clean:
	rm -f libsegfault.so
	rm -f test1 test2

check:	all test1 test2
	./test1
	LD_LIBRARY_PATH="." ./test2

libsegfault.so:	segfault.c
	$(CC) \
		-fPIC -fpic $(CFLAGS) $(EXTRA_CFLAGS) -D_GNU_SOURCE \
		-shared \
		-olibsegfault.so \
		segfault.c \
		$(LDFLAGS) -ludis86 -ldl

test1:	test1.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -otest1 test1.c $(LDFLAGS) -ldl

test2:	test2.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -otest2 test2.c $(LDFLAGS) -L. -lsegfault
