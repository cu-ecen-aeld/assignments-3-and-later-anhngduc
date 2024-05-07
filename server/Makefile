CROSS_COMPILE=

CC=${CROSS_COMPILE}gcc
CFLAGS= -g -Wall -Werror

all: aesdsocket.o
	echo ${CC}
	$(CC) -g -Wall	-c -o aesdsocket.o aesdsocket.c
	$(CC) -g -Wall -I / aesdsocket.o -o aesdsocket

.PHONY: clean
clean:
	-rm -f *.o aesdsocket *.elf *.map