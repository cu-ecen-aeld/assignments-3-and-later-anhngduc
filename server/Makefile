CROSS_COMPILE=

CC=${CROSS_COMPILE}gcc
CFLAGS= -g -Wall -Werror
LDFLAGS=-pthread

all: aesdsocket.o
	echo ${CC}
	$(CC) -g -Wall -c -o aesdsocket.o aesdsocket.c $(LDFLAGS)
	$(CC) -g -Wall -I / aesdsocket.o -o aesdsocket $(LDFLAGS)

.PHONY: clean
clean:
	-rm -f *.o aesdsocket *.elf *.map