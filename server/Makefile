CROSS_COMPILE=

CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
TARGET ?= aesdsocket
LDFLAGS ?= -pthread -lrt

all: aesdsocket.o
	echo ${CC}
	$(CC) $(CFLAGS) -g -Wall -c -o aesdsocket.o aesdsocket.c $(LDFLAGS)
	$(CC) $(CFLAGS) -g -Wall -I / aesdsocket.o -o aesdsocket $(LDFLAGS)

.PHONY: clean
clean:
	-rm -f *.o aesdsocket *.elf *.map