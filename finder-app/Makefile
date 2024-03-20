CROSS_COMPILE=

CC=${CROSS_COMPILE}gcc

all: writer.o
	echo ${CC}
	$(CC) -g -Wall	-c -o writer.o writer.c
	$(CC) -g -Wall -I / writer.o -o writer

.PHONY: clean
clean:
	-rm -f *.o writer *.elf *.map