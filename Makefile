SHELL = /bin/bash
CC = gcc
CFLAGS = -lnet -lpthread 
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC}  $@.c -o $@ ${CFLAGS}

clean:
	rm ${EXE}
