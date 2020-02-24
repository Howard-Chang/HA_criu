SHELL = /bin/bash
CC = gcc
CFLAGS = -lnet -lpthread -g -O0 
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC}  $@.c -o $@ ${CFLAGS}

clean:
	rm ${EXE}
