NAME=network
CC=gcc
CFLAGS=-Wall -g
LFLAGS=-lpcap
OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(NAME) $(LFLAGS)

.PHONY: clean all
clean:
	rm -fv $(NAME) *.o
