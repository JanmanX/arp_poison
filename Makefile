CC=gcc
CFLAGS=-Wall -g
LFLAGS=-lpcap
SOURCES=$(wildcard src/*.c src/*.h)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o bin/$@ $(LFLAGS)

.PHONY: clean all

clean:
	rm -fv src/*.o bin/*
