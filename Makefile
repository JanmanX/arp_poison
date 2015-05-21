CC=gcc
CFLAGS=-Wall -g
LFLAGS=-lpcap

OUTPUT=bin
PROGS=src/syn_flood.c src/arp_poison.c
SOURCES=$(wildcard src/lib/*.c)
OBJECTS=$(patsubst %.c,%.o,$(SOURCES))

all: syn_flood arp_poison

syn_flood:
	$(CC) $(CFLAGS) $(SOURCES) src/syn_flood.c -o $(OUTPUT)/syn_flood $(LFLAGS)

arp_poison:

	$(CC) $(CFLAGS) $(SOURCES) src/arp_poison.c -o $(OUTPUT)/arp_poison $(LFLAGS)


.PHONY: clean all

clean:
	rm -fv src/lib/*.o src/*.o bin/*
