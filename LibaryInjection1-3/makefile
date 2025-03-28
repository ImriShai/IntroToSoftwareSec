# Makefile for compiling and running the specified commands

# Compiler and flags
CC = gcc
CFLAGS = -ldl
SHARED_FLAGS = --shared -fPIC

# Targets
all: benignRandom ibc.so.6

benignRandom: benignRandom.c
	$(CC) benignRandom.c -o benignRandom $(CFLAGS)

ibc.so.6: myLib.c
	$(CC) $(SHARED_FLAGS) myLib.c -o ibc.so.6 $(CFLAGS)

run:
	export LD_LIBRARY_PATH="."

clean:
	rm -f benignRandom ibc.so.6