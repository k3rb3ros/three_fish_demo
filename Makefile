###########################
# Compiles threefish_demo #
###########################
CC=g++ -std=c++0x
CFLAGS=-O0 -g -Wall -Wextra
LPATHS=-Llib/
LDFLAGS=-lskein3fish
SOURCES=threefish_demo.cpp
OBJECTS=$(SOURCES:.cpp=.o)
BINARY=threefish_demo

all: $(BINARY) $(OBJECTS)
.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) $(LPATHS) $(OBJECTS) -o $@ $(LDFLAGS)

clean: 
	rm -v $(BINARY) $(OBJECTS)
