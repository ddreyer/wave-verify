CXX = g++
CFLAGS = -I./include/asn1c -Ofast
CC = gcc
CXXFLAGS = -I./include/verify -I./include/asn1c -I./src -Ofast -std=c++17 -lstdc++ 
AR = ar

VERIFY_CPP_SOURCES = src/verify/verify.cpp
VERIFY_C_SOURCES = $(wildcard src/asn1c/*.c) $(wildcard src/ed25519/src/*.c) src/SHA3IUF/sha3.c

BINDIR = bin
VERIFY_OBJECTS = $(addprefix $(BINDIR)/,$(VERIFY_C_SOURCES:.c=.o)) $(addprefix $(BINDIR)/,$(VERIFY_CPP_SOURCES:.cpp=.o)) 

all: verify.a

verify.a: $(VERIFY_OBJECTS)
	$(AR) rcs verify.a $+

$(BINDIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BINDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf bin verify.a
