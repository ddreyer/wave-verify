CXX = g++
CFLAGS = -I./include/verify -I./include/asn1c
CC = gcc
CXXFLAGS = -std=c++17 -I./include/verify -I./include/asn1c -I./src
AR = ar

VERIFY_CPP_SOURCES = $(wildcard hash-library/*.cpp) $(wildcard src/verify/*.cpp)
VERIFY_C_SOURCES = $(wildcard ed25519/src/*.c) $(wildcard src/asn1c_files/*.c)

BINDIR = bin
VERIFY_OBJECTS = $(addprefix $(BINDIR)/,$(VERIFY_C_SOURCES:.c=.o)) $(addprefix $(BINDIR)/,$(VERIFY_CPP_SOURCES:.cpp=.o)) 

all: verify.a

verify.a: $(VERIFY_OBJECTS) $(V_OBJECTS)
	$(AR) rcs verify.a $+

$(BINDIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BINDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf bin verify.a
