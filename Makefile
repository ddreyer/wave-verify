CC      = g++
CFLAGS  = -I/usr/local/asn1cpp/include
LIBS = -lm -lnsl -pthread
OSSLIBS = /usr/local/asn1cpp/lib/libosscpp.so /usr/local/asn1cpp/lib/libcpptoed.so -ldl
OBJECTS=$(SRCS:.c=.o) 
SRCS=$(wildcard aes-gcm/*.c)
AESCFLAGS=-c -Wall

all: verify

verify: $(OBJECTS) objects.o verify.o
		g++ -o $@ $^ $(LIBS) $(OSSLIBS)

verify.o: verify.cpp
		$(CC) -I. $(CFLAGS) -c $<

objects.o: objects.cpp
		$(CC) -I. $(CFLAGS) -DOSSPRINT -c $<

$(OBJECTS): $(SRCS)
		gcc $(AESCFLAGS) -c $< -o $@ 

.PHONY: clean cleanest

clean:
		rm *.o

		
