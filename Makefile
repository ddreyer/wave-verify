CC      = g++
CFLAGS  = -I/usr/local/asn1cpp/include
LIBS = -lm -lnsl -pthread
OSSLIBS = /usr/local/asn1cpp/lib/libosscpp.so /usr/local/asn1cpp/lib/libcppsoed.so -ldl
AES_OBJECTS=$(AES_SRCS:.c=.o) 
AES_SRCS=aes-gcm/aes.c aes-gcm/cipher.c aes-gcm/cipher_wrap.c aes-gcm/gcm.c aes-gcm/utils.c
AESCFLAGS=-c -Wall
ED_OBJECTS=$(ED_SRCS:.c=.o)
ED_SRCS=$(wildcard ed25519/src/*.c)
HASH_OBJECTS=$(HASH_SRCS:.cpp=.o)
HASH_SRCS=hash-library/keccak.cpp

all: verify

verify: $(HASH_OBJECTS) $(ED_OBJECTS) $(AES_OBJECTS) objects.o verify.o
		g++ -o $@ $^ $(LIBS) $(OSSLIBS)
		./verify

verify.o: verify.cpp
		$(CC) -I. $(CFLAGS) -c $<

objects.o: objects.cpp
		$(CC) -I. $(CFLAGS) -DOSSPRINT -c $<

$(AES_OBJECTS): aes-gcm/%.o : aes-gcm/%.c
		gcc -c -Wall -c $< -o $@ 

$(ED_OBJECTS): ed25519/src/%.o: ed25519/src/%.c
		gcc -c $< -o $@

$(HASH_OBJECTS): hash-library/%.o: hash-library/%.cpp
		$(CC) -c $< -o $@

.PHONY: clean cleanest

clean:
		rm *.o

		
