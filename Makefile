CCX=g++
CC=gcc
CFLAGS=-I. -Iasn1c_files
AES_OBJECTS=$(AES_SRCS:.c=.o)
AES_SRCS=aes-gcm/aes.c aes-gcm/cipher.c aes-gcm/cipher_wrap.c aes-gcm/gcm.c aes-gcm/utils.c
ED_OBJECTS=$(ED_SRCS:.c=.o)
ED_SRCS=$(wildcard ed25519/src/*.c)
HASH_OBJECTS=$(HASH_SRCS:.cpp=.o)
HASH_SRCS=hash-library/keccak.cpp
ASN1_OBJECTS=$(ASN1_SRCS:.c=.o)
ASN1_SRCS=$(wildcard asn1c_files/*.c)


all: verify

verify: $(HASH_OBJECTS) $(ED_OBJECTS) $(AES_OBJECTS) $(ASN1_OBJECTS) verify.o main.o
		$(CCX) -o $@ $^
		./verify

verify.o: verify.cpp
		$(CCX) $(CFLAGS) -c $<

main.o: main.cpp
		$(CCX) $(CFLAGS) -c $<

$(AES_OBJECTS): aes-gcm/%.o : aes-gcm/%.c
		$(CC) -c -Wall -c $< -o $@ 

$(ED_OBJECTS): ed25519/src/%.o: ed25519/src/%.c
		$(CC) -c $< -o $@

$(HASH_OBJECTS): hash-library/%.o: hash-library/%.cpp
		$(CCX) -c $< -o $@

$(ASN1_OBJECTS): asn1c_files/%.o: asn1c_files/%.c
		$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean cleanest

clean:
		rm -f *.o aes-gcm/*.o ed25519/*.o hash-library/*.o asn1c_files/*.o

		
