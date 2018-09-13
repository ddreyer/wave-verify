include Makefile.am.libasncodec

LIBS += -lm
CFLAGS += $(ASN_MODULE_CFLAGS) -DASN_PDU_COLLECTION -I. -Iasn1c_files
ASN_LIBRARY ?= libasncodec.a
ASN_PROGRAM ?= verify
ASN_PROGRAM_SRCS ?= \
	main.cpp\
	verify.cpp

ASN_MODULE_OBJECTS=$(ASN_MODULE_SRCS:.c=.o)
ASN_MODULE_SRCS=$(wildcard asn1c_files/*.c)
AES_OBJECTS=$(AES_SRCS:.c=.o)
AES_SRCS=aes-gcm/aes.c aes-gcm/cipher.c aes-gcm/cipher_wrap.c aes-gcm/gcm.c aes-gcm/utils.c
ED_OBJECTS=$(ED_SRCS:.c=.o)
ED_SRCS=$(wildcard ed25519/src/*.c)
HASH_OBJECTS=$(HASH_SRCS:.cpp=.o)
HASH_SRCS=hash-library/keccak.cpp

all: $(ASN_PROGRAM)

verify.o: verify.cpp
		$(CXX) $(CFLAGS) -c $<

main.o: main.cpp
		$(CXX) $(CFLAGS) -c $<

$(ASN_PROGRAM): $(ASN_LIBRARY) $(ED_OBJECTS) $(AES_OBJECTS) $(HASH_OBJECTS) $(ASN_PROGRAM_SRCS:.cpp=.o)
	$(CXX) $(CFLAGS) $(CPPFLAGS) -o $(ASN_PROGRAM) $(ASN_PROGRAM_SRCS:.cpp=.o) $(LDFLAGS) $(ASN_LIBRARY) $(LIBS)
	./$(ASN_PROGRAM)

$(ASN_LIBRARY): $(ASN_MODULE_SRCS:.c=.o)
	$(AR) rcs $@ $(ASN_MODULE_SRCS:.c=.o)

$(AES_OBJECTS): aes-gcm/%.o : aes-gcm/%.c
		$(CC) -c -Wall -c $< -o $@ 

$(ED_OBJECTS): ed25519/src/%.o: ed25519/src/%.c
		$(CC) -c $< -o $@

$(HASH_OBJECTS): hash-library/%.o: hash-library/%.cpp
		$(CXX) -c $< -o $@


clean:
	rm -f $(ASN_PROGRAM) $(ASN_LIBRARY)
	rm -f $(ASN_MODULE_SRCS:.c=.o)
	rm -f aes-gcm/*.o ed25519/*.o hash-library/*.o

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	/usr/local/bin/asn1c -fcompound-names objects-lite.asn


		
