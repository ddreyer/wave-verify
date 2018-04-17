CC      = g++
CFLAGS  = -I/usr/local/asn1cpp/include
LIBS = -lm -lnsl
OSSLIBS = /usr/local/asn1cpp/lib/libosscpp.a /usr/local/asn1cpp/lib/libcpptoed.a 


verify: objects.o verify.o 
		$(CC) -o $@ $^ $(LIBS) $(OSSLIBS)

verify.o: verify.cpp 
		$(CC) -I. $(CFLAGS) -c $<
objects.o: objects.cpp
	$(CC) -I. $(CFLAGS) -DOSSPRINT -c $<

.PHONY: clean cleanest

clean:
		rm *.o

		
