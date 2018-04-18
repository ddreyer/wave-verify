CC      = g++
CFLAGS  = -I/usr/local/asn1cpp/include
LIBS = -lm -lnsl -pthread
OSSLIBS = /usr/local/asn1cpp/lib/libosscpp.so /usr/local/asn1cpp/lib/libcpptoed.so -ldl 


verify: objects.o verify.o 
		$(CC) -o $@ $^ $(LIBS) $(OSSLIBS)

verify.o: verify.cpp 
		$(CC) -I. $(CFLAGS) -c $<
objects.o: objects.cpp
	$(CC) -I. $(CFLAGS) -DOSSPRINT -c $<

.PHONY: clean cleanest

clean:
		rm *.o

		
