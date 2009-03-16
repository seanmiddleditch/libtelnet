CFLAGS = -Wall -g -O0 -DHAVE_ZLIB -DENABLE_COLOR
LFLAGS = -L. -ltelnet -lz

all: telnet-proxy telnet-client telnet-chatd

%.o: %.c libtelnet.h
	$(CC) -o $@ -c $(CFLAGS) $<

libtelnet.a: libtelnet.o libtelnet.h
	$(AR) rcs $@ $< 

telnet-proxy: telnet-proxy.o libtelnet.a Makefile
	$(CC) -o $@ $< $(LFLAGS)

telnet-client: telnet-client.o libtelnet.a Makefile
	$(CC) -o $@ $(CFLAGS) $< $(LFLAGS)

telnet-chatd: telnet-chatd.o libtelnet.a Makefile
	$(CC) -o $@ $(CFLAGS) $< $(LFLAGS)

clean:
	rm -f libtelnet.a libtelnet.o telnet-proxy telnet-proxy.o \
		telnet-client telnet-client.o telnet-chatd telnet-chatd.c

dist:
	rm -fr libtelnet-dist
	rm -f libtelnet-dist.tar.gz
	mkdir libtelnet-dist
	cp Makefile README libtelnet.h libtelnet.c telnet-proxy.c \
		telnet-client.c telnet-chatd.c libtelnet-dist
	tar -cf libtelnet-dist.tar libtelnet-dist
	gzip libtelnet-dist.tar
	rm -fr libtelnet-dist

.PHONY: all clean dist
