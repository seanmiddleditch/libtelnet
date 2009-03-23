VERSION = 0.9
CFLAGS = -Wall -g -O0 -DHAVE_ZLIB -DHAVE_ALLOCA -DENABLE_COLOR
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
		telnet-client telnet-client.o telnet-chatd telnet-chatd.o

dist:
	rm -fr libtelnet-$(VERSION)
	rm -f libtelnet-$(VERSION).tar.gz
	mkdir libtelnet-$(VERSION)
	cp Makefile README libtelnet.h libtelnet.c telnet-proxy.c \
		telnet-client.c telnet-chatd.c libtelnet-$(VERSION)
	tar -cf libtelnet-$(VERSION).tar libtelnet-$(VERSION)
	gzip libtelnet-$(VERSION).tar
	rm -fr libtelnet-$(VERSION)

.PHONY: all clean dist
