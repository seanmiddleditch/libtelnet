CFLAGS = -Wall -g -O0 -DHAVE_ZLIB -DENABLE_COLOR
LFLAGS = -lz

all: telnet-proxy telnet-client

telnet-proxy: telnet-proxy.c libtelnet.c libtelnet.h Makefile
	$(CC) -o telnet-proxy $(CFLAGS) telnet-proxy.c libtelnet.c $(LFLAGS)

telnet-client: telnet-client.c libtelnet.c libtelnet.h Makefile
	$(CC) -o telnet-client $(CFLAGS) telnet-client.c libtelnet.c $(LFLAGS)
