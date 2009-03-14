CFLAGS = -Wall -g -O0 -DHAVE_ZLIB
LFLAGS = -lz

telnet-proxy: telnet-proxy.c libtelnet.c libtelnet.h
	$(CC) -o telnet-proxy $(CFLAGS) telnet-proxy.c libtelnet.c $(LFLAGS)
