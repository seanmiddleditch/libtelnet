CFLAGS = -Wall -g -O0 -DHAVE_ZLIB -DENABLE_COLOR
LFLAGS = -lz

telnet-proxy: telnet-proxy.c libtelnet.c libtelnet.h Makefile
	$(CC) -o telnet-proxy $(CFLAGS) telnet-proxy.c libtelnet.c $(LFLAGS)
