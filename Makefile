telnet-proxy: telnet-proxy.c libtelnet.c libtelnet.h
	$(CC) -o telnet-proxy -Wall telnet-proxy.c libtelnet.c
