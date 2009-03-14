/*
 * Sean Middleditch
 * sean@sourcemud.org
 *
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law. 
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#include "libtelnet.h"

struct conn_t {
	const char *name;
	int sock;
	struct libtelnet_t telnet;
	struct conn_t *remote;
};

static const char *get_cmd(unsigned char cmd) {
	static char buffer[4];

	switch (cmd) {
	case 255: return "IAC";
	case 254: return "DONT";
	case 253: return "DO";
	case 252: return "WONT";
	case 251: return "WILL";
	case 250: return "SB";
	case 249: return "GA";
	case 248: return "EL";
	case 247: return "EC";
	case 246: return "AYT";
	case 245: return "AO";
	case 244: return "IP";
	case 243: return "BREAK";
	case 242: return "DM";
	case 241: return "NOP";
	case 240: return "SE";
	case 239: return "EOR";
	case 238: return "ABORT";
	case 237: return "SUSP";
	case 236: return "xEOF";
	default:
		snprintf(buffer, sizeof(buffer), "%d", (int)cmd);
		return buffer;
	}
}

static const char *get_opt(unsigned char opt) {
	switch (opt) {
	case 0: return "BINARY";
	case 1: return "ECHO";
	case 2: return "RCP";
	case 3: return "SGA";
	case 4: return "NAMS";
	case 5: return "STATUS";
	case 6: return "TM";
	case 7: return "RCTE";
	case 8: return "NAOL";
	case 9: return "NAOP";
	case 10: return "NAOCRD";
	case 11: return "NAOHTS";
	case 12: return "NAOHTD";
	case 13: return "NAOFFD";
	case 14: return "NAOVTS";
	case 15: return "NAOVTD";
	case 16: return "NAOLFD";
	case 17: return "XASCII";
	case 18: return "LOGOUT";
	case 19: return "BM";
	case 20: return "DET";
	case 21: return "SUPDUP";
	case 22: return "SUPDUPOUTPUT";
	case 23: return "SNDLOC";
	case 24: return "TTYPE";
	case 25: return "EOR";
	case 26: return "TUID";
	case 27: return "OUTMRK";
	case 28: return "TTYLOC";
	case 29: return "3270REGIME";
	case 30: return "X3PAD";
	case 31: return "NAWS";
	case 32: return "TSPEED";
	case 33: return "LFLOW";
	case 34: return "LINEMODE";
	case 35: return "XDISPLOC";
	case 36: return "ENVIRON";
	case 37: return "AUTHENTICATION";
	case 38: return "ENCRYPT";
	case 39: return "NEW-ENVIRON";
	case 70: return "MSSP";
	case 85: return "COMPRESS";
	case 86: return "COMPRESS2";
	case 93: return "ZMP";
	case 255: return "EXOPL";
	default: return "unknown";
	}
}

static void print_buffer(unsigned char *buffer, unsigned int size) {
	unsigned int i;
	for (i = 0; i != size; ++i) {
		if (buffer[i] == ' ' || (isprint(buffer[i]) && !isspace(buffer[i])))
			printf("%c", (char)buffer[i]);
		else if (buffer[i] == '\n')
			printf("<\e[1m0x%02X\e[22m>\n", (int)buffer[i]);
		else
			printf("<\e[1m0x%02X\e[22m>", (int)buffer[i]);
	}
}

void libtelnet_data_cb(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s DATA: ", conn->name);
	print_buffer(buffer, size);
	printf("\e[0m\n");

	libtelnet_send_data(&conn->remote->telnet, buffer, size,
			conn->remote);
}

void libtelnet_send_cb(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;
	int rs;

	/* DONT SPAM
	printf("%s SEND: ", conn->name);
	print_buffer(buffer, size);
	printf("\e[0m\n");
	*/

	/* send data */
	while (size > 0) {
		if ((rs = send(conn->sock, buffer, size, 0)) == -1) {
			fprintf(stderr, "send() failed: %s\n", strerror(errno));
			exit(1);
		} else if (rs == 0) {
			fprintf(stderr, "send() unexpectedly returned 0\n");
			exit(1);
		}

		/* update pointer and size to see if we've got more to send */
		buffer += rs;
		size -= rs;
	}
}

void libtelnet_command_cb(struct libtelnet_t *telnet, unsigned char cmd,
		void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s IAC %s\e[0m\n", conn->name, get_cmd(cmd));

	libtelnet_send_command(&conn->remote->telnet, cmd, conn->remote);
}

void libtelnet_negotiate_cb(struct libtelnet_t *telnet, unsigned char cmd,
		unsigned char opt, void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s IAC %s %d (%s)\e[0m\n", conn->name, get_cmd(cmd),
			(int)opt, get_opt(opt));

	libtelnet_send_negotiate(&conn->remote->telnet, cmd, opt,
			conn->remote);
}

void libtelnet_subrequest_cb(struct libtelnet_t *telnet, unsigned char type,
		unsigned char *buffer, unsigned int size, void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s SUB %d (%s)", conn->name, (int)type, get_opt(type));
	if (size > 0) {
		printf(" [%u]: ", size);
		print_buffer(buffer, size);
	}
	printf("\e[0m\n");

	libtelnet_send_subrequest(&conn->remote->telnet, type, buffer, size,
			conn->remote);
}

void libtelnet_compress_cb(struct libtelnet_t *telnet, char enabled,
		void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s COMPRESSION %s\e[0m\n", conn->name, enabled ? "ON" : "OFF");
}

void libtelnet_error_cb(struct libtelnet_t *telnet,
		enum libtelnet_error_t error, void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	printf("%s ERROR: %d\e[0m\n", conn->name, (int)error);
	exit(1);
}

int main(int argc, char **argv) {
	unsigned char buffer[512];
	int listen_sock;
	int rs;
	struct sockaddr_in addr;
	socklen_t addrlen;
	struct pollfd pfd[2];
	struct conn_t server;
	struct conn_t client;

	/* check usage */
	if (argc != 4) {
		fprintf(stderr, "Usage:\n ./telnet-proxy <remote ip> <remote port> "
				"<local port>\n");
		return 1;
	}
	
	/* create listening socket */
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* reuse address option */
	rs = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &rs, sizeof(rs));

	/* bind to listening addr/port */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(strtol(argv[3], 0, 10));
	if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}

	/* wait for client */
	if (listen(listen_sock, 5) == -1) {
		fprintf(stderr, "listen() failed: %s\n", strerror(errno));
		return 1;
	}
	addrlen = sizeof(addr);
	if ((client.sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen)) == -1) {
		fprintf(stderr, "accept() failed: %s\n", strerror(errno));
		return 1;
	}
	
	/* stop listening now that we have a client */
	close(listen_sock);
	
	/* create server socket */
	if ((server.sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* connect to server */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (bind(server.sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
		fprintf(stderr, "inet_pton() failed: %s\n", strerror(errno));
		return 1;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(strtol(argv[2], 0, 10));
	if (connect(server.sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "server() failed: %s\n", strerror(errno));
		return 1;
	}

	/* initialize connection structs */
	server.name = "\e[35mSERVER";
	server.remote = &client;
	client.name = "\e[34mCLIENT";
	client.remote = &server;

	/* initialize telnet boxes
	 * NOTE: we set the server connect to the CLIENT mode because we
	 * are acting as a client of the server; likewise, we set the
	 * client connection to SERVER mode becauser we are acting as a
	 * server to the client. */
	libtelnet_init(&server.telnet, LIBTELNET_MODE_CLIENT);
	libtelnet_init(&client.telnet, LIBTELNET_MODE_SERVER);

	/* initialize poll descriptors */
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = server.sock;
	pfd[0].events = POLLIN;
	pfd[1].fd = client.sock;
	pfd[1].events = POLLIN;

	/* loop while both connections are open */
	while (poll(pfd, 2, -1) != -1) {
		/* read from server */
		if (pfd[0].revents & POLLIN) {
			if ((rs = recv(server.sock, buffer, sizeof(buffer), 0)) > 0) {
				libtelnet_push(&server.telnet, buffer, rs, (void*)&server);
			} else if (rs == 0) {
				printf("%s DISCONNECTED\e[0m\n", server.name);
				break;
			} else {
				fprintf(stderr, "recv(server) failed: %s\n", strerror(errno));
				exit(1);
			}
		}

		/* read from client */
		if (pfd[1].revents & POLLIN) {
			if ((rs = recv(client.sock, buffer, sizeof(buffer), 0)) > 0) {
				libtelnet_push(&client.telnet, buffer, rs, (void*)&client);
			} else if (rs == 0) {
				printf("%s DISCONNECTED\e[0m\n", client.name);
				break;
			} else {
				fprintf(stderr, "recv(client) failed: %s\n", strerror(errno));
				exit(1);
			}
		}
	}

	/* clean up */
	libtelnet_free(&server.telnet);
	libtelnet_free(&client.telnet);
	close(server.sock);
	close(client.sock);

	return 0;
}
