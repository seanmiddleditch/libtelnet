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
#include <netdb.h>
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

#ifdef ENABLE_COLOR
# define COLOR_SERVER "\e[35m"
# define COLOR_CLIENT "\e[34m"
# define COLOR_BOLD "\e[1m"
# define COLOR_UNBOLD "\e[22m"
# define COLOR_NORMAL "\e[0m"
#else
# define COLOR_SERVER ""
# define COLOR_CLIENT ""
# define COLOR_BOLD ""
# define COLOR_UNBOLD ""
# define COLOR_NORMAL ""
#endif

struct conn_t {
	const char *name;
	int sock;
	libtelnet_t telnet;
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
			printf("<" COLOR_BOLD "0x%02X" COLOR_UNBOLD ">\n",
					(int)buffer[i]);
		else
			printf("<" COLOR_BOLD "0x%02X" COLOR_UNBOLD ">", (int)buffer[i]);
	}
}

static void _send(int sock, unsigned char *buffer, unsigned int size) {
	int rs;

	/* send data */
	while (size > 0) {
		if ((rs = send(sock, buffer, size, 0)) == -1) {
			if (errno != EINTR && errno != ECONNRESET) {
				fprintf(stderr, "send() failed: %s\n", strerror(errno));
				exit(1);
			} else {
				return;
			}
		} else if (rs == 0) {
			fprintf(stderr, "send() unexpectedly returned 0\n");
			exit(1);
		}

		/* update pointer and size to see if we've got more to send */
		buffer += rs;
		size -= rs;
	}
}

static void _event_handler(libtelnet_t *telnet, libtelnet_event_t *ev,
		void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	switch (ev->type) {
	/* data received */
	case LIBTELNET_EV_DATA:
		printf("%s DATA: ", conn->name);
		print_buffer(ev->buffer, ev->size);
		printf(COLOR_NORMAL "\n");

		libtelnet_send_data(&conn->remote->telnet, ev->buffer, ev->size);
		break;
	/* data must be sent */
	case LIBTELNET_EV_SEND:
		/* DONT SPAM
		printf("%s SEND: ", conn->name);
		print_buffer(ev->buffer, ev->size);
		printf(COLOR_BOLD "\n");
		*/

		_send(conn->sock, ev->buffer, ev->size);
		break;
	/* IAC command */
	case LIBTELNET_EV_IAC:
		printf("%s IAC %s" COLOR_NORMAL "\n", conn->name,
				get_cmd(ev->command));

		libtelnet_send_command(&conn->remote->telnet, ev->command);
		break;
	/* negotiation, WILL */
	case LIBTELNET_EV_WILL:
		printf("%s IAC WILL %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->telopt, get_opt(ev->telopt));
		libtelnet_send_negotiate(&conn->remote->telnet, LIBTELNET_WILL,
				ev->telopt);
		break;
	/* negotiation, WONT */
	case LIBTELNET_EV_WONT:
		printf("%s IAC WONT %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->telopt, get_opt(ev->telopt));
		libtelnet_send_negotiate(&conn->remote->telnet, LIBTELNET_WONT,
				ev->telopt);
		break;
	/* negotiation, DO */
	case LIBTELNET_EV_DO:
		printf("%s IAC DO %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->telopt, get_opt(ev->telopt));
		libtelnet_send_negotiate(&conn->remote->telnet, LIBTELNET_DO,
				ev->telopt);
		break;
	case LIBTELNET_EV_DONT:
		printf("%s IAC DONT %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->telopt, get_opt(ev->telopt));
		libtelnet_send_negotiate(&conn->remote->telnet, LIBTELNET_DONT,
				ev->telopt);
		break;
	/* subnegotiation */
	case LIBTELNET_EV_SUBNEGOTIATION:
		printf("%s SUB %d (%s)", conn->name, (int)ev->telopt,
				get_opt(ev->telopt));
		if (ev->size > 0) {
			printf(" [%u]: ", ev->size);
			print_buffer(ev->buffer, ev->size);
		}
		printf(COLOR_NORMAL "\n");

		libtelnet_send_subnegotiation(&conn->remote->telnet, ev->telopt,
				ev->buffer, ev->size);
		break;
	/* compression notification */
	case LIBTELNET_EV_COMPRESS:
		printf("%s COMPRESSION %s" COLOR_NORMAL "\n", conn->name,
				ev->command ? "ON" : "OFF");
		break;
	/* warning */
	case LIBTELNET_EV_WARNING:
		printf("%s WARNING: %.*s" COLOR_NORMAL "\n", conn->name, ev->size,
				ev->buffer);
		break;
	/* error */
	case LIBTELNET_EV_ERROR:
		printf("%s ERROR: %.*s" COLOR_NORMAL "\n", conn->name, ev->size,
				ev->buffer);
		exit(1);
	}
}

int main(int argc, char **argv) {
	unsigned char buffer[512];
	short listen_port;
	int listen_sock;
	int rs;
	struct sockaddr_in addr;
	socklen_t addrlen;
	struct pollfd pfd[2];
	struct conn_t server;
	struct conn_t client;
	struct addrinfo *ai;
	struct addrinfo hints;

	/* check usage */
	if (argc != 4) {
		fprintf(stderr, "Usage:\n ./telnet-proxy <remote ip> <remote port> "
				"<local port>\n");
		return 1;
	}

	/* parse listening port */
	listen_port = strtol(argv[3], 0, 10);

	/* loop forever, until user kills process */
	for (;;) {
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
		addr.sin_port = htons(listen_port);
		if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			fprintf(stderr, "bind() failed: %s\n", strerror(errno));
			return 1;
		}

		printf("LISTENING ON PORT %d\n", listen_port);

		/* wait for client */
		if (listen(listen_sock, 1) == -1) {
			fprintf(stderr, "listen() failed: %s\n", strerror(errno));
			return 1;
		}
		addrlen = sizeof(addr);
		if ((client.sock = accept(listen_sock, (struct sockaddr *)&addr,
				&addrlen)) == -1) {
			fprintf(stderr, "accept() failed: %s\n", strerror(errno));
			return 1;
		}

		printf("CLIENT CONNECTION RECEIVED\n");
		
		/* stop listening now that we have a client */
		close(listen_sock);

		/* look up server host */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if ((rs = getaddrinfo(argv[1], argv[2], &hints, &ai)) != 0) {
			fprintf(stderr, "getaddrinfo() failed for %s: %s\n", argv[1],
					gai_strerror(rs));
			return 1;
		}
		
		/* create server socket */
		if ((server.sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			fprintf(stderr, "socket() failed: %s\n", strerror(errno));
			return 1;
		}

		/* bind server socket */
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		if (bind(server.sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			fprintf(stderr, "bind() failed: %s\n", strerror(errno));
			return 1;
		}

		/* connect */
		if (connect(server.sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			fprintf(stderr, "server() failed: %s\n", strerror(errno));
			return 1;
		}

		/* free address lookup info */
		freeaddrinfo(ai);

		printf("SERVER CONNECTION ESTABLISHED\n");

		/* initialize connection structs */
		server.name = COLOR_SERVER "SERVER";
		server.remote = &client;
		client.name = COLOR_CLIENT "CLIENT";
		client.remote = &server;

		/* initialize telnet boxes */
		libtelnet_init(&server.telnet, _event_handler, LIBTELNET_FLAG_PROXY,
				&server);
		libtelnet_init(&client.telnet, _event_handler, LIBTELNET_FLAG_PROXY,
				&client);

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
					libtelnet_push(&server.telnet, buffer, rs);
				} else if (rs == 0) {
					printf("%s DISCONNECTED" COLOR_NORMAL "\n", server.name);
					break;
				} else {
					fprintf(stderr, "recv(server) failed: %s\n",
							strerror(errno));
					exit(1);
				}
			}

			/* read from client */
			if (pfd[1].revents & POLLIN) {
				if ((rs = recv(client.sock, buffer, sizeof(buffer), 0)) > 0) {
					libtelnet_push(&client.telnet, buffer, rs);
				} else if (rs == 0) {
					printf("%s DISCONNECTED" COLOR_NORMAL "\n", client.name);
					break;
				} else {
					fprintf(stderr, "recv(client) failed: %s\n",
							strerror(errno));
					exit(1);
				}
			}
		}

		/* clean up */
		libtelnet_free(&server.telnet);
		libtelnet_free(&client.telnet);
		close(server.sock);
		close(client.sock);

		/* all done */
		printf("BOTH CONNECTIONS CLOSED\n");
	}

	/* not that we can reach this, but GCC will cry if it's not here */
	return 0;
}
