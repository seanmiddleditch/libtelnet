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
#include <termios.h>
#include <unistd.h>

#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#include "libtelnet.h"

static struct termios orig_tios;
static libtelnet_t telnet;
static int do_echo;

static void _cleanup(void) {
	tcsetattr(STDOUT_FILENO, TCSADRAIN, &orig_tios);
}

static void _input(unsigned char *buffer, int size) {
	static unsigned char crlf[] = { '\r', '\n' };
	int i;

	for (i = 0; i != size; ++i) {
		/* if we got a CR or LF, replace with CRLF
		 * NOTE that usually you'd get a CR in UNIX, but in raw
		 * mode we get LF instead (not sure why)
		 */
		if (buffer[i] == '\r' || buffer[i] == '\n') {
			if (do_echo)
				write(STDOUT_FILENO, crlf, 2);
			libtelnet_send_data(&telnet, crlf, 2);
		} else {
			if (do_echo)
				write(STDOUT_FILENO, buffer + i, 1);
			libtelnet_send_data(&telnet, buffer + i, 1);
		}
	}
}

static void _send(int sock, unsigned char *buffer, unsigned int size) {
	int rs;

	/* send data */
	while (size > 0) {
		if ((rs = send(sock, buffer, size, 0)) == -1) {
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

static void _event_handler(libtelnet_t *telnet, libtelnet_event_t *ev,
		void *user_data) {
	int sock = *(int*)user_data;

	switch (ev->type) {
	/* data received */
	case LIBTELNET_EV_DATA:
		write(STDOUT_FILENO, ev->buffer, ev->size);
		break;
	/* data must be sent */
	case LIBTELNET_EV_SEND:
		_send(sock, ev->buffer, ev->size);
		break;
	/* accept any options we want */
	case LIBTELNET_EV_NEGOTIATE:
		switch (ev->command) {
		case LIBTELNET_WILL:
			switch (ev->telopt) {
			/* accept request to enable compression */
			case LIBTELNET_TELOPT_COMPRESS2:
				libtelnet_send_negotiate(telnet, LIBTELNET_DO, ev->telopt);
				break;
			/* server "promises" to echo, so turn off local echo */
			case LIBTELNET_TELOPT_ECHO:
				do_echo = 0;
				libtelnet_send_negotiate(telnet, LIBTELNET_DO, ev->telopt);
				break;
			/* unknown -- reject */
			default:
				libtelnet_send_negotiate(telnet, LIBTELNET_DONT, ev->telopt);
				break;
			}
			break;

		case LIBTELNET_WONT:
			switch (ev->telopt) {
			/* server wants us to do echoing, by telling us it won't */
			case LIBTELNET_TELOPT_ECHO:
				do_echo = 1;
				libtelnet_send_negotiate(telnet, LIBTELNET_DONT, ev->telopt);
				break;
			}
			break;

		case LIBTELNET_DO:
			switch (ev->telopt) {
			/* accept request to enable terminal-type requests */
			case LIBTELNET_TELOPT_TTYPE:
				libtelnet_send_negotiate(telnet, LIBTELNET_WILL, ev->telopt);
				break;
			/* unknown - reject */
			default:
				libtelnet_send_negotiate(telnet, LIBTELNET_WONT, ev->telopt);
				break;
			}
			break;

		case LIBTELNET_DONT:
			/* ignore for now */
			break;
		}
		break;
	/* respond to particular subnegotiations */
	case LIBTELNET_EV_SUBNEGOTIATION:
		/* respond with our terminal type */
		if (ev->telopt == LIBTELNET_TELOPT_TTYPE) {
			/* NOTE: we just assume the server sent a legitimate
			 * sub-negotiation, as there really isn't anything else
			 * it's allowed to send
			 */
			char buffer[64];
			buffer[0] = 0; /* IS code for RFC 1091 */
			snprintf(buffer + 1, sizeof(buffer) - 1, "%s", getenv("TERM"));
			libtelnet_send_subnegotiation(telnet, LIBTELNET_TELOPT_TTYPE,
					(unsigned char *)buffer, 1 + strlen(buffer + 1));
		}
		break;
	/* error */
	case LIBTELNET_EV_ERROR:
		fprintf(stderr, "ERROR: %.*s\n", ev->size, ev->buffer);
		exit(1);
	default:
		/* ignore */
		break;
	}
}

int main(int argc, char **argv) {
	unsigned char buffer[512];
	int rs;
	int sock;
	struct sockaddr_in addr;
	struct pollfd pfd[2];
	struct addrinfo *ai;
	struct addrinfo hints;
	struct termios tios;

	/* check usage */
	if (argc != 3) {
		fprintf(stderr, "Usage:\n ./telnet-client <host> <port>\n");
		return 1;
	}

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
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* bind server socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}

	/* connect */
	if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
		fprintf(stderr, "server() failed: %s\n", strerror(errno));
		return 1;
	}

	/* free address lookup info */
	freeaddrinfo(ai);

	/* get current terminal settings, set raw mode, make sure we
	 * register atexit handler to restore terminal settings
	 */
	tcgetattr(STDOUT_FILENO, &orig_tios);
	atexit(_cleanup);
	tios = orig_tios;
	cfmakeraw(&tios);
	tcsetattr(STDOUT_FILENO, TCSADRAIN, &tios);

	/* set input echoing on by default */
	do_echo = 1;

	/* initialize telnet box */
	libtelnet_init(&telnet, _event_handler, 0, &sock);

	/* initialize poll descriptors */
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = STDIN_FILENO;
	pfd[0].events = POLLIN;
	pfd[1].fd = sock;
	pfd[1].events = POLLIN;

	/* loop while both connections are open */
	while (poll(pfd, 2, -1) != -1) {
		/* read from stdin */
		if (pfd[0].revents & POLLIN) {
			if ((rs = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
				_input(buffer, rs);
			} else if (rs == 0) {
				break;
			} else {
				fprintf(stderr, "recv(server) failed: %s\n",
						strerror(errno));
				exit(1);
			}
		}

		/* read from client */
		if (pfd[1].revents & POLLIN) {
			if ((rs = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
				libtelnet_push(&telnet, buffer, rs);
			} else if (rs == 0) {
				break;
			} else {
				fprintf(stderr, "recv(client) failed: %s\n",
						strerror(errno));
				exit(1);
			}
		}
	}

	/* clean up */
	libtelnet_free(&telnet);
	close(sock);

	return 0;
}
