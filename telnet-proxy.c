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

#include "libtelnet.h"

static int server_sock;
static int client_sock;

static struct libtelnet_t server_telnet;
static struct libtelnet_t client_telnet;

static const char* get_name(int sock) {
	if (sock == server_sock)
		return "\e[31mSERVER";
	else
		return "\e[34mCLIENT";
}

static struct libtelnet_t *other_telnet(struct libtelnet_t *telnet) {
	if (telnet == &server_telnet)
		return &client_telnet;
	else
		return &server_telnet;
}

static void* other_socket(int sock) {
	if (sock == server_sock)
		return (void*)&client_sock;
	else
		return (void*)&server_sock;
}

static void print_buffer(unsigned char *buffer, unsigned int size) {
	unsigned int i;
	for (i = 0; i != size; ++i) {
		if (buffer[i] == ' ' || (isprint(buffer[i]) && !isspace(buffer[i])))
			printf("%c", (char)buffer[i]);
		else if (buffer[i] == '\n')
			printf("<%02X>\n", (int)buffer[i]);
		else
			printf("<%02X>", (int)buffer[i]);
	}
}

void libtelnet_input_cb(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
	int sock = *(int*)user_data;

	printf("%s INPUT: ", get_name(sock));
	print_buffer(buffer, size);
	printf("\e[0m\n");

	libtelnet_send_data(other_telnet(telnet), buffer, size,
			other_socket(sock));
}

void libtelnet_output_cb(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
	int sock = *(int*)user_data;

	/* DONT SPAM
	printf("%s OUTPUT: ", get_name(sock));
	print_buffer(buffer, size);
	printf("\e[0m\n");
	*/

	/* send data */
	send(sock, buffer, size, 0);
}

void libtelnet_command_cb(struct libtelnet_t *telnet, unsigned char cmd,
		void *user_data) {
	int sock = *(int*)user_data;

	printf("%s IAC %d\e[0m\n", get_name(sock), (int)cmd);

	libtelnet_send_command(other_telnet(telnet), cmd, other_socket(sock));
}

void libtelnet_negotiate_cb(struct libtelnet_t *telnet, unsigned char cmd,
		unsigned char opt, void *user_data) {
	int sock = *(int*)user_data;

	printf("%s IAC %d %d\e[0m\n", get_name(sock), (int)cmd, (int)opt);

	libtelnet_send_negotiate(other_telnet(telnet), cmd, opt,
			other_socket(sock));
}

void libtelnet_subrequest_cb(struct libtelnet_t *telnet, unsigned char type,
		unsigned char *buffer, unsigned int size, void *user_data) {
	int sock = *(int*)user_data;

	printf("%s SUBREQ %d: ", get_name(sock), (int)type);
	print_buffer(buffer, size);
	printf("\e[0m\n");

	libtelnet_send_subrequest(other_telnet(telnet), type, buffer, size,
			other_socket(sock));
}

void libtelnet_error_cb(struct libtelnet_t *telnet,
		enum libtelnet_error_t error, void *user_data) {
	int sock = *(int*)user_data;

	printf("%s ERROR: %d\e[0m\n", get_name(sock), (int)error);
}

int main(int argc, char **argv) {
	unsigned char buffer[512];
	int listen_sock;
	int rs;
	struct sockaddr_in addr;
	socklen_t addrlen;
	struct pollfd pfd[2];

	/* check usage */
	if (argc != 4) {
		fprintf(stderr, "Usage:\n ./telnet-proxy <remote ip> <remote port> <local port>\n");
		return 1;
	}
	
	/* create listening socket */
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* re-use addr */
	rs = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &rs, sizeof(rs));

	/* bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(strtol(argv[3], 0, 10));
	if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}

	/* listen */
	if (listen(listen_sock, 5) == -1) {
		fprintf(stderr, "listen() failed: %s\n", strerror(errno));
		return 1;
	}

	/* wait for client connection */
	if ((client_sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen)) == -1) {
		fprintf(stderr, "accept() failed: %s\n", strerror(errno));
		return 1;
	}
	
	/* create server socket */
	if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return 1;
	}

	/* bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		return 1;
	}

	/* connect */
	memset(&addr, 0, sizeof(addr));
	if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
		fprintf(stderr, "inet_pton() failed: %s\n", strerror(errno));
		return 1;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(strtol(argv[2], 0, 10));
	if (connect(server_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "server() failed: %s\n", strerror(errno));
		return 1;
	}

	/* initialize telnet boxes */
	libtelnet_init(&server_telnet);
	libtelnet_init(&client_telnet);

	/* initialize poll descriptors */
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = server_sock;
	pfd[0].events = POLLIN | POLLHUP;
	pfd[1].fd = client_sock;
	pfd[1].events = POLLIN | POLLHUP;

	/* loop while both connections are open */
	while (poll(pfd, 2, -1) != -1) {
		/* read from server */
		if (pfd[0].revents & POLLIN) {
			if ((rs = recv(pfd[0].fd, buffer, sizeof(buffer), 0)) > 0)
				libtelnet_push(&server_telnet, buffer, rs, (void*)&pfd[0].fd);
		}
		if (pfd[0].revents & POLLHUP)
			break;

		/* read from client */
		if (pfd[1].revents & POLLIN) {
			if ((rs = recv(pfd[1].fd, buffer, sizeof(buffer), 0)) > 0)
				libtelnet_push(&client_telnet, buffer, rs, (void*)&pfd[1].fd);
		}
		if (pfd[1].revents & POLLHUP)
			break;
	}

	/* clean up */
	libtelnet_free(&server_telnet);
	libtelnet_free(&client_telnet);
	close(server_sock);
	close(client_sock);
	close(listen_sock);

	return 0;
}
