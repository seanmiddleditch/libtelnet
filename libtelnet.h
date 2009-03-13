/*
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law. 
 */

/* sub request buffer size increment (defualt 4K) */
#define LIBTELNET_BUFFER_SIZE (4 * 1024)
/* sub request buffer size (default 16K) */
#define LIBTELNET_BUFFER_SIZE_MAX (16 * 1024)

/* telnet special values */
#define LIBTELNET_IAC 255
#define LIBTELNET_DONT 254
#define LIBTELNET_DO 253
#define LIBTELNET_WONT 252
#define LIBTELNET_WILL 251
#define LIBTELNET_SB 250
#define LIBTELNET_SE 240

/* telnet options */
#define LIBTELNET_OPTION_BINARY 0
#define LIBTELNET_OPTION_ECHO 1
#define LIBTELNET_OPTION_NAWS 31
#define LIBTELNET_OPTION_ZMP 93

/* telnet states */
enum libtelnet_state_t {
	LIBTELNET_STATE_TEXT = 0,
	LIBTELNET_STATE_IAC,
	LIBTELNET_STATE_DO,
	LIBTELNET_STATE_DONT,
	LIBTELNET_STATE_WILL,
	LIBTELNET_STATE_WONT,
	LIBTELNET_STATE_SB,
	LIBTELNET_STATE_SB_IAC,
};

/* error codes */
enum libtelnet_error_t {
	LIBTELNET_ERROR_OK = 0,
	LIBTELNET_ERROR_OVERFLOW, /* input exceeds buffer size */
	LIBTELNET_ERROR_PROTOCOL, /* invalid sequence of special bytes */
	LIBTELNET_ERROR_UNKNOWN, /* some crazy unexplainable unknown error */
};

/* callback prototypes */
typedef (void)(*libtelnet_input)(struct libtelnet_t *telnet, unsigned char
		byte, void *user_data);
typedef (void)(*libtelnet_output)(struct libtelnet_t *telnet, unsigned char
		byte, void *user_data);
typedef (void)(*libtelnet_command)(struct libtelnet_t *telnet, unsigned char
		cmd, void *user_data);
typedef (void)(*libtelnet_negotiate)(struct libtelnet_t *telnet, unsigned char
		cmd, unsigned char opt, void *user_data);
typedef (void)(*libtelnet_subrequest)(struct libtelnet_t *telnet, unsigned char
		cmd, unsigned char type, unsigned char *data, size_t size,
		void *user_data);
typedef (void)(*libtelnet_error)(struct libtelnet_t *telnet,
		enum libtelnet_error_t error, void *user_data);

/* state tracker */
struct libtelnet_t {
	/* current state */
	enum libtelnet_state_t state;
	/* sub-request buffer */
	char *buffer;
	/* current size of the buffer */
	size_t size;
	/* length of data in the buffer */
	size_t length;

	/* callbacks */
	libtelnet_input input_cb;
	libtelnet_output output_cb;
	libtelnet_command command_cb;
	libtelnet_negotiate negotiate_cb;
	libtelnet_subrequest subrequest_cb;
};

/* initialize a telnet state tracker */
void libtelnet_init(struct libtelnet_t *telnet);

/* free up any memory allocated by a state tracker */
void libtelnet_close(struct libtelnet_t *telnet);

/* push a single byte into the state tracker */
void libtelnet_push_byte(struct libtelnet_t *telnet, unsigned char byte,
	void *user_data);

/* push a byte buffer into the state tracker */
void libtelnet_push_buffer(struct libtelnet_t *telnet, unsigned char *buffer,
	size_t size, void *user_data);

/* send an iac command */
void libtelnet_send_command(struct libtelnet_t *telnet, unsigned char cmd,
	void *user_data);

/* send negotiation */
void libtelnet_send_negotiate(struct libtelnet_t *telnet, unsigned char cmd,
	unsigned char opt, void *user_data);

/* send non-command data (escapes IAC bytes) */
void libtelnet_send_data(struct libtelnet_t *telnet, unsigned char *buffer,
	size_t size, void *user_data);

/* send sub-request */
void libtelnet_send_subrequest(struct libtelnet_t *telnet, unsigned char type,
	unsigned char *buffer, size_t size, void *user_data);
