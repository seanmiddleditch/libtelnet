/*
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law. 
 */

#if !defined(LIBTELNET_INCLUDE)
#define LIBTELNET 1

/* sub request buffer size, normal (defualt 1K) */
#define LIBTELNET_BUFFER_SIZE_SMALL (1 * 1024)
/* sub request buffer size, enlarged (default 16K) */
#define LIBTELNET_BUFFER_SIZE_LARGE (16 * 1024)

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
	LIBTELNET_ERROR_NOMEM, /* memory allocation failure */
	LIBTELNET_ERROR_OVERFLOW, /* input exceeds buffer size */
	LIBTELNET_ERROR_PROTOCOL, /* invalid sequence of special bytes */
	LIBTELNET_ERROR_UNKNOWN, /* some crazy unexplainable unknown error */
};

/* libtelnet callback declarations
 * APPLICATION MUST IMPLEMENT THESE FUNCTIONS!!
 */
extern void libtelnet_input_cb(struct libtelnet_t *telnet, unsigned char
		byte, void *user_data);
extern void libtelnet_output_cb(struct libtelnet_t *telnet, unsigned char
		byte, void *user_data);
extern void libtelnet_command_cb(struct libtelnet_t *telnet, unsigned char
		cmd, void *user_data);
extern void libtelnet_negotiate_cb(struct libtelnet_t *telnet, unsigned char
		cmd, unsigned char opt, void *user_data);
extern void libtelnet_subrequest_cb(struct libtelnet_t *telnet, unsigned char
		cmd, unsigned char type, unsigned char *data, size_t size,
		void *user_data);
extern void libtelnet_error_cb(struct libtelnet_t *telnet,
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
};

/* initialize a telnet state tracker */
extern void libtelnet_init(struct libtelnet_t *telnet);

/* free up any memory allocated by a state tracker */
extern void libtelnet_free(struct libtelnet_t *telnet);

/* push a single byte into the state tracker */
extern void libtelnet_push_byte(struct libtelnet_t *telnet, unsigned char byte,
	void *user_data);

/* push a byte buffer into the state tracker */
extern void libtelnet_push_buffer(struct libtelnet_t *telnet,
	unsigned char *buffer, size_t size, void *user_data);

/* send an iac command */
extern void libtelnet_send_command(struct libtelnet_t *telnet,
	unsigned char cmd, void *user_data);

/* send negotiation */
extern void libtelnet_send_negotiate(struct libtelnet_t *telnet,
	unsigned char cmd, unsigned char opt, void *user_data);

/* send non-command data (escapes IAC bytes) */
extern void libtelnet_send_data(struct libtelnet_t *telnet,
	unsigned char *buffer, size_t size, void *user_data);

/* send sub-request */
extern void libtelnet_send_subrequest(struct libtelnet_t *telnet,
	unsigned char type, unsigned char *buffer, size_t size, void *user_data);

#endif /* !defined(LIBTELNET_INCLUDE) */
