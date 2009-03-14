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

#if !defined(LIBTELNET_INCLUDE)
#define LIBTELNET 1

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
#define LIBTELNET_OPTION_COMPRESS2 86
#define LIBTELNET_OPTION_ZMP 93

/* libtelnet modes */
enum libtelnet_mode_t {
	LIBTELNET_MODE_SERVER = 0,
	LIBTELNET_MODE_CLIENT
};

/* telnet states */
enum libtelnet_state_t {
	LIBTELNET_STATE_DATA = 0,
	LIBTELNET_STATE_IAC,
	LIBTELNET_STATE_DO,
	LIBTELNET_STATE_DONT,
	LIBTELNET_STATE_WILL,
	LIBTELNET_STATE_WONT,
	LIBTELNET_STATE_SB,
	LIBTELNET_STATE_SB_IAC
};

/* error codes */
enum libtelnet_error_t {
	LIBTELNET_ERROR_OK = 0,
	LIBTELNET_ERROR_NOMEM, /* memory allocation failure */
	LIBTELNET_ERROR_OVERFLOW, /* data exceeds buffer size */
	LIBTELNET_ERROR_PROTOCOL, /* invalid sequence of special bytes */
	LIBTELNET_ERROR_UNKNOWN /* some crazy unexplainable unknown error */
};

/* state tracker */
struct libtelnet_t {
	/* zlib (mccp2) compression */
#ifdef HAVE_ZLIB
	z_stream *zlib;
#endif
	/* sub-request buffer */
	unsigned char *buffer;
	/* current size of the buffer */
	unsigned int size;
	/* length of data in the buffer */
	unsigned int length;
	/* current state */
	enum libtelnet_state_t state;
	/* processing mode */
	enum libtelnet_mode_t mode;
};

/* libtelnet callback declarations
 * APPLICATION MUST IMPLEMENT THESE FUNCTIONS!!
 */
extern void libtelnet_data_cb(struct libtelnet_t *telnet,
		unsigned char *buffer, unsigned int size, void *user_data);
extern void libtelnet_send_cb(struct libtelnet_t *telnet,
		unsigned char *buffer, unsigned int size, void *user_data);
extern void libtelnet_command_cb(struct libtelnet_t *telnet,
		unsigned char cmd, void *user_data);
extern void libtelnet_negotiate_cb(struct libtelnet_t *telnet,
		unsigned char cmd, unsigned char opt, void *user_data);
extern void libtelnet_subnegotiation_cb(struct libtelnet_t *telnet,
		unsigned char opt, unsigned char *data, unsigned int size,
		void *user_data);
#ifdef HAVE_ZLIB
extern void libtelnet_compress_cb(struct libtelnet_t *telnet,
		char enabled, void *user_data);
#endif
extern void libtelnet_error_cb(struct libtelnet_t *telnet,
		enum libtelnet_error_t error, void *user_data);

/* initialize a telnet state tracker */
extern void libtelnet_init(struct libtelnet_t *telnet,
		enum libtelnet_mode_t mode);

/* free up any memory allocated by a state tracker */
extern void libtelnet_free(struct libtelnet_t *telnet);

/* push a byte buffer into the state tracker */
extern void libtelnet_push(struct libtelnet_t *telnet,
		unsigned char *buffer, unsigned int size, void *user_data);

/* send an iac command */
extern void libtelnet_send_command(struct libtelnet_t *telnet,
		unsigned char cmd, void *user_data);

/* send negotiation */
extern void libtelnet_send_negotiate(struct libtelnet_t *telnet,
		unsigned char cmd, unsigned char opt, void *user_data);

/* send non-command data (escapes IAC bytes) */
extern void libtelnet_send_data(struct libtelnet_t *telnet,
		unsigned char *buffer, unsigned int size, void *user_data);

/* send sub-request */
extern void libtelnet_send_subnegotiation(struct libtelnet_t *telnet,
		unsigned char opt, unsigned char *buffer, unsigned int size,
		void *user_data);

#endif /* !defined(LIBTELNET_INCLUDE) */
