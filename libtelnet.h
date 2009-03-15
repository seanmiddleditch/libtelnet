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
#define LIBTELNET_INCLUDE 1

/* forward declarations */
struct libtelnet_t;
struct libtelnet_cb_t;

/* telnet special values */
#define LIBTELNET_IAC 255
#define LIBTELNET_DONT 254
#define LIBTELNET_DO 253
#define LIBTELNET_WONT 252
#define LIBTELNET_WILL 251
#define LIBTELNET_SB 250
#define LIBTELNET_SB 250
#define LIBTELNET_GA 249
#define LIBTELNET_EL 248
#define LIBTELNET_EC 247
#define LIBTELNET_AYT 246
#define LIBTELNET_AO 245
#define LIBTELNET_IP 244
#define LIBTELNET_BREAK 243
#define LIBTELNET_DM 242
#define LIBTELNET_NOP 241
#define LIBTELNET_SE 240
#define LIBTELNET_EOR 239
#define LIBTELNET_ABORT 238
#define LIBTELNET_SUSP 237
#define LIBTELNET_EOF 236

/* telnet options */
#define LIBTELNET_TELOPT_BINARY 0
#define LIBTELNET_TELOPT_ECHO 1
#define LIBTELNET_TELOPT_RCP 2
#define LIBTELNET_TELOPT_SGA 3
#define LIBTELNET_TELOPT_NAMS 4
#define LIBTELNET_TELOPT_STATUS 5
#define LIBTELNET_TELOPT_TM 6
#define LIBTELNET_TELOPT_RCTE 7
#define LIBTELNET_TELOPT_NAOL 8
#define LIBTELNET_TELOPT_NAOP 9
#define LIBTELNET_TELOPT_NAOCRD 10
#define LIBTELNET_TELOPT_NAOHTS 11
#define LIBTELNET_TELOPT_NAOHTD 12
#define LIBTELNET_TELOPT_NAOFFD 13
#define LIBTELNET_TELOPT_NAOVTS 14
#define LIBTELNET_TELOPT_NAOVTD 15
#define LIBTELNET_TELOPT_NAOLFD 16
#define LIBTELNET_TELOPT_XASCII 17
#define LIBTELNET_TELOPT_LOGOUT 18
#define LIBTELNET_TELOPT_BM 19
#define LIBTELNET_TELOPT_DET 20
#define LIBTELNET_TELOPT_SUPDUP 21
#define LIBTELNET_TELOPT_SUPDUPOUTPUT 22
#define LIBTELNET_TELOPT_SNDLOC 23
#define LIBTELNET_TELOPT_TTYPE 24
#define LIBTELNET_TELOPT_EOR 25
#define LIBTELNET_TELOPT_TUID 26
#define LIBTELNET_TELOPT_OUTMRK 27
#define LIBTELNET_TELOPT_TTYLOC 28
#define LIBTELNET_TELOPT_3270REGIME 29
#define LIBTELNET_TELOPT_X3PAD 30
#define LIBTELNET_TELOPT_NAWS 31
#define LIBTELNET_TELOPT_TSPEED 32
#define LIBTELNET_TELOPT_LFLOW 33
#define LIBTELNET_TELOPT_LINEMODE 34
#define LIBTELNET_TELOPT_XDISPLOC 35
#define LIBTELNET_TELOPT_ENVIRON 36
#define LIBTELNET_TELOPT_AUTHENTICATION 37
#define LIBTELNET_TELOPT_ENCRYPT 38
#define LIBTELNET_TELOPT_NEW_ENVIRON 39
#define LIBTELNET_TELOPT_COMPRESS 85
#define LIBTELNET_TELOPT_COMPRESS2 86
#define LIBTELNET_TELOPT_ZMP 93
#define LIBTELNET_TELOPT_EXOPL 255

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

/* libtelnet callback declarations */
struct libtelnet_cb_t {
	/* received (processed) data */
	void (*data)(struct libtelnet_t *telnet,
			unsigned char *buffer, unsigned int size, void *user_data);
	/* processed data to buffer for sending */
	void (*send)(struct libtelnet_t *telnet,
			unsigned char *buffer, unsigned int size, void *user_data);
	/* unknown command notification */
	void (*command)(struct libtelnet_t *telnet,
			unsigned char cmd, void *user_data);
	/* negotiation notification */
	void (*negotiate)(struct libtelnet_t *telnet,
			unsigned char cmd, unsigned char opt, void *user_data);
	/* unknown subnegotiation notification */
	void (*subnegotiation)(struct libtelnet_t *telnet,
			unsigned char opt, unsigned char *data, unsigned int size,
			void *user_data);
	/* error handler */
	void (*error)(struct libtelnet_t *telnet,
			enum libtelnet_error_t error, void *user_data);

	#ifdef HAVE_ZLIB
	void (*compress)(struct libtelnet_t *telnet,
			char enabled, void *user_data);
	#endif
};

/* state tracker */
struct libtelnet_t {
	/* callback table */
	struct libtelnet_cb_t *cb;
#ifdef HAVE_ZLIB
	/* zlib (mccp2) compression */
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

/* initialize a telnet state tracker */
extern void libtelnet_init(struct libtelnet_t *telnet,
		struct libtelnet_cb_t *cb, enum libtelnet_mode_t mode);

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
