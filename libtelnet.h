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
typedef struct libtelnet_t libtelnet_t;
typedef struct libtelnet_event_t libtelnet_event_t;
typedef struct libtelnet_rfc1143_t libtelnet_rfc1143_t;

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

/* libtelnet feature flags */
#define LIBTELNET_FLAG_PROXY (1<<0)

#define LIBTELNET_PFLAG_DEFLATE (1<<7)

/* telnet states */
enum libtelnet_state_t {
	LIBTELNET_STATE_DATA = 0,
	LIBTELNET_STATE_IAC,
	LIBTELNET_STATE_DO,
	LIBTELNET_STATE_DONT,
	LIBTELNET_STATE_WILL,
	LIBTELNET_STATE_WONT,
	LIBTELNET_STATE_SB,
	LIBTELNET_STATE_SB_DATA,
	LIBTELNET_STATE_SB_DATA_IAC
};
typedef enum libtelnet_state_t libtelnet_state_t;

/* error codes */
enum libtelnet_error_t {
	LIBTELNET_EOK = 0,
	LIBTELNET_EBADVAL, /* invalid parameter, or API misuse */
	LIBTELNET_ENOMEM, /* memory allocation failure */
	LIBTELNET_EOVERFLOW, /* data exceeds buffer size */
	LIBTELNET_EPROTOCOL, /* invalid sequence of special bytes */
	LIBTELNET_ECOMPRESS /* error handling compressed streams */
};
typedef enum libtelnet_error_t libtelnet_error_t;

/* event codes */
enum libtelnet_event_type_t {
	LIBTELNET_EV_DATA = 0,
	LIBTELNET_EV_SEND,
	LIBTELNET_EV_IAC,
	LIBTELNET_EV_WILL,
	LIBTELNET_EV_WONT,
	LIBTELNET_EV_DO,
	LIBTELNET_EV_DONT,
	LIBTELNET_EV_SUBNEGOTIATION,
	LIBTELNET_EV_COMPRESS,
	LIBTELNET_EV_WARNING,
	LIBTELNET_EV_ERROR
};
typedef enum libtelnet_event_type_t libtelnet_event_type_t;

/* event information */
struct libtelnet_event_t {
	/* data buffer: for DATA, SEND, SUBNEGOTIATION, and ERROR events */
	const unsigned char *buffer;
	unsigned int size;
	/* type of event */ 
	enum libtelnet_event_type_t type;
	/* IAC command */
	unsigned char command;
	/* telopt info: for negotiation events SUBNEGOTIATION */
	unsigned char telopt;
	/* accept status: for WILL and DO events */
	unsigned char accept;
};

/* option negotiation state (RFC 1143) */
struct libtelnet_rfc1143_t {
	unsigned char telopt;
	char us:4, him:4;
};

/* event handler declaration */
typedef void (*libtelnet_event_handler_t)(libtelnet_t *telnet,
		libtelnet_event_t *event, void *user_data);

/* state tracker */
struct libtelnet_t {
	/* user data */
	void *ud;
	/* event handler */
	libtelnet_event_handler_t eh;
#ifdef HAVE_ZLIB
	/* zlib (mccp2) compression */
	z_stream *z;
#endif
	/* RFC1143 option negotiation states */
	struct libtelnet_rfc1143_t *q;
	/* sub-request buffer */
	unsigned char *buffer;
	/* current size of the buffer */
	unsigned int buffer_size;
	/* current buffer write position (also length of buffer data) */
	unsigned int buffer_pos;
	/* current state */
	enum libtelnet_state_t state;
	/* option flags */
	unsigned char flags;
	/* current subnegotiation telopt */
	unsigned char sb_telopt;
	/* length of RFC1143 queue */
	unsigned char q_size;
};

/* initialize a telnet state tracker */
extern void libtelnet_init(libtelnet_t *telnet, libtelnet_event_handler_t eh,
		unsigned char flags, void *user_data);

/* free up any memory allocated by a state tracker */
extern void libtelnet_free(libtelnet_t *telnet);

/* push a byte buffer into the state tracker */
extern void libtelnet_push(libtelnet_t *telnet, const unsigned char *buffer,
		unsigned int size);

/* send an iac command */
extern void libtelnet_send_command(libtelnet_t *telnet, unsigned char cmd);

/* send an iac command with a telopt */
extern void libtelnet_send_telopt(libtelnet_t *telnet, unsigned char cmd,
		unsigned char telopt);

/* send negotiation, with RFC1143 checking.
 * will not actually send unless necessary, but will update internal
 * negotiation queue.
 */
extern void libtelnet_send_negotiate(libtelnet_t *telnet, unsigned char cmd,
		unsigned char opt);

/* send non-command data (escapes IAC bytes) */
extern void libtelnet_send_data(libtelnet_t *telnet,
		const unsigned char *buffer, unsigned int size);

/* send sub-request, equivalent to:
 *   libtelnet_send_telopt(telnet, LIBTELNET_SB, telopt)
 *   libtelnet_send_data(telnet, buffer, size);
 *   libtelnet_send_command(telnet, LIBTELNET_SE);
 * manually generating sequence may be easier for complex subnegotiations
 * thare are most easily implemented with a series of send_data calls.
 */
extern void libtelnet_send_subnegotiation(libtelnet_t *telnet,
		unsigned char telopt, const unsigned char *buffer, unsigned int size);

/* begin sending compressed data (server only) */
extern void libtelnet_begin_compress2(libtelnet_t *telnet);

/* send formatted data (through libtelnet_send_data) */
#ifdef __GNUC__
# define LIBTELNET_GNU_PRINTF(f,a) __attribute__((printf(f, a)))
#else
# define LIBTELNET_GNU_PRINTF(f,a)
#endif

extern int libtelnet_printf(libtelnet_t *telnet, const char *fmt, ...);

/* send formatted data with \r and \n translated */
extern int libtelnet_printf2(libtelnet_t *telnet, const char *fmt, ...);

#endif /* !defined(LIBTELNET_INCLUDE) */
