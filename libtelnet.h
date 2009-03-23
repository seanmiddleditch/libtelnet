/*
 * libtelnet 0.9
 *
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

/* printf type checking feature in GCC and some other compilers */
#if __GNUC__
# define TELNET_GNU_PRINTF(f,a) __attribute__((format(printf, f, a)))
# define TELNET_GNU_SENTINEL __attribute__((sentinel))
#else
# define TELNET_GNU_PRINTF(f,a)
# define TELNET_GNU_SENTINEL
#endif

/* forward declarations */
typedef struct telnet_t telnet_t;
typedef struct telnet_event_t telnet_event_t;
typedef struct telnet_telopt_t telnet_telopt_t;

/* telnet special values */
#define TELNET_IAC 255
#define TELNET_DONT 254
#define TELNET_DO 253
#define TELNET_WONT 252
#define TELNET_WILL 251
#define TELNET_SB 250
#define TELNET_GA 249
#define TELNET_EL 248
#define TELNET_EC 247
#define TELNET_AYT 246
#define TELNET_AO 245
#define TELNET_IP 244
#define TELNET_BREAK 243
#define TELNET_DM 242
#define TELNET_NOP 241
#define TELNET_SE 240
#define TELNET_EOR 239
#define TELNET_ABORT 238
#define TELNET_SUSP 237
#define TELNET_EOF 236

/* telnet options */
#define TELNET_TELOPT_BINARY 0
#define TELNET_TELOPT_ECHO 1
#define TELNET_TELOPT_RCP 2
#define TELNET_TELOPT_SGA 3
#define TELNET_TELOPT_NAMS 4
#define TELNET_TELOPT_STATUS 5
#define TELNET_TELOPT_TM 6
#define TELNET_TELOPT_RCTE 7
#define TELNET_TELOPT_NAOL 8
#define TELNET_TELOPT_NAOP 9
#define TELNET_TELOPT_NAOCRD 10
#define TELNET_TELOPT_NAOHTS 11
#define TELNET_TELOPT_NAOHTD 12
#define TELNET_TELOPT_NAOFFD 13
#define TELNET_TELOPT_NAOVTS 14
#define TELNET_TELOPT_NAOVTD 15
#define TELNET_TELOPT_NAOLFD 16
#define TELNET_TELOPT_XASCII 17
#define TELNET_TELOPT_LOGOUT 18
#define TELNET_TELOPT_BM 19
#define TELNET_TELOPT_DET 20
#define TELNET_TELOPT_SUPDUP 21
#define TELNET_TELOPT_SUPDUPOUTPUT 22
#define TELNET_TELOPT_SNDLOC 23
#define TELNET_TELOPT_TTYPE 24
#define TELNET_TELOPT_EOR 25
#define TELNET_TELOPT_TUID 26
#define TELNET_TELOPT_OUTMRK 27
#define TELNET_TELOPT_TTYLOC 28
#define TELNET_TELOPT_3270REGIME 29
#define TELNET_TELOPT_X3PAD 30
#define TELNET_TELOPT_NAWS 31
#define TELNET_TELOPT_TSPEED 32
#define TELNET_TELOPT_LFLOW 33
#define TELNET_TELOPT_LINEMODE 34
#define TELNET_TELOPT_XDISPLOC 35
#define TELNET_TELOPT_ENVIRON 36
#define TELNET_TELOPT_AUTHENTICATION 37
#define TELNET_TELOPT_ENCRYPT 38
#define TELNET_TELOPT_NEW_ENVIRON 39
#define TELNET_TELOPT_MSSP 70
#define TELNET_TELOPT_COMPRESS2 86
#define TELNET_TELOPT_ZMP 93
#define TELNET_TELOPT_EXOPL 255

#define TELNET_TELOPT_MCCP2 86

/* special codes for the subnegotiation commands for certain telopts */
#define TELNET_TTYPE_IS 0
#define TELNET_TTYPE_SEND 1

#define TELNET_ENVIRON_IS 0
#define TELNET_ENVIRON_SEND 1
#define TELNET_ENVIRON_INFO 2
#define TELNET_ENVIRON_VAR 0
#define TELNET_ENVIRON_VALUE 1
#define TELNET_ENVIRON_ESC 2
#define TELNET_ENVIRON_USERVAR 3

#define TELNET_MSSP_VAR 1
#define TELNET_MSSP_VAL 2

/* libtelnet feature flags */
#define TELNET_FLAG_PROXY (1<<0)

#define TELNET_PFLAG_DEFLATE (1<<7)

/* telnet states */
enum telnet_state_t {
	TELNET_STATE_DATA = 0,
	TELNET_STATE_IAC,
	TELNET_STATE_WILL,
	TELNET_STATE_WONT,
	TELNET_STATE_DO,
	TELNET_STATE_DONT,
	TELNET_STATE_SB,
	TELNET_STATE_SB_DATA,
	TELNET_STATE_SB_DATA_IAC
};
typedef enum telnet_state_t telnet_state_t;

/* error codes */
enum telnet_error_t {
	TELNET_EOK = 0,
	TELNET_EBADVAL, /* invalid parameter, or API misuse */
	TELNET_ENOMEM, /* memory allocation failure */
	TELNET_EOVERFLOW, /* data exceeds buffer size */
	TELNET_EPROTOCOL, /* invalid sequence of special bytes */
	TELNET_ECOMPRESS /* error handling compressed streams */
};
typedef enum telnet_error_t telnet_error_t;

/* event codes */
enum telnet_event_type_t {
	TELNET_EV_DATA = 0,
	TELNET_EV_SEND,
	TELNET_EV_IAC,
	TELNET_EV_WILL,
	TELNET_EV_WONT,
	TELNET_EV_DO,
	TELNET_EV_DONT,
	TELNET_EV_SUBNEGOTIATION,
	TELNET_EV_COMPRESS,
	TELNET_EV_WARNING,
	TELNET_EV_ERROR
};
typedef enum telnet_event_type_t telnet_event_type_t;

/* event information */
struct telnet_event_t {
	/* ZMP argument list */
	const char **argv;
	size_t argc;
	/* data buffer: for DATA, SEND, SUBNEGOTIATION, and ERROR events */
	const char *buffer;
	size_t size;
	/* type of event */ 
	enum telnet_event_type_t type;
	/* IAC command */
	unsigned char command;
	/* telopt info: for negotiation events SUBNEGOTIATION */
	unsigned char telopt;
};

/* event handler declaration */
typedef void (*telnet_event_handler_t)(telnet_t *telnet,
		telnet_event_t *event, void *user_data);

/* telopt support table element; use telopt of -1 for end marker */
struct telnet_telopt_t {
	short telopt; /* one of the TELOPT codes or -1 */
	unsigned char us; /* TELNET_WILL or TELNET_WONT */
	unsigned char him; /* TELNET_DO or TELNET_DONT */
};

/* state tracker */
struct telnet_t {
	/* user data */
	void *ud;
	/* telopt support table */
	const telnet_telopt_t *telopts;
	/* event handler */
	telnet_event_handler_t eh;
#ifdef HAVE_ZLIB
	/* zlib (mccp2) compression */
	z_stream *z;
#endif
	/* RFC1143 option negotiation states */
	struct telnet_rfc1143_t *q;
	/* sub-request buffer */
	char *buffer;
	/* current size of the buffer */
	size_t buffer_size;
	/* current buffer write position (also length of buffer data) */
	size_t buffer_pos;
	/* current state */
	enum telnet_state_t state;
	/* option flags */
	unsigned char flags;
	/* current subnegotiation telopt */
	unsigned char sb_telopt;
	/* length of RFC1143 queue */
	unsigned char q_size;
};

/* initialize a telnet state tracker */
extern void telnet_init(telnet_t *telnet, const telnet_telopt_t *telopts,
		telnet_event_handler_t eh, unsigned char flags, void *user_data);

/* free up any memory allocated by a state tracker */
extern void telnet_free(telnet_t *telnet);

/* push a byte buffer into the state tracker */
extern void telnet_recv(telnet_t *telnet, const char *buffer,
		size_t size);

/* send an iac command */
extern void telnet_iac(telnet_t *telnet, unsigned char cmd);

/* send negotiation, with RFC1143 checking.
 * will not actually send unless necessary, but will update internal
 * negotiation queue.
 */
extern void telnet_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char opt);

/* send non-command data (escapes IAC bytes) */
extern void telnet_send(telnet_t *telnet,
		const char *buffer, size_t size);

/* send IAC SB followed by the telopt code */
extern void telnet_begin_sb(telnet_t *telnet,
		unsigned char telopt);

/* send IAC SE */
#define telnet_finish_sb(telnet) telnet_iac((telnet), TELNET_SE)

/* shortcut for sending a complete subnegotiation buffer.
 * equivalent to:
 *   telnet_begin_sb(telnet, telopt);
 *   telnet_send(telnet, buffer, size);
 *   telnet_finish_sb(telnet);
 */
extern void telnet_subnegotiation(telnet_t *telnet, unsigned char telopt,
		const char *buffer, size_t size);

/* begin sending compressed data (server only) */
extern void telnet_begin_compress2(telnet_t *telnet);

/* send formatted data with \r and \n translated, and IAC escaped */
extern int telnet_printf(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/* send formatted data with just IAC escaped */
extern int telnet_printf2(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/* send TTYPE/ENVIRON/NEW-ENVIRON/MSSP data */
extern void telnet_format_sb(telnet_t *telnet, unsigned char telopt,
		size_t count, ...);

/* send ZMP commands */
extern void telnet_send_zmp(telnet_t *telnet, size_t argc, const char **argv);
extern void telnet_send_zmpv(telnet_t *telnet, ...) TELNET_GNU_SENTINEL;

#endif /* !defined(LIBTELNET_INCLUDE) */
