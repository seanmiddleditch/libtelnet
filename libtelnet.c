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

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#ifdef HAVE_ALLOCA
#include <alloca.h>
#endif

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "libtelnet.h"

/* inlinable functions */
#if __GNUC__ || __STDC_VERSION__ >= 199901L
# define INLINE __inline__
#else
# define INLINE
#endif

/* RFC1143 option negotiation state */
typedef struct telnet_rfc1143_t {
	unsigned char telopt;
	char us:4, him:4;
} telnet_rfc1143_t;

/* RFC1143 state names */
#define Q_NO 0
#define Q_YES 1
#define Q_WANTNO 2
#define Q_WANTYES 3
#define Q_WANTNO_OP 4
#define Q_WANTYES_OP 5

/* buffer sizes */
static const size_t _buffer_sizes[] = { 0, 512, 2048, 8192, 16384, };
static const size_t _buffer_sizes_count = sizeof(_buffer_sizes) /
		sizeof(_buffer_sizes[0]);

/* event dispatch helper */
static INLINE void _event(telnet_t *telnet, telnet_event_type_t type,
		unsigned char command, unsigned char telopt,
		const char *buffer, size_t size, const char **argv, size_t argc) {
	telnet_event_t ev;
	ev.argv = argv;
	ev.argc = argc;
	ev.buffer = buffer;
	ev.size = size;
	ev.type = type;
	ev.command = command;
	ev.telopt = telopt;

	telnet->eh(telnet, &ev, telnet->ud);
}

/* error generation function */
static telnet_error_t _error(telnet_t *telnet, unsigned line,
		const char* func, telnet_error_t err, int fatal, const char *fmt,
		...) {
	char buffer[512];
	va_list va;

	/* format error intro */
	snprintf(buffer, sizeof(buffer), "%s:%u in %s: ", __FILE__, line, func);

	/* format informational text */
	va_start(va, fmt);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
			fmt, va);
	va_end(va);

	/* send error event to the user */
	_event(telnet, fatal ? TELNET_EV_ERROR : TELNET_EV_WARNING, err,
			0, buffer, strlen(buffer), 0, 0);
	
	return err;
}

#ifdef HAVE_ZLIB
/* initialize the zlib box for a telnet box; if deflate is non-zero, it
 * initializes zlib for delating (compression), otherwise for inflating
 * (decompression).  returns TELNET_EOK on success, something else on
 * failure.
 */
telnet_error_t _init_zlib(telnet_t *telnet, int deflate, int err_fatal) {
	z_stream *z;
	int rs;

	/* if compression is already enabled, fail loudly */
	if (telnet->z != 0)
		return _error(telnet, __LINE__, __func__, TELNET_EBADVAL,
				err_fatal, "cannot initialize compression twice");

	/* allocate zstream box */
	if ((z= (z_stream *)calloc(1, sizeof(z_stream))) == 0)
		return _error(telnet, __LINE__, __func__, TELNET_ENOMEM, err_fatal,
				"malloc() failed: %s", strerror(errno));

	/* initialize */
	if (deflate) {
		if ((rs = deflateInit(z, Z_DEFAULT_COMPRESSION)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, TELNET_ECOMPRESS,
					err_fatal, "deflateInit() failed: %s", zError(rs));
		}
		telnet->flags |= TELNET_PFLAG_DEFLATE;
	} else {
		if ((rs = inflateInit(z)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, TELNET_ECOMPRESS,
					err_fatal, "inflateInit() failed: %s", zError(rs));
		}
		telnet->flags &= ~TELNET_PFLAG_DEFLATE;
	}

	telnet->z = z;

	return TELNET_EOK;
}
#endif

/* push bytes out, compressing them first if need be */
static void _send(telnet_t *telnet, const char *buffer,
		size_t size) {
#ifdef HAVE_ZLIB
	/* if we have a deflate (compression) zlib box, use it */
	if (telnet->z != 0 && telnet->flags & TELNET_PFLAG_DEFLATE) {
		char deflate_buffer[1024];
		int rs;

		/* initialize z state */
		telnet->z->next_in = (unsigned char *)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = (unsigned char *)deflate_buffer;
		telnet->z->avail_out = sizeof(deflate_buffer);

		/* deflate until buffer exhausted and all output is produced */
		while (telnet->z->avail_in > 0 || telnet->z->avail_out == 0) {
			/* compress */
			if ((rs = deflate(telnet->z, Z_SYNC_FLUSH)) != Z_OK) {
				_error(telnet, __LINE__, __func__, TELNET_ECOMPRESS, 1,
						"deflate() failed: %s", zError(rs));
				deflateEnd(telnet->z);
				free(telnet->z);
				telnet->z = 0;
				break;
			}

			_event(telnet, TELNET_EV_SEND, 0, 0, deflate_buffer,
					sizeof(deflate_buffer) - telnet->z->avail_out, 0, 0);

			/* prepare output buffer for next run */
			telnet->z->next_out = (unsigned char *)deflate_buffer;
			telnet->z->avail_out = sizeof(deflate_buffer);
		}

	/* COMPRESS2 is not negotiated, just send */
	} else
#endif /* HAVE_ZLIB */
		_event(telnet, TELNET_EV_SEND, 0, 0, buffer, size, 0, 0);
}

/* check if we support a particular telopt; if us is non-zero, we
 * check if we (local) supports it, otherwise we check if he (remote)
 * supports it.  return non-zero if supported, zero if not supported.
 */
static INLINE int _check_telopt(telnet_t *telnet, unsigned char telopt,
		int us) {
	int i;

	/* if we have no telopts table, we obviously don't support it */
	if (telnet->telopts == 0)
		return 0;

	/* loop unti found or end marker (us and him both 0) */
	for (i = 0; telnet->telopts[i].telopt != -1; ++i) {
		if (telnet->telopts[i].telopt == telopt) {
			if (us && telnet->telopts[i].us == TELNET_WILL)
				return 1;
			else if (!us && telnet->telopts[i].him == TELNET_DO)
				return 1;
			else
				return 0;
		}
	}

	/* not found, so not supported */
	return 0;
}

/* retrieve RFC1143 option state */
static INLINE telnet_rfc1143_t _get_rfc1143(telnet_t *telnet,
		unsigned char telopt) {
	const telnet_rfc1143_t empty = { telopt, 0, 0};
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i)
		if (telnet->q[i].telopt == telopt)
			return telnet->q[i];

	/* not found, return empty value */
	return empty;
}

/* save RFC1143 option state */
static INLINE void _set_rfc1143(telnet_t *telnet, unsigned char telopt,
		char us, char him) {
	telnet_rfc1143_t *qtmp;
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i) {
		if (telnet->q[i].telopt == telopt) {
			telnet->q[i].us = us;
			telnet->q[i].him = him;
			return;
		}
	}

	/* we're going to need to track state for it, so grow the queue
	 * by 4 (four) elements and put the telopt into it; bail on allocation
	 * error.  we go by four because it seems like a reasonable guess as
	 * to the number of enabled options for most simple code, and it
	 * allows for an acceptable number of reallocations for complex code.
	 */
	if ((qtmp = (telnet_rfc1143_t *)realloc(telnet->q,
			sizeof(telnet_rfc1143_t) * (telnet->q_size + 4))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"malloc() failed: %s", strerror(errno));
		return;
	}
	memset(&qtmp[telnet->q_size], 0, sizeof(telnet_rfc1143_t) * 4);
	telnet->q = qtmp;
	telnet->q[telnet->q_size].telopt = telopt;
	telnet->q[telnet->q_size].us = us;
	telnet->q[telnet->q_size].him = him;
	telnet->q_size += 4;
}

/* send negotiation bytes */
static INLINE void _send_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	char bytes[3] = { TELNET_IAC, cmd, telopt };
	_send(telnet, bytes, 3);
}

/* negotiation handling magic for RFC1143 */
static void _negotiate(telnet_t *telnet, unsigned char telopt) {
	telnet_rfc1143_t q;

	/* in PROXY mode, just pass it thru and do nothing */
	if (telnet->flags & TELNET_FLAG_PROXY) {
		switch ((int)telnet->state) {
		case TELNET_STATE_WILL:
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			break;
		case TELNET_STATE_WONT:
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0, 0, 0);
			break;
		case TELNET_STATE_DO:
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			break;
		case TELNET_STATE_DONT:
			_event(telnet, TELNET_EV_DONT, 0, telopt, 0, 0, 0, 0);
			break;
		}
		return;
	}

	/* lookup the current state of the option */
	q = _get_rfc1143(telnet, telopt);

	/* start processing... */
	switch ((int)telnet->state) {
	/* request to enable option on remote end or confirm DO */
	case TELNET_STATE_WILL:
		switch (q.him) {
		case Q_NO:
			if (_check_telopt(telnet, telopt, 0)) {
				_set_rfc1143(telnet, telopt, q.us, Q_YES);
				_send_negotiate(telnet, TELNET_DO, telopt);
				_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			} else
				_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, q.us, Q_NO);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_YES);
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, q.us, Q_YES);
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTNO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			break;
		}
		break;

	/* request to disable option on remote end, confirm DONT, reject DO */
	case TELNET_STATE_WONT:
		switch (q.him) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, q.us, Q_NO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, q.us, Q_NO);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTYES);
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTYES:
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_NO);
			break;
		}
		break;

	/* request to enable option on local end or confirm WILL */
	case TELNET_STATE_DO:
		switch (q.us) {
		case Q_NO:
			if (_check_telopt(telnet, telopt, 1)) {
				_set_rfc1143(telnet, telopt, Q_YES, q.him);
				_send_negotiate(telnet, TELNET_WILL, telopt);
				_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			} else
				_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_NO, q.him);
			_event(telnet, TELNET_EV_DONT, 0, telopt, 0, 0, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_YES, q.him);
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_YES, q.him);
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_WANTNO, q.him);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0, 0, 0);
			break;
		}
		break;

	/* request to disable option on local end, confirm WONT, reject WILL */
	case TELNET_STATE_DONT:
		switch (q.us) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_NO, q.him);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			_event(telnet, TELNET_EV_DONT, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_NO, q.him);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_WANTYES, q.him);
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0, 0, 0);
			break;
		case Q_WANTYES:
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_NO, q.him);
			break;
		}
		break;
	}
}

/* process a subnegotiation buffer; return non-zero if the current buffer
 * must be aborted and reprocessed due to COMPRESS2 being activated
 */
static int _subnegotiate(telnet_t *telnet) {
	switch (telnet->sb_telopt) {
#ifdef HAVE_ZLIB
	/* received COMPRESS2 begin marker, setup our zlib box and
	 * start handling the compressed stream if it's not already.
	 */
	case TELNET_TELOPT_COMPRESS2:
		if (telnet->sb_telopt == TELNET_TELOPT_COMPRESS2) {
			if (_init_zlib(telnet, 0, 1) != TELNET_EOK)
				return 0;

			/* standard SB notification */
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);

			/* notify app that compression was enabled */
			_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0, 0, 0);
			return 1;
		}
		return 0;
#endif /* HAVE_ZLIB */
#ifdef HAVE_ALLOCA

	/* ZMP command */
	case TELNET_TELOPT_ZMP: {
		const char **argv, *c;
		size_t i, argc;
		/* make sure this is a valid ZMP buffer */
		if (telnet->buffer_pos == 0 ||
				telnet->buffer[telnet->buffer_pos - 1] != 0) {
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"incomplete ZMP frame");
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);
			return 0;
		}

		/* count arguments */
		for (argc = 0, c = telnet->buffer; c != telnet->buffer +
				telnet->buffer_pos; ++argc)
			c += strlen(c) + 1;

		/* allocate argument array, bail on error */
		if ((argv = (const char **)alloca(sizeof(char *) * argc)) == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"alloca() failed: %s", strerror(errno));
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);
			return 0;
		}

		/* populate argument array */
		for (i = 0, c = telnet->buffer; i != argc; ++i) {
			argv[i] = c;
			c += strlen(c) + 1;
		}

		/* invoke event with our arguments */
		_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
				telnet->buffer, telnet->buffer_pos, argv, argc);
		return 0;
	}

	/* any of a number of commands that use the form <BYTE>data<BYTE>data,
	 * including TTYPE, ENVIRON, NEW-ENVIRON, and MSSP
	 */
	case TELNET_TELOPT_TTYPE:
	case TELNET_TELOPT_ENVIRON:
	case TELNET_TELOPT_NEW_ENVIRON:
	case TELNET_TELOPT_MSSP: {
		char **argv, *c, *l;
		size_t i, argc;

		/* if we have no data, just pass it through */
		if (telnet->buffer_pos == 0) {
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);
			return 0;
		}

		/* very first byte must be in range 0-3 */
		if ((unsigned)telnet->buffer[0] > 3) {
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"telopt %d subneg has invalid data", telnet->sb_telopt);
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);
			return 0;
		}

		/* count arguments; each argument is preceded by a byte in the
		 * range 0-3, so just count those.
		 * NOTE: we don't support the ENVIRON/NEW-ENVIRON ESC handling
		 * properly at all.  guess that's a FIXME.
		 */
		for (argc = 0, i = 0; i != telnet->buffer_pos; ++i)
			if ((unsigned)telnet->buffer[i] <= 3)
				++argc;

		/* allocate argument array, bail on error */
		if ((argv = (char **)alloca(sizeof(char *) * argc)) == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"alloca() failed: %s", strerror(errno));
			_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
					telnet->buffer, telnet->buffer_pos, 0, 0);
			return 0;
		}

		/* allocate strings in argument array */
		for (i = 0, l = telnet->buffer; i != argc; ++i) {
			/* search for end marker */
			c = l + 1;
			while (c != telnet->buffer + telnet->buffer_pos &&
					(unsigned)*c > 3)
				++c;

			/* allocate space; bail on error */
			if ((argv[i] = (char *)alloca(c - l + 1)) == 0) {
				_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
						"alloca() failed: %s", strerror(errno));
				_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
						telnet->buffer, telnet->buffer_pos, 0, 0);
				return 0;
			}

			/* copy data */
			memcpy(argv[i], l, c - l);
			argv[i][c - l] = 0;

			/* prepare for next loop */
			l = c;
		}

		/* invoke event with our arguments */
		_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
				telnet->buffer, telnet->buffer_pos, (const char **)argv, argc);
		return 0;
	}
#endif /* HAVE_ALLOCA */

	/* other generic subnegotiation */
	default:
		_event(telnet, TELNET_EV_SUBNEGOTIATION, 0, telnet->sb_telopt,
				telnet->buffer, telnet->buffer_pos, 0, 0);
		return 0;
	}
}

/* initialize a telnet state tracker */
void telnet_init(telnet_t *telnet, const telnet_telopt_t *telopts,
		telnet_event_handler_t eh, unsigned char flags, void *user_data) {
	memset(telnet, 0, sizeof(telnet_t));
	telnet->ud = user_data;
	telnet->telopts = telopts;
	telnet->eh = eh;
	telnet->flags = flags;
}

/* free up any memory allocated by a state tracker */
void telnet_free(telnet_t *telnet) {
	/* free sub-request buffer */
	if (telnet->buffer != 0) {
		free(telnet->buffer);
		telnet->buffer = 0;
		telnet->buffer_size = 0;
		telnet->buffer_pos = 0;
	}

#ifdef HAVE_ZLIB
	/* free zlib box */
	if (telnet->z != 0) {
		if (telnet->flags & TELNET_PFLAG_DEFLATE)
			deflateEnd(telnet->z);
		else
			inflateEnd(telnet->z);
		free(telnet->z);
		telnet->z = 0;
	}
#endif

	/* free RFC1143 queue */
	if (telnet->q) {
		free(telnet->q);
		telnet->q = 0;
		telnet->q_size = 0;
	}
}

/* push a byte into the telnet buffer */
static telnet_error_t _buffer_byte(telnet_t *telnet,
		unsigned char byte) {
	char *new_buffer;
	size_t i;

	/* check if we're out of room */
	if (telnet->buffer_pos == telnet->buffer_size) {
		/* find the next buffer size */
		for (i = 0; i != _buffer_sizes_count; ++i) {
			if (_buffer_sizes[i] == telnet->buffer_size)
				break;
		}

		/* overflow -- can't grow any more */
		if (i >= _buffer_sizes_count - 1) {
			_error(telnet, __LINE__, __func__, TELNET_EOVERFLOW, 0,
					"subnegotiation buffer size limit reached");
			return TELNET_EOVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (char *)realloc(telnet->buffer, _buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"realloc() failed");
			return TELNET_ENOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->buffer_size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->buffer_pos++] = byte;
	return TELNET_EOK;
}

static void _process(telnet_t *telnet, const char *buffer, size_t size) {
	unsigned char byte;
	size_t i, start;
	for (i = start = 0; i != size; ++i) {
		byte = buffer[i];
		switch (telnet->state) {
		/* regular data */
		case TELNET_STATE_DATA:
			/* on an IAC byte, pass through all pending bytes and
			 * switch states */
			if (byte == TELNET_IAC) {
				if (i != start)
					_event(telnet, TELNET_EV_DATA, 0, 0, &buffer[start],
							i - start, 0, 0);
				telnet->state = TELNET_STATE_IAC;
			}
			break;

		/* IAC command */
		case TELNET_STATE_IAC:
			switch (byte) {
			/* subnegotiation */
			case TELNET_SB:
				telnet->state = TELNET_STATE_SB;
				break;
			/* negotiation commands */
			case TELNET_WILL:
				telnet->state = TELNET_STATE_WILL;
				break;
			case TELNET_WONT:
				telnet->state = TELNET_STATE_WONT;
				break;
			case TELNET_DO:
				telnet->state = TELNET_STATE_DO;
				break;
			case TELNET_DONT:
				telnet->state = TELNET_STATE_DONT;
				break;
			/* IAC escaping */
			case TELNET_IAC:
				_event(telnet, TELNET_EV_DATA, 0, 0, (char*)&byte, 1, 0, 0);
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				_event(telnet, TELNET_EV_IAC, byte, 0, 0, 0, 0, 0);
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case TELNET_STATE_WILL:
		case TELNET_STATE_WONT:
		case TELNET_STATE_DO:
		case TELNET_STATE_DONT:
			_negotiate(telnet, byte);
			start = i + 1;
			telnet->state = TELNET_STATE_DATA;
			break;

		/* subnegotiation -- determine subnegotiation telopt */
		case TELNET_STATE_SB:
			telnet->sb_telopt = byte;
			telnet->buffer_pos = 0;
			telnet->state = TELNET_STATE_SB_DATA;
			break;

		/* subnegotiation -- buffer bytes until end request */
		case TELNET_STATE_SB_DATA:
			/* IAC command in subnegotiation -- either IAC SE or IAC IAC */
			if (byte == TELNET_IAC) {
				telnet->state = TELNET_STATE_SB_DATA_IAC;
			/* buffer the byte, or bail if we can't */
			} else if (_buffer_byte(telnet, byte) != TELNET_EOK) {
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
			}
			break;

		/* IAC escaping inside a subnegotiation */
		case TELNET_STATE_SB_DATA_IAC:
			switch (byte) {
			/* end subnegotiation */
			case TELNET_SE:
				/* return to default state */
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;

				/* process subnegotiation */
				if (_subnegotiate(telnet) != 0) {
					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke telnet_recv to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					telnet_recv(telnet, &buffer[start], size - start);
					return;
				}
				break;
			/* escaped IAC byte */
			case TELNET_IAC:
				/* push IAC into buffer */
				if (_buffer_byte(telnet, TELNET_IAC) !=
						TELNET_EOK) {
					start = i + 1;
					telnet->state = TELNET_STATE_DATA;
				} else {
					telnet->state = TELNET_STATE_SB_DATA;
				}
				break;
			/* something else -- protocol error.  attempt to process
			 * content in subnegotiation buffer, then evaluate the
			 * given command as an IAC code.
			 */
			default:
				_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
						"unexpected byte after IAC inside SB: %d",
						byte);

				/* enter IAC state */
				start = i + 1;
				telnet->state = TELNET_STATE_IAC;

				/* process subnegotiation; see comment in
				 * TELNET_STATE_SB_DATA_IAC about invoking telnet_recv()
				 */
				if (_subnegotiate(telnet) != 0) {
					telnet_recv(telnet, &buffer[start], size - start);
					return;
				} else {
					/* recursive call to get the current input byte processed
					 * as a regular IAC command.  we could use a goto, but
					 * that would be gross.
					 */
					_process(telnet, (char *)&byte, 1);
				}
				break;
			}
			break;
		}
	}

	/* pass through any remaining bytes */ 
	if (telnet->state == TELNET_STATE_DATA && i != start)
		_event(telnet, TELNET_EV_DATA, 0, 0, buffer + start, i - start, 0, 0);
}

/* push a bytes into the state tracker */
void telnet_recv(telnet_t *telnet, const char *buffer,
		size_t size) {
#ifdef HAVE_ZLIB
	/* if we have an inflate (decompression) zlib stream, use it */
	if (telnet->z != 0 && !(telnet->flags & TELNET_PFLAG_DEFLATE)) {
		char inflate_buffer[4096];
		int rs;

		/* initialize zlib state */
		telnet->z->next_in = (unsigned char*)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = (unsigned char *)inflate_buffer;
		telnet->z->avail_out = sizeof(inflate_buffer);

		/* inflate until buffer exhausted and all output is produced */
		while (telnet->z->avail_in > 0 || telnet->z->avail_out == 0) {
			/* reset output buffer */

			/* decompress */
			rs = inflate(telnet->z, Z_SYNC_FLUSH);

			/* process the decompressed bytes on success */
			if (rs == Z_OK || rs == Z_STREAM_END)
				_process(telnet, inflate_buffer, sizeof(inflate_buffer) -
						telnet->z->avail_out);
			else
				_error(telnet, __LINE__, __func__, TELNET_ECOMPRESS, 1,
						"inflate() failed: %s", zError(rs));

			/* prepare output buffer for next run */
			telnet->z->next_out = (unsigned char *)inflate_buffer;
			telnet->z->avail_out = sizeof(inflate_buffer);

			/* on error (or on end of stream) disable further inflation */
			if (rs != Z_OK) {
				_event(telnet, TELNET_EV_COMPRESS, 0, 0, 0, 0, 0, 0);

				inflateEnd(telnet->z);
				free(telnet->z);
				telnet->z = 0;
				break;
			}
		}

	/* COMPRESS2 is not negotiated, just process */
	} else
#endif /* HAVE_ZLIB */
		_process(telnet, buffer, size);
}

/* send an iac command */
void telnet_iac(telnet_t *telnet, unsigned char cmd) {
	char bytes[2] = { TELNET_IAC, cmd };
	_send(telnet, bytes, 2);
}

/* send negotiation */
void telnet_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	telnet_rfc1143_t q;

	/* if we're in proxy mode, just send it now */
	if (telnet->flags & TELNET_FLAG_PROXY) {
		char bytes[3] = { TELNET_IAC, cmd, telopt };
		_send(telnet, bytes, 3);
		return;
	}
	
	/* get current option states */
	q = _get_rfc1143(telnet, telopt);

	switch (cmd) {
	/* advertise willingess to support an option */
	case TELNET_WILL:
		switch (q.us) {
		case Q_NO:
			_set_rfc1143(telnet, telopt, Q_WANTYES, q.him);
			_send_negotiate(telnet, TELNET_WILL, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, Q_WANTNO_OP, q.him);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, Q_WANTYES, q.him);
			break;
		}
		break;

	/* force turn-off of locally enabled option */
	case TELNET_WONT:
		switch (q.us) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, Q_WANTNO, q.him);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, Q_WANTYES_OP, q.him);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, Q_WANTNO, q.him);
			break;
		}
		break;

	/* ask remote end to enable an option */
	case TELNET_DO:
		switch (q.him) {
		case Q_NO:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTYES);
			_send_negotiate(telnet, TELNET_DO, telopt);
			break;
		case Q_WANTNO:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTNO_OP);
			break;
		case Q_WANTYES_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTYES);
			break;
		}
		break;

	/* demand remote end disable an option */
	case TELNET_DONT:
		switch (q.him) {
		case Q_YES:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTNO);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case Q_WANTYES:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTYES_OP);
			break;
		case Q_WANTNO_OP:
			_set_rfc1143(telnet, telopt, q.us, Q_WANTNO);
			break;
		}
		break;
	}
}

/* send non-command data (escapes IAC bytes) */
void telnet_send(telnet_t *telnet, const char *buffer,
		size_t size) {
	size_t i, l;

	for (l = i = 0; i != size; ++i) {
		/* dump prior portion of text, send escaped bytes */
		if (buffer[i] == TELNET_IAC) {
			/* dump prior text if any */
			if (i != l)
				_send(telnet, buffer + l, i - l);
			l = i + 1;

			/* send escape */
			telnet_iac(telnet, TELNET_IAC);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l)
		_send(telnet, buffer + l, i - l);
}

/* send subnegotiation header */
void telnet_begin_sb(telnet_t *telnet, unsigned char telopt) {
	const char sb[3] = { TELNET_IAC, TELNET_SB, telopt };
	_send(telnet, sb, 3);
}


/* send complete subnegotiation */
void telnet_subnegotiation(telnet_t *telnet, unsigned char telopt,
		const char *buffer, size_t size) {
	const char sb[3] = { TELNET_IAC, TELNET_SB, telopt };
	static const char se[2] = { TELNET_IAC, TELNET_SE };

	_send(telnet, sb, 3);
	telnet_send(telnet, buffer, size);
	_send(telnet, se, 2);

#ifdef HAVE_ZLIB
	/* if we're a proxy and we just sent the COMPRESS2 marker, we must
	 * make sure all further data is compressed if not already.
	 */
	if (telnet->flags & TELNET_FLAG_PROXY &&
			telopt == TELNET_TELOPT_COMPRESS2) {

		if (_init_zlib(telnet, 1, 1) != TELNET_EOK)
			return;

		/* notify app that compression was enabled */
		_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0, 0, 0);
	}
#endif /* HAVE_ZLIB */
}

void telnet_begin_compress2(telnet_t *telnet) {
#ifdef HAVE_ZLIB
	static const char compress2[] = { TELNET_IAC, TELNET_SB,
			TELNET_TELOPT_COMPRESS2, TELNET_IAC, TELNET_SE };

	/* attempt to create output stream first, bail if we can't */
	if (_init_zlib(telnet, 1, 0) != TELNET_EOK)
		return;

	/* send compression marker.  we send directly to the event handler
	 * instead of passing through _send because _send would result in
	 * the compress marker itself being compressed.
	 */
	_event(telnet, TELNET_EV_SEND, 0, 0, compress2, sizeof(compress2), 0, 0);

	/* notify app that compression was successfully enabled */
	_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0, 0, 0);
#endif /* HAVE_ZLIB */
}

/* send formatted data with \r and \n translation in addition to IAC IAC */
int telnet_printf(telnet_t *telnet, const char *fmt, ...) {
    static const char CRLF[] = { '\r', '\n' };
    static const char CRNUL[] = { '\r', '\0' };
	char buffer[4096];
	va_list va;
	int rs, i, l;

	/* format */
	va_start(va, fmt);
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	/* send */
	for (l = i = 0; i != rs; ++i) {
		/* special characters */
		if (buffer[i] == TELNET_IAC || buffer[i] == '\r' ||
				buffer[i] == '\n') {
			/* dump prior portion of text */
			if (i != l)
				_send(telnet, buffer + l, i - l);
			l = i + 1;

			/* IAC -> IAC IAC */
			if (buffer[i] == TELNET_IAC)
				telnet_iac(telnet, TELNET_IAC);
			/* automatic translation of \r -> CRNUL */
			else if (buffer[i] == '\r')
				_send(telnet, CRNUL, 2);
			/* automatic translation of \n -> CRLF */
			else if (buffer[i] == '\n')
				_send(telnet, CRLF, 2);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l)
		_send(telnet, buffer + l, i - l);

	return rs;
}

/* send formatted data through telnet_send */
int telnet_printf2(telnet_t *telnet, const char *fmt, ...) {
	char buffer[4096];
	va_list va;
	int rs;

	/* format */
	va_start(va, fmt);
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	/* send */
	telnet_send(telnet, buffer, rs);

	return rs;
}

/* send formatted subnegotiation data for TTYPE/ENVIRON/NEW-ENVIRON/MSSP */
void telnet_format_sb(telnet_t *telnet, unsigned char telopt,
		size_t count, ...) {
	va_list va;
	size_t i;

	/* subnegotiation header */
	telnet_begin_sb(telnet, telopt);

	/* iterate over the arguments pulling out integers and strings */
	va_start(va, count);
	for (i = 0; i != count; ++i) {
		char t;
		const char* s;
		t = va_arg(va, int);
		s = va_arg(va, const char *);
		telnet_send(telnet, &t, 1);
		telnet_send(telnet, s, strlen(s));
	}
	va_end(va);

	/* footer */
	telnet_finish_sb(telnet);
}

/* send ZMP data */
void telnet_send_zmp(telnet_t *telnet, size_t argc, const char **argv) {
	size_t i;

	/* ZMP header */
	telnet_begin_sb(telnet, TELNET_TELOPT_ZMP);

	/* send out each argument, including trailing NUL byte */
	for (i = 0; i != argc; ++i)
		telnet_send(telnet, argv[i], strlen(argv[i] + 1));

	/* ZMP footer */
	telnet_finish_sb(telnet);
}

/* send ZMP data using varargs  */
void telnet_send_zmpv(telnet_t *telnet, ...) {
	va_list va;
	const char* arg;

	/* ZMP header */
	telnet_begin_sb(telnet, TELNET_TELOPT_ZMP);

	/* send out each argument, including trailing NUL byte */
	va_start(va, telnet);
	while ((arg = va_arg(va, const char *)) != NULL)
		telnet_send(telnet, arg, strlen(arg) + 1);
	va_end(va);

	/* ZMP footer */
	telnet_finish_sb(telnet);
}
