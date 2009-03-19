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

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#include "libtelnet.h"

/* RFC1143 option negotiation state */
typedef struct telnet_rfc1143_t {
	unsigned char telopt;
	char us:4, him:4;
} telnet_rfc1143_t;

/* RFC1143 state names */
#define RFC1143_NO 0x00
#define RFC1143_YES 0x01

#define RFC1143_WANT 0x02
#define RFC1143_OP 0x04

#define RFC1143_WANTNO (RFC1143_WANT|RFC1143_YES)
#define RFC1143_WANTYES (RFC1143_WANT|RFC1143_NO)
#define RFC1143_WANTNO_OP (RFC1143_WANTNO|RFC1143_OP)
#define RFC1143_WANTYES_OP (RFC1143_WANTYES|RFC1143_OP)

/* buffer sizes */
static const size_t _buffer_sizes[] = {
	0,
	512,
	2048,
	8192,
	16384,
};
static const size_t _buffer_sizes_count = sizeof(_buffer_sizes) /
		sizeof(_buffer_sizes[0]);

/* event dispatch helper; return value is value of the accept field of the
 * event struct after dispatch; used for the funky REQUEST event */
static int _event(telnet_t *telnet, telnet_event_type_t type,
		unsigned char command, unsigned char telopt,
		const char *buffer, size_t size) {
	telnet_event_t ev;
	ev.buffer = buffer;
	ev.size = size;
	ev.type = type;
	ev.command = command;
	ev.telopt = telopt;
	ev.accept = 0;

	telnet->eh(telnet, &ev, telnet->ud);

	return ev.accept;
}

/* error generation function */
static telnet_error_t _error(telnet_t *telnet, unsigned line,
		const char* func, telnet_error_t err, int fatal, const char *fmt,
		...) {
	char buffer[512];
	va_list va;

	/* format error intro */
	snprintf(buffer, sizeof(buffer), "%s:%u in %s: ", __FILE__, line, func);

	va_start(va, fmt);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
			fmt, va);
	va_end(va);

	_event(telnet, fatal ? TELNET_EV_ERROR : TELNET_EV_WARNING, err,
			0, (char *)buffer, strlen(buffer));
	
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
					sizeof(deflate_buffer) - telnet->z->avail_out);

			/* prepare output buffer for next run */
			telnet->z->next_out = (unsigned char *)deflate_buffer;
			telnet->z->avail_out = sizeof(deflate_buffer);
		}

	/* COMPRESS2 is not negotiated, just send */
	} else
#endif /* HAVE_ZLIB */
		_event(telnet, TELNET_EV_SEND, 0, 0, buffer, size);
}

/* retrieve RFC1143 option state */
telnet_rfc1143_t _get_rfc1143(telnet_t *telnet, unsigned char telopt) {
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
void _set_rfc1143(telnet_t *telnet, telnet_rfc1143_t q) {
	telnet_rfc1143_t *qtmp;
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i) {
		if (telnet->q[i].telopt == q.telopt) {
			telnet->q[i] = q;
			return;
		}
	}

	/* we're going to need to track state for it, so grow the queue
	 * and put the telopt into it; bail on allocation error
	 */
	if ((qtmp = (telnet_rfc1143_t *)realloc(telnet->q, sizeof(
			telnet_rfc1143_t) * (telnet->q_size + 1))) == 0) {
		_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
				"malloc() failed: %s", strerror(errno));
		return;
	}
	telnet->q = qtmp;
	telnet->q[telnet->q_size++] = q;
}

/* send negotiation bytes */
static void _send_negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	char bytes[3] = { TELNET_IAC, cmd, telopt };
	_send(telnet, bytes, 3);
}

/* negotiation handling magic for RFC1143 */
static void _negotiate(telnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	telnet_rfc1143_t q;

	/* in PROXY mode, just pass it thru and do nothing */
	if (telnet->flags & TELNET_FLAG_PROXY) {
		switch (cmd) {
		case TELNET_WILL:
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0);
			break;
		case TELNET_WONT:
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case TELNET_DO:
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0);
			break;
		case TELNET_DONT:
			_event(telnet, TELNET_EV_DONT, 0, telopt, 0, 0);
			break;
		}
		return;
	}

	/* lookup the current state of the option */
	q = _get_rfc1143(telnet, telopt);

	/* start processing... */
	switch (cmd) {
	/* request to enable option on remote end or confirm DO */
	case TELNET_WILL:
		switch (q.him) {
		case RFC1143_NO:
			if (_event(telnet, TELNET_EV_WILL, cmd, telopt, 0, 0) == 1) {
				q.him = RFC1143_YES;
				_set_rfc1143(telnet, q);
				_send_negotiate(telnet, TELNET_DO, telopt);
			} else
				_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WONT, cmd, telopt, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case RFC1143_WANTNO_OP:
			q.him = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WILL, cmd, telopt, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case RFC1143_WANTYES:
			q.him = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WILL, cmd, telopt, 0, 0);
			break;
		case RFC1143_WANTYES_OP:
			q.him = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			_event(telnet, TELNET_EV_WILL, cmd, telopt, 0, 0);
			break;
		}
		break;

	/* request to disable option on remote end, confirm DONT, reject DO */
	case TELNET_WONT:
		switch (q.him) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO_OP:
			q.him = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_DO, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTYES:
		case RFC1143_WANTYES_OP:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			break;
		}
		break;

	/* request to enable option on local end or confirm WILL */
	case TELNET_DO:
		switch (q.us) {
		case RFC1143_NO:
			if (_event(telnet, TELNET_EV_DO, cmd, telopt, 0, 0) == 1) {
				q.us = RFC1143_YES;
				_set_rfc1143(telnet, q);
				_send_negotiate(telnet, TELNET_WILL, telopt);
			} else
				_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_DONT, cmd, telopt, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case RFC1143_WANTNO_OP:
			q.us = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_DO, cmd, telopt, 0, 0);
			_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case RFC1143_WANTYES:
			q.us = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_DO, cmd, telopt, 0, 0);
			break;
		case RFC1143_WANTYES_OP:
			q.us = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			_event(telnet, TELNET_EV_DO, cmd, telopt, 0, 0);
			break;
		}
		break;

	/* request to disable option on local end, confirm WONT, reject WILL */
	case TELNET_DONT:
		switch (q.us) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			_event(telnet, TELNET_EV_DONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO_OP:
			q.us = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_event(telnet, TELNET_EV_WILL, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTYES:
		case RFC1143_WANTYES_OP:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			break;
		}
		break;
	}
}

/* initialize a telnet state tracker */
void telnet_init(telnet_t *telnet, telnet_event_handler_t eh,
		unsigned char flags, void *user_data) {
	memset(telnet, 0, sizeof(telnet_t));
	telnet->ud = user_data;
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
			telnet_free(telnet);
			return TELNET_EOVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (char *)realloc(telnet->buffer,
				_buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			_error(telnet, __LINE__, __func__, TELNET_ENOMEM, 0,
					"realloc() failed");
			telnet_free(telnet);
			return TELNET_ENOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->buffer_size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->buffer_pos++] = byte;
	return TELNET_EOK;
}

static void _process(telnet_t *telnet, const char *buffer,
		size_t size) {
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
							i - start);
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
				_event(telnet, TELNET_EV_DATA, 0, 0, (char*)&byte, 1);
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				_event(telnet, TELNET_EV_IAC, byte, 0, 0, 0);
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case TELNET_STATE_DO:
			_negotiate(telnet, TELNET_DO, byte);
			start = i + 1;
			telnet->state = TELNET_STATE_DATA;
			break;
		case TELNET_STATE_DONT:
			_negotiate(telnet, TELNET_DONT, byte);
			start = i + 1;
			telnet->state = TELNET_STATE_DATA;
			break;
		case TELNET_STATE_WILL:
			_negotiate(telnet, TELNET_WILL, byte);
			start = i + 1;
			telnet->state = TELNET_STATE_DATA;
			break;
		case TELNET_STATE_WONT:
			_negotiate(telnet, TELNET_WONT, byte);
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

				/* invoke callback */
				_event(telnet, TELNET_EV_SUBNEGOTIATION, 0,
						telnet->sb_telopt, telnet->buffer, telnet->buffer_pos);

#ifdef HAVE_ZLIB
				/* received COMPRESS2 begin marker, setup our zlib box and
				 * start handling the compressed stream if it's not already.
				 */
				if (telnet->sb_telopt == TELNET_TELOPT_COMPRESS2) {
					if (_init_zlib(telnet, 0, 1) != TELNET_EOK)
						break;

					/* notify app that compression was enabled */
					_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0);

					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke telnet_push to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					telnet_push(telnet, &buffer[start], size - start);
					return;
				}
#endif /* HAVE_ZLIB */

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
			/* something else -- protocol error */
			default:
				_error(telnet, __LINE__, __func__, TELNET_EPROTOCOL, 0,
						"unexpected byte after IAC inside SB: %d",
						byte);
				start = i + 1;
				telnet->state = TELNET_STATE_DATA;
				break;
			}
			break;
		}
	}

	/* pass through any remaining bytes */ 
	if (telnet->state == TELNET_STATE_DATA && i != start)
		_event(telnet, TELNET_EV_DATA, 0, 0, buffer + start, i - start);
}

/* push a bytes into the state tracker */
void telnet_push(telnet_t *telnet, const char *buffer,
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
				_event(telnet, TELNET_EV_COMPRESS, 0, 0, 0, 0);

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
void telnet_send_command(telnet_t *telnet, unsigned char cmd) {
	char bytes[2] = { TELNET_IAC, cmd };
	_send(telnet, bytes, 2);
}

/* send negotiation */
void telnet_send_negotiate(telnet_t *telnet, unsigned char cmd,
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
		case RFC1143_NO:
			q.us = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_WILL, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.us = RFC1143_WANTNO_OP;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES:
			break;
		case RFC1143_WANTNO_OP:
			break;
		case RFC1143_WANTYES_OP:
			q.us = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			break;
		}
		break;

	/* force turn-off of locally enabled option */
	case TELNET_WONT:
		switch (q.us) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.us = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_WONT, telopt);
			break;
		case RFC1143_WANTNO:
			break;
		case RFC1143_WANTYES:
			q.us = RFC1143_WANTYES_OP;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTNO_OP:
			q.us = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES_OP:
			break;
		}
		break;

	/* ask remote end to enable an option */
	case TELNET_DO:
		switch (q.him) {
		case RFC1143_NO:
			q.him = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_DO, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.him = RFC1143_WANTNO_OP;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES:
			break;
		case RFC1143_WANTNO_OP:
			break;
		case RFC1143_WANTYES_OP:
			q.him = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			break;
		}
		break;

	/* demand remote end disable an option */
	case TELNET_DONT:
		switch (q.him) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.him = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_send_negotiate(telnet, TELNET_DONT, telopt);
			break;
		case RFC1143_WANTNO:
			break;
		case RFC1143_WANTYES:
			q.him = RFC1143_WANTYES_OP;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTNO_OP:
			q.him = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES_OP:
			break;
		}
		break;
	}
}

/* send non-command data (escapes IAC bytes) */
void telnet_send_data(telnet_t *telnet, const char *buffer,
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
			telnet_send_command(telnet, TELNET_IAC);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l)
		_send(telnet, buffer + l, i - l);
}

/* send subnegotiation header */
void telnet_begin_subnegotiation(telnet_t *telnet, unsigned char telopt) {
	const char sb[3] = { TELNET_IAC, TELNET_SB, telopt };
	_send(telnet, sb, 3);
}


/* send complete subnegotiation */
void telnet_send_subnegotiation(telnet_t *telnet, unsigned char telopt,
		const char *buffer, size_t size) {
	const char sb[3] = { TELNET_IAC, TELNET_SB, telopt };
	static const char se[2] = { TELNET_IAC, TELNET_SE };

	_send(telnet, sb, 3);
	telnet_send_data(telnet, buffer, size);
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
		_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0);
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
	_event(telnet, TELNET_EV_SEND, 0, 0, compress2, sizeof(compress2));

	/* notify app that compression was successfully enabled */
	_event(telnet, TELNET_EV_COMPRESS, 1, 0, 0, 0);
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
				_send(telnet, (char *)buffer + l, i - l);
			l = i + 1;

			/* IAC -> IAC IAC */
			if (buffer[i] == TELNET_IAC)
				telnet_send_command(telnet, TELNET_IAC);
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
		_send(telnet, (char *)buffer + l, i - l);

	return rs;
}

/* send formatted data through telnet_send_data */
int telnet_printf2(telnet_t *telnet, const char *fmt, ...) {
	char buffer[4096];
	va_list va;
	int rs;

	/* format */
	va_start(va, fmt);
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	/* send */
	telnet_send_data(telnet, (char *)buffer, rs);

	return rs;
}
