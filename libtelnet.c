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
static const unsigned int _buffer_sizes[] = {
	0,
	512,
	2048,
	8192,
	16384,
};
static const unsigned int _buffer_sizes_count = sizeof(_buffer_sizes) /
		sizeof(_buffer_sizes[0]);

/* event dispatch helper; return value is value of the accept field of the
 * event struct after dispatch; used for the funky REQUEST event */
static int _event(libtelnet_t *telnet, libtelnet_event_type_t type,
		unsigned char command, unsigned char telopt,
		const unsigned char *buffer, unsigned int size) {
	libtelnet_event_t ev;
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
static libtelnet_error_t _error(libtelnet_t *telnet, unsigned line,
		const char* func, libtelnet_error_t err, int fatal, const char *fmt,
		...) {
	char buffer[512];
	va_list va;

	/* format error intro */
	snprintf(buffer, sizeof(buffer), "%s:%u in %s: ", __FILE__, line, func);

	va_start(va, fmt);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
			fmt, va);
	va_end(va);

	_event(telnet, fatal ? LIBTELNET_EV_ERROR : LIBTELNET_EV_WARNING, err,
			0, (unsigned char *)buffer, strlen(buffer));
	
	return err;
}

#ifdef HAVE_ZLIB
/* initialize the zlib box for a telnet box; if deflate is non-zero, it
 * initializes zlib for delating (compression), otherwise for inflating
 * (decompression).  returns LIBTELNET_EOK on success, something else on
 * failure.
 */
libtelnet_error_t _init_zlib(libtelnet_t *telnet, int deflate, int err_fatal) {
	z_stream *z;
	int rs;

	/* if compression is already enabled, fail loudly */
	if (telnet->z != 0)
		return _error(telnet, __LINE__, __func__, LIBTELNET_EBADVAL,
				err_fatal, "cannot initialize compression twice");

	/* allocate zstream box */
	if ((z= (z_stream *)calloc(1, sizeof(z_stream))) == 0)
		return _error(telnet, __LINE__, __func__, LIBTELNET_ENOMEM, err_fatal,
				"malloc() failed: %s", strerror(errno));

	/* initialize */
	if (deflate) {
		if ((rs = deflateInit(z, Z_DEFAULT_COMPRESSION)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, LIBTELNET_ECOMPRESS,
					err_fatal, "deflateInit() failed: %s", zError(rs));
		}
		telnet->flags |= LIBTELNET_PFLAG_DEFLATE;
	} else {
		if ((rs = inflateInit(z)) != Z_OK) {
			free(z);
			return _error(telnet, __LINE__, __func__, LIBTELNET_ECOMPRESS,
					err_fatal, "inflateInit() failed: %s", zError(rs));
		}
		telnet->flags &= ~LIBTELNET_PFLAG_DEFLATE;
	}

	telnet->z = z;

	return LIBTELNET_EOK;
}
#endif

/* push bytes out, compressing them first if need be */
static void _send(libtelnet_t *telnet, const unsigned char *buffer,
		unsigned int size) {
#ifdef HAVE_ZLIB
	/* if we have a deflate (compression) zlib box, use it */
	if (telnet->z != 0 && telnet->flags & LIBTELNET_PFLAG_DEFLATE) {
		unsigned char deflate_buffer[1024];
		int rs;

		/* initialize z state */
		telnet->z->next_in = (unsigned char *)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = deflate_buffer;
		telnet->z->avail_out = sizeof(deflate_buffer);

		/* deflate until buffer exhausted and all output is produced */
		while (telnet->z->avail_in > 0 || telnet->z->avail_out == 0) {
			/* compress */
			if ((rs = deflate(telnet->z, Z_SYNC_FLUSH)) != Z_OK) {
				_error(telnet, __LINE__, __func__, LIBTELNET_ECOMPRESS, 1,
						"deflate() failed: %s", zError(rs));
				deflateEnd(telnet->z);
				free(telnet->z);
				telnet->z = 0;
				break;
			}

			_event(telnet, LIBTELNET_EV_SEND, 0, 0, deflate_buffer,
					sizeof(deflate_buffer) - telnet->z->avail_out);

			/* prepare output buffer for next run */
			telnet->z->next_out = deflate_buffer;
			telnet->z->avail_out = sizeof(deflate_buffer);
		}

	/* COMPRESS2 is not negotiated, just send */
	} else
#endif /* HAVE_ZLIB */
		_event(telnet, LIBTELNET_EV_SEND, 0, 0, buffer, size);
}

/* retrieve RFC1143 option state */
libtelnet_rfc1143_t _get_rfc1143(libtelnet_t *telnet, unsigned char telopt) {
	static const libtelnet_rfc1143_t empty = { 0, 0, 0};
	int i;

	/* search for entry */
	for (i = 0; i != telnet->q_size; ++i)
		if (telnet->q[i].telopt == telopt)
			return telnet->q[i];

	/* not found, return empty value */
	return empty;
}

/* save RFC1143 option state */
void _set_rfc1143(libtelnet_t *telnet, libtelnet_rfc1143_t q) {
	libtelnet_rfc1143_t *qtmp;
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
	if ((qtmp = (libtelnet_rfc1143_t *)malloc(sizeof(
			libtelnet_rfc1143_t) * (telnet->q_size + 1))) == 0) {
		_error(telnet, __LINE__, __func__, LIBTELNET_ENOMEM, 0,
				"malloc() failed: %s", strerror(errno));
		return;
	}
	telnet->q = qtmp;
	telnet->q[telnet->q_size++] = q;
}

/* negotiation handling magic for RFC1143 */
static void _negotiate(libtelnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	libtelnet_rfc1143_t q;

	/* in PROXY mode, just pass it thru and do nothing */
	if (telnet->flags & LIBTELNET_FLAG_PROXY) {
		switch (cmd) {
		case LIBTELNET_WILL:
			_event(telnet, LIBTELNET_EV_WILL, 0, telopt, 0, 0);
			break;
		case LIBTELNET_WONT:
			_event(telnet, LIBTELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case LIBTELNET_DO:
			_event(telnet, LIBTELNET_EV_DO, 0, telopt, 0, 0);
			break;
		case LIBTELNET_DONT:
			_event(telnet, LIBTELNET_EV_DONT, 0, telopt, 0, 0);
			break;
		}
		return;
	}

	/* lookup the current state of the option */
	q = _get_rfc1143(telnet, telopt);

	/* start processing... */
	switch (cmd) {
	/* request to enable option on remote end or confirm DO */
	case LIBTELNET_WILL:
		switch (q.him) {
		case RFC1143_NO:
			if (_event(telnet, LIBTELNET_EV_WILL, cmd, telopt, 0, 0) == 1) {
				q.him = RFC1143_YES;
				_set_rfc1143(telnet, q);
				libtelnet_send_telopt(telnet, LIBTELNET_DO, telopt);
			} else
				libtelnet_send_telopt(telnet, LIBTELNET_DONT, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_error(telnet, __LINE__, __func__, LIBTELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case RFC1143_WANTNO_OP:
			q.him = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_error(telnet, __LINE__, __func__, LIBTELNET_EPROTOCOL, 0,
					"DONT answered by WILL");
			break;
		case RFC1143_WANTYES:
			q.him = RFC1143_YES;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES_OP:
			q.him = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			libtelnet_send_telopt(telnet, LIBTELNET_DONT, telopt);
			break;
		}
		break;

	/* request to disable option on remote end, confirm DONT, reject DO */
	case LIBTELNET_WONT:
		switch (q.him) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			libtelnet_send_telopt(telnet, LIBTELNET_DONT, telopt);
			_event(telnet, LIBTELNET_EV_WONT, 0, telopt,
					0, 0);
			break;
		case RFC1143_WANTNO:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, LIBTELNET_EV_WONT, 0, telopt,
					0, 0);
			break;
		case RFC1143_WANTNO_OP:
			q.him = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_event(telnet, LIBTELNET_EV_DO, 0, telopt,
					0, 0);
			break;
		case RFC1143_WANTYES:
		case RFC1143_WANTYES_OP:
			q.him = RFC1143_NO;
			_set_rfc1143(telnet, q);
			break;
		}
		break;

	/* request to enable option on local end or confirm WILL */
	case LIBTELNET_DO:
		switch (q.us) {
		case RFC1143_NO:
			if (_event(telnet, LIBTELNET_EV_DO, cmd, telopt, 0, 0) == 1) {
				q.us = RFC1143_YES;
				_set_rfc1143(telnet, q);
				libtelnet_send_telopt(telnet, LIBTELNET_WILL, telopt);
			} else
				libtelnet_send_telopt(telnet, LIBTELNET_WONT, telopt);
			break;
		case RFC1143_YES:
			break;
		case RFC1143_WANTNO:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_error(telnet, __LINE__, __func__, LIBTELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case RFC1143_WANTNO_OP:
			q.us = RFC1143_YES;
			_set_rfc1143(telnet, q);
			_error(telnet, __LINE__, __func__, LIBTELNET_EPROTOCOL, 0,
					"WONT answered by DO");
			break;
		case RFC1143_WANTYES:
			q.us = RFC1143_YES;
			_set_rfc1143(telnet, q);
			break;
		case RFC1143_WANTYES_OP:
			q.us = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			libtelnet_send_telopt(telnet, LIBTELNET_WONT, telopt);
			break;
		}
		break;

	/* request to disable option on local end, confirm WONT, reject WILL */
	case LIBTELNET_DONT:
		switch (q.us) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			libtelnet_send_telopt(telnet, LIBTELNET_WONT, telopt);
			_event(telnet, LIBTELNET_EV_DONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO:
			q.us = RFC1143_NO;
			_set_rfc1143(telnet, q);
			_event(telnet, LIBTELNET_EV_WONT, 0, telopt, 0, 0);
			break;
		case RFC1143_WANTNO_OP:
			q.us = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_event(telnet, LIBTELNET_EV_WILL, 0, telopt, 0, 0);
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
void libtelnet_init(libtelnet_t *telnet, libtelnet_event_handler_t eh,
		unsigned char flags, void *user_data) {
	memset(telnet, 0, sizeof(libtelnet_t));
	telnet->ud = user_data;
	telnet->eh = eh;
	telnet->flags = flags;
}

/* free up any memory allocated by a state tracker */
void libtelnet_free(libtelnet_t *telnet) {
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
		if (telnet->flags & LIBTELNET_PFLAG_DEFLATE)
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
static libtelnet_error_t _buffer_byte(libtelnet_t *telnet,
		unsigned char byte) {
	unsigned char *new_buffer;
	unsigned int i;

	/* check if we're out of room */
	if (telnet->buffer_pos == telnet->buffer_size) {
		/* find the next buffer size */
		for (i = 0; i != _buffer_sizes_count; ++i) {
			if (_buffer_sizes[i] == telnet->buffer_size)
				break;
		}

		/* overflow -- can't grow any more */
		if (i >= _buffer_sizes_count - 1) {
			_error(telnet, __LINE__, __func__, LIBTELNET_EOVERFLOW, 0,
					"subnegotiation buffer size limit reached");
			libtelnet_free(telnet);
			return LIBTELNET_EOVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (unsigned char *)realloc(telnet->buffer,
				_buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			_error(telnet, __LINE__, __func__, LIBTELNET_ENOMEM, 0,
					"realloc() failed");
			libtelnet_free(telnet);
			return LIBTELNET_ENOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->buffer_size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->buffer_pos++] = byte;
	return LIBTELNET_EOK;
}

static void _process(libtelnet_t *telnet, const unsigned char *buffer,
		unsigned int size) {
	unsigned char byte;
	unsigned int i, start;
	for (i = start = 0; i != size; ++i) {
		byte = buffer[i];
		switch (telnet->state) {
		/* regular data */
		case LIBTELNET_STATE_DATA:
			/* on an IAC byte, pass through all pending bytes and
			 * switch states */
			if (byte == LIBTELNET_IAC) {
				if (i != start)
					_event(telnet, LIBTELNET_EV_DATA, 0, 0, &buffer[start],
							i - start);
				telnet->state = LIBTELNET_STATE_IAC;
			}
			break;

		/* IAC command */
		case LIBTELNET_STATE_IAC:
			switch (byte) {
			/* subnegotiation */
			case LIBTELNET_SB:
				telnet->state = LIBTELNET_STATE_SB;
				break;
			/* negotiation commands */
			case LIBTELNET_WILL:
				telnet->state = LIBTELNET_STATE_WILL;
				break;
			case LIBTELNET_WONT:
				telnet->state = LIBTELNET_STATE_WONT;
				break;
			case LIBTELNET_DO:
				telnet->state = LIBTELNET_STATE_DO;
				break;
			case LIBTELNET_DONT:
				telnet->state = LIBTELNET_STATE_DONT;
				break;
			/* IAC escaping */
			case LIBTELNET_IAC:
				_event(telnet, LIBTELNET_EV_DATA, 0, 0, &byte, 1);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				_event(telnet, LIBTELNET_EV_IAC, byte, 0, 0, 0);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case LIBTELNET_STATE_DO:
			_negotiate(telnet, LIBTELNET_DO, byte);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_DONT:
			_negotiate(telnet, LIBTELNET_DONT, byte);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WILL:
			_negotiate(telnet, LIBTELNET_WILL, byte);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WONT:
			_negotiate(telnet, LIBTELNET_WONT, byte);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;

		/* subnegotiation -- determine subnegotiation telopt */
		case LIBTELNET_STATE_SB:
			telnet->sb_telopt = byte;
			telnet->buffer_pos = 0;
			telnet->state = LIBTELNET_STATE_SB_DATA;
			break;

		/* subnegotiation -- buffer bytes until end request */
		case LIBTELNET_STATE_SB_DATA:
			/* IAC command in subnegotiation -- either IAC SE or IAC IAC */
			if (byte == LIBTELNET_IAC) {
				telnet->state = LIBTELNET_STATE_SB_DATA_IAC;
			/* buffer the byte, or bail if we can't */
			} else if (_buffer_byte(telnet, byte) != LIBTELNET_EOK) {
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			}
			break;

		/* IAC escaping inside a subnegotiation */
		case LIBTELNET_STATE_SB_DATA_IAC:
			switch (byte) {
			/* end subnegotiation */
			case LIBTELNET_SE:
				/* return to default state */
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;

				/* invoke callback */
				_event(telnet, LIBTELNET_EV_SUBNEGOTIATION, 0,
						telnet->sb_telopt, telnet->buffer, telnet->buffer_pos);

#ifdef HAVE_ZLIB
				/* received COMPRESS2 begin marker, setup our zlib box and
				 * start handling the compressed stream if it's not already.
				 */
				if (telnet->sb_telopt == LIBTELNET_TELOPT_COMPRESS2) {
					if (_init_zlib(telnet, 0, 1) != LIBTELNET_EOK)
						break;

					/* notify app that compression was enabled */
					_event(telnet, LIBTELNET_EV_COMPRESS, 1, 0, 0, 0);

					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke libtelnet_push to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					libtelnet_push(telnet, &buffer[start], size - start);
					return;
				}
#endif /* HAVE_ZLIB */

				break;
			/* escaped IAC byte */
			case LIBTELNET_IAC:
				/* push IAC into buffer */
				if (_buffer_byte(telnet, LIBTELNET_IAC) !=
						LIBTELNET_EOK) {
					start = i + 1;
					telnet->state = LIBTELNET_STATE_DATA;
				} else {
					telnet->state = LIBTELNET_STATE_SB_DATA;
				}
				break;
			/* something else -- protocol error */
			default:
				_error(telnet, __LINE__, __func__, LIBTELNET_EPROTOCOL, 0,
						"unexpected byte after IAC inside SB: %d",
						byte);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
				break;
			}
			break;
		}
	}

	/* pass through any remaining bytes */ 
	if (telnet->state == LIBTELNET_STATE_DATA && i != start)
		_event(telnet, LIBTELNET_EV_DATA, 0, 0, buffer + start, i - start);
}

/* push a bytes into the state tracker */
void libtelnet_push(libtelnet_t *telnet, const unsigned char *buffer,
		unsigned int size) {
#ifdef HAVE_ZLIB
	/* if we have an inflate (decompression) zlib stream, use it */
	if (telnet->z != 0 && !(telnet->flags & LIBTELNET_PFLAG_DEFLATE)) {
		unsigned char inflate_buffer[4096];
		int rs;

		/* initialize zlib state */
		telnet->z->next_in = (unsigned char *)buffer;
		telnet->z->avail_in = size;
		telnet->z->next_out = inflate_buffer;
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
				_error(telnet, __LINE__, __func__, LIBTELNET_ECOMPRESS, 1,
						"inflate() failed: %s", zError(rs));

			/* prepare output buffer for next run */
			telnet->z->next_out = inflate_buffer;
			telnet->z->avail_out = sizeof(inflate_buffer);

			/* on error (or on end of stream) disable further inflation */
			if (rs != Z_OK) {
				_event(telnet, LIBTELNET_EV_COMPRESS, 0, 0, 0, 0);

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
void libtelnet_send_command(libtelnet_t *telnet, unsigned char cmd) {
	unsigned char bytes[2] = { LIBTELNET_IAC, cmd };
	_send(telnet, bytes, 2);
}

/* send an iac command with telopt */
void libtelnet_send_telopt(libtelnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	unsigned char bytes[3] = { LIBTELNET_IAC, cmd, telopt };
	_send(telnet, bytes, 3);
}

/* send negotiation */
void libtelnet_send_negotiate(libtelnet_t *telnet, unsigned char cmd,
		unsigned char telopt) {
	libtelnet_rfc1143_t q;

	/* if we're in proxy mode, just send it now */
	if (telnet->flags & LIBTELNET_FLAG_PROXY) {
		unsigned char bytes[3] = { LIBTELNET_IAC, cmd, telopt };
		_send(telnet, bytes, 3);
		return;
	}
	
	/* get current option states */
	q = _get_rfc1143(telnet, telopt);

	switch (cmd) {
	/* advertise willingess to support an option */
	case LIBTELNET_WILL:
		switch (q.us) {
		case RFC1143_NO:
			q.us = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_negotiate(telnet, LIBTELNET_WILL, telopt);
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
	case LIBTELNET_WONT:
		switch (q.us) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.us = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_negotiate(telnet, LIBTELNET_WONT, telopt);
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
	case LIBTELNET_DO:
		switch (q.him) {
		case RFC1143_NO:
			q.him = RFC1143_WANTYES;
			_set_rfc1143(telnet, q);
			_negotiate(telnet, LIBTELNET_DO, telopt);
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
	case LIBTELNET_DONT:
		switch (q.him) {
		case RFC1143_NO:
			break;
		case RFC1143_YES:
			q.him = RFC1143_WANTNO;
			_set_rfc1143(telnet, q);
			_negotiate(telnet, LIBTELNET_DONT, telopt);
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
void libtelnet_send_data(libtelnet_t *telnet, const unsigned char *buffer,
		unsigned int size) {
	unsigned int i, l;

	for (l = i = 0; i != size; ++i) {
		/* dump prior portion of text, send escaped bytes */
		if (buffer[i] == LIBTELNET_IAC) {
			/* dump prior text if any */
			if (i != l)
				_send(telnet, buffer + l, i - l);
			l = i + 1;

			/* send escape */
			libtelnet_send_command(telnet, LIBTELNET_IAC);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l)
		_send(telnet, buffer + l, i - l);
}

/* send sub-request */
void libtelnet_send_subnegotiation(libtelnet_t *telnet, unsigned char telopt,
		const unsigned char *buffer, unsigned int size) {
	libtelnet_send_telopt(telnet, LIBTELNET_SB, telopt);
	libtelnet_send_data(telnet, buffer, size);
	libtelnet_send_command(telnet, LIBTELNET_SE);

#ifdef HAVE_ZLIB
	/* if we're a proxy and we just sent the COMPRESS2 marker, we must
	 * make sure all further data is compressed if not already.
	 */
	if (telnet->flags & LIBTELNET_FLAG_PROXY &&
			telopt == LIBTELNET_TELOPT_COMPRESS2) {

		if (_init_zlib(telnet, 1, 1) != LIBTELNET_EOK)
			return;

		/* notify app that compression was enabled */
		_event(telnet, LIBTELNET_EV_COMPRESS, 1, 0, 0, 0);
	}
#endif /* HAVE_ZLIB */
}

void libtelnet_begin_compress2(libtelnet_t *telnet) {
#ifdef HAVE_ZLIB
	static const unsigned char compress2[] = { LIBTELNET_IAC, LIBTELNET_SB,
			LIBTELNET_TELOPT_COMPRESS2, LIBTELNET_IAC, LIBTELNET_SE };

	/* attempt to create output stream first, bail if we can't */
	if (_init_zlib(telnet, 1, 0) != LIBTELNET_EOK)
		return;

	/* send compression marker.  we send directly to the event handler
	 * instead of passing through _send because _send would result in
	 * the compress marker itself being compressed.
	 */
	_event(telnet, LIBTELNET_EV_SEND, 0, 0, compress2, sizeof(compress2));

	/* notify app that compression was successfully enabled */
	_event(telnet, LIBTELNET_EV_COMPRESS, 1, 0, 0, 0);
#endif /* HAVE_ZLIB */
}

/* send formatted data through libtelnet_send_data */
int libtelnet_printf(libtelnet_t *telnet, const char *fmt, ...) {
	char buffer[4096];
	va_list va;
	int rs;

	/* format */
	va_start(va, fmt);
	rs = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	/* send */
	libtelnet_send_data(telnet, (unsigned char *)buffer, rs);

	return rs;
}

/* send formatted data with \r and \n translation in addition to IAC IAC */
int libtelnet_printf2(libtelnet_t *telnet, const char *fmt, ...) {
    static const unsigned char CRLF[] = { '\r', '\n' };
    static const unsigned char CRNUL[] = { '\r', '\0' };
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
		if (buffer[i] == LIBTELNET_IAC || buffer[i] == '\r' ||
				buffer[i] == '\n') {
			/* dump prior portion of text */
			if (i != l)
				_send(telnet, (unsigned char *)buffer + l, i - l);
			l = i + 1;

			/* IAC -> IAC IAC */
			if (buffer[i] == LIBTELNET_IAC)
				libtelnet_send_command(telnet, LIBTELNET_IAC);
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
		_send(telnet, (unsigned char *)buffer + l, i - l);

	return rs;
}
