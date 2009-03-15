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

/* error handler helpers */
#ifdef ERROR
#  undef ERROR
#endif
#define ERROR(telnet, code, user_data, msg) \
		_error(telnet, __FILE__, __LINE__, code, user_data, "%s", msg)
#define ERROR_NOMEM(telnet, user_data, msg) \
		_error(telnet, __FILE__, __LINE__, LIBTELNET_ENOMEM, user_data, \
		"%s: %s", msg, strerror(errno))
#define ERROR_ZLIB(telnet, user_data, rs, msg) \
		_error(telnet, __FILE__, __LINE__, LIBTELNET_EUNKNOWN, \
		user_data, "%s: %s", msg, zError(rs))

/* buffer sizes */
static const unsigned int _buffer_sizes[] = {
	0,
	512,
	2048,
	8192,
	16384,
};
static const unsigned int _buffer_sizes_count =
	sizeof(_buffer_sizes) / sizeof(_buffer_sizes[0]);

/* event dispatch helper */
static void _event(struct libtelnet_t *telnet,
		enum libtelnet_event_type_t type, unsigned char command,
		unsigned char telopt, unsigned char *buffer, unsigned int size,
		void *user_data) {
	struct libtelnet_event_t ev;
	ev.type = type;
	ev.command = command;
	ev.telopt = telopt;
	ev.buffer = buffer;
	ev.size = size;

	telnet->eh(telnet, &ev, user_data);
}

/* error generation function */
static void _error(struct libtelnet_t *telnet, const char *file, unsigned line,
		enum libtelnet_error_t err, void *user_data, const char *fmt, ...) {
	char buffer[512];
	va_list va;

	/* format error intro */
	snprintf(buffer, sizeof(buffer), "%s:%u: ",
			file, line);

	va_start(va, fmt);
	vsnprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
			fmt, va);
	va_end(va);

	_event(telnet, LIBTELNET_EV_ERROR, err, 0, 0, 0, user_data);
}

/* initialize the zlib box for a telnet box; if deflate is non-zero, it
 * initializes zlib for delating (compression), otherwise for inflating
 * (decompression)
 */
z_stream *_init_zlib(struct libtelnet_t *telnet, int deflate,
		void *user_data) {
	z_stream *zlib;
	int rs;

	/* allocate zstream box */
	if ((zlib = (z_stream *)calloc(1, sizeof(z_stream)))
			== 0) {
		ERROR_NOMEM(telnet, user_data, "malloc() failed");
		return 0;
	}

	/* initialize */
	if (deflate) {
		if ((rs = deflateInit(zlib, Z_DEFAULT_COMPRESSION)) != Z_OK) {
			free(zlib);
			ERROR_ZLIB(telnet, user_data, rs, "deflateInit() failed");
			return 0;
		}
	} else {
		if ((rs = inflateInit(zlib)) != Z_OK) {
			free(zlib);
			ERROR_ZLIB(telnet, user_data, rs, "inflateInit() failed");
			return 0;
		}
	}

	return zlib;
}

/* initialize a telnet state tracker */
void libtelnet_init(struct libtelnet_t *telnet, libtelnet_event_handler_t eh,
		enum libtelnet_mode_t mode) {
	memset(telnet, 0, sizeof(struct libtelnet_t));
	telnet->eh = eh;
	telnet->mode = mode;
}

/* free up any memory allocated by a state tracker */
void libtelnet_free(struct libtelnet_t *telnet) {
	/* free sub-request buffer */
	if (telnet->buffer != 0) {
		free(telnet->buffer);
		telnet->buffer = 0;
		telnet->size = 0;
		telnet->length = 0;
	}

	/* free zlib box(es) */
	if (telnet->z_inflate != 0) {
		inflateEnd(telnet->z_inflate);
		free(telnet->z_inflate);
		telnet->z_inflate = 0;
	}
	if (telnet->z_deflate != 0) {
		deflateEnd(telnet->z_deflate);
		free(telnet->z_deflate);
		telnet->z_deflate = 0;
	}
}

/* push a byte into the telnet buffer */
static enum libtelnet_error_t _buffer_byte(struct libtelnet_t *telnet,
		unsigned char byte, void *user_data) {
	unsigned char *new_buffer;
	int i;

	/* check if we're out of room */
	if (telnet->length == telnet->size) {
		/* find the next buffer size */
		for (i = 0; i != _buffer_sizes_count; ++i) {
			if (_buffer_sizes[i] == telnet->size)
				break;
		}

		/* overflow -- can't grow any more */
		if (i >= _buffer_sizes_count - 1) {
			_error(telnet, __FILE__, __LINE__, LIBTELNET_EOVERFLOW,
					user_data, "subnegotiation buffer size limit reached");
			libtelnet_free(telnet);
			return LIBTELNET_EOVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (unsigned char *)realloc(telnet->buffer,
				_buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			ERROR_NOMEM(telnet, user_data, "realloc() failed");
			libtelnet_free(telnet);
			return LIBTELNET_ENOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->length++] = byte;
	return LIBTELNET_EOK;
}

static void _process(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
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
							i - start, user_data);
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
				_event(telnet, LIBTELNET_EV_DATA, 0, 0, &byte, 1, user_data);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				_event(telnet, LIBTELNET_EV_IAC, byte, 0, 0, 0, user_data);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case LIBTELNET_STATE_DO:
			_event(telnet, LIBTELNET_EV_NEGOTIATE, LIBTELNET_DO, byte,
					0, 0, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_DONT:
			_event(telnet, LIBTELNET_EV_NEGOTIATE, LIBTELNET_DONT, byte,
					0, 0, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WILL:
			_event(telnet, LIBTELNET_EV_NEGOTIATE, LIBTELNET_WILL, byte,
					0, 0, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WONT:
			_event(telnet, LIBTELNET_EV_NEGOTIATE, LIBTELNET_WONT, byte,
					0, 0, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;

		/* subnegotiation -- buffer bytes until end request */
		case LIBTELNET_STATE_SB:
			/* IAC command in subnegotiation -- either IAC SE or IAC IAC */
			if (byte == LIBTELNET_IAC) {
				telnet->state = LIBTELNET_STATE_SB_IAC;
			/* buffer the byte, or bail if we can't */
			} else if (_buffer_byte(telnet, byte, user_data) !=
					LIBTELNET_EOK) {
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			}
			break;

		/* IAC escaping inside a subnegotiation */
		case LIBTELNET_STATE_SB_IAC:
			switch (byte) {
			/* end subnegotiation */
			case LIBTELNET_SE:
				/* return to default state */
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;

				/* zero-size buffer is a protocol error */
				if (telnet->length == 0) {
					ERROR(telnet, LIBTELNET_EPROTOCOL, user_data,
							"subnegotiation has zero data");
					break;
				}

				/* invoke callback */
				_event(telnet, LIBTELNET_EV_SUBNEGOTIATION, 0,
						telnet->buffer[0], telnet->buffer + 1,
						telnet->length - 1, user_data);
				telnet->length = 0;

#ifdef HAVE_ZLIB
				/* if we are a client or a proxy and just received the
				 * COMPRESS2 begin marker, setup our zlib box and start
				 * handling the compressed stream if it's not already.
				 */
				if (telnet->buffer[0] == LIBTELNET_TELOPT_COMPRESS2 &&
						telnet->z_inflate == 0 &&
						(telnet->mode == LIBTELNET_MODE_CLIENT ||
						 telnet->mode == LIBTELNET_MODE_PROXY)) {

					if ((telnet->z_inflate = _init_zlib(telnet, 0, user_data))
							== 0)
						break;

					/* notify app that compression was enabled */
					_event(telnet, LIBTELNET_EV_COMPRESS, 1, 0, 0, 0,
							user_data);

					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke libtelnet_push to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					libtelnet_push(telnet, &buffer[start], size - start,
							user_data);
					return;
				}
#endif /* HAVE_ZLIB */

				break;
			/* escaped IAC byte */
			case LIBTELNET_IAC:
				/* push IAC into buffer */
				if (_buffer_byte(telnet, LIBTELNET_IAC, user_data) !=
						LIBTELNET_EOK) {
					start = i + 1;
					telnet->state = LIBTELNET_STATE_DATA;
				} else {
					telnet->state = LIBTELNET_STATE_SB;
				}
				break;
			/* something else -- protocol error */
			default:
				_error(telnet, __FILE__, __LINE__, LIBTELNET_EPROTOCOL,
						user_data, "unexpected byte after IAC inside SB: %d",
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
		_event(telnet, LIBTELNET_EV_DATA, 0, 0, buffer + start, i - start,
				user_data);
}

/* push a bytes into the state tracker */
void libtelnet_push(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
#ifdef HAVE_ZLIB
	/* if we have an inflate (decompression) zlib stream, use it */
	if (telnet->z_inflate != 0) {
		unsigned char inflate_buffer[4096];
		int rs;

		/* initialize zlib state */
		telnet->z_inflate->next_in = buffer;
		telnet->z_inflate->avail_in = size;
		telnet->z_inflate->next_out = inflate_buffer;
		telnet->z_inflate->avail_out = sizeof(inflate_buffer);

		/* inflate until buffer exhausted and all output is produced */
		while (telnet->z_inflate->avail_in > 0 || telnet->z_inflate->avail_out == 0) {
			/* reset output buffer */

			/* decompress */
			rs = inflate(telnet->z_inflate, Z_SYNC_FLUSH);

			/* process the decompressed bytes on success */
			if (rs == Z_OK || rs == Z_STREAM_END)
				_process(telnet, inflate_buffer, sizeof(inflate_buffer) -
						telnet->z_inflate->avail_out, user_data);
			else
				ERROR_ZLIB(telnet, user_data, rs, "inflate() failed");

			/* prepare output buffer for next run */
			telnet->z_inflate->next_out = inflate_buffer;
			telnet->z_inflate->avail_out = sizeof(inflate_buffer);

			/* on error (or on end of stream) disable further inflation */
			if (rs != Z_OK) {
				_event(telnet, LIBTELNET_EV_COMPRESS, 0, 0, 0, 0, user_data);

				inflateEnd(telnet->z_inflate);
				free(telnet->z_inflate);
				telnet->z_inflate = 0;
				break;
			}
		}

	/* COMPRESS2 is not negotiated, just process */
	} else
#endif /* HAVE_ZLIB */
		_process(telnet, buffer, size, user_data);
}

static void _send(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
#ifdef HAVE_ZLIB
	/* if we have a deflate (compression) zlib box, use it */
	if (telnet->z_deflate != 0) {
		unsigned char deflate_buffer[1024];
		int rs;

		/* initialize z_deflate state */
		telnet->z_deflate->next_in = buffer;
		telnet->z_deflate->avail_in = size;
		telnet->z_deflate->next_out = deflate_buffer;
		telnet->z_deflate->avail_out = sizeof(deflate_buffer);

		/* deflate until buffer exhausted and all output is produced */
		while (telnet->z_deflate->avail_in > 0 || telnet->z_deflate->avail_out == 0) {
			/* compress */
			if ((rs = deflate(telnet->z_deflate, Z_SYNC_FLUSH)) != Z_OK) {
				ERROR_ZLIB(telnet, user_data, rs, "deflate() failed");
				deflateEnd(telnet->z_deflate);
				free(telnet->z_deflate);
				telnet->z_deflate = 0;
				break;
			}

			_event(telnet, LIBTELNET_EV_SEND, 0, 0, deflate_buffer,
					sizeof(deflate_buffer) - telnet->z_deflate->avail_out,
					user_data);

			/* prepare output buffer for next run */
			telnet->z_deflate->next_out = deflate_buffer;
			telnet->z_deflate->avail_out = sizeof(deflate_buffer);
		}

	/* COMPRESS2 is not negotiated, just send */
	} else
#endif /* HAVE_ZLIB */
		_event(telnet, LIBTELNET_EV_SEND, 0, 0, buffer, size, user_data);
}

/* send an iac command */
void libtelnet_send_command(struct libtelnet_t *telnet, unsigned char cmd,
		void *user_data) {
	unsigned char bytes[2] = { LIBTELNET_IAC, cmd };
	_send(telnet, bytes, 2, user_data);
}

/* send negotiation */
void libtelnet_send_negotiate(struct libtelnet_t *telnet, unsigned char cmd,
		unsigned char opt, void *user_data) {
	unsigned char bytes[3] = { LIBTELNET_IAC, cmd, opt };
	_send(telnet, bytes, 3, user_data);
}

/* send non-command data (escapes IAC bytes) */
void libtelnet_send_data(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
	unsigned int i, l;
	for (l = i = 0; i != size; ++i) {
		/* dump prior portion of text, send escaped bytes */
		if (buffer[i] == LIBTELNET_IAC) {
			/* dump prior text if any */
			if (i != l)
				_send(telnet, buffer + l, i - l, user_data);
			l = i + 1;

			/* send escape */
			libtelnet_send_command(telnet, LIBTELNET_IAC, user_data);
		}
	}

	/* send whatever portion of buffer is left */
	if (i != l)
		_send(telnet, buffer + l, i - l, user_data);
}

/* send sub-request */
void libtelnet_send_subnegotiation(struct libtelnet_t *telnet,
		unsigned char opt, unsigned char *buffer, unsigned int size,
		void *user_data)  {
	libtelnet_send_command(telnet, LIBTELNET_SB, user_data);
	libtelnet_send_data(telnet, &opt, 1, user_data);
	libtelnet_send_data(telnet, buffer, size, user_data);
	libtelnet_send_command(telnet, LIBTELNET_SE, user_data);

#ifdef HAVE_ZLIB
	/* if we're a proxy and we just sent the COMPRESS2 marker, we must
	 * make sure all further data is compressed if not already.
	 */
	if (telnet->mode == LIBTELNET_MODE_PROXY &&
			telnet->z_deflate == 0 &&
			opt == LIBTELNET_TELOPT_COMPRESS2) {

		if ((telnet->z_deflate = _init_zlib(telnet, 1, user_data)) == 0)
			return;

		/* notify app that compression was enabled */
		_event(telnet, LIBTELNET_EV_COMPRESS, 1, 0, 0, 0, user_data);
	}
#endif /* HAVE_ZLIB */
}
