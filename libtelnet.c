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

#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#include "libtelnet.h"

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

/* initialize a telnet state tracker */
void libtelnet_init(struct libtelnet_t *telnet, enum libtelnet_mode_t mode) {
	memset(telnet, 0, sizeof(struct libtelnet_t));
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

	/* free zlib box */
	if (telnet->zlib != 0) {
		inflateEnd(telnet->zlib);
		free(telnet->zlib);
		telnet->zlib = 0;
	}
}

/* push a byte into the telnet buffer */
static enum libtelnet_error_t _buffer_byte(
		struct libtelnet_t *telnet, unsigned char byte, void *user_data) {
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
			libtelnet_error_cb(telnet, LIBTELNET_ERROR_OVERFLOW, user_data);
			libtelnet_free(telnet);
			return LIBTELNET_ERROR_OVERFLOW;
		}

		/* (re)allocate buffer */
		new_buffer = (unsigned char *)realloc(telnet->buffer,
				_buffer_sizes[i + 1]);
		if (new_buffer == 0) {
			libtelnet_error_cb(telnet, LIBTELNET_ERROR_NOMEM,
				user_data);
			libtelnet_free(telnet);
			return LIBTELNET_ERROR_NOMEM;
		}

		telnet->buffer = new_buffer;
		telnet->size = _buffer_sizes[i + 1];
	}

	/* push the byte, all set */
	telnet->buffer[telnet->length++] = byte;
	return LIBTELNET_ERROR_OK;
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
					libtelnet_data_cb(telnet, &buffer[start], i - start,
							user_data);
				telnet->state = LIBTELNET_STATE_IAC;
			}
			break;

		/* IAC command */
		case LIBTELNET_STATE_IAC:
			switch (byte) {
			/* subrequest */
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
				libtelnet_data_cb(telnet, &byte, 1, user_data);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
				break;
			/* some other command */
			default:
				libtelnet_command_cb(telnet, byte, user_data);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			}
			break;

		/* negotiation commands */
		case LIBTELNET_STATE_DO:
			libtelnet_negotiate_cb(telnet, LIBTELNET_DO, byte, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_DONT:
			libtelnet_negotiate_cb(telnet, LIBTELNET_DONT, byte, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WILL:
			libtelnet_negotiate_cb(telnet, LIBTELNET_WILL, byte, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;
		case LIBTELNET_STATE_WONT:
			libtelnet_negotiate_cb(telnet, LIBTELNET_WONT, byte, user_data);
			start = i + 1;
			telnet->state = LIBTELNET_STATE_DATA;
			break;

		/* subrequest -- buffer bytes until end request */
		case LIBTELNET_STATE_SB:
			/* IAC command in subrequest -- either IAC SE or IAC IAC */
			if (byte == LIBTELNET_IAC) {
				telnet->state = LIBTELNET_STATE_SB_IAC;
			/* buffer the byte, or bail if we can't */
			} else if (_buffer_byte(telnet, byte, user_data) !=
					LIBTELNET_ERROR_OK) {
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
			} else {
				telnet->state = LIBTELNET_STATE_SB;
			}
			break;

		/* IAC escaping inside a subrequest */
		case LIBTELNET_STATE_SB_IAC:
			switch (byte) {
			/* end subrequest */
			case LIBTELNET_SE:
				/* return to default state */
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;

				/* zero-size buffer is a protocol error */
				if (telnet->length == 0) {
					libtelnet_error_cb(telnet, LIBTELNET_ERROR_PROTOCOL,
						user_data);
					break;
				}

				/* invoke callback */
				libtelnet_subrequest_cb(telnet, telnet->buffer[0],
					telnet->buffer + 1, telnet->length - 1, user_data);
				telnet->length = 0;

#ifdef HAVE_ZLIB
				/* if we are a client and just received the COMPRESS2
				 * begin marker, setup our zlib box and start handling
				 * the compressed stream
				 */
				if (telnet->mode == LIBTELNET_MODE_CLIENT &&
						telnet->buffer[0] == LIBTELNET_OPTION_COMPRESS2) {
					/* allocate zstream box */
					if ((telnet->zlib = (z_stream *)malloc(sizeof(z_stream)))
							== 0) {
						libtelnet_error_cb(telnet,
							LIBTELNET_ERROR_NOMEM, user_data);
					}

					/* initialize */
					memset(telnet->zlib, 0, sizeof(z_stream));
					if (inflateInit(telnet->zlib) != Z_OK) {
						free(telnet->zlib);
						telnet->zlib = 0;
						libtelnet_error_cb(telnet,
							LIBTELNET_ERROR_UNKNOWN, user_data);
						break;
					}

					/* notify app that compression was enabled */
					libtelnet_compress_cb(telnet, 1, user_data);

					/* any remaining bytes in the buffer are compressed.
					 * we have to re-invoke libtelnet_push to get those
					 * bytes inflated and abort trying to process the
					 * remaining compressed bytes in the current _process
					 * buffer argument
					 */
					libtelnet_push(telnet, &buffer[i + 1], size - i - 1,
							user_data);
					return;
				}
#endif /* HAVE_ZLIB */

				break;
			/* escaped IAC byte */
			case LIBTELNET_IAC:
				/* push IAC into buffer */
				if (_buffer_byte(telnet, LIBTELNET_IAC, user_data) !=
						LIBTELNET_ERROR_OK) {
					start = i + 1;
					telnet->state = LIBTELNET_STATE_DATA;
				} else {
					telnet->state = LIBTELNET_STATE_SB;
				}
				break;
			/* something else -- protocol error */
			default:
				libtelnet_error_cb(telnet, LIBTELNET_ERROR_PROTOCOL,
						user_data);
				start = i + 1;
				telnet->state = LIBTELNET_STATE_DATA;
				break;
			}
			break;
		}
	}

	/* pass through any remaining bytes */ 
	if (i != start)
		libtelnet_data_cb(telnet, &buffer[start], i - start, user_data);
}

/* push a bytes into the state tracker */
void libtelnet_push(struct libtelnet_t *telnet, unsigned char *buffer,
		unsigned int size, void *user_data) {
#ifdef HAVE_ZLIB
	/* if we are a client and we have a zlib box, then COMPRESS2 has been
	 * negotiated and we need to inflate the buffer before processing
	 */
	if (telnet->mode == LIBTELNET_MODE_CLIENT && telnet->zlib != 0) {
		unsigned char inflate_buffer[4096];
		int rs;

		/* initialize zlib state */
		telnet->zlib->next_in = buffer;
		telnet->zlib->avail_in = size;
		telnet->zlib->next_out = inflate_buffer;
		telnet->zlib->avail_out = sizeof(inflate_buffer);

		/* inflate until buffer exhausted and all output is produced */
		while (telnet->zlib->avail_in > 0 || telnet->zlib->avail_out == 0) {
			/* reset output buffer */

			/* decompress */
			rs = inflate(telnet->zlib, Z_SYNC_FLUSH);

			/* process the decompressed bytes on success */
			if (rs == Z_OK || rs == Z_STREAM_END)
				_process(telnet, inflate_buffer, sizeof(inflate_buffer) -
						telnet->zlib->avail_out, user_data);
			else
				libtelnet_error_cb(telnet, LIBTELNET_ERROR_UNKNOWN,
						user_data);

			/* prepare output buffer for next run */
			telnet->zlib->next_out = inflate_buffer;
			telnet->zlib->avail_out = sizeof(inflate_buffer);

			/* on error (or on end of stream) disable further inflation */
			if (rs != Z_OK) {
				libtelnet_compress_cb(telnet, 0, user_data);

				inflateEnd(telnet->zlib);
				free(telnet->zlib);
				telnet->zlib = 0;
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
	/* if we are a server and we have a zlib box, then COMPRESS2 has been
	 * negotiated and we need to deflate the buffer before sending it out
	 */
	if (telnet->mode == LIBTELNET_MODE_SERVER && telnet->zlib != 0) {
		unsigned char deflate_buffer[1024];

		/* initialize zlib state */
		telnet->zlib->next_in = buffer;
		telnet->zlib->avail_in = size;
		telnet->zlib->next_out = deflate_buffer;
		telnet->zlib->avail_out = sizeof(deflate_buffer);

		/* deflate until buffer exhausted and all output is produced */
		while (telnet->zlib->avail_in > 0 || telnet->zlib->avail_out == 0) {
			/* reset output buffer */

			/* compress */
			if (deflate(telnet->zlib, Z_SYNC_FLUSH) != Z_OK) {
				libtelnet_error_cb(telnet, LIBTELNET_ERROR_UNKNOWN,
						user_data);
				deflateEnd(telnet->zlib);
				free(telnet->zlib);
				telnet->zlib = 0;
				break;
			}

			libtelnet_send_cb(telnet, deflate_buffer, sizeof(deflate_buffer) -
					telnet->zlib->avail_out, user_data);

			/* prepare output buffer for next run */
			telnet->zlib->next_out = deflate_buffer;
			telnet->zlib->avail_out = sizeof(deflate_buffer);
		}

	/* COMPRESS2 is not negotiated, just send */
	} else
#endif /* HAVE_ZLIB */
		libtelnet_send_cb(telnet, buffer, size, user_data);
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
void libtelnet_send_subrequest(struct libtelnet_t *telnet, unsigned char type,
		unsigned char *buffer, unsigned int size, void *user_data)  {
	libtelnet_send_command(telnet, LIBTELNET_SB, user_data);
	libtelnet_send_data(telnet, &type, 1, user_data);
	libtelnet_send_data(telnet, buffer, size, user_data);
	libtelnet_send_command(telnet, LIBTELNET_SE, user_data);

#ifdef HAVE_ZLIB
	/* if we're a server and we just sent the COMPRESS2 marker, we must
	 * make sure all further data is compressed
	 */
	if (telnet->mode == LIBTELNET_MODE_SERVER && type ==
			LIBTELNET_OPTION_COMPRESS2) {
		/* allocate zstream box */
		if ((telnet->zlib = (z_stream *)malloc(sizeof(z_stream)))
				== 0) {
			libtelnet_error_cb(telnet,
				LIBTELNET_ERROR_NOMEM, user_data);
		}

		/* initialize */
		memset(telnet->zlib, 0, sizeof(z_stream));
		if (deflateInit(telnet->zlib, Z_DEFAULT_COMPRESSION) != Z_OK) {
			free(telnet->zlib);
			telnet->zlib = 0;
			libtelnet_error_cb(telnet,
				LIBTELNET_ERROR_UNKNOWN, user_data);
		}

		/* notify app that compression was enabled */
		libtelnet_compress_cb(telnet, 1, user_data);
	}
#endif /* HAVE_ZLIB */
}
