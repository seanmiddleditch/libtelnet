/*
 * libtelnet - TELNET protocol handling library
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

#if defined(HAVE_ALLOCA)
# include <alloca.h>
#endif

#include "libtelnet.h"
#include "libtelnetutil.h"

/* inlinable functions */
#if defined(__GNUC__) || __STDC_VERSION__ >= 199901L
# define INLINE __inline__
#else
# define INLINE
#endif

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
		if (buffer[i] == (char)TELNET_IAC || buffer[i] == '\r' ||
				buffer[i] == '\n') {
			/* dump prior portion of text */
			if (i != l)
				_send(telnet, buffer + l, i - l);
			l = i + 1;

			/* IAC -> IAC IAC */
			if (buffer[i] == (char)TELNET_IAC)
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
int telnet_raw_printf(telnet_t *telnet, const char *fmt, ...) {
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
