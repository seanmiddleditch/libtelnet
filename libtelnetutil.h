/*
 * libtelnetutil - TELNET protocol handling library (utilities)
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

#if !defined(LIBTELNETUTIL_INCLUDE)
#define LIBTELNETUTIL_INCLUDE 1

/* C++ support */
#if defined(__cplusplus)
extern "C" {
#endif

/* TTYPE special values */
#define TELNET_TTYPE_IS 0
#define TELNET_TTYPE_SEND 1

/* NEW-ENVIRON special values */
#define TELNET_ENVIRON_IS 0
#define TELNET_ENVIRON_SEND 1
#define TELNET_ENVIRON_INFO 2
#define TELNET_ENVIRON_VAR 0
#define TELNET_ENVIRON_VALUE 1
#define TELNET_ENVIRON_ESC 2
#define TELNET_ENVIRON_USERVAR 3

/* MSSP special values */
#define TELNET_MSSP_VAR 1
#define TELNET_MSSP_VAL 2

/* begin sending compressed data (server only) */
extern void telnet_begin_compress2(telnet_t *telnet);

/* send formatted data with \r and \n translated, and IAC escaped */
extern int telnet_printf(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/* send formatted data with just IAC escaped */
extern int telnet_raw_printf(telnet_t *telnet, const char *fmt, ...)
		TELNET_GNU_PRINTF(2, 3);

/* send TTYPE/ENVIRON/NEW-ENVIRON/MSSP data */
extern void telnet_format_sb(telnet_t *telnet, unsigned char telopt,
		size_t count, ...);

/* send ZMP commands */
extern void telnet_send_zmp(telnet_t *telnet, size_t argc, const char **argv);
extern void telnet_send_zmpv(telnet_t *telnet, ...) TELNET_GNU_SENTINEL;

/* C++ support */
#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* !defined(LIBTELNETUTIL_INCLUDE) */
