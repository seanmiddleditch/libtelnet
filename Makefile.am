pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtelnet.pc

dist_man_MANS = man/libtelnet.3 man/telnet_init.3 man/telnet_free.3 \
		man/telnet_send.3 man/telnet_recv.3 man/telnet_iac.3 \
		man/telnet_negotiate.3 man/telnet_printf.3 man/telnet_raw_printf.3 \
		man/telnet_begin_compress2.3 man/telnet_begin_sb.3 man/telnet_finish_sb.3 \
		man/telnet-proxy.1 man/telnet-client.1 man/telnet-chatd.1

libtelnet_includedir = $(includedir)
libtelnet_include_HEADERS = libtelnet.h

lib_LTLIBRARIES = libtelnet.la
libtelnet_la_SOURCES = libtelnet.c libtelnet.h
libtelnet_la_LDFLAGS = -version-info 1:0:0

bin_PROGRAMS = telnet-client telnet-chatd telnet-proxy

telnet_client_SOURCES = telnet-client.c libtelnet.h
telnet_client_LDADD = libtelnet.la

telnet_chatd_SOURCES = telnet-chatd.c libtelnet.h
telnet_chatd_LDADD = libtelnet.la

telnet_proxy_SOURCES = telnet-proxy.c libtelnet.h
telnet_proxy_LDADD = libtelnet.la
