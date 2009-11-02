pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtelnet.pc

dist_man_MANS = libtelnet.3 telnet_init.3 telnet_free.3 telnet_send.3 \
		telnet_recv.3 telnet_iac.3 telnet_negotiate.3

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
