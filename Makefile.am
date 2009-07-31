lib_LTLIBRARIES = libtelnet.la
libtelnet_la_SOURCES = libtelnet.c libtelnet.h

bin_PROGRAMS = telnet-client telnet-chatd telnet-proxy

telnet_client_SOURCES = telnet-client.c telnet-client.h
telnet_client_LDADD = libtelnet.la

telnet_chatd_SOURCES = telnet-chatd.c telnet-chatd.h
telnet_chatd_LDADD = libtelnet.la

telnet_proxy_SOURCES = telnet-proxy.c telnet-proxy.h
telnet_proxy_LDADD = libtelnet.la
