SUBDIRS = . util man

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtelnet.pc

libtelnet_includedir = $(includedir)
libtelnet_include_HEADERS = libtelnet.h libtelnetutil.h

lib_LTLIBRARIES = libtelnet.la libtelnetutil.la
libtelnet_la_SOURCES = libtelnet.c libtelnet.h
libtelnet_la_LDFLAGS = -version-info 2:0:0
libtelnetutil_la_SOURCES = libtelnetutil.c libtelnetutil.h
libtelnetutil_la_LDFLAGS = -version-info 2:0:0
