SUBDIRS = . util man

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtelnet.pc

libtelnet_includedir = $(includedir)
libtelnet_include_HEADERS = libtelnet.h

lib_LTLIBRARIES = libtelnet.la
libtelnet_la_SOURCES = libtelnet.c libtelnet.h
libtelnet_la_LDFLAGS = -version-info 1:0:0
