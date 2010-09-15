AC_INIT([libtelnet], [0.20], [http://github.com/elanthis/libtelnet/tree/master])

AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_LIBTOOL

# disable building of tools
AC_ARG_ENABLE(util,
	[AC_HELP_STRING([--disable-util],
		[disable the building of programs in util/ directory])],
	[BUILD_UTIL=$enableval],
	[BUILD_UTIL=yes])
AM_CONDITIONAL([BUILD_UTIL], [test "x$BUILD_UTIL" = "xyes"])

# find Doxygen
AC_PATH_PROG(PATH_DOXYGEN, doxygen)
AM_CONDITIONAL([BUILD_DOCS], [test "x$PATH_DOXYGEN" != "x"])

# zlib support
AC_CHECK_LIB(z,deflate,ZLIB=yes,ZLIB=no)
if test "x$ZLIB" = "xyes" ; then
	LIBS="$LIBS -lz"
	AC_DEFINE(HAVE_ZLIB, 1, [We have zlib])
fi

AC_CONFIG_FILES([Makefile util/Makefile test/Makefile libtelnet.pc doc/Makefile doc/man/Makefile doc/man/man3/Makefile doc/man/man1/Makefile])
AC_OUTPUT
