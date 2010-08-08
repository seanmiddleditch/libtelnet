AC_INIT([libtelnet], [0.13], [http://github.com/elanthis/libtelnet/tree/master])

AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_LIBTOOL

AC_FUNC_ALLOCA

# disable building of tools
AC_ARG_ENABLE(util,
	[AC_HELP_STRING([--disable-util],
		[disable the building of programs in util/ directory])],
	[BUILD_UTIL=$enableval],
	[BUILD_UTIL=yes])
AM_CONDITIONAL([BUILD_UTIL], [test "x$BUILD_UTIL" = "xyes"])

# zlib support
AC_CHECK_LIB(z,deflate,ZLIB=yes,ZLIB=no)
if test "x$ZLIB" = "xyes" ; then
	LIBS="$LIBS -lz"
	AC_DEFINE(HAVE_ZLIB, 1, [We have zlib])
fi

AC_CONFIG_FILES([Makefile util/Makefile man/Makefile test/Makefile libtelnet.pc])
AC_OUTPUT
