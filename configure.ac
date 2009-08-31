AC_INIT([libtelnet], [0.11], [http://github.com/elanthis/libtelnet/tree/master])

AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_LIBTOOL

# zlib support
AC_CHECK_LIB(z,deflate,ZLIB=yes,ZLIB=no)
if test "x$ZLIB" = "xyes" ; then
	LIBS="$LIBS -lz"
	AC_DEFINE(HAVE_ZLIB, 1, [We have zlib])
	LIBTELNET_HAVE_ZLIB="-DHAVE_ZLIB"
	AC_SUBST(LIBTELNET_HAVE_ZLIB)
fi

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
