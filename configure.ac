AC_INIT(vpp_protobuf, 1.0)
: ${CFLAGS=""}
LT_INIT
AM_INIT_AUTOMAKE
AM_SILENT_RULES

AC_PROG_CC
AM_PROG_CC_C_O

AC_CHECK_PROG( [PROTOC_C], [protoc-c], yes)

if test x"$PROTOC_C" != x"yes" ; then
	    AC_MSG_ERROR([Please install protobuf-c-compiler.])
fi

AC_CHECK_HEADERS(
	[google/protobuf-c/protobuf-c.h],
	[], [AC_MSG_ERROR([protobuf-c header files not found])],
)
AC_CHECK_HEADERS(
	[ev.h],
	[], [AC_MSG_ERROR([libev header files not found])],
)

AC_OUTPUT([Makefile])
