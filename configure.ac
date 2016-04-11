AC_INIT(protobuf, 1.0)
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

AC_ARG_WITH(plugin-toolkit,
            AC_HELP_STRING([--with-plugin-toolkit],
            [build using the vpp toolkit]),
            [with_plugin_toolkit=${prefix}/include],
            [with_plugin_toolkit=.])

AC_SUBST(TOOLKIT_INCLUDE,[${with_plugin_toolkit}])
AM_CONDITIONAL(WITH_PLUGIN_TOOLKIT, test "$with_plugin_toolkit" != ".")
AC_OUTPUT([Makefile])
