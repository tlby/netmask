dnl Process this file with autoconf to produce a configure script.
AC_INIT([netmask], [2.4.4])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])


dnl Checks for programs.
: ${CFLAGS='-Wall -g -O3'}
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(syslog.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(strerror strtoul)

AC_OUTPUT(Makefile)
