dnl Process this file with autoconf to produce a configure script.
AC_INIT([netmask], [2.4.1])
AC_CONFIG_SRCDIR([main.c])
AM_INIT_AUTOMAKE


dnl Checks for programs.
: ${CFLAGS='-Wall -g -O6'}
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
