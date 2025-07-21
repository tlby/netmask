#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([netmask],[2.5.0])
AC_CONFIG_SRCDIR([netmask.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall gnu])
AX_CODE_COVERAGE

dnl Checks for programs.
AC_PROG_CC
PKG_CHECK_MODULES([CHECK], [check])

dnl Checks for libraries.
AC_CHECK_INCLUDES_DEFAULT

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h syslog.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strerror strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
