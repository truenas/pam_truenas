AC_PREREQ([2.69])
AC_INIT([pam-truenas], [1.0], [andrew.walker@truenas.com])
AC_CONFIG_SRCDIR([src/pam_truenas.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0])

# Check for keyutils library
AC_CHECK_LIB([keyutils], [request_key], [], [
    AC_MSG_ERROR([keyutils library not found])
])

# Check for PAM
AC_CHECK_LIB([pam], [pam_start], [], [
    AC_MSG_ERROR([PAM library not found])
])

# Check for TrueNAS SCRAM library
AC_CHECK_LIB([truenas_scram], [scram_hi], [], [
    AC_MSG_ERROR([TrueNAS SCRAM library not found])
])

# Check for TrueNAS password encoding library
AC_CHECK_LIB([truenas_pwenc], [pwenc_init_context], [], [
    AC_MSG_ERROR([TrueNAS password encoding library not found])
])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h security/pam_ext.h], [], [
    AC_MSG_ERROR([PAM headers not found])
])

# Check for TrueNAS headers
AC_CHECK_HEADERS([truenas_scram.h], [], [
    AC_MSG_ERROR([TrueNAS SCRAM header not found])
])
AC_CHECK_HEADERS([truenas_pwenc.h], [], [
    AC_MSG_ERROR([TrueNAS password encoding header not found])
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_INT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memset strchr strdup strlen strtoul])

# Check for strlcpy
AC_CHECK_FUNCS([strlcpy], [
    AC_DEFINE([HAVE_STRLCPY], [1], [Define to 1 if you have the strlcpy function.])
])

# Check for explicit_bzero or memset_explicit
AC_CHECK_FUNCS([explicit_bzero], [], [
    AC_CHECK_FUNCS([memset_explicit], [
        AC_DEFINE([HAVE_MEMSET_EXPLICIT], [1], [Define to 1 if you have the memset_explicit function.])
    ], [
        AC_MSG_ERROR([Neither explicit_bzero nor memset_explicit found])
    ])
])

# PAM module directory
AC_ARG_WITH([pam-dir],
    [AS_HELP_STRING([--with-pam-dir=DIR], [PAM module directory])],
    [pamdir=$withval],
    [pamdir='/usr/lib/security'])
AC_SUBST([pamdir])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
