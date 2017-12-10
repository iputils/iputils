# -*- autoconf -*-
# Autotools init.
AC_PREREQ([2.59])
AC_INIT([iputils],
	[m4_esyscmd([build-aux/git-version-gen --prefix s .tarball-version])],
	[], [], [https://github.com/iputils/iputils])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz subdir-objects tar-pax])
AC_CONFIG_SRCDIR([ping.h])
AC_CONFIG_HEADERS([config.h])
AM_SILENT_RULES

# Checks for compiler, and programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99

m4_ifndef([PKG_PROG_PKG_CONFIG],
	[m4_fatal([Could not locate the pkg-config autoconf
	  macros. These are usually located in /usr/share/aclocal/pkg.m4.
	  If your macros are in a different location, try setting the
	  environment variable AL_OPTS="-I/other/macro/dir" before running
	  ./autogen.sh or autoreconf again.])])
PKG_PROG_PKG_CONFIG

AC_CHECK_PROG([XSLTPROC], [xsltproc], [xsltproc])
AM_CONDITIONAL([BUILD_MAN], [test $XSLTPROC = "xsltproc"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ \
	gcrypt.h \
	gnutls/openssl.h \
	inttypes.h \
	limits.h \
	linux/rtnetlink.h \
	memory.h \
	netdb.h \
	netinet/icmp6.h \
	netinet/in.h \
	netinet/ip6.h \
	openssl/md5.h \
	pwd.h \
	string.h \
	strings.h \
	sys/capability.h \
	sys/time.h \
	sys/types.h \
	sys/uio.h \
	sys/utsname.h \
	syslog.h \
	unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_SIZE_T

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
]], [[
struct icmp6_nodeinfo nodeinfo;
]])],
[AC_DEFINE([HAVE_STRUCT_ICMP6_NODEINFO], [1], [Define to 1 if you have struct icmp6_nodeinfo])
])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
]], [[
struct tm time;
]])],
[AC_DEFINE([TIME_WITH_SYS_TIME], [1], [Define to 1 if struct tm is available.])
])

# Checks for functions.
dnl clock_gettime() may require linking with realtime library.
AC_CHECK_FUNCS([clock_gettime], [],
	[AC_CHECK_LIB([rt], [clock_gettime], [REALTIME_LIBS="-lrt"])]
)
AC_SUBST([REALTIME_LIBS])

# Check for libraries.
ACX_PTHREAD

PKG_CHECK_MODULES([LIBCAP], [libcap], [have_libcap=yes], [have_libcap=no])
AS_IF([test "x$have_libcap" = xyes], [
	AC_DEFINE([CAPABILITIES], [1], [If set the system supports capabilities.])
	AC_DEFINE([HAVE_LIBCAP], [1], [If set the system supports capabilities.])
])
AM_CONDITIONAL([ENABLE_CAP], [test x$have_libcap = xyes])

### IDN ###
PKG_CHECK_MODULES([LIBIDN2], [libidn2], [have_libidn2=yes], [have_libidn2=no])
AC_ARG_ENABLE([idn2],
	AS_HELP_STRING([--disable-idn2], [disable Internationalized Domain Names @<:@default=enabled@:>@]),
	[enable_idn2=no], [enable_idn2=yes])
AS_IF([test "x$enable_idn2" = xyes && test x$have_libidn2 = xyes], [
	AC_DEFINE([USE_IDN], [1], [If set use Internationalized Domain Names conversions.])
])
AM_CONDITIONAL([BUILD_IDN2], [test x$have_libidn2 = xyes])

### Crypto ###
dnl ping can use any of the three
dnl ninfod requires gcrypt
PKG_CHECK_MODULES([NETTLE], [nettle], [have_nettle=yes], [have_nettle=no])
AC_CHECK_PROG([LIBGCRYPT_CONFIG], [libgcrypt-config], [libgcrypt-config], [false])
LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`
PKG_CHECK_MODULES([OPENSSL], [openssl], [have_openssl=yes], [have_openssl=no])
AC_ARG_WITH([crypto],
	[AS_HELP_STRING([--with-crypto=type],
		[Use crypto lib where type can be: auto, nettle, gcrypt, openssl, none])],
	[crypto_type="$withval"], [crypto_type="auto"])
CRYPTO_LIBS=''
AS_CASE([$crypto_type],
	[auto], [AS_IF([test "x$have_nettle" = xyes], [crypto_type=nettle; CRYPTO_LIBS="$NETTLE_LIBS"], [
			AS_IF([$LIBGCRYPT_CONFIG --version 1>/dev/null], [crypto_type=gcrypt; CRYPTO_LIBS="$LIBGCRYPT_LIBS"], [
				AS_IF([test "x$have_openssl" = xyes],
					[crypto_type=openssl; CRYPTO_LIBS="$OPENSSL_LIBS"],
					[crypto_type=none])
			])
		])],
	[nettle], [CRYPTO_LIBS="$NETTLE_LIBS"],
	[gcrypt], [CRYPTO_LIBS="$LIBGCRYPT_LIBS"],
	[openssl], [CRYPTO_LIBS="$OPENSSL_LIBS"],
	[crypto_type=none]
)
AS_IF([test "x$crypto_type" = xnettle], [
	AC_DEFINE([USE_NETTLE], [1], [If set use nettle library.])
])
AS_IF([test "x$crypto_type" = xgcrypt], [
	AC_DEFINE([USE_GCRYPT], [1], [If set use gcrypt library.])
])
AS_IF([test "x$crypto_type" != xnone], [
	AC_DEFINE([USE_CRYPTO], [1], [If set use one of the crypto libraries.])
])
AM_CONDITIONAL([HAVE_GCRYPT], [test "x$LIBGCRYPT_LIBS" != x])
AM_CONDITIONAL([HAVE_CRYPTO], [test "x$CRYPTO_LIBS" != x])
AC_SUBST([LIBGCRYPT_CFLAGS])
AC_SUBST([LIBGCRYPT_LIBS])
AC_SUBST([CRYPTO_LIBS])

# Features
AC_ARG_ENABLE([pthreads],
	AS_HELP_STRING([--enable-pthreads], [enable threads @<:@default=disabled@:>@]),
	[enable_pthreads=yes], [enable_pthreads=no])
AS_IF([test "x$enable_pthreads" = xyes], [
	AC_DEFINE([ENABLE_THREADS], [1], [If set yes use threads.])
])
AM_CONDITIONAL([BUILD_THREADS], [test x$enable_pthreads = xyes])

AC_ARG_ENABLE([ping6_rthdr],
	AS_HELP_STRING([--enable-ping6-rthdr], [enable ping6 deprecated source routing @<:@default=disabled@:>@]),
	[enable_ping6_rthdr=yes], [enable_ping6_rthdr=no])
AS_IF([test "x$enable_ping6_rthdr" = xyes], [
	AC_DEFINE([ENABLE_PING6_RTHDR], [1],
		[If set enable ping6 source routing (deprecated by RFC5095).])
])

AC_ARG_ENABLE([rdisc_server],
	AS_HELP_STRING([--enable-rdisc-server], [enable rdisc server @<:@default=disabled@:>@]),
	[enable_rdisc_server=yes], [enable_rdisc_server=no])
AS_IF([test "x$enable_rdisc_server" = xyes], [
	AC_DEFINE([RDISC_SERVER], [1],
		[If set enable rdisc server code.])
])

AC_ARG_ENABLE([ninfod],
	AS_HELP_STRING([--enable-ninfod], [enable ninfod @<:@default=disabled@:>@]),
	[enable_ninfod=yes], [enable_ninfod=no])
AM_CONDITIONAL([BUILD_NINFOD], [test x$enable_ninfod = xyes])

AC_ARG_ENABLE([sysfs],
	AS_HELP_STRING([--disable-sysfs], [disable sysfs support @<:@default=enabled@:>@]),
	[enable_sysfs=no], [enable_sysfs=yes])
AS_IF([test "x$enable_sysfs" = xyes], [
	AC_DEFINE([USE_SYSFS], [1], [If set use /sys file system.])
])

AC_ARG_WITH([arping-default-device],
	[AS_HELP_STRING([--with-arping-default-device=name], [arping default device name])],
	[arping_default_device="$withval"], [arping_default_device=""])
AS_IF([test "x$arping_default_device" != x], [
	AC_DEFINE_UNQUOTED([DEFAULT_DEVICE], ["$arping_default_device"], [arping default device name.])
])

# Write files
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
