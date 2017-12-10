AUTOMAKE_OPTIONS = gnu
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = \
	-include config.h \
	-I$(top_srcdir)

bin_PROGRAMS = \
	arping \
	clockdiff \
	ping \
	rarpd \
	rdisc \
	tracepath \
	traceroute6 \
	tftpd

arping_SOURCES = arping.c
arping_LDADD = $(LIBCAP_LIBS) $(REALTIME_LIBS)

clockdiff_SOURCES = clockdiff.c
clockdiff_LDADD = $(LIBCAP_LIBS)

ping_SOURCES = ping.c ping.h ping6_common.c ping_common.c in6_flowlabel.h
ping_LDADD = $(LIBCAP_LIBS) -lresolv $(LDFLAG_M)

if HAVE_CRYPTO
ping_SOURCES += iputils_md5dig.h
ping_LDADD += $(CRYPTO_LIBS)
endif

rarpd_SOURCES = rarpd.c

rdisc_SOURCES = rdisc.c

tracepath_SOURCES = tracepath.c
tracepath_LDADD = $(LIBIDN2_LIBS)

traceroute6_SOURCES = traceroute6.c
traceroute6_LDADD = $(LIBCAP_LIBS)

tftpd_SOURCES = tftp.h tftpd.c tftpsubs.c

if BUILD_IDN2
arping_LDADD += $(LIBIDN2_LIBS)
ping_LDADD += $(LIBIDN2_LIBS)
traceroute6_LDADD += $(LIBIDN2_LIBS)
endif

include ninfod/Makemodule.am

include doc/Makemodule.am

install-exec-hook:
	if [ `id -u` -eq 0 ]; then setcap cap_net_raw+ep $(DESTDIR)$(bindir)/ping; fi
