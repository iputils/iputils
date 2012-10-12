#
# Configuration
#

# CC
CC=gcc
# Path to parent kernel include files directory
LIBC_INCLUDE=/usr/include
# Libraries
ADDLIB=-lm

#
# Options
#

# Capability support (with libcap)
USE_CAP=yes
# sysfs support (with libsysfs)
USE_SYSFS=yes

# -------------------------------------
# What a pity, all new gccs are buggy and -Werror does not work. Sigh.
#CCOPT=-Wstrict-prototypes -Wall -g -Werror
CCOPT=-Wstrict-prototypes -Wall -g
CCOPTOPT=-O2
GLIBCFIX=-D_GNU_SOURCE
DEFINES=
LDLIB=

ifneq ($(USE_CAP),no)
	DEFINES += -DCAPABILITIES
	LIB_CAP = -lcap
endif

ifneq ($(USE_SYSFS),no)
	DEFINES += -DUSE_SYSFS
	LIB_SYSFS = -lsysfs
endif

# -------------------------------------
IPV4_TARGETS=tracepath ping clockdiff rdisc arping tftpd rarpd
IPV6_TARGETS=tracepath6 traceroute6 ping6
TARGETS=$(IPV4_TARGETS) $(IPV6_TARGETS)

CFLAGS=$(CCOPTOPT) $(CCOPT) $(GLIBCFIX) $(DEFINES)
LDLIBS=$(LDLIB) $(ADDLIB)

LASTTAG:=`git describe HEAD | sed -e 's/-.*//'`
TAG:=`date +s%Y%m%d`

# -------------------------------------
.PHONY: all clean man html check-kernel modules snapshot

all: $(TARGETS)

# arping
arping: arping.o
	$(LINK.o) $^ $(LIB_SYSFS) $(LIB_CAP) $(LDLIBS) -o $@

# clockdiff
clockdiff: clockdiff.o
	$(LINK.o) $^ $(LIB_CAP) $(LDLIBS) -o $@

# ping / ping6
ping: ping.o ping_common.o
	$(LINK.o) $^ $(LIB_CAP) $(LDLIBS) -o $@
ping6: ping6.o ping_common.o
	$(LINK.o) $^ -lresolv -lcrypto $(LIB_CAP) $(LDLIBS) -o $@
ping.o ping6.o ping_common.o: ping_common.h

# rarpd

# rdisc_srv
rdisc_srv.o: rdisc.c
	$(CC) $(CFLAGS) -DRDISC_SERVER -o rdisc_srv.o rdisc.c

# tracepath

# tracepath6

# traceroute6
traceroute6: traceroute6.o
	$(LINK.o) $^ $(LIB_CAP) $(LDLIBS) -o $@

# tftpd
tftpd: tftpd.o tftpsubs.o
tftpd.o tftpsubs.o: tftp.h

# -------------------------------------
# modules / check-kernel are only for ancient kernels; obsolete
check-kernel:
ifeq ($(KERNEL_INCLUDE),)
	@echo "Please, set correct KERNEL_INCLUDE"; false
else
	@set -e; \
	if [ ! -r $(KERNEL_INCLUDE)/linux/autoconf.h ]; then \
		echo "Please, set correct KERNEL_INCLUDE"; false; fi
endif

modules: check-kernel
	$(MAKE) KERNEL_INCLUDE=$(KERNEL_INCLUDE) -C Modules

# -------------------------------------
man:
	$(MAKE) -C doc man

html:
	$(MAKE) -C doc html

clean:
	@rm -f *.o $(TARGETS)
	@$(MAKE) -C Modules clean
	@$(MAKE) -C doc clean

# -------------------------------------
snapshot:
	@if [ "`uname -n`" != "pleiades" ]; then echo "Not authorized to advance snapshot"; exit 1; fi
	@date "+[$(TAG)]" > RELNOTES.NEW
	@echo >>RELNOTES.NEW
	@git log $(LASTTAG).. | git shortlog >> RELNOTES.NEW
	@echo >> RELNOTES.NEW
	@cat RELNOTES >> RELNOTES.NEW
	@mv RELNOTES.NEW RELNOTES
	@date "+static char SNAPSHOT[] = \"$(TAG)\";" > SNAPSHOT.h
	@$(MAKE) -C doc snapshot
	@$(MAKE) man
	@git commit -a -m "iputils-$(TAG)"
	@git tag -s -m "iputils-$(TAG)" $(TAG)
	@git archive --format=tar --prefix=iputils-$(TAG)/ $(TAG) | bzip2 -9 > ../iputils-$(TAG).tar.bz2

