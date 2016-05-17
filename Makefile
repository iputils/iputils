#
# Configuration
#

# Path to parent kernel include files directory
LIBC_INCLUDE=/usr/include
# Libraries
ADDLIB=
# Linker flags
LDFLAG_STATIC=-Wl,-Bstatic
LDFLAG_DYNAMIC=-Wl,-Bdynamic
LDFLAG_CAP=-lcap
LDFLAG_GCRYPT=-lgcrypt -lgpg-error
LDFLAG_NETTLE=-lnettle
LDFLAG_CRYPTO=-lcrypto
LDFLAG_IDN=-lidn
LDFLAG_RESOLV=-lresolv
LDFLAG_SYSFS=-lsysfs
LDFLAG_RT=-lrt
LDFLAG_M=-lm

#
# Options
#

# Capability support (with libcap) [yes|static|no]
USE_CAP=yes
# sysfs support (with libsysfs - deprecated) [no|yes|static]
USE_SYSFS=no
# IDN support  [yes|no|static]
USE_IDN=yes

# Do not use getifaddrs [no|yes|static]
WITHOUT_IFADDRS=no
# arping default device (e.g. eth0) []
ARPING_DEFAULT_DEVICE=

# nettle library for ipv6 ping [yes|no|static]
USE_NETTLE=yes
# libgcrypt library for ipv6 ping [no|yes|static]
USE_GCRYPT=no
# Crypto library for ping6 [shared|static|no]
USE_CRYPTO=shared
# Resolv library for ping6 [yes|static]
USE_RESOLV=yes
# ping6 source routing (deprecated by RFC5095) [no|yes|RFC3542]
ENABLE_PING6_RTHDR=no

# rdisc server (-r option) support [no|yes]
ENABLE_RDISC_SERVER=no

# -------------------------------------
# What a pity, all new gccs are buggy and -Werror does not work. Sigh.
# CFLAGS+=-fno-strict-aliasing -Wstrict-prototypes -Wall -Werror -g
CFLAGS?=-O3 -g
CFLAGS+=-fno-strict-aliasing -Wstrict-prototypes -Wall
CPPFLAGS+=-D_GNU_SOURCE
LDLIB=

FUNC_LIB = $(if $(filter static,$(1)),$(LDFLAG_STATIC) $(2) $(LDFLAG_DYNAMIC),$(2))

# USE_GCRYPT: DEF_GCRYPT, LIB_GCRYPT
# USE_CRYPTO: LIB_CRYPTO
ifneq ($(USE_GCRYPT),no)
	LIB_CRYPTO = $(call FUNC_LIB,$(USE_GCRYPT),$(LDFLAG_GCRYPT))
	DEF_CRYPTO = -DUSE_GCRYPT
else
ifneq ($(USE_NETTLE),no)
	LIB_CRYPTO = $(call FUNC_LIB,$(USE_NETTLE),$(LDFLAG_NETTLE))
	DEF_CRYPTO = -DUSE_NETTLE
else
ifneq ($(USE_CRYPTO),no)
	LIB_CRYPTO = $(call FUNC_LIB,$(USE_CRYPTO),$(LDFLAG_CRYPTO))
	DEF_CRYPTO = -DUSE_OPENSSL
endif
endif
endif

# USE_RESOLV: LIB_RESOLV
LIB_RESOLV = $(call FUNC_LIB,$(USE_RESOLV),$(LDFLAG_RESOLV))

# USE_CAP:  DEF_CAP, LIB_CAP
ifneq ($(USE_CAP),no)
	DEF_CAP = -DCAPABILITIES
	LIB_CAP = $(call FUNC_LIB,$(USE_CAP),$(LDFLAG_CAP))
endif

# USE_SYSFS: DEF_SYSFS, LIB_SYSFS
ifneq ($(USE_SYSFS),no)
	DEF_SYSFS = -DUSE_SYSFS
	LIB_SYSFS = $(call FUNC_LIB,$(USE_SYSFS),$(LDFLAG_SYSFS))
endif

# USE_IDN: DEF_IDN, LIB_IDN
ifneq ($(USE_IDN),no)
	DEF_IDN = -DUSE_IDN
	LIB_IDN = $(call FUNC_LIB,$(USE_IDN),$(LDFLAG_IDN))
endif

# WITHOUT_IFADDRS: DEF_WITHOUT_IFADDRS
ifneq ($(WITHOUT_IFADDRS),no)
	DEF_WITHOUT_IFADDRS = -DWITHOUT_IFADDRS
endif

# ENABLE_RDISC_SERVER: DEF_ENABLE_RDISC_SERVER
ifneq ($(ENABLE_RDISC_SERVER),no)
	DEF_ENABLE_RDISC_SERVER = -DRDISC_SERVER
endif

# ENABLE_PING6_RTHDR: DEF_ENABLE_PING6_RTHDR
ifneq ($(ENABLE_PING6_RTHDR),no)
	DEF_ENABLE_PING6_RTHDR = -DPING6_ENABLE_RTHDR
ifeq ($(ENABLE_PING6_RTHDR),RFC3542)
	DEF_ENABLE_PING6_RTHDR += -DPINR6_ENABLE_RTHDR_RFC3542
endif
endif

# -------------------------------------
TARGETS=ping tracepath traceroute6 clockdiff rdisc arping tftpd rarpd

LDLIBS=$(LDLIB) $(ADDLIB)

UNAME_N:=$(shell uname -n)
LASTTAG:=$(shell git describe HEAD | sed -e 's/-.*//')
TODAY=$(shell date +%Y-%m-%d)
DATE=$(shell date -d $(TODAY) +%Y%m%d)
TAG:=$(shell date -d $(TODAY) +s%Y%m%d)


# -------------------------------------
.PHONY: all ninfod clean distclean man html check-kernel modules snapshot

all: $(TARGETS)

%.s: %.c
	$(COMPILE.c) $< $(DEF_$(patsubst %.o,%,$@)) -S -o $@
%.o: %.c
	$(COMPILE.c) $< $(DEF_$(patsubst %.o,%,$@)) -o $@
LINK.o += $(CFLAGS)
$(TARGETS): %: %.o
	$(LINK.o) $^ $(LIB_$@) $(LDLIBS) -o $@

# -------------------------------------
# arping
DEF_arping = $(DEF_SYSFS) $(DEF_CAP) $(DEF_IDN) $(DEF_WITHOUT_IFADDRS)
LIB_arping = $(LIB_SYSFS) $(LIB_CAP) $(LIB_IDN) $(LDFLAG_RT)

ifneq ($(ARPING_DEFAULT_DEVICE),)
DEF_arping += -DDEFAULT_DEVICE=\"$(ARPING_DEFAULT_DEVICE)\"
endif

# clockdiff
DEF_clockdiff = $(DEF_CAP)
LIB_clockdiff = $(LIB_CAP)

# ping / ping6
DEF_ping = $(DEF_CAP) $(DEF_IDN) $(DEF_CRYPTO) $(DEF_WITHOUT_IFADDRS)
DEF_ping_common = $(DEF_ping)
DEF_ping6_common = $(DEF_ping)
LIB_ping = $(LIB_CAP) $(LIB_IDN) $(LIB_CRYPTO) $(LIB_RESOLV) $(LDFLAG_M)

ping: ping_common.o ping6_common.o
ping.o ping_common.o ping6_common.o: ping.h in6_flowlabel.h
ping6.o ping6_common.o: ping.h in6_flowlabel.h

# rarpd
DEF_rarpd =
LIB_rarpd =

# rdisc
DEF_rdisc = $(DEF_ENABLE_RDISC_SERVER)
LIB_rdisc =

# tracepath
DEF_tracepath = $(DEF_IDN)
LIB_tracepath = $(LIB_IDN)

# traceroute6
DEF_traceroute6 = $(DEF_CAP) $(DEF_IDN)
LIB_traceroute6 = $(LIB_CAP) $(LIB_IDN)

# tftpd
DEF_tftpd =
DEF_tftpsubs =
LIB_tftpd =

tftpd: tftpsubs.o
tftpd.o tftpsubs.o: tftp.h

# -------------------------------------
# ninfod
ninfod:
	@set -e; \
		if [ ! -f ninfod/Makefile ]; then \
			cd ninfod; \
			./configure; \
			cd ..; \
		fi; \
		$(MAKE) -C ninfod

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
	@set -e; \
		if [ -f ninfod/Makefile ]; then \
			$(MAKE) -C ninfod clean; \
		fi

distclean: clean
	@set -e; \
		if [ -f ninfod/Makefile ]; then \
			$(MAKE) -C ninfod distclean; \
		fi

# -------------------------------------
RPMBUILD=rpmbuild
RPMTMP=.rpmtmp
snapshot:
	@echo "[$(TAG)]" > RELNOTES.NEW
	@echo >>RELNOTES.NEW
	@git log --no-merges $(LASTTAG).. | git shortlog >> RELNOTES.NEW
	@echo >> RELNOTES.NEW
	@cat RELNOTES >> RELNOTES.NEW
	@mv RELNOTES.NEW RELNOTES
	@sed -e "s/^%define ssdate .*/%define ssdate $(DATE)/" iputils.spec > iputils.spec.tmp
	@mv iputils.spec.tmp iputils.spec
	@echo "#define SNAPSHOT \"$(TAG)\"" > SNAPSHOT.h
	@$(MAKE) -C doc snapshot
	@$(MAKE) man
	@git commit -a -m "iputils-$(TAG)"
	@git tag -s -m "iputils-$(TAG)" $(TAG)
	@git archive --format=tar --prefix=iputils-$(TAG)/ $(TAG) | bzip2 -9 > ../iputils-$(TAG).tar.bz2

rpm:
	@git archive --format=tar --prefix=iputils/ HEAD | bzip2 -9 > $(RPMTMP)/iputils.tar.bz2
	@$(RPMBUILD) -ta --define 'current yes' $(RPMTMP)/iputils.tar.bz2
	@rm -f $(RPMTMP)/iputils.tar.bz2

