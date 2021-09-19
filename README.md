[![Build Status](https://travis-ci.org/iputils/iputils.svg?branch=master)](https://travis-ci.org/iputils/iputils)
[![Coverity Status](https://scan.coverity.com/projects/1944/badge.svg?flat=1)](https://scan.coverity.com/projects/1944)

The iputils package is set of small useful utilities for Linux networking.

## Supported libc
- glibc
- uClibc
- musl

## Localization
Localization is hosted on [Fedora Weblate](https://translate.fedoraproject.org/projects/iputils/iputils/).

## Tools are included in iputils
- arping
- clockdiff
- ninfod
- ping
- rarpd
- rdisc
- tracepath

## Tools removed from iputils

Some obsolete tools has been removed (see
[#363](https://github.com/iputils/iputils/issues/363)).

| Tool | Removing commit | Last release | Replacement
| ---- | --------------- | ------------ | -----------
| tftpd | [341975a](https://github.com/iputils/iputils/commit/341975ab9c8d196b2a0d7af78a5ddea497495089) | [20210722](https://github.com/iputils/iputils/releases/tag/20210722) | [tftp-hpa](https://git.kernel.org/pub/scm/network/tftp/tftp-hpa.git), [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
| traceroute6 | [a139421](https://github.com/iputils/iputils/commit/a1394212fd4b3e3259104467d9861909961b219e) | [20210722](https://github.com/iputils/iputils/releases/tag/20210722) | [mtr](https://www.bitwizard.nl/mtr/), [traceroute](http://traceroute.sourceforge.net/), [tracepath](https://github.com/iputils/iputils/blob/master/tracepath.c)

## History
### Alexey Kuznetsov (1999–2002)
- first release (1999-04-16):  [`iputils-ss990417.tar.gz`](http://ftp.icm.edu.pl/packages/linux-iproute/ip-routing/iputils-ss990417.tar.gz)
- latest release (2002-09-26): [`iputils-ss020927.tar.gz`](http://ftp.icm.edu.pl/packages/linux-iproute/ip-routing/iputils-ss020927.tar.gz)

### Hideaki Yoshifuji (2006–2015)
- first release (2006-04-25): [`iputils-s20060425.tar.bz2`](http://www.skbuff.net/iputils/iputils-s20060425.tar.bz2)
- latest release (2015-12-18): [`iputils-s20151218.tar.bz2`](http://www.skbuff.net/iputils/iputils-s20151218.tar.bz2)

<!-- vim: set tw=80: -->
