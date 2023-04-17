[![Build Status](https://github.com/iputils/iputils/actions/workflows/ci.yml/badge.svg)](https://github.com/iputils/iputils/actions/workflows/ci.yml)
[![Coverity Status](https://scan.coverity.com/projects/1944/badge.svg?flat=1)](https://scan.coverity.com/projects/1944)

The iputils package is set of small useful utilities for Linux networking.

## Installation
```
$ ./configure && meson build
# cd builddir && meson install
```

Configuration can be adjusted (prefix, what is being build, etc.), see
[`meson_options.txt`](https://github.com/iputils/iputils/blob/master/meson.build),
[`meson.build`](https://github.com/iputils/iputils/blob/master/meson.build).

Build dependencies are listed in scripts in
[ci directory](https://github.com/iputils/iputils/tree/master/ci).

## Supported libc
- [glibc](https://www.gnu.org/software/libc/)
- [uClibc-ng](https://uclibc-ng.org/)
- [musl](https://musl.libc.org/)

## Contributing
### Issues
* If reporting a bug, please document how to reproduce it.
* Please always test the latest master branch.
* Finding the commit which introduced the problem helps (bisecting).
* Document the kernel and distribution that were used.
* Tests should ideally use network namespaces to not interfere with the rest of the system.

### Pull requests
* If fixing a bug, please document how to reproduce it.
* Finding the commit which introduced the problem helps (bisecting). Add `Fixme:` tag.
* If adding a feature, please describe why it's useful to add it.
* Commits should be signed: `Signed-off-by: Your Name <me@example.org>`, see
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin.
* Although the coding style for most tools is ancient, new code should follow the Linux kernel coding style.
See https://www.kernel.org/doc/html/latest/process/coding-style.html.
* To update the code in the pull request, use `git push -f`. Do *not* open a new pull request.

### Reviewers
* Reviewers are very welcome. Post your comments or add `Reviewed-by: Your Name <me@example.org>`.

### Translators
Localization is hosted on [Fedora Weblate](https://translate.fedoraproject.org/projects/iputils/iputils/).

## Tools are included in iputils
- [arping](https://github.com/iputils/iputils/blob/master/arping.c)
- [clockdiff](https://github.com/iputils/iputils/blob/master/clockdiff.c)
- [ping](https://github.com/iputils/iputils/tree/master/ping)
- [tracepath](https://github.com/iputils/iputils/blob/master/tracepath.c)

## Tools removed from iputils
Some obsolete tools has been removed (see
[#363](https://github.com/iputils/iputils/issues/363)).

| Tool | Removing commit | Last release | Replacement
| ---- | --------------- | ------------ | -----------
| ninfod | [8f0d897](https://github.com/iputils/iputils/commit/8f0d897) | [20211215](https://github.com/iputils/iputils/releases/tag/20211215) | experimental unused protocol
| rarpd | [fba7b62](https://github.com/iputils/iputils/commit/fba7b62) | [20211215](https://github.com/iputils/iputils/releases/tag/20211215) | superseded by DHCP protocol
| rdisc | [7447806](https://github.com/iputils/iputils/commit/7447806) | [20211215](https://github.com/iputils/iputils/releases/tag/20211215) | superseded by DHCP protocol
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
