#!/bin/sh
# Copyright (c) 2019-2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$ARCH" ]; then
	echo "missing \$ARCH!" >&2
	exit 1
fi

case "$ARCH" in
arm64)
	gcc_arch="aarch64"
	meson_arch="aarch64"
	;;
ppc64el)
	gcc_arch="powerpc64le"
	meson_arch="ppc64"
	;;
s390x)
	gcc_arch="$ARCH"
	meson_arch="$ARCH"
	;;
*) echo "unsupported arch: '$1'!" >&2; exit 1;;
esac

dpkg --add-architecture $ARCH
apt update

apt install -y --no-install-recommends \
	dpkg-dev \
	gcc-${gcc_arch}-linux-gnu \
	libc6-dev-${ARCH}-cross \
	libcap-dev:$ARCH \
	libidn2-0-dev:$ARCH \
	libssl-dev:$ARCH

cat <<EOF > meson.cross
[binaries]
c = '${gcc_arch}-linux-gnu-gcc'
pkgconfig = '${gcc_arch}-linux-gnu-pkg-config'

[host_machine]
system = 'linux'
cpu_family = '$meson_arch'
cpu = '$meson_arch'
endian = 'little'
EOF
