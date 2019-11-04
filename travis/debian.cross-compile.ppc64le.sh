#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>
set -e

dpkg --add-architecture ppc64el
apt update

apt install -y --no-install-recommends \
	dpkg-dev \
	gcc-powerpc64le-linux-gnu \
	libc6-dev-ppc64el-cross \
	libcap-dev:ppc64el \
	libidn2-0-dev:ppc64el \
	libssl-dev:ppc64el

cat <<EOF > meson.cross
[binaries]
c = 'powerpc64le-linux-gnu-gcc'
pkgconfig = 'powerpc64le-linux-gnu-pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'ppc64'
cpu = 'ppc64'
endian = 'little'
EOF
