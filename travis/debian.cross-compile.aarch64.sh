#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>
set -e

dpkg --add-architecture arm64
apt update

apt install -y --no-install-recommends \
	dpkg-dev \
	gcc-aarch64-linux-gnu \
	libc6-dev-arm64-cross \
	libcap-dev:arm64 \
	libidn2-0-dev:arm64 \
	libssl-dev:arm64

cat <<EOF > meson.cross
[binaries]
c = 'aarch64-linux-gnu-gcc'
pkgconfig = 'aarch64-linux-gnu-pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
EOF
