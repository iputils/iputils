#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>
set -e

if [ "$DISTRO_VERSION" = "oldstable" ]; then
	cat <<EOF | tee /etc/apt/sources.list.d/stretch-backports.list
deb http://http.debian.net/debian stretch-backports main contrib non-free
EOF
BACKPORT_REPO="stretch-backports"
fi

if [ "$DISTRO_VERSION" = "xenial" ]; then
	cat <<EOF | tee /etc/apt/sources.list.d/xenial-backports.list
deb http://archive.ubuntu.com/ubuntu xenial-backports main restricted universe multiverse
EOF
BACKPORT_REPO="xenial-backports"
fi

apt update

apt install -y --no-install-recommends \
	clang \
	docbook-xsl-ns \
	file \
	gcc \
	gettext \
	libcap-dev \
	libidn2-0-dev \
	libssl-dev \
	make \
	meson \
	pkg-config \
	xsltproc

if [ "$BACKPORT_REPO" ]; then
	apt install -y --no-install-recommends -t $BACKPORT_REPO meson
fi
