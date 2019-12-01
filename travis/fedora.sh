#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>
set -e

yum -y install \
	clang \
	gcc \
	gettext \
	libcap-devel \
	libxslt \
	make \
	pkg-config \
	which

yum -y install libidn2-devel docbook5-style-xsl || true

# supported since Centos 7 (Centos 6 don't have python 3.5 meson dependency)
if [ "$(basename $0)" = "centos.sh" ]; then
	yum -y install epel-release
fi

yum -y install meson ninja-build
