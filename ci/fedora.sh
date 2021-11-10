#!/bin/sh
# Copyright (c) 2019-2021 Petr Vorel <petr.vorel@gmail.com>
set -ex

yum -y install \
	clang \
	gcc \
	gettext \
	iproute \
	libcap-devel \
	libxslt \
	make \
	pkg-config

yum -y install libidn2-devel docbook5-style-xsl || true

# supported since CentOS 7 (CentOS 6 don't have python 3.5 meson dependency)
if [ "$(basename $0)" = "centos.sh" ]; then
	# CentOS 7: provided by epel
	yum -y install epel-release

	# CentOS >= 8 provided by PowerTools (but epel still needed)
	if [ "$DISTRO_VERSION" != 7 ]; then
		yum -y install dnf-plugins-core
		yum config-manager --set-enabled powertools
	fi
fi

yum -y install meson ninja-build
