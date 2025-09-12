#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019-2025 Petr Vorel <petr.vorel@gmail.com>
set -ex

yum='yum -y install'

$yum \
	clang \
	file \
	findutils \
	gcc \
	gettext \
	git \
	iproute \
	jq \
	libcap-devel \
	libxslt \
	pkg-config

if [ "$(basename $0)" = "centos.sh" ] || [ "$(basename $0)" = "rockylinux.sh" ]; then
	# CentOS Linux 7: libidn2-devel, meson, ninja-build are provided by EPEL
	# CentOS/RHEL/Rocky 8: docbook5-style-xsl is provided by EPEL
	$yum epel-release

	# Enable CRB (formerly PowerTools) on CentOS/RHEL/Rocky >= 8 via EPEL
	# CentOS/RHEL/Rocky >= 8: meson and ninja-build are provided by CRB
	if [ "$DISTRO_VERSION" != 7 ]; then
		# Update epel-release because CentOS Stream 9 ships 9-2.el9,
		# which is unfortunately too old to provide the crb command.
		dnf -y install 'dnf-command(config-manager)' epel-release
		crb enable
	fi
fi

$yum docbook5-style-xsl libidn2-devel meson ninja-build

if [ "$WITH_TEST_DEPS" ]; then
	if ! $yum perl-Test-Command perl-Socket-GetAddrInfo; then
		$yum perl-CPAN
		perl -MCPAN -e 'install Socket::GetAddrInfo; install Test::Command; install Test::More'
	fi
fi
