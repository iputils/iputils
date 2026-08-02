#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2018-2026 Petr Vorel <pvorel@suse.cz>
set -ex

zypper='zypper --non-interactive install --no-recommends'

$zypper \
	clang \
	docbook_5 \
	docbook5-xsl-stylesheets \
	file \
	gcc \
	gettext-tools \
	git \
	iproute2 \
	jq \
	libcap-devel \
	libcap-progs \
	libidn2-devel \
	libxslt-tools \
	meson \
	ninja \
	pkgconf

if [ "$WITH_TEST_DEPS" ]; then
	if ! $zypper perl-Test-Command perl-Socket-GetAddrInfo; then
		$zypper make perl
		perl -MCPAN -e 'install Socket::GetAddrInfo; install Test::Command; install Test::More'
	fi
fi
