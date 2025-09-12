#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2018-2025 Petr Vorel <pvorel@suse.cz>
set -ex

zypper='zypper --non-interactive install --no-recommends'

if [ "$WITH_TEST_DEPS" ]; then
	TEST_DEPS="
	perl-Test-Command
"
	if ! $zypper perl-Socket-GetAddrInfo; then
		$zypper make perl
		PERL_MM_USE_DEFAULT=1 cpan -T Socket::GetAddrInfo
	fi
fi

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
	pkg-config \
	$TEST_DEPS
