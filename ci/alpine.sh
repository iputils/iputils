#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019-2025 Petr Vorel <petr.vorel@gmail.com>
set -ex

apk update

if [ "$WITH_TEST_DEPS" ]; then
	TEST_DEPS="
	perl-socket-getaddrinfo
	perl-test-command
"
fi

# NOTE: libidn2-dev is not in 3.10, only in edge
apk add \
	clang \
	docbook-xml \
	docbook-xsl \
	file \
	gcc \
	git \
	gettext-dev \
	iproute2 \
	jq \
	libcap-dev \
	libxslt \
	meson \
	musl-dev \
	pkgconfig \
	$TEST_DEPS
