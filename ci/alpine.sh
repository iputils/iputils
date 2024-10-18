#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019-2024 Petr Vorel <petr.vorel@gmail.com>
set -ex

apk update

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
	pkgconfig
