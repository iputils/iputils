#!/bin/sh
# Copyright (c) 2019-2021 Petr Vorel <petr.vorel@gmail.com>
set -ex

apk update

# NOTE: libidn2-dev is not in 3.10, only in edge
apk add \
	clang \
	docbook-xml \
	docbook-xsl \
	gcc \
	iproute2 \
	gettext-dev \
	libcap-dev \
	libxslt \
	make \
	meson \
	musl-dev \
	pkgconfig
