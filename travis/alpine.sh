#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>
set -e

apk update

# NOTE: libidn2-dev is not in 3.10, only in edge
apk add \
	clang \
	docbook-xml \
	docbook-xsl \
	gcc \
	gettext-dev \
	libcap-dev \
	libxslt \
	make \
	meson \
	musl-dev \
	pkgconfig
