#!/bin/sh
# Copyright (c) 2018 Petr Vorel <pvorel@suse.cz>
set -e

zypper --non-interactive install --no-recommends \
	clang \
	docbook_5 \
	docbook5-xsl-stylesheets \
	gcc \
	gettext-tools \
	libcap-devel \
	libcap-progs \
	libidn2-devel \
	libxslt-tools \
	make \
	meson \
	ninja \
	pkg-config \
	which
