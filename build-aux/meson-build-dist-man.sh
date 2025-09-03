#!/bin/sh -eu
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) Iputils Project, 2024-2025
#
# This script should be invoked by meson itself on 'meson dist'
# (invoked by tools/create-tarballs.sh).

if [ "${CC:-}" ]; then
	echo "$0: CC=$CC"
	if ! $CC -dumpmachine | grep $(uname -m); then
		echo "$0: CC ($CC) is probably cross compile toolchain, unset it for man page generating"
		unset CC
	fi
fi

cd "$MESON_DIST_ROOT"
DIR=$(mktemp -d)

meson setup "$DIR" -DBUILD_MANS=true -DBUILD_HTML_MANS=true -DSKIP_TESTS=true
meson compile -C "$DIR"
cp -v "$DIR"/doc/* doc/
rm -rf "$DIR"
