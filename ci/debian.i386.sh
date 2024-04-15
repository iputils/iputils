#!/bin/sh -eux
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2024 Petr Vorel <pvorel@suse.cz>

dpkg --add-architecture i386
apt update

apt install -y --no-install-recommends \
	gcc-multilib \
	libcap-dev:i386 \
	libc6-dev-i386 \
	libc6:i386 \
	libidn2-0-dev:i386 \
	libssl-dev:i386 \
	pkg-config:i386
