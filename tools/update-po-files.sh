#!/bin/sh -eux
# Copyright (c) 2023 Petr Vorel <pvorel@suse.cz>

DIR=builddir

meson . $DIR
ninja iputils-pot -C $DIR
ninja iputils-update-po -C $DIR
