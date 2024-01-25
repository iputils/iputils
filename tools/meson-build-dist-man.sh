#!/bin/sh
# This script should be invoked by meson itself (via 'meson dist')
# See https://github.com/mesonbuild/meson/issues/2166 and more specifically,
# https://github.com/mesonbuild/meson/issues/2166#issuecomment-629696911.
set -eu

cd "$MESON_DIST_ROOT"
DIR=$(mktemp -d)
meson setup "$DIR" -DBUILD_MANS=true -DBUILD_HTML_MANS=true
meson compile -C "$DIR"
cp "$DIR"/doc/* doc/
rm -rf "$DIR"
