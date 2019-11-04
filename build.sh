#!/bin/sh

CC="${CC:-gcc}"
BUILD_DIR="${BUILD_DIR:-builddir}"
PREFIX="${PREFIX:-$HOME/iputils-install}"

# ninja-build is not detected causes build failing => symlink to ninja
# needed for CentOS 7 but maybe for others
if ! which ninja > /dev/null >&2; then
	if which ninja-build > /dev/null >&2; then
		ln -sv $(which ninja-build) /usr/local/bin/ninja
	else
		echo "ninja binary not found (tried ninja and $NINJA on $PATH)" >&2
		exit 1
	fi
fi

which meson > /dev/null 2>&1 || { echo "meson binary not found" >&2; exit 1; }

BUILD_OPTS="-Dprefix=$PREFIX -DBUILD_RARPD=true -DBUILD_TFTPD=true -DBUILD_TRACEROUTE6=true $EXTRA_BUILD_OPTS"
[ -z "$EXTRA_BUILD_OPTS" ] && BUILD_OPTS="$BUILD_OPTS -DBUILD_HTML_MANS=true"
[ -f "meson.cross" ] && BUILD_OPTS="--cross-file $PWD/meson.cross $BUILD_OPTS"

cd `dirname $0`

echo "=== compiler version ==="
$CC --version

echo "=== meson version ==="
meson --version

echo "=== ninja version ==="
ninja --version

echo "=== build ==="
echo "Build options: $BUILD_OPTS"
meson $BUILD_DIR $BUILD_OPTS && \
make -j$(getconf _NPROCESSORS_ONLN) && make install
ret=$?

cat << EOF
============
END OF BUILD
============

EOF

if [ $ret -ne 0 ]; then
	log="$DIR/meson-logs/meson-log.txt"
	if [ -f "$log" ]; then
		echo "=== START $log ==="
		cat $log
		echo "=== END $log ==="
	fi
fi

exit $ret
