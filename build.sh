#!/bin/sh

CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
CC="${CC:-gcc}"
BUILD_DIR="${BUILD_DIR:-builddir}"
PREFIX="${PREFIX:-$HOME/iputils-install}"
LOG_DIR="$(readlink -f $(dirname $0))/$BUILD_DIR/meson-logs"

print_logs()
{
	local log

	for log in $LOG_DIR/*.txt; do
		[ -f "$log" ] || continue
		echo "=== $log ==="
		cat $log
		echo
	done
}

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
echo "CFLAGS: $CFLAGS"

export CFLAGS
meson $BUILD_DIR $BUILD_OPTS && \
make -j$(getconf _NPROCESSORS_ONLN) && make install
ret=$?

if [ $ret -ne 0 ]; then
	print_logs
	echo "BUILD FAILED"
	exit $ret
fi

cat << EOF
=======
TESTING
=======
EOF

cd $BUILD_DIR
meson test
ret=$?

if [ $ret -ne 0 ]; then
	print_logs
	echo "TESTING FAILED"
fi

echo "BUILD AND TESTING PASSED"
exit $ret
