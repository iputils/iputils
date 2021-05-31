#!/bin/sh

CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
CC="${CC:-gcc}"
BUILD_DIR="${BUILD_DIR:-builddir}"
PREFIX="${PREFIX:-$HOME/iputils-install}"

BUILD_OPTS="-Dprefix=$PREFIX -DBUILD_RARPD=true -DBUILD_TFTPD=true -DBUILD_TRACEROUTE6=true $EXTRA_BUILD_OPTS"
[ -z "$EXTRA_BUILD_OPTS" ] && BUILD_OPTS="$BUILD_OPTS -DBUILD_HTML_MANS=true"
[ -f "meson.cross" ] && BUILD_OPTS="--cross-file $PWD/meson.cross $BUILD_OPTS"

# NOTE: meson iself checkes for minimal version
# see meson_version in meson.build, it fails if not required
# Meson version is 0.37.1 but project requires >=0.39.
check_build_dependencies()
{
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
}

print_versions()
{
	echo "=== compiler version ==="
	$CC --version

	echo "=== meson version ==="
	meson --version

	echo "=== ninja version ==="
	ninja --version
}

configure()
{
	echo "=== configure ==="
	echo "Build options: $BUILD_OPTS"
	echo "CFLAGS: $CFLAGS"

	export CFLAGS
	meson $BUILD_DIR $BUILD_OPTS
}

build()
{
	echo "=== build ==="
	make -j$(getconf _NPROCESSORS_ONLN)
}

install()
{
	echo "=== install ==="

	make install
}

print_logs()
{
	local ret=$1
	local log

	[ $ret -eq 0 ] && return

	log="$BUILD_DIR/meson-logs/meson-log.txt"
	if [ -f "$log" ]; then
		echo "=== START $log ==="
		cat $log
		echo "=== END $log ==="
	fi

	exit $ret
}

cd `dirname $0`

[ -z "$1" -o "$1" = "dependencies" ] && check_build_dependencies

[ -z "$1" -o "$1" = "info" ] && print_versions

if [ -z "$1" -o "$1" = "configure" ]; then
	configure
	print_logs $?
fi

if [ -z "$1" -o "$1" = "build" ]; then
	build
	print_logs $?
fi

if [ -z "$1" -o "$1" = "install" ]; then
	install
	print_logs $?
fi
