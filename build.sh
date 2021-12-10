#!/bin/sh
# Copyright (c) 2019-2021 Petr Vorel <pvorel@suse.cz>

CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
CC="${CC:-gcc}"
BUILD_DIR="${BUILD_DIR:-builddir}"
PREFIX="${PREFIX:-$HOME/iputils-install}"

BUILD_OPTS="-Dprefix=$PREFIX -DBUILD_RARPD=true $EXTRA_BUILD_OPTS"
[ -z "$EXTRA_BUILD_OPTS" ] && BUILD_OPTS="$BUILD_OPTS -DBUILD_HTML_MANS=true"
[ -f "meson.cross" ] && BUILD_OPTS="--cross-file $PWD/meson.cross $BUILD_OPTS"

# NOTE: meson iself checkes for minimal version
# see meson_version in meson.build, it fails if not required
# Meson version is 0.37.1 but project requires >=0.40.
check_build_dependencies()
{
	# ninja-build is not detected causes build failing => symlink to ninja
	# needed for CentOS 7 but maybe for others
	if ! command -v ninja > /dev/null; then
		if command -v ninja-build > /dev/null; then
			ln -sv $(command -v ninja-build) /usr/local/bin/ninja
		else
			echo "ninja binary not found (tried ninja and $NINJA on $PATH)" >&2
			exit 1
		fi
	fi

	command -v meson > /dev/null 2>&1 || { echo "meson binary not found" >&2; exit 1; }
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

run()
{
	local ret

	eval "$@"
	ret=$?

	if [ $ret -ne 0 ]; then
		echo "ERROR: '$@' failed, exit code: $ret" >&2
		exit $ret
	fi
}

configure()
{
	echo "=== configure ==="
	echo "Build options: $BUILD_OPTS"
	echo "CFLAGS: $CFLAGS"

	export CFLAGS

	run "meson $BUILD_DIR $BUILD_OPTS"
}

build()
{
	echo "=== build ==="
	run "make -j$(getconf _NPROCESSORS_ONLN)"
}

install()
{
	echo "=== install ==="
	run "make install"
}

run_tests()
{
	local ret

	echo "=== tests ==="
	cd $BUILD_DIR

	meson test
	ret=$?
	echo "$ret test failures"

	cd - > /dev/null

	exit $ret
}

print_log()
{
	local log="$BUILD_DIR/meson-logs/$1"

	if [ ! -f "$log" ]; then
		echo "'$log' is missing"
		return
	fi

	echo "=== START $log ==="
	cat $log
	echo "=== END $log ==="
}

cd `dirname $0`

cmd=
case "$1" in
	dependencies|info|configure|build|build-log|install|install-log|test|test-log|"") cmd="$1";;
	*) echo "ERROR: wrong command '$1'" >&2; exit 1;;
esac

if [ -z "$cmd" -o "$cmd" = "dependencies" ]; then
	check_build_dependencies
fi

if [ -z "$cmd" -o "$cmd" = "info" ]; then
	print_versions
fi

if [ -z "$cmd" -o "$cmd" = "configure" ]; then
	configure
fi

if [ -z "$cmd" -o "$cmd" = "build" ]; then
	build
fi

if [ "$cmd" = "build-log" ]; then
	print_log meson-log.txt
fi

if [ -z "$cmd" -o "$cmd" = "install" ]; then
	install
fi

if [ "$cmd" = "install-log" ]; then
	print_log install-log.txt
fi

if [ -z "$cmd" -o "$cmd" = "test" ]; then
	if [ -f "meson.cross" ]; then
		echo "INFO: cross-compile build, skipping running tests" >&2
	else
		run_tests
	fi
fi

if [ "$cmd" = "test-log" ]; then
	print_log testlog.txt
fi
