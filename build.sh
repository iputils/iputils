#!/bin/sh -eux
# Copyright (c) 2019-2024 Petr Vorel <pvorel@suse.cz>

CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
CC="${CC:-gcc}"
BUILD_DIR="${BUILD_DIR:-builddir}"
PREFIX="${PREFIX:-$HOME/iputils-install}"

[ -z "${EXTRA_BUILD_OPTS:-}" ] && EXTRA_BUILD_OPTS="-DBUILD_HTML_MANS=true"
BUILD_OPTS="-Dprefix=$PREFIX $EXTRA_BUILD_OPTS"
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

configure_32()
{
	echo "=== configure_32 ==="

	local arch="$(uname -m)"
	local dir

	CFLAGS="-m32 $CFLAGS"

	if [ -z "${PKG_CONFIG_LIBDIR:-}" ]; then
		if [ "$arch" != "x86_64" ]; then
			echo "ERROR: auto-detection not supported platform $arch, export PKG_CONFIG_LIBDIR!"
			exit 1
		fi

		for dir in /usr/lib/i386-linux-gnu/pkgconfig \
			/usr/lib32/pkgconfig /usr/lib/pkgconfig; do
			if [ -d "$dir" ]; then
				PKG_CONFIG_LIBDIR="$dir"
				break
			fi
		done
		if [ -z "$PKG_CONFIG_LIBDIR" ]; then
			echo "WARNING: PKG_CONFIG_LIBDIR not found, build might fail"
		fi
		export PKG_CONFIG_LIBDIR
	fi
}

configure()
{
	if [ "${BUILD_32:-}" ]; then
		configure_32
	fi

	echo "=== configure ==="
	echo "Build options: $BUILD_OPTS"
	echo "CFLAGS: $CFLAGS"

	export CFLAGS

	meson setup $BUILD_DIR $BUILD_OPTS
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

dist()
{
	local formats="xztar,gztar,zip"
	local f

	echo "=== dist ($formats) ==="
	meson dist -C $BUILD_DIR --formats $formats

	for f in $(echo "$formats" | sed 's/,/ /g'); do
		f=$(echo "$f" | sed 's/\(.*\)tar/tar.\1/')
		f=$BUILD_DIR/meson-dist/iputils-20240117.$f
		ls -lah $f
		file $f | grep -E '(compressed|archive) data'
	done
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
case "${1:-}" in
	build|build-log|configure|dependencies|dist|info|install|install-log|test|test-log|"") cmd="${1:-}";;
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

if [ -z "$cmd" -o "$cmd" = "dist" ]; then
	dist
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
