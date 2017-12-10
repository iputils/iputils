#!/bin/sh
autoreconf --force --install
ret=$?
if [ $ret -ne 0 ]; then
	echo "autoreconf: failed with return code: $ret"
	exit $ret
fi
echo 'The iputils build system is now prepared. To build, run:'
echo './configure && make'
exit 0
