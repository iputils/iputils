#!/bin/sh
# Meson install script to setcap or setuid to an executable.

exec_path="$1/$2"
perm_type="$3"
setcap="$4"

if [ -n "$DESTDIR" ]; then
	exec_path="${DESTDIR%/}/${exec_path}"
fi

_log() {
	echo "$(basename $0): $1"
}

case "$perm_type" in
	caps)
		if [ "$2" = "rdisc" ]; then
			params="cap_net_raw,cap_net_admin+ep"
			_log "calling: $setcap $params $exec_path"
			"$setcap" $params "$exec_path"
		else
			params="cap_net_raw+p"
			_log "calling: $setcap $params $exec_path"
			"$setcap" $params "$exec_path"
		fi
	;;
	setuid)
		_log "changing '$exec_path' to be setuid root executable"
		chown -v root "$exec_path"
		chmod -v u+s "$exec_path"
	;;
	*)
		_log "unexpected argument: '$perm_type'"
		exit 1
	;;
esac

exit 0
