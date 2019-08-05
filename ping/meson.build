inc = include_directories('..')

executable('ping', [
		'ping.c',
		'ping_common.c',
		'ping6_common.c',
		git_version_h
	],
	include_directories : inc,
	dependencies : [
		cap_dep,
		crypto_dep,
		idn_dep,
		intl_dep,
		m_dep,
		resolv_dep
	],
	link_with : [libcommon],
	install: true)

if (get_option('SETCAP_OR_SUID_PING') and not get_option('NO_SETCAP_OR_SUID'))
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		join_paths(get_option('prefix'), get_option('bindir')),
		'ping',
		perm_type,
		setcap_path
	)
endif
