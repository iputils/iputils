inc = include_directories('..')

executable('ping', [
		'ping.c',
		'ping_common.c',
		'ping6_common.c',
		'node_info.c',
		git_version_h
	],
	include_directories : inc,
	dependencies : [
		cap_dep,
		idn_dep,
		intl_dep,
		m_dep,
		resolv_dep
	],
	link_with : [libcommon],
	install: true)

if (setcap_ping)
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		bindir,
		'ping',
		perm_type,
		setcap_path
	)
endif
