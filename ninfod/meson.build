inc = include_directories('..')
ninfod_sources = files('''
	icmp6_nodeinfo.h
	ni_ifaddrs.c
	ni_ifaddrs.h
	ninfod.c
	ninfod.h
	ninfod_addrs.c
	ninfod_core.c
	ninfod_name.c
'''.split())
executable('ninfod', [ninfod_sources, git_version_h],
	dependencies : [cap_dep, crypto_dep, rt_dep, threads],
	include_directories : inc,
	install: true,
	install_dir: 'sbin')
conf_data = configuration_data()
conf_data.set('prefix', get_option('prefix'))
configure_file(input : 'ninfod.sh.in',
	output : 'ninfod.sh',
	configuration : conf_data,
	install : true,
	install_dir : join_paths(get_option('sysconfdir'), 'init.d'))
