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
	link_with : [libcommon],
	include_directories : inc,
	install: true,
	install_dir: get_option('sbindir'))
conf_data = configuration_data()
conf_data.set('prefix', get_option('prefix'))

if systemd.found()
	subs = configuration_data()
	subs.set('sbindir', join_paths(get_option('prefix'), get_option('sbindir')))
	unit_file = configure_file(
		input: '../systemd/ninfod.service.in',
		output: 'ninfod.service',
		configuration: subs
	)
	install_data(unit_file, install_dir: systemdunitdir)
else
	configure_file(input : 'ninfod.sh.in',
		output : 'ninfod.sh',
		configuration : conf_data,
		install : true,
		install_dir : join_paths(get_option('sysconfdir'), 'init.d'))
endif
