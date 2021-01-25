inc = include_directories('..')

executable('tftpd', ['tftpd.c', 'tftpsubs.c', git_version_h],
	include_directories : inc,
	link_with : [libcommon],
	install: true,
	install_dir: sbindir)

subs = configuration_data()
subs.set('sbindir', sbindir)
subs.set('tftpdatadir', join_paths(prefix, get_option('localstatedir')))
unit_file = configure_file(
        input: 'xinetd.conf.in',
        output: 'tftp',
        configuration: subs
)
etcdir = join_paths(prefix, get_option('sysconfdir'))
xinetdir = join_paths(etcdir, 'xinetd.d')
install_data(unit_file, install_dir: xinetdir)
