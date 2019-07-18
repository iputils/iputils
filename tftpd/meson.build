inc = include_directories('..')

executable('tftpd', ['tftpd.c', 'tftpsubs.c', git_version_h],
	include_directories : inc,
	link_with : [libcommon],
	install: true)
