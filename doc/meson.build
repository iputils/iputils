manpages = '''
	arping
	clockdiff
	ping
	rarpd
	tftpd
	tracepath
	traceroute6
'''.split()
custom_man_xsl = files('custom-man.xsl')

if build_rinfod == true
	manpages += ['rdisc']
endif

if build_ninfod == true
	manpages += ['ninfod']
endif

xsltproc = find_program('xsltproc', required : false)
if xsltproc.found()
	foreach man : manpages
		custom_target(man + '.8',
			output : man + '.8',
			input : man + '.xml',
			command : [
				xsltproc,
				'-o', '@OUTPUT@',
				'--nonet',
				'--stringparam', 'man.output.quietly', '1',
				'--stringparam', 'funcsynopsis.style', 'ansi',
				'--stringparam', 'man.th.extra1.suppress', '1',
				'--stringparam', 'iputils.version', meson.project_version(),
				custom_man_xsl,
				'@INPUT@',
			],
			install : true,
			install_dir : join_paths(get_option('mandir'), 'man8'),
		)
	endforeach
endif
