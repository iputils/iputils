manpages = []
custom_man_xsl = files('custom-man.xsl')
custom_html_xsl = files('custom-html.xsl')

if build_arping == true
	manpages += ['arping']
endif

if build_clockdiff == true
	manpages += ['clockdiff']
endif

if build_ping == true
	manpages += ['ping']
endif

if build_rarpd == true
	manpages += ['rarpd']
endif

if build_rinfod == true
	manpages += ['rdisc']
endif

if build_tftpd == true
	manpages += ['tftpd']
endif

if build_tracepath == true
	manpages += ['tracepath']
endif

if build_traceroute6 == true
	manpages += ['traceroute6']
endif

if build_ninfod == true
	manpages += ['ninfod']
endif

xsltproc = find_program('xsltproc', required : false)
xsltproc_args = [
	'--nonet',
	'--stringparam', 'man.output.quietly', '1',
	'--stringparam', 'funcsynopsis.style', 'ansi',
	'--stringparam', 'man.th.extra1.suppress', '1',
	'--stringparam', 'iputils.version', meson.project_version(),
]

if xsltproc.found()
	testrun = run_command([xsltproc, '--nonet',
		'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'])
	xsltproc_works = testrun.returncode() == 0
else
	warning('No docbook stylesheet found for generating man pages')
	xsltproc_works = false
endif

if build_mans and xsltproc_works
	foreach man : manpages
		custom_target(man + '.8',
			output : man + '.8',
			input : man + '.xml',
			command : [
				xsltproc,
				'-o', '@OUTPUT@',
				xsltproc_args,
				custom_man_xsl,
				'@INPUT@',
			],
			install : true,
			install_dir : join_paths(get_option('mandir'), 'man8'),
		)
	endforeach
endif

if build_html_mans and xsltproc_works
	foreach man : manpages
		custom_target(man + '.html',
			output : man + '.html',
			input : man + '.xml',
			command : [
				xsltproc,
				'-o', '@OUTPUT@',
				xsltproc_args,
				custom_html_xsl,
				'@INPUT@',
			],
			install : true,
			install_dir : join_paths(get_option('datadir'), meson.project_name()),
		)
	endforeach
endif
