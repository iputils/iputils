# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) Iputils Project, 2017-2024

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

if build_tracepath == true
	manpages += ['tracepath']
endif

# Use the docs included in a dist tarball if available
if meson.version().version_compare('>=0.58.0')
	fs = import('fs')
	out_man_pages = []
	out_html_pages = []
	generated_docs_exist = true
	foreach page : manpages
		man_page_name = page.replace('.xml', '.8')
		html_page_name = page.replace('.xml', '.html')
		out_man_pages += man_page_name
		out_html_pages += html_page_name
		if not fs.exists(man_page_name) or not fs.exists(html_page_name)
			generated_docs_exist = false
		endif
	endforeach
	if generated_docs_exist
		install_man(out_man_pages)
	        install_data(out_html_pages, install_dir : join_paths(get_option('datadir'), meson.project_name()))
		subdir_done()
	endif
else
	warning('Will not attempt to use pre-generated man pages (meson <0.58.0)')
endif

xsltproc = find_program('xsltproc', required : build_mans or build_html_mans)
xsltproc_args = [
	'--nonet',
	'--stringparam', 'man.output.quietly', '1',
	'--stringparam', 'funcsynopsis.style', 'ansi',
	'--stringparam', 'man.th.extra1.suppress', '1',
	'--stringparam', 'iputils.version', meson.project_version(),
]

if xsltproc.found()
	doc_targets = []
	if build_mans
		doc_targets += ['manpages']
	endif
	if build_html_mans
		doc_targets += ['html']
	endif
	xsltproc_works = true
	foreach doc_target : doc_targets
		xsl = 'http://docbook.sourceforge.net/release/xsl-ns/current/' + doc_target + '/docbook.xsl'
		testrun = run_command([xsltproc, '--nonet', xsl])
		if testrun.returncode() != 0
			xsltproc_works = false
			message('WARNING: xsltproc: cannot process ' + xsl)
		endif
	endforeach
endif

if xsltproc_works == false
	message('Docs cannot be built: xsltproc does not work correctly')
	build_mans = false
	build_html_mans = false
endif

if build_mans
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

if build_html_mans
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
