project('iputils', 'c',
	default_options : [
		'c_std=c99',
		'warning_level=3',
	],
	meson_version : '>=0.39',
	version : 's20190709') # keep in sync with: git describe | awk -F- '{print $1}'

cc = meson.get_compiler('c')

add_project_arguments(
	'-include', 'config.h',
	'-include', 'git-version.h',
	language : 'c'
)

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set('_GNU_SOURCE', 1, description : 'Enable GNU extensions on systems that have them.')

# Check functions.
foreach f : '''
	__fpending
	nanosleep
'''.split()
	if cc.has_function(f, args : '-D_GNU_SOURCE')
		conf.set('HAVE_' + f.to_upper(), 1,
			description : 'Define to 1 if you have the ' + f + ' function')
	endif
endforeach

if cc.compiles('''
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/icmp6.h>
	int main(void) {
		struct icmp6_nodeinfo nodeinfo;
		return 0;
	}
''', name : 'struct icmp6_nodeinfo')
	conf.set('HAVE_STRUCT_ICMP6_NODEINFO', 1,
		description : 'Defined if struct icmp6_nodeinfo exists.')
endif

if cc.compiles('''
	#include <sys/types.h>
	#include <sys/time.h>
	#include <time.h>
	int main(void) {
		struct tm time;
		return 0;
	}
''', name : 'struct tm time;')
	conf.set('TIME_WITH_SYS_TIME', 1,
		description : 'Defined if struct tm exists.')
endif

m_dep = cc.find_library('m')
resolv_dep = cc.find_library('resolv')
if cc.has_function('clock_gettime')
	rt_dep = cc.find_library('disabler-appears-to-disable-executable-build', required : false)
else
	rt_dep = cc.find_library('rt')
endif

opt = get_option('USE_CAP')
if opt == true
	cap_dep = cc.find_library('cap')
	conf.set('HAVE_LIBCAP', 1,
		description : 'Defined if libcap exists.')
else
	cap_dep = dependency('disabler-appears-to-disable-executable-build', required : false)
endif

opt = get_option('ARPING_DEFAULT_DEVICE')
if opt != ''
	conf.set_quoted('DEFAULT_DEVICE', opt, description : 'arping default device.')
endif

# Some systems needs intl for gettext
intl_dep = []
opt = get_option('USE_GETTEXT')
if opt == true
	prefix = get_option('prefix')
	localedir = get_option('localedir')
	add_project_arguments(['-DGETTEXT_PACKAGE="iputils"'], language: 'c')

	conf.set('ENABLE_NLS', 1, description : 'If set enable I18N.')
	conf.set_quoted('LOCALEDIR', join_paths(prefix, localedir))
	subdir ('po')
	intl_dep += cc.find_library('intl', required : false)
endif

opt = get_option('USE_IDN')
if opt == true
	idn_dep = cc.find_library('idn2', required : false)
	if idn_dep.found()
		add_project_arguments('-DUSE_IDN', language : 'c')
		conf.set('USE_IDN', 1,
			description : 'If set use Internationalized Domain Name library.')
	endif
else
	idn_dep = dependency('disabler-appears-to-disable-executable-build', required : false)
endif

crypto = get_option('USE_CRYPTO')
crypto_dep = []
if crypto == 'nettle'
	crypto_dep += dependency('nettle')
	conf.set('USE_NETTLE', 1, description : 'If set use nettle crypto library.')
elif crypto == 'gcrypt'
	crypto_dep += cc.find_library('gcrypt')
	crypto_dep += dependency('gpg-error', required : true)
	conf.set('USE_GCRYPT', 1, description : 'If set use gcrypt crypto library.')
elif crypto == 'openssl'
	crypto_dep += dependency('openssl')
	conf.set('USE_OPENSSL', 1, description : 'if set use openssl crypto library.')
elif crypto == 'kernel'
	crypto_dep += dependency('disabler-appears-to-disable-executable-build', required : false)
	conf.set('USE_KERNEL_CRYPTO_API', 1, description : 'if set use Linux kernel Crypto API.')
elif crypto == 'none'
	crypto_dep += dependency('disabler-appears-to-disable-executable-build', required : false)
	conf.set('PING6_NONCE_MEMORY', 1,
		description : 'If set RFC6744 random does not use any CRYPTO lib.')
endif

systemd = dependency('systemd', required : false)
systemdunitdir = get_option('systemdunitdir')
if systemdunitdir == '' and systemd.found()
	systemdunitdir = systemd.get_pkgconfig_variable('systemdsystemunitdir')
endif

build_arping = get_option('BUILD_ARPING')
build_clockdiff = get_option('BUILD_CLOCKDIFF')
build_ping = get_option('BUILD_PING')
build_rarpd = get_option('BUILD_RARPD')
build_rinfod = get_option('BUILD_RDISC')
build_tftpd = get_option('BUILD_TFTPD')
build_tracepath = get_option('BUILD_TRACEPATH')
build_traceroute6 = get_option('BUILD_TRACEROUTE6')

build_mans = get_option('BUILD_MANS')
build_html_mans = get_option('BUILD_HTML_MANS')

if build_rinfod == true
	opt = get_option('ENABLE_RDISC_SERVER')
	if opt == true
		conf.set('RDISC_SERVER', 1, description : 'If set build rdisc server.')
	endif
endif

build_ninfod = get_option('BUILD_NINFOD')
if build_ninfod == true
	if crypto == 'none'
		error('BUILD_NINFOD=true and USE_CRYPTO=none cannot be combined')
	endif
	if cc.has_header('stdio.h') and cc.has_header('stdlib.h') and cc.has_header('stddef.h')
		conf.set('STDC_HEADERS', 1, description : 'Defined if we have standard c headers.')
	endif
	foreach h : [
		'gcrypt.h',
		'gnutls/openssl.h',
		'inttypes.h',
		'limits.h',
		'linux/rtnetlink.h',
		'memory.h',
		'netdb.h',
		'netinet/icmp6.h',
		'netinet/in.h',
		'netinet/ip6.h',
		'openssl/md5.h',
		'pwd.h',
		'stdint.h',
		'stdlib.h',
		'string.h',
		'strings.h',
		'sys/capability.h',
		'syslog.h',
		'sys/time.h',
		'sys/types.h',
		'sys/uio.h',
		'sys/utsname.h',
		'unistd.h',
	]
		if cc.has_header(h)
			conf.set('HAVE_' + h.to_upper().underscorify(), 1,
				description : 'Define if ' + h + ' can be included.')
		endif
	endforeach
	if cc.has_header('stdio.h') and cc.has_header('stdlib.h') and cc.has_header('stddef.h') and cc.has_header('stdarg.h')
		conf.set('STDC_HEADERS', 1,
			description : 'Define to 1 if you have the ANSI C header files.')
	endif
	threads = dependency('threads')
	if threads.found()
		conf.set('ENABLE_THREADS', 1,
			description : 'Defined if libpthread is found.')
	endif
	if host_machine.endian() == 'big'
		conf.set('WORDS_BIGENDIAN', 1,
			description : 'Defined if processor stores words with the most significant byte first.')
	endif
	opt = get_option('NINFOD_MESSAGES')
	if opt == true
		conf.set('ENABLE_DEBUG', 1, description : 'Enable ninfod syslog messages.')
	endif
endif

foreach h : [
	'error.h',
]
	if cc.has_header(h)
		conf.set('HAVE_' + h.to_upper().underscorify(), 1,
			description : 'Define if ' + h + ' can be included.')
	endif
endforeach

git_version_h = vcs_tag(
	input : 'git-version.h.meson',
	output : 'git-version.h',
	fallback : meson.project_version()
)

config_h = configure_file(
	output : 'config.h',
	configuration : conf)

setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap', required : false)
if get_option('NO_SETCAP_OR_SUID')
	perm_type = 'none'
	setcap_path = '/dev/null'
elif cap_dep.found() and setcap.found()
	perm_type = 'caps'
	setcap_path = setcap.path()
else
	perm_type = 'setuid'
	setcap_path = '/dev/null'
endif

############################################################
common_sources = files('iputils_common.h', 'iputils_common.c')
libcommon = static_library(
	'common',
	[common_sources, git_version_h],
	install : false)

if build_ping == true
	executable('ping', ['ping.c', 'ping_common.c', 'ping6_common.c', git_version_h],
		dependencies : [m_dep, cap_dep, idn_dep, intl_dep, crypto_dep, resolv_dep],
		link_with : [libcommon],
		install: true)
	meson.add_install_script('build-aux/setcap-setuid.sh',
		join_paths(get_option('prefix'), get_option('bindir')),
		'ping',
		perm_type,
		setcap_path
	)
endif

if build_tracepath == true
	executable('tracepath', ['tracepath.c', git_version_h],
		dependencies : [idn_dep, intl_dep],
		link_with : [libcommon],
		install: true)
endif

if build_traceroute6 == true
	executable('traceroute6', ['traceroute6.c', git_version_h],
		dependencies : [cap_dep, intl_dep, idn_dep],
		link_with : [libcommon],
		install: true)
	meson.add_install_script('build-aux/setcap-setuid.sh',
		join_paths(get_option('prefix'), get_option('bindir')),
		'traceroute6',
		perm_type,
		setcap_path
	)
endif

if build_clockdiff == true
	executable('clockdiff', ['clockdiff.c', git_version_h],
		dependencies : [cap_dep, intl_dep],
		link_with : [libcommon],
		install: true)
	meson.add_install_script('build-aux/setcap-setuid.sh',
		join_paths(get_option('prefix'), get_option('bindir')),
		'clockdiff',
		perm_type,
		setcap_path
	)
endif

if build_rinfod == true
	executable('rdisc', ['rdisc.c', git_version_h],
		install_dir: get_option('sbindir'),
		link_with : [libcommon],
		install: true)
	if systemd.found()
		subs = configuration_data()
		subs.set('sbindir', join_paths(get_option('prefix'), get_option('sbindir')))
		unit_file = configure_file(
			input: 'systemd/rdisc.service.in',
			output: 'rdisc.service',
			configuration: subs
		)
		install_data(unit_file, install_dir: systemdunitdir)
	endif
endif

if build_arping == true
	executable('arping', ['arping.c', git_version_h],
		dependencies : [rt_dep, cap_dep, idn_dep, intl_dep],
		link_with : [libcommon],
		install: true)
	meson.add_install_script('build-aux/setcap-setuid.sh',
		join_paths(get_option('prefix'), get_option('bindir')),
		'arping',
		perm_type,
		setcap_path
	)
endif

if build_tftpd == true
	executable('tftpd', ['tftpd.c', 'tftpsubs.c', git_version_h],
		link_with : [libcommon],
		install: true)
endif

if build_rarpd == true
	executable('rarpd', ['rarpd.c', git_version_h],
		install_dir: get_option('sbindir'),
		link_with : [libcommon],
		install: true)
	if systemd.found()
		subs = configuration_data()
		subs.set('sbindir', join_paths(get_option('prefix'), get_option('sbindir')))
		unit_file = configure_file(
			input: 'systemd/rarpd.service.in',
			output: 'rarpd@.service',
			configuration: subs
		)
		install_data(unit_file, install_dir: systemdunitdir)
	endif
endif

if build_ninfod == true
	subdir ('ninfod')
endif

if build_mans == true or build_html_mans == true
	subdir ('doc')
endif

############################################################
# FIXME: write tests
#test('ping to 127.0.0.1', p, args : ['-p 1', '127.0.0.1'])
