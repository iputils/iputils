project('iputils', 'c',
	default_options : [
		'c_std=c99',
		'warning_level=2',
	],
	version : 's20161105') # keep in sync with: git describe | awk -F- '{print $1}'

cc = meson.get_compiler('c')

add_project_arguments(
	'-include', 'config.h',
	'-include', 'git-version.h',
	language : 'c'
)

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', meson.project_name())

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
rt_dep = cc.find_library('rt')

opt = get_option('USE_CAP')
if opt == true
	cap_dep = cc.find_library('cap')
	conf.set('HAVE_LIBCAP', 1,
		description : 'Defined if libcap exists.')
else
	cap_dep = []
endif

opt = get_option('ARPING_DEFAULT_DEVICE')
if opt != ''
	conf.set_quoted('DEFAULT_DEVICE', opt, description : 'arping default device.')
endif

opt = get_option('USE_SYSFS')
if opt == true
	conf.set('USE_SYSFS', 1, description : 'If set use /sys file system.')
endif

opt = get_option('USE_IDN')
if opt == true
	idn_dep = cc.find_library('idn2', required : false)
	add_project_arguments('-DUSE_IDN', language : 'c')
else
	idn_dep = []
endif

opt = get_option('USE_CRYPTO')
if opt == 'nettle'
	crypto_dep = dependency('nettle')
	add_project_arguments('-DUSE_NETTLE', language : 'c')
elif opt == 'gcrypt'
	crypto_dep = cc.find_library('gcrypt')
	add_project_arguments('-DUSE_GCRYPT', language : 'c')
elif opt == 'openssl'
	crypto_dep = dependency('openssl')
	add_project_arguments('-DUSE_OPENSSL', language : 'c')
elif opt == 'none'
	crypto_dep = []
	conf.set('PING6_NONCE_MEMORY', 1, description : 'If set RFC6744 random does not use any CRYPTO lib.')
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
	if cc.has_header('stdio.h') and cc.has_header('stdlib.h') and cc.has_header('stddef.h')
		conf.set('STDC_HEADERS', 1, description : 'Defined if we have standard c headers.')
	endif
	check_headers = [
		['HAVE_GCRYPT_H', 'gcrypt.h'],
		['HAVE_GNUTLS_OPENSSL_H', 'gnutls/openssl.h'],
		['HAVE_INTTYPES_H', 'inttypes.h'],
		['HAVE_LIMITS_H', 'limits.h'],
		['HAVE_LINUX_RTNETLINK_H', 'linux/rtnetlink.h'],
		['HAVE_MEMORY_H', 'memory.h'],
		['HAVE_NETDB_H', 'netdb.h'],
		['HAVE_NETINET_ICMP6_H', 'netinet/icmp6.h'],
		['HAVE_NETINET_IN_H', 'netinet/in.h'],
		['HAVE_NETINET_IP6_H', 'netinet/ip6.h'],
		['HAVE_OPENSSL_MD5_H', 'openssl/md5.h'],
		['HAVE_PTHREAD_H', 'pthread.h'],
		['HAVE_PWD_H', 'pwd.h'],
		['HAVE_STRINGS_H', 'strings.h'],
		['HAVE_STRING_H', 'string.h'],
		['HAVE_SYSLOG_H', 'syslog.h'],
		['HAVE_SYS_CAPABILITY_H', 'sys/capability.h'],
		['HAVE_SYS_TIME_H', 'sys/time.h'],
		['HAVE_SYS_TYPES_H', 'sys/types.h'],
		['HAVE_SYS_UIO_H', 'sys/uio.h'],
		['HAVE_SYS_UTSNAME_H', 'sys/utsname.h'],
		['HAVE_UNISTD_H', 'unistd.h'],
	]
	foreach p : check_headers
		h = p.get(1)
		if cc.has_header(h)
			conf.set(p.get(0), 1,
				description : 'Define if ' + h + ' can be included.')
		endif
	endforeach
	threads = dependency('threads')
	if threads.found()
		# FIXME: these are redundant, one should be removed.
		conf.set('ENABLE_THREADS', 1,
			description : 'Defined if libpthread is found.')
		conf.set('HAVE_LIBPTHREAD', 1,
			description : 'Defined if libpthread is found.')
	endif
endif

git_version_h = vcs_tag(
	input : 'git-version.h.meson',
	output : 'git-version.h'
)

config_h = configure_file(
	output : 'config.h',
	configuration : conf)

############################################################
if build_ping == true
	executable('ping', ['ping.c', 'ping_common.c', 'ping6_common.c', git_version_h],
		dependencies : [m_dep, cap_dep, idn_dep, crypto_dep, resolv_dep],
		install: true)
endif

if build_tracepath == true
	executable('tracepath', ['tracepath.c', git_version_h],
		dependencies : idn_dep,
		install: true)
endif

if build_traceroute6 == true
	executable('traceroute6', ['traceroute6.c', git_version_h],
		dependencies : [cap_dep, idn_dep],
		install: true)
endif

if build_clockdiff == true
	executable('clockdiff', ['clockdiff.c', git_version_h],
		dependencies : [cap_dep],
		install: true)
endif

if build_rinfod == true
	executable('rdisc', ['rdisc.c', git_version_h],
		install: true)
endif

if build_arping == true
	executable('arping', ['arping.c', git_version_h],
		dependencies : [rt_dep, cap_dep, idn_dep],
		install: true)
endif

if build_tftpd == true
	executable('tftpd', ['tftpd.c', 'tftpsubs.c', git_version_h],
		install: true)
endif

if build_rarpd == true
	executable('rarpd', ['rarpd.c', git_version_h],
		install: true)
endif

if build_ninfod == true
	if crypto_dep == []
		error('BUILD_NINFOD=true and USE_CRYPTO=none cannot be compiled')
	endif
	subdir ('ninfod')
endif

if build_mans == true or build_html_mans == true
	subdir ('doc')
endif

############################################################
# FIXME: write tests
#test('ping to 127.0.0.1', p, args : ['-p 1', '127.0.0.1'])
