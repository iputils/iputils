project('iputils', 'c',
	default_options : [
		'c_std=c99',
		'warning_level=2',
	],
	version : '20170717') # version hardcoded

cc = meson.get_compiler('c')

conf = configuration_data()
conf.set_quoted('SNAPSHOT', meson.project_version())

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
	add_project_arguments('-DCAPABILITIES', language : 'c')
else
	cap_dep = []
endif

opt = get_option('ARPING_DEFAULT_DEVICE')
if opt != ''
	conf.set_quoted('DEFAULT_DEVICE', opt, description : 'arping default device.')
endif

opt = get_option('USE_PING6_RTHDR')
if opt == true
	conf.set('ENABLE_PING6_RTHDR', 1, description : 'If set enable ping6 source routing (deprecated by RFC5095).')
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
endif

build_rinfod = get_option('BUILD_RDISC')
build_mans = get_option('BUILD_MANS')

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

config_h = configure_file(
	output : 'SNAPSHOT.h',
	configuration : conf)

############################################################
executable('ping', ['ping.c', 'ping_common.c', 'ping6_common.c'],
	dependencies : [m_dep, cap_dep, idn_dep, crypto_dep, resolv_dep],
	install: true)

executable('tracepath', 'tracepath.c',
	dependencies : idn_dep,
	install: true)

executable('traceroute6', 'traceroute6.c',
	dependencies : [cap_dep, idn_dep],
	install: true)

executable('clockdiff', 'clockdiff.c',
	dependencies : [cap_dep],
	install: true)

if build_rinfod == true
	executable('rdisc', 'rdisc.c',
		install: true)
endif

executable('arping', 'arping.c',
	dependencies : [rt_dep, cap_dep, idn_dep],
	install: true)

executable('tftpd', ['tftpd.c', 'tftpsubs.c'],
	install: true)

executable('rarpd', 'rarpd.c',
	install: true)

if build_ninfod == true
	subdir ('ninfod')
endif

if build_mans == true
	subdir ('doc')
endif

############################################################
# FIXME: write tests
#test('ping to 127.0.0.1', p, args : ['-p 1', '127.0.0.1'])
