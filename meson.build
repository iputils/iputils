project('iputils', 'c',
	version : '20170717') # version hardcoded

global_cflags = ['-D_GNU_SOURCE', '-O3', '-g', '-fno-strict-aliasing', '-Wstrict-prototypes', '-Wall']
add_project_arguments(global_cflags, language: 'c')

message('meson build is EXPERIMENTAL, please DO NOT USE for production!\n')

cc = meson.get_compiler('c')
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

opt = get_option('USE_IDN')
if opt == '1'
	idn_dep = cc.find_library('idn')
	add_project_arguments('-DUSE_IDN', language : 'c')
elif opt == '2'
	idn_dep = cc.find_library('idn2', required : false)
	message('libidn2 is unsupported at this moment.\n')
	idn_dep = []
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

ping_src = ['ping.c', 'ping_common.c', 'ping6_common.c']
p = executable('ping', ping_src,
	dependencies : [m_dep, cap_dep, idn_dep, crypto_dep, resolv_dep])

executable('tracepath', 'tracepath.c',
	dependencies : idn_dep)

executable('traceroute6', 'traceroute6.c',
	dependencies : [cap_dep, idn_dep])

executable('clockdiff', 'clockdiff.c',
	dependencies : [cap_dep])

executable('rdisc', 'rdisc.c')

executable('arping', 'arping.c',
	dependencies : [rt_dep, cap_dep, idn_dep])

executable('tftpd', ['tftpd.c', 'tftpsubs.c'])

executable('rarpd', 'rarpd.c')

#test('ping to 127.0.0.1', p, args : ['-p 1', '127.0.0.1'])
