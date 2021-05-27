inc = include_directories('..')

ping = executable('ping', [
		'ping.c',
		'ping_common.c',
		'ping6_common.c',
		'node_info.c',
		git_version_h
	],
	include_directories : inc,
	dependencies : [
		cap_dep,
		idn_dep,
		intl_dep,
		m_dep,
		resolv_dep
	],
	link_with : [libcommon],
	install: true)

if (setcap_ping)
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		bindir,
		'ping',
		perm_type,
		setcap_path
	)
endif

##### TESTS #####

# TODO: ::1 generates DEPRECATION: ":" is not allowed in test name "ping -c1 ::1", it has been replaced with "_"
foreach dst : [ 'localhost', '127.0.0.1', '::1' ]
  foreach switch : [ '', '-4', '-6']
	args = [ '-c1', dst ]
	should_fail = false

	if switch != ''
	  args = [switch] + args
	  if (switch == '-4' and dst == '::1') or \
		 (switch == '-6' and dst == '127.0.0.1')
		 should_fail = true
	  endif
	endif

	name = 'ping ' + ' '.join(args)
	test(name, ping, args : args, should_fail : should_fail)
  endforeach
endforeach

ping_tests_opt = [
  [ '-c1'],
  [ '-c5', '-i0.1'],
  [ '-c1', '-I', 'lo'],
  ['-c 1', '-w1'],
  ['-c 1', '-W1'],
  ['-c 1', '-W1.1'],
]
foreach dst : [ '127.0.0.1', '::1' ]
  foreach args : ping_tests_opt
	args += [ dst ]
	name = 'ping ' + ' '.join(args)
	test(name, ping, args : args)
  endforeach
endforeach

ping_tests_opt_fail = [
  [ '-c1.1'],
  [ '-i0,1'],
  [ '-I', 'nonexisting'],
  ['-w0.1'],
  ['-w0,1'],
]
foreach dst : [ '127.0.0.1', '::1' ]
  foreach args : ping_tests_opt_fail
	args += [ dst ]
	name = 'ping ' + ' '.join(args)
	test(name, ping, args : args, should_fail : true)
  endforeach
endforeach
