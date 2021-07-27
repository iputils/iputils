# Copyright (c) 2021 Petr Vorel <pvorel@suse.cz>
# TODO: ::1 generates DEPRECATION: ":" is not allowed in test name "ping -c1 ::1", it has been replaced with "_"

# GitHub CI does not have working IPv6
# https://github.com/actions/virtual-environments/issues/668
ipv6_dst = []
ipv6_switch = []
r = run_command('ip', '-6', 'a')
if r.stdout().strip().contains('::1')
  message('IPv6 enabled')
  ipv6_dst = [ '::1' ]
  ipv6_switch = [ '-6' ]
else
  message('WARNING: IPv6 disabled')
endif

run_as_root = false
r = run_command('id', '-u')
if r.stdout().strip().to_int() == 0
  message('running as root')
  run_as_root = true
else
  message('running as normal user')
endif

cmd = ping
cmd_name = 'ping '
args = ['-V']

name = 'ping ' + ' '.join(args)
test(name, ping, args : args)

foreach dst : [ 'localhost', '127.0.0.1' ] + ipv6_dst
  foreach switch : [ '', '-4' ] + ipv6_switch
	args = [ '-c1', dst ]
	should_fail = false

	if switch != ''
	  args = [switch] + args
	  if (switch == '-4' and dst == '::1') or (switch == '-6' and dst == '127.0.0.1')
		 should_fail = true
	  endif
	endif

	name = cmd_name + ' '.join(args)
	test(name, cmd, args : args, should_fail : should_fail)
  endforeach
endforeach

ping_tests_opt = [
  [ '-c1' ],
  [ '-c5', '-i0.1' ],
  [ '-c1', '-I', 'lo' ],
  [ '-c1', '-w1' ],
  [ '-c1', '-W1' ],
  [ '-c1', '-W1.1' ],
]
foreach dst : [ '127.0.0.1' ] + ipv6_dst
  foreach args : ping_tests_opt
	args += [ dst ]
	name = cmd_name + ' '.join(args)
	test(name, cmd, args : args)
  endforeach
endforeach

ping_tests_opt_fail = [
  [ '-c1.1' ],
  [ '-I', 'nonexisting' ],
  [ '-w0.1' ],
  [ '-w0,1' ],
]
foreach dst : [ '127.0.0.1' ] + ipv6_dst
  foreach args : ping_tests_opt_fail
	args += [ dst ]
	name = cmd_name + ' '.join(args)
	test(name, cmd, args : args, should_fail : true)
  endforeach
endforeach

ping_tests_user_fail = [
  [ '-c1', '-i0.001' ], # -c1 required to quit ping when running as root
]
foreach dst : [ '127.0.0.1' ] + ipv6_dst
  foreach args : ping_tests_user_fail
	args += [ dst ]
	name = cmd_name + ' '.join(args)
	test(name, cmd, args : args, should_fail : not run_as_root)
  endforeach
endforeach
