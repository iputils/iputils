#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Petr Vorel <pvorel@suse.cz>

use Test::Command tests => 6;
use Test::More;

my $lib = File::Basename::dirname(Cwd::abs_path($0)) . '/../lib.pl';
require "$lib";

my $ping = get_cmd($ARGV[0] // 'ping');

# no arg
{
	my $cmd = Test::Command->new(cmd => "$ping");
	$cmd->exit_is_num(2);
	subtest 'output' => sub {
		$cmd->stderr_is_eq("$ping: usage error: Destination address required\n");
	}
}

# -c1 -i0.001 127.0.0.1
{
	my $cmd = Test::Command->new(cmd => "$ping -c1 -i0.001 127.0.0.1");
	$cmd->exit_is_num($> == 0 ? 0 : 2);
	subtest 'output' => sub {
		if ($> == 0) {
			$cmd->stdout_like(qr/^PING 127\.0\.0\.1.*bytes of data\.$/m, 'Ping header');
			$cmd->stdout_like(qr/64 bytes from 127\.0\.0\.1: icmp_seq=1 ttl=\d+ time=\d+\.\d+ ms/m, 'Ping reply line');
			$cmd->stdout_like(qr/1 packets transmitted, 1 received, 0% packet loss/, 'Ping success summary');
			$cmd->stdout_like(qr{^PING 127\.0\.0\.1 \(127\.0\.0\.1\) 56\(84\) bytes of data\.
64 bytes from 127\.0\.0\.1: icmp_seq=1 ttl=\d+ time=\d\.\d{3} ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time \d+ms
rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$},
'Entire ping output matched exactly');
		} else {
			$cmd->stderr_like(qr/cannot flood/i);
			$cmd->stdout_like(qr/PING 127\.0\.0\.1/);
			$cmd->stderr_like(qr/use -i 0\.002/);
			$cmd->stderr_like(qr/.*ping: cannot flood, minimal interval for user must be >= 2 ms, use -i 0\.002 \(or higher\)/);
		}
	}
}

# -c1 -i0.001 ::1
SKIP: {
    if ($ENV{SKIP_IPV6}) {
        skip 'IPv6 tests', 2;
    }
	my $cmd = Test::Command->new(cmd => "$ping -c1 -i0.001 ::1", env => { LC_ALL => 'C', LANG   => 'C' });
	$cmd->exit_is_num($> == 0 ? 0 : 2);
	subtest 'output' => sub {
		if ($> == 0) {
			$cmd->stdout_like(qr/^PING ::1 \(::1\) 56 data bytes$/m, 'Ping header');
			$cmd->stdout_like(qr/64 bytes from ::1: icmp_seq=1 ttl=\d+ time=\d+\.\d+ ms/m, 'Ping reply line');
			$cmd->stdout_like(qr/1 packets transmitted, 1 received, 0% packet loss/, 'Ping success summary');
		$cmd->stdout_like(qr{^PING ::1 \(::1\) 56 data bytes
64 bytes from ::1: icmp_seq=1 ttl=\d+ time=\d\.\d{3} ms

--- ::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time \d+ms
rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$},
'Entire ping output matched exactly');
		} else {
			$cmd->stderr_like(qr/cannot flood/i);
			$cmd->stdout_like(qr/PING ::1/);
			$cmd->stderr_like(qr/use -i 0\.002/);
			$cmd->stderr_like(qr/.*ping: cannot flood, minimal interval for user must be >= 2 ms, use -i 0\.002 \(or higher\)/);
		}
	}
}
