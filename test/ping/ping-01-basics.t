#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Petr Vorel <pvorel@suse.cz>

use Socket qw(AF_INET AF_INET6 AF_UNSPEC AI_CANONNAME IPPROTO_UDP SOCK_STREAM);
use Socket::GetAddrInfo qw(getaddrinfo);
use Test::Command tests => 11;
use Test::More;

my $lib = File::Basename::dirname(Cwd::abs_path($0)) . '/../lib.pl';
require "$lib";

my $ping = get_cmd($ARGV[0] // 'ping');

# Mock getaddrinfo() related code in ping/ping.c main() followed by logic in
# ping4_run() and ping6_run().
sub get_target
{
	my $target = shift;
	my $target_ai_family = shift // AF_UNSPEC;

	# ping/ping.c main(): getaddrinfo() to detect IPv4 vs. IPv6
	my $hints = {
		flags     => AI_CANONNAME,
		family    => $target_ai_family,
		socktype  => SOCK_STREAM,
	};

	die "invalid family: '$target_ai_family'" unless ($target_ai_family == AF_INET
		|| $target_ai_family == AF_INET6 || $target_ai_family == AF_UNSPEC);

	my ($err, @res) = getaddrinfo($target, undef, $hints);
	die "getaddrinfo error: $err\n" if $err;

	foreach my $ai (@res) {
		next if $target_ai_family != AF_UNSPEC && $target_ai_family != $ai->{family};

		# ping/ping.c ping6_run(): AF_INET6 does not perform getaddrinfo()
		return $target if ($ai->{family} == AF_INET6);

		# ping/ping6_common.c ping4_run(): AF_INET has extra getaddrinfo() to
		# get canonname.
		$hints = {
			ai_family   => AF_INET,
			ai_protocol => IPPROTO_UDP,

			# getaddrinfo_flags: USE_IDN=true adds AI_IDN | AI_CANONIDN, but
			# they aren't supported by musl (via Alpine):
			# Your vendor has not defined Socket macro AI_IDN and AI_CANONIDN, used at
			# builddir/meson-private/dist-unpack/iputils-20250605/test/ping/ping-01-basics.t line 43
			ai_flags    => AI_CANONNAME | AI_CANONIDN,
		};
		my ($err, @res) = getaddrinfo($target, undef, $hints);
		die "getaddrinfo error: $err\n" if $err;

		return defined($ai->{canonname}) ? $ai->{canonname} : $target;
	}
}

# -V
{
    my $cmd = Test::Command->new(cmd => "$ping -V");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/^ping from iputils /, 'Print version');
		$cmd->stdout_like(qr/libcap: (yes|no), IDN: (yes|no), NLS: (yes|no), error.h: (yes|no), getrandom\(\): (yes|no), __fpending\(\): (yes|no)$/, 'Print config');
	}
}

# 127.0.0.1
{
    my $cmd = Test::Command->new(cmd => "$ping -c1 127.0.0.1");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/64 bytes from 127\.0\.0\.1/, 'Ping received from 127.0.0.1');
		$cmd->stdout_like(qr/0% packet loss/, 'No packet loss');
		$cmd->stdout_like(qr/time=\d+\.\d+ ms/, 'Ping time present');
		$cmd->stdout_like(qr~rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$~,
			'RTT time present');
		$cmd->stdout_like(qr{^PING 127\.0\.0\.1 \(127\.0\.0\.1\) 56\(84\) bytes of data\.
64 bytes from 127\.0\.0\.1: icmp_seq=1 ttl=\d+ time=\d\.\d{3} ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time \d+ms
rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$},
'Entire ping output matched exactly');
	}
}

# ::1
SKIP: {
    if ($ENV{SKIP_IPV6}) {
        skip 'IPv6 tests', 2;
    }
    my $cmd = Test::Command->new(cmd => "$ping -c1 ::1");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/64 bytes from ::1/, 'Ping received from ::1');
		$cmd->stdout_like(qr/0% packet loss/, 'No packet loss');
		$cmd->stdout_like(qr/time=\d+\.\d+ ms/, 'Ping time present');
		$cmd->stdout_like(qr~rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$~,
			'RTT time present');
		$cmd->stdout_like(qr{^PING ::1 \(::1\) 56 data bytes
64 bytes from ::1: icmp_seq=1 ttl=\d+ time=\d\.\d{3} ms

--- ::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time \d+ms
rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$},
'Entire ping output matched exactly');
	}
}

my $localhost = "localhost";
my $localhost_target_ipv4 = get_target($localhost, AF_INET);
my $localhost_target_ipv6 = get_target($localhost, AF_INET6);
diag("localhost_cannon_ipv4: '$localhost_target_ipv4'");
diag("localhost_cannon_ipv6: '$localhost_target_ipv6'");
die "Undefined cannonical name for $localhost on IPv4" unless defined $localhost_target_ipv4;
die "Undefined cannonical name for $localhost on IPv6" unless defined $localhost_target_ipv6;

# localhost
{
    my $cmd = Test::Command->new(cmd => "$ping -c1 $localhost");
    $cmd->exit_is_num(0);
}

# -4 localhost
{
    my $cmd = Test::Command->new(cmd => "$ping -c1 -4 $localhost");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/64 bytes from $localhost_target_ipv4 \(127\.0\.0\.1\)/, "Ping received from $localhost (IPv4)");
		$cmd->stdout_like(qr/0% packet loss/, 'No packet loss');
		$cmd->stdout_like(qr/time=\d+\.\d+ ms/, 'Ping time present');
		$cmd->stdout_like(qr~rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$~,
			'RTT time present');
		$cmd->stdout_like(qr{^PING $localhost_target_ipv4 \(127\.0\.0\.1\) 56\(84\) bytes of data\.
64 bytes from $localhost_target_ipv4 \(127\.0\.0\.1\): icmp_seq=1 ttl=\d+ time=\d\.\d{3} ms

--- $localhost_target_ipv4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time \d+ms
rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$},
'Entire ping output matched exactly');
	}
}

# -6 localhost
SKIP: {
    if ($ENV{SKIP_IPV6}) {
        skip 'IPv6 tests', 2;
    }
    my $cmd = Test::Command->new(cmd => "$ping -c1 -6 $localhost");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/64 bytes from $localhost_target_ipv6 \(::1\)/, "Ping received from $localhost (IPv6)");
		$cmd->stdout_like(qr/0% packet loss/, 'No packet loss');
		$cmd->stdout_like(qr/time=\d+\.\d+ ms/, 'Ping time present');
		$cmd->stdout_like(qr~rtt min/avg/max/mdev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms$~,
			'RTT time present');
	}
}
