#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Eduard Zateev <hackerowskiy@gmail.com>

use Test::Command tests => 2;
use Test::More;

my $lib = File::Basename::dirname(Cwd::abs_path($0)) . '/../lib.pl';
require "$lib";

my $ping = get_cmd($ARGV[0] // 'ping');

SKIP: {
	if ($> != 0) {
		skip 'source route test requires CAP_NET_RAW', 2;
	}

	my $cmd = Test::Command->new(cmd => "$ping -4 -c1 -w1 127.0.0.1 127.0.0.1");
	$cmd->stdout_like(qr/^PING 127\.0\.0\.1/m, 'Source route reaches ping setup');
	$cmd->stderr_is_eq('', 'Setting source route does not fail');
}
