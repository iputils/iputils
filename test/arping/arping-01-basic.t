#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Petr Vorel <pvorel@suse.cz>

use Test::Command tests => 6;
use Test::More;

my $lib = File::Basename::dirname(Cwd::abs_path($0)) . '/../lib.pl';
require "$lib";

my $arping = get_cmd($ARGV[0] // 'arping');

# -V
{
    my $cmd = Test::Command->new(cmd => "$arping -V");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/^arping from iputils /, 'Print version');
		$cmd->stdout_like(qr/libcap: (yes|no), IDN: (yes|no), NLS: (yes|no), error.h: (yes|no), getrandom\(\): (yes|no), __fpending\(\): (yes|no)$/, 'Print config');
	}
}

SKIP: {
	my $strace = `command -v strace 2>/dev/null`;
	chomp $strace;
	skip 'strace and root privileges are required for sendto fault injection', 4
		unless $strace && $> == 0;

	for my $case ([1, '-c 1'], [2, '-c 3 -w 3 -i 1']) {
		my ($when, $args) = @$case;
		my $cmd = Test::Command->new(
			cmd => "$strace -qq -e inject=sendto:error=EPERM:when=$when -o /dev/null $arping -I lo $args 192.0.2.1"
		);
		$cmd->exit_is_num(1);
		subtest "sendto failure on packet $when" => sub {
			$cmd->stderr_like(qr/sendto: Operation not permitted/,
				"Report injected sendto failure for packet $when");
		};
	}
}
