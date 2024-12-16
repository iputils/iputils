#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Petr Vorel <pvorel@suse.cz>

use Test::Command tests => 2;
use Test::More;

my $lib = File::Basename::dirname(Cwd::abs_path($0)) . '/../lib.pl';
require "$lib";

my $clockdiff = get_cmd($ARGV[0] // 'clockdiff');

# -V
{
    my $cmd = Test::Command->new(cmd => "$clockdiff -V");
    $cmd->exit_is_num(0);
	subtest 'output' => sub {
		$cmd->stdout_like(qr/^clockdiff from iputils /, 'Print version');
		$cmd->stdout_like(qr/libcap: (yes|no), IDN: (yes|no), NLS: (yes|no), error.h: (yes|no), getrandom\(\): (yes|no), __fpending\(\): (yes|no)$/, 'Print config');
	}
}
