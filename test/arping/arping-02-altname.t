#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) Iputils Project, 2026

use IPC::Open3;
use Symbol qw(gensym);
use Test::More;

$ENV{LC_ALL} = 'C';
$ENV{LANG} = 'C';

my $arping = $ARGV[0] // 'arping';

if (system('unshare', '-Urn', 'true') != 0) {
    plan skip_all => 'unprivileged user and network namespaces are unavailable';
}

if (system('unshare', '-Urn', 'sh', '-c',
           'ip link set dev lo up && ip link property add dev lo altname iputils-test-alt') != 0) {
    plan skip_all => 'iproute2 or the kernel does not support interface altnames';
}

my $script = 'ip link set dev lo up && ip link property add dev lo altname iputils-test-alt && "$1" -I iputils-test-alt 127.0.0.1';
my $stderr = gensym;
my $pid = open3(my $stdin, my $stdout, $stderr,
                'unshare', '-Urn', 'sh', '-c', $script, 'sh', $arping);
close $stdin;

my $stdout_text = do { local $/; <$stdout> // '' };
my $stderr_text = do { local $/; <$stderr> // '' };
waitpid($pid, 0);
my $status = $? >> 8;

is($status, 2, 'altname resolves to the loopback interface');
like($stdout_text . $stderr_text, qr/Interface "iputils-test-alt" is not ARPable/,
     'interface validation reports the resolved device');

done_testing();
