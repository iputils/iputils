#!/usr/bin/perl -w
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2025 Petr Vorel <pvorel@suse.cz>

our @EXPORT_OK = qw(get_cmd);

sub init
{
	exit 77 if (defined($ENV{VARIANT}) && $ENV{VARIANT} eq 'cross-compile');

	$ENV{LC_ALL} = 'C';
	$ENV{LANG} = 'C';

	diag("Running as UID: $>");
}

sub get_cmd
{
	my $cmd = shift;

	init();

	diag("PATH = $ENV{PATH}");
	diag("passed cmd: $cmd");
	printf("# actually used cmd: ");
	system("/bin/sh", "-c", "command -v $cmd");

	return "$cmd";
}

1;
