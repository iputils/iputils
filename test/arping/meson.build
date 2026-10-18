# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2021-2025 Petr Vorel <pvorel@suse.cz>

message('Build directory is: ' + meson.current_build_dir())

arping_tests = ['arping-01-basic.t']
if conf.has('HAVE_IFLA_ALT_IFNAME')
  arping_tests += ['arping-02-altname.t']
endif

foreach t : arping_tests
  test(t, find_program(t), args: arping)
endforeach
