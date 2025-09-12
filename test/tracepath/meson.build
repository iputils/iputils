# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2021-2025 Petr Vorel <pvorel@suse.cz>

message('Build directory is: ' + meson.current_build_dir())

foreach t : ['tracepath-01-basic.t']
  test(t, find_program(t), args: tracepath)
endforeach
