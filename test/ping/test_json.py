#!/usr/bin/python3
"""
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2024 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
"""

from json import loads
from os import getenv
from subprocess import Popen, PIPE
from sys import argv, exit

if getenv('VARIANT') == 'cross-compile':
  exit(77)

count = 3

if len(argv) > 1:
  ping = argv[1]
else:
  ping = 'builddir/ping/ping'

for arguments in [
  ['-4', 'localhost'],
  ['::1'],
  ['-V'],
]:
  for i, line in enumerate(Popen([ping, '-jc', str(count)] + arguments, stdout=PIPE).stdout, 1):
    data = loads(line)
    print(data)

    assert isinstance(data, dict), 'data type does not match'

    if arguments[0] == '-V':
      assert 'version' in data, f'Missing "version"'

    if 'bytes' in data:
      assert data.get('bytes') == 64, f'"bytes" does not match, expected 64'
      assert data.get('seq') == i, f'"seq" does not match, expected {i}'
    elif 'rtt' in data:
      assert data.get('transmitted') == count, f'"transmitted" does not match, expected {count}'
      for a in ['min', 'avg', 'max', 'mdev']:
        assert a in data['rtt'], f'Missing "{a}" in "rtt"'
