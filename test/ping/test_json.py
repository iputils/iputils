#!/usr/bin/python3
"""
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2024-2025 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
"""

from json import loads
from os import getenv
from subprocess import Popen, PIPE
from sys import argv, exit, stderr

if getenv('VARIANT') == 'cross-compile':
  exit(77)

count = 2

if len(argv) > 1:
  ping = argv[1]
else:
  ping = 'builddir/ping/ping'

for arguments in [
  ['-4', 'localhost'],
  ['::1'],
  ['-V'],
  ['-s5000', '-Mdo', 'opensuse.org'],
  # flood statistics
  ['-s50000', '-c50', '-6', '-A', '-n', 'ip.opensuse.org'],
]:
  command = [ping, '-jc', str(count)] + arguments
  print(command)
  for i, line in enumerate(Popen(command, stdout=PIPE).stdout, 1):
    print(line)
    data = loads(line)
    print(data)

    assert isinstance(data, dict), 'data type does not match'

    if arguments[0] == '-V':
      assert 'version' in data, f'Missing "version"'
      continue

    if 'bytes' in data:
      if arguments[0][1] != 's':
        assert data.get('bytes') == 64, f'"bytes" does not match, expected 64'
      assert data.get('seq') == i, f'"seq" does not match, expected {i}'
    elif 'rtt' in data:
      if len(arguments) > 1 and arguments[1][2:4] == '50':
        count = 50
      assert data.get('transmitted') == count, f'"transmitted" does not match, expected {count}'
      for a in ['min', 'avg', 'max', 'mdev']:
        assert a in data['rtt'], f'Missing "{a}" in "rtt"'
      assert len(data['rtt'].keys()) == 4
    elif 'pipe' in data:
      assert isinstance(data.get('pipe'), int)
    elif 'ipg' in data:
      assert data.get('ipg')
      assert data.get('ewma')
    elif 'error' in data:
      errdata = data['error']
      assert isinstance(errdata, list)
      if arguments[1] == '-Mdo':
        assert errdata[0] == 'sendmsg'
        # in Alpine, it is "Message too large"
        assert errdata[1] in ['Message too long', 'Message too large']
    else:
      print('Excess data! Missing test coverage or stray output?', file=stderr)
      exit(1)
