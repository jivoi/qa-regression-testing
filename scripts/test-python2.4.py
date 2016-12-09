#!/usr/bin/python
#
#    test-python2.4.py quality assurance test script
#    script wrapper for usage under Checkbox
#    Copyright (C) 2010 Canonical Ltd.
#    Author: C de-Avillez <carlos.de.avillez@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

'''
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get install python2.4
'''

# QRT-Depends: test-python.py
# QRT-Packages: python2.4 netcat-openbsd w3m
# QRT-Deprecated: 10.04

import subprocess
import sys

if __name__ == '__main__':
    print 'python2.4 regression tests'
    prc = subprocess.Popen([ 'python', 'test-python.py', 'python2.4'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
