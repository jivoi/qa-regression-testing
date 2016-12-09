#!/usr/bin/python
#
#    test-openjdk7.py quality assurance test script
#    Copyright (C) 2012-2014 Canonical Ltd.
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
'''

# QRT-Depends: testlib_data.py testlib_ssl.py testlib_browser.py test-openjdk.py
# QRT-Packages: eclipse openjdk-7-jdk openjdk-7-jre-zero icedtea-7-plugin chromium-browser firefox
# QRT-Alternates: netbeans

import subprocess
import sys

if __name__ == '__main__':
    print 'openjdk7 regression tests'
    prc = subprocess.Popen([ 'python', 'test-openjdk.py', '--jdk=openjdk-7'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
