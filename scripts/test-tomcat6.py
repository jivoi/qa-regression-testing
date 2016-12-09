#!/usr/bin/python
#
#    test-tomcat6.py quality assurance test script
#    Copyright (C) 2013 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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

# QRT-Depends: test-tomcat.py tomcat testlib_httpd.py
# QRT-Packages: tomcat6 tomcat6-examples tomcat6-admin elinks lsb-release curl libapache2-mod-jk apache2-mpm-worker

import subprocess
import sys

if __name__ == '__main__':
    prc = subprocess.Popen([ 'python', 'test-tomcat.py', 'tomcat6', '-v'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
