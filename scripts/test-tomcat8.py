#!/usr/bin/python
#
#    test-tomcat8.py quality assurance test script
#    Copyright (C) 2013-2016 Canonical Ltd.
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
# QRT-Packages: tomcat8 tomcat8-examples tomcat8-admin elinks lsb-release curl apache2 libapache2-mod-jk haveged
# QRT-Alternates: apache2:!precise apache2-mpm-worker:precise

# tomcat 8 startup need entropy, else it hangs, so we install haveged for
# testing.

import subprocess
import sys

if __name__ == '__main__':
    prc = subprocess.Popen([ 'python', 'test-tomcat.py', 'tomcat8', '-v'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
