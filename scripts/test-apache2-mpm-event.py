#!/usr/bin/python
#
#    test-apache2-mpm-event.py quality assurance test script
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
    $ sudo apt-get remove --purge apache2-*
    $ sudo apt-get install apache2-mpm-event
    $ sudo apt-get -y install elinks ssl-cert openssl lsb-release libapache2-svn subversion davfs2 sudo python-pexpect
'''

# QRT-Depends: testlib_httpd.py testlib_ssl.py test-apache2.py
# QRT-Packages: libapache2-svn subversion elinks ssl-cert openssl lsb-release davfs2 python-pexpect openssl apache2-utils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: apache2:!precise apache2-mpm-event:precise
# QRT-Privilege: root
# QRT-Conflicts: apache2-mpm-itk apache2-mpm-prefork apache2-mpm-worker

import subprocess
import sys

if __name__ == '__main__':
    print 'apache-mpm-event regression tests'
    # bypass for bug 627142 -- apache2 init script hangs on 'stty sane'
    subprocess.call(['sed', '-i', 's/^stty sane/#&/', '/etc/init.d/apache2'])
    prc = subprocess.Popen([ 'python', './test-apache2.py'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
