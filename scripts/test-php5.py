#!/usr/bin/python
#
#    test-php5.py quality assurance test script
#    Copyright (C) 2016 Canonical Ltd.
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

# QRT-Depends: test-php.py php testlib_httpd.py private/qrt/php.py data/c0419bt_.pfb data/exif-data.jpg
# QRT-Packages: php5-cli php5-sqlite php5-gd php5-xmlrpc libapache2-mod-php5 elinks php-pear php5-cgi php5-tidy php5-curl php5-enchant
# Only required on 13.10 and higher
# QRT-Alternates: php5-json apache2:!precise apache2-mpm-prefork:precise
# QRT-Privilege: root

import subprocess
import sys

if __name__ == '__main__':
    prc = subprocess.Popen([ 'python', 'test-php.py', 'php5', '-v'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
