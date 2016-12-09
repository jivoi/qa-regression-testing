#!/usr/bin/python
#
#    test-php7.0.py quality assurance test script
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
# QRT-Packages: php7.0-cli php7.0-sqlite3 php7.0-gd php7.0-xmlrpc libapache2-mod-php7.0 apache2 elinks php-pear php7.0-cgi php7.0-tidy php7.0-curl php7.0-enchant php7.0-json php7.0-mbstring php7.0-zip php7.0-soap php7.0-bz2
# QRT-Privilege: root

import subprocess
import sys

if __name__ == '__main__':
    prc = subprocess.Popen([ 'python', 'test-php.py', 'php7.0', '-v'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
