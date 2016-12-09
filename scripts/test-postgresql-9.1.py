#!/usr/bin/python
#
#    test-postgresql-9.1.py quality assurance test script
#    Copyright (C) 2014 Canonical Ltd.
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

  How to run:
    $ sudo apt-get -y install gnupg2
'''

# QRT-Depends: test-postgresql.py
# QRT-Packages: sudo lsb-release postgresql-common libpq-dev procps language-pack-ru ssl-cert locales python-pygresql patch postgresql-9.1 postgresql-contrib-9.1 postgresql-plpython-9.1 postgresql-plperl-9.1 postgresql-pltcl-9.1 postgresql-server-dev-9.1 hunspell-en-us postgresql-plpython3-9.1 libecpg-dev
# QRT-Privilege: root

import subprocess
import sys

if __name__ == '__main__':
    prc = subprocess.Popen([ 'python', 'test-postgresql.py', '-v'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
