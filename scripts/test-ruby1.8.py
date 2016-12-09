#!/usr/bin/python
#
#    test-ruby1.8.py quality assurance test script
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


# QRT-Depends: testlib_dovecot.py private/qrt/ruby.py test-ruby.py
# QRT-Packages: dovecot-imapd dovecot-pop3d openssl ruby1.8 libopenssl-ruby1.8 libhttpclient-ruby1.8 openbsd-inetd libwww-perl
# QRT-Privilege: root

import subprocess
import sys

if __name__ == '__main__':
    print 'ruby 1.8 regression tests'
    # bypass for bug 627142 -- apache2 init script hangs on 'stty sane'
    #subprocess.call(['sed', '-i', 's/^stty sane/#&/', '/etc/init.d/apache2'])
    prc = subprocess.Popen([ 'python', 'test-ruby.py', 'ruby1.8'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
