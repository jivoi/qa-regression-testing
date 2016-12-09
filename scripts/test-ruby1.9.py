#!/usr/bin/python
#
#    test-ruby1.9.py quality assurance test script
#    script wrapper for usage under Checkbox
#    Copyright (C) 2010-2011 Canonical Ltd.
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
# QRT-Packages: dovecot-imapd dovecot-pop3d openssl ruby1.9 libopenssl-ruby1.9 libhttpclient-ruby1.9 openbsd-inetd libwww-perl
# QRT-Privilege: root
# QRT-Deprecated: 10.10

import subprocess
import sys
import testlib

if __name__ == '__main__':
    print 'ruby 1.9 regression tests'
    if testlib.manager.lsb_release["Release"] >= 10.10:
        print >>sys.stderr, "ruby1.9 does not exist in Ubuntu 10.10 and higher"
        sys.exit(1)

    # bypass for bug 627142 -- apache2 init script hangs on 'stty sane'
    #subprocess.call(['sed', '-i', 's/^stty sane/#&/', '/etc/init.d/apache2'])
    prc = subprocess.Popen([ 'python', 'test-ruby.py', 'ruby1.9'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
