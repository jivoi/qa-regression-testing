#!/usr/bin/python
#
#    test-ruby2.1.py quality assurance test script
#    script wrapper for usage under Checkbox
#    Copyright (C) 2011-2014 Canonical Ltd.
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
# QRT-Packages: dovecot-imapd dovecot-pop3d openssl ruby2.1 openbsd-inetd libwww-perl
# QRT-Privilege: root

import subprocess
import sys
import testlib

if __name__ == '__main__':
    print 'ruby 2.1 regression tests'
    if testlib.manager.lsb_release["Release"] < 14.10:
        print >>sys.stderr, "ruby2.1 does not exist in Ubuntu 14.04 and earlier"
        sys.exit(1)
    # bypass for bug 627142 -- apache2 init script hangs on 'stty sane'
    #subprocess.call(['sed', '-i', 's/^stty sane/#&/', '/etc/init.d/apache2'])
    prc = subprocess.Popen([ 'python', 'test-ruby.py', 'ruby2.1'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
