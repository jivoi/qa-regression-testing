#!/usr/bin/python
#
#    test-rubygems.py quality assurance test script
#    script wrapper for usage under Checkbox
#    Copyright (C) 2012 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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


# QRT-Depends: private/qrt/ruby.py test-ruby.py
# QRT-Packages: rubygems
# QRT-Privilege: root

import subprocess
import sys
import testlib

if __name__ == '__main__':
    print 'rubygems regression tests'
    if testlib.manager.lsb_release["Release"] < 11.10:
        print >>sys.stderr, "rubygems does not exist in Ubuntu 11.10 and earlier"
        sys.exit(1)
    prc = subprocess.Popen([ 'python', 'test-ruby.py', 'rubygems'],
                    stdout=sys.stdout,
                    stderr=subprocess.STDOUT)
    prc.wait()
    sys.exit(prc.returncode)
