#!/usr/bin/python
#
#    test-libgc.py quality assurance test script for libgc
#    Copyright (C) 2012 Canonical Ltd.
#    Author: Steve Beattie <steve.beattie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: libgc-dev build-essential
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/Pkg.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install libgc-dev build-essential && ./test-libgc.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''

import unittest, sys
import testlib

use_private = True
try:
    from private.qrt.mytest import MyPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibGCTest(testlib.TestlibCase):
    '''Test libgc .'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_00_build(self):
        '''Fake test to build binaries'''
        self.announce("%s" % (self.gcc_version))

        self.assertShellExitEquals(0, ["make", "clean", "-C", "libgc"])
        self.assertShellExitEquals(0, ["make", "-C", "libgc"])

    def test_cve_2012_2673_malloc1(self):
        '''Test malloc(-1), part of CVE-2012-2673'''

        expected = 0
        rc, out = testlib.cmd(['libgc/malloc-1'])
        self.assertEqual(rc, expected, "Failure running libgc/malloc-1\nexpected %d got %d\nError: %s\n" %(expected, rc, out))

    def test_cve_2012_2673_calloc_overflow(self):
        '''Test calloc(m * n) overflow, part of CVE-2012-2673'''

        expected = 0
        rc, out = testlib.cmd(['libgc/calloc-mult-overflow'])
        self.assertEqual(rc, expected, "Failure running libgc/calloc-mult-overflow\nexpected %d got %d\nError: %s\n" %(expected, rc, out))

if __name__ == '__main__':
    unittest.main()
