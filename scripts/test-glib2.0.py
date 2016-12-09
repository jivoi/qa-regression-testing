#!/usr/bin/python
#
#    test-glib2.0.py quality assurance test script for glib2.0
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
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
# packages required for test to run:
# QRT-Packages: build-essential pkg-config libglib2.0-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/glib20.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install glib2.0  && ./test-glib2.0.py -v'
'''


import unittest, sys, os
import testlib

try:
    from private.qrt.glib20 import Privateglib20Test
except ImportError:
    class Privateglib20Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class glib20Test(testlib.TestlibCase, Privateglib20Test):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('glib2.0')
        self.make_clean()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.make_clean()
        os.chdir(self.fs_dir)

    def test_lp418135(self):
        '''Symlink copying does not destroy original file modes (CVE-2009-3289)'''

        if self.lsb_release['Release'] < 8.04:
            self._skipped("Dapper not affected")
            return

        self.make_target("symlink-copying")
        self.assertShellExitEquals(0, ["./symlink-copying"])

if __name__ == '__main__':
    # simple
    unittest.main()
