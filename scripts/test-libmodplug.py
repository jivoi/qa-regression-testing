#!/usr/bin/python
#
#    test-libmodplug.py quality assurance test script for libmodplug
#    Copyright (C) 2009-2011 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: vlc libmodplug-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_data.py private/qrt/libmodplug.py

'''
  This test script needs to be run in a VM.

  How to run:
    $ sudo apt-get -y install lsb-release vlc libmodplug-dev
    $ sudo ./test-libmodplug.py -v

'''

import unittest, sys
import testlib_data

use_private = True
try:
    from private.qrt.libmodplug import LibmodplugPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibmodplugTest(testlib_data.DataCommon):
    '''Test libmodplug.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['vlc']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_mod(self):
        '''Test mod files'''
        for exe in self.exes:
            self._cmd([exe], "mod", url=False)

    def test_abc(self):
        '''Test abc files'''
        for exe in self.exes:
            self._cmd([exe], "abc", url=False)

    def test_s3m(self):
        '''Test s3m files'''
        for exe in self.exes:
            self._cmd([exe], "s3m", url=False)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibmodplugTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibmodplugPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
