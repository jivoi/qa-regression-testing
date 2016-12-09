#!/usr/bin/python
#
#    test-freetype.py quality assurance test script for freetype
#    Copyright (C) 2009-2013 Canonical Ltd.
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

'''
  This test script needs to be run in a VM.

  How to run:
    $ sudo apt-get -y install lsb-release freetype2-demos
    $ sudo ./test-freetype.py -v

  NOTE:
    - You must close the ftview window by hitting 'q' on the keyboard, or
      it will exit with error code 1.

'''

# QRT-Depends: testlib_data.py private/qrt/freetype.py
# QRT-Packages: freetype2-demos valgrind

import unittest, sys
import testlib_data

use_private = True
try:
    from private.qrt.freetype import FreetypePrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class FreetypeTest(testlib_data.DataCommon):
    '''Test freetype.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['ftview']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_ttf(self):
        '''Test TTF'''
        for exe in self.exes:
            self._cmd([exe, '20'], "ttf", url=False, expected_rc=0)

    def test_otf(self):
        '''Test OTF'''
        for exe in self.exes:
            self._cmd([exe, '20'], "otf", url=False, expected_rc=0)

    def test_pfb(self):
        '''Test PFB'''
        for exe in self.exes:
            self._cmd([exe, '20'], "pfb", url=False, expected_rc=0)

    def test_bdf(self):
        '''Test BDF'''
        for exe in self.exes:
            self._cmd([exe, '-r', '100', '12'], "bdf", url=False, expected_rc=0)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(FreetypeTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(FreetypePrivateTest))

    print "\n\nIMPORTANT: Hit 'q' key on keyboard to exit font viewer...\n\n"

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
