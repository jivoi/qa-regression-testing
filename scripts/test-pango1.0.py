#!/usr/bin/python
#
#    test-pango1.0.py quality assurance test script for pango1.0
#    Copyright (C) 2009 Canonical Ltd.
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
    $ sudo apt-get -y install lsb-release libpango1.0-dev
    $ sudo ./test-pango1.0.py -v


  NOTES:
  - test-arabic.txt has some missing glyphs
  - HELLO.txt has missing glyphs for Burmese
  - test-long-paragraph.txt does not render in kvm (all black/garbled)
  - test-tibetan.txt has almost all missing glyphs (need font?)
'''

# QRT-Depends: pango1.0 testlib_data.py
# QRT-Packages: libpango1.0-dev

import unittest, sys
import testlib_data

use_private = True
try:
    from private.qrt.pango10 import Pango10PrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class Pango10Test(testlib_data.DataCommon):
    '''Test pango1.0.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self, dir='./pango1.0')
        self.exes = ['pango-view']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_examples(self):
        '''Test example files'''
        for exe in self.exes:
            self._cmd([exe], "txt", url=False, expected_rc=1, dir='pango1.0')

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Pango10Test))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Pango10PrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
