#!/usr/bin/python
#
#    test-mpfr.py quality assurance test script for mpfr
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
    How to run against a clean schroot named 'jaunty':
        schroot -c jaunty -u root -- sh -c 'apt-get -y install lsb-release lcalc  && ./test-mpfr.py -v'

    TODO:
    This currently just tests that the library works by running a simple
    program from universe that is linked to it.
'''

# QRT-Packages: lcalc

import unittest, sys
import testlib

use_private = True
try:
    from private.qrt.mpfr import MpfrPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class MpfrTest(testlib.TestlibCase):
    '''Test mpfr.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_lcalc(self):
        '''Test lcalc'''
        rc, report = testlib.cmd(['lcalc', '-z', '1000'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        output = '1419.422480946'

        result = "Couldn't find %s in report" % output
        self.assertTrue(output in report, result + report)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MpfrTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MpfrPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
