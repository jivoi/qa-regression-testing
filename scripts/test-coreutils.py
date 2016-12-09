#!/usr/bin/python
#
#    test-coreutils.py quality assurance test script for coreutils tools
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Steve Beattie <steve.beattie@canonical.com>
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
  How to run in a VM:
    $ ./test-coreutils.py -v

  TODO:
    - test the other utils that aren't included here
    - perform more than run tests on a few tools
'''
# QRT-Packages: coreutils

import unittest
import testlib
import sys

class CoreutilsTest(testlib.TestlibCase):
    '''Test coreutils package functionality'''

    def test_true(self):
        '''Test true'''
        rc, report = testlib.cmd(['/bin/true'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_false(self):
        '''Test false'''
        rc, report = testlib.cmd(['/bin/false'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2014_9471(self):
        '''Test TZ= handling'''
        rc, report = testlib.cmd(['/bin/date', '--date=TZ="123"345" @1'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CoreutilsTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
