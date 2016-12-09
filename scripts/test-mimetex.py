#!/usr/bin/python
#
#    test-mimetex.py quality assurance test script for mimetex
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
# packages required for test to run:
# QRT-Packages: mimetex
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release mimetex  && ./test-mimetex.py -v'
'''


import unittest, sys
import testlib

try:
    from private.qrt.mimetex import PrivateMimetexTest
except ImportError:
    class PrivateMimetexTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class MimetexTest(testlib.TestlibCase, PrivateMimetexTest):
    '''Test mimetex.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _run_mimetex(self, command, string):
        '''Run Mimetex and search in results'''
        (rc, report) = testlib.cmd(["/usr/bin/mimetex", command])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Search for string in report
        result = "Couldn't find string '%s' in result: \n" % string
        self.assertTrue(string in report, result + report)

    def test_cve_2009_1382_1(self):
        '''Test CVE-2009-1382 \picture'''
        # All the CVE-2009-1382 tests are from here:
        # http://scary.beasts.org/security/CESA-2009-009.html

        command = "\picture(12,34){(" + ("A" * 165) + "$10,10){testing}}"
        result = "................"
        self._run_mimetex(command, result)

    def test_cve_2009_1382_2(self):
        '''Test CVE-2009-1382 \circle'''

        command = "\circle(10;" + ("A" * 400) + ")"
        result = "........***....."
        self._run_mimetex(command, result)

    def test_cve_2009_1382_3(self):
        '''Test CVE-2009-1382 \input'''

        command = "\input[" + ("A" * 2000) + "]{mimetex.cgi}"
        result = "**.***......***....****.........**.***.....**"
        self._run_mimetex(command, result)

    def test_cve_2009_2459_1(self):
        '''Test CVE-2009-2459 \input'''

        command = "\input{doesntexist.txt}"
        result = "**.........**.***.....***...*****..*****.***....**...****..****....***.."
        self._run_mimetex(command, result)

    def test_cve_2009_2459_2(self):
        '''Test CVE-2009-2459 \counter'''

        command = "\counter"
        result = "*.........**.***.....***...*****..*****.***....**...****..****....***..."
        self._run_mimetex(command, result)


if __name__ == '__main__':
    # simple
    unittest.main()
