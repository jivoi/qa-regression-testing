#!/usr/bin/python
#
#    test-openexr.py quality assurance test script for PKG
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
# QRT-Packages: openexr
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/openexr.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release openexr  && ./test-openexr.py -v'
'''

import unittest, sys, tempfile, os
import testlib

use_private = True
try:
    from private.qrt.openexr import PrivateOpenEXRTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class OpenEXRTest(testlib.TestlibCase, PrivateOpenEXRTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="openexr-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _exrheader_check(self, filename):
        '''Checks if the file specified can be parsed with exrheader'''

        (rc, report) = testlib.cmd(["/usr/bin/exrheader", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        checks = ( 'file format version:', 'comments', 'compression' )

        for check in checks:
            result = "Couldn't find '%s' in report: %s\n" % (check, report)
            self.assertTrue(check in report, result)

    def test_exrmakepreview(self):
        '''Test exrmakepreview utility'''

        outfilename="test.exr"

        (rc, report) = testlib.cmd(["/usr/bin/exrmakepreview",
                                    "./data/GoldenGate.exr",
                                    os.path.join(self.tempdir, outfilename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's see if it generated a valid image
        self._exrheader_check(outfilename)


if __name__ == '__main__':
    unittest.main()

