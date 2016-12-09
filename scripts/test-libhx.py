#!/usr/bin/python
#
#    test-libhx.py quality assurance test script for libhx
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: libhx-dev build-essential
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release libhx-dev build-essential && ./test-libhx.py -v'
'''


import unittest, sys, os, tempfile, shutil
import testlib

try:
    from private.qrt.libhx import PrivatelibhxTest
except ImportError:
    class PrivatelibhxTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class libhxTest(testlib.TestlibCase, PrivatelibhxTest):
    '''Test libhx.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libhx-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_CVE_2010_2947(self):
        '''Test CVE-2010-2947'''

        source_dist = './libhx/CVE-2010-2947.c'
        source = os.path.join(self.tempdir, "CVE-2010-2947.c")
        binary = os.path.join(self.tempdir, "CVE-2010-2947")
        shutil.copy(source_dist, source)

        rc, report = testlib.cmd(['gcc', '-o', binary, '-lHX', source])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
