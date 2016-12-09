#!/usr/bin/python
#
#    test-jbigkit.py quality assurance test script for jbigkit
#    Copyright (C) 2014 Canonical Ltd.
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
# QRT-Packages: jbigkit-bin file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''


import os
import subprocess
import sys
import unittest
import testlib
import tempfile

try:
    from private.qrt.jbigkit import PrivateJbigkitTest
except ImportError:
    class PrivateJbigkitTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class JbigkitTest(testlib.TestlibCase, PrivateJbigkitTest):
    '''Test jbigkit.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="jbigkit-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_pbmtojbg(self):
        '''Test pbmtojbg'''

        input_file  = "./data/well-formed.pbm"
        output_file = os.path.join(self.tempdir, "output.jbg")
        output_mime = 'MS Windows icon resource'

        (rc, report) = testlib.cmd(["/usr/bin/pbmtojbg",
                                    input_file,
                                    output_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        self.assertFileType(output_file, output_mime)

    def test_pbmtojbg85(self):
        '''Test pbmtojbg85'''

        input_file  = "./data/well-formed.pbm"
        output_file = os.path.join(self.tempdir, "output.jbg85")
        output_mime = 'MS Windows icon resource'


        (rc, report) = testlib.cmd(["/usr/bin/pbmtojbg85",
                                    input_file,
                                    output_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        self.assertFileType(output_file, output_mime)

    def test_jbgtopbm(self):
        '''Test jbgtopbm'''

        input_file  = "./data/well-formed.jbg"
        output_file = os.path.join(self.tempdir, "output.pbm")
        output_mime = 'Netpbm PBM "rawbits" image data'

        (rc, report) = testlib.cmd(["/usr/bin/jbgtopbm",
                                    input_file,
                                    output_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        self.assertFileType(output_file, output_mime)

    def test_jbgtopbm85(self):
        '''Test jbgtopbm85'''

        input_file  = "./data/well-formed.jbg85"
        output_file = os.path.join(self.tempdir, "output.pbm")
        output_mime = 'Netpbm PBM "rawbits" image data'

        (rc, report) = testlib.cmd(["/usr/bin/jbgtopbm85",
                                    input_file,
                                    output_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        self.assertFileType(output_file, output_mime)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
