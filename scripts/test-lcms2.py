#!/usr/bin/python
#
#    test-lcms.py quality assurance test script for lcms
#    Copyright (C) 2008-2013 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Author: Jamie Strandboge <jamie@canonical.com>
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file liblcms-utils  && ./test-lcms.py -v'
'''

# QRT-Depends: data lcms private/qrt/lcms.py
# QRT-Packages: liblcms2-utils file

import unittest, sys, tempfile, os
import testlib

use_private = True
try:
    from private.qrt.lcms2 import LcmsPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LcmsTest(testlib.TestlibCase):
    '''Test lcms.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="lcms-")
        self.icmfile1 = "lcms/canon_eos400d/canon_eos400d_daylight.icc"
        self.icmfile2 = "lcms/canon_eos400d/canon_eos400d_lightcube.icc"

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_jpgicc(self):
        '''Test the jpgicc utility without profiles'''

        output = os.path.join(self.tempdir, 'output.jpg')
        (rc, report) = testlib.cmd(["/usr/bin/jpgicc", "./data/well-formed.jpg", output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the file-type to make sure it generated a valid image
        self.assertFileType(output, 'JPEG image data, JFIF standard 1.01', strict=False)

    def test_jpgicc_with_profiles(self):
        '''Test the jpgicc utility with profiles'''

        output = os.path.join(self.tempdir, 'output.jpg')
        (rc, report) = testlib.cmd(["/usr/bin/jpgicc", "-i", self.icmfile1,
                                        "-o", self.icmfile2, "./data/well-formed.jpg", output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the file-type to make sure it generated a valid image
        self.assertFileType(output, 'JPEG image data, JFIF standard 1.01', strict=False)

    def test_tificc(self):
        '''Test the tificc utility without profiles'''

        output = os.path.join(self.tempdir, 'output.tiff')
        (rc, report) = testlib.cmd(["/usr/bin/tificc", "./data/well-formed.tiff", output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the file-type to make sure it generated a valid image
        self.assertFileType(output, 'TIFF image data, little-endian', strict=False)

    def test_tificc_with_profiles(self):
        '''Test the tificc utility with profiles'''

        output = os.path.join(self.tempdir, 'output.tiff')
        (rc, report) = testlib.cmd(["/usr/bin/tificc", "-i", self.icmfile1,
                                        "-o", self.icmfile2, "./data/well-formed.tiff", output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the file-type to make sure it generated a valid image
        self.assertFileType(output, 'TIFF image data, little-endian', strict=False)

    def test_psicc_csa(self):
        '''Test the psicc utility csa output'''

        (rc, report) = testlib.cmd(["/usr/bin/psicc", "-i", self.icmfile1])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_output = 'CIEBasedABC'
        result = 'psicc returned:\n\n %s\n\nWe expected it to contain:\n\n%s\n' % (report.rstrip(), expected_output)
        self.assertTrue(expected_output in report, result + report)

    def test_psicc_crd(self):
        '''Test the psicc utility crd output'''

        (rc, report) = testlib.cmd(["/usr/bin/psicc", "-o", self.icmfile1])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_output = 'ColorRenderingType'
        result = 'psicc returned:\n\n %s\n\nWe expected it to contain:\n\n%s\n' % (report.rstrip(), expected_output)
        self.assertTrue(expected_output in report, result + report)

    def test_linkicc(self):
        '''Test the linkicc utility'''

        output_file = os.path.join(self.tempdir, 'output.icc')
        (rc, report) = testlib.cmd(["/usr/bin/linkicc", "-o", output_file, '*sRGB', self.icmfile1, self.icmfile2])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        if self.lsb_release['Release'] == 6.06:
            mime_type = 'Microsoft ICM Color Profile'
        elif self.lsb_release['Release'] < 14.04:
            mime_type = 'Kodak Color Management System, ICC Profile'
        else:
            mime_type = 'ColorSync ICC Profile'

        self.assertFileType(output_file, mime_type)

    def test_icc_convert(self):
        '''Convert color spaces without error'''

        (rc, report) = testlib.cmd(["/usr/bin/jpgicc", 'lcms/valid-icc.jpg', '/dev/null'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_icc_tags(self):
        '''Cleanly fails when reading invalid ICC tags (CVE-2007-2741)'''

        (rc, report) = testlib.cmd(["/usr/bin/jpgicc", 'lcms/invalid-icc.jpg', '/dev/null'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LcmsTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LcmsPrivateTests))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
