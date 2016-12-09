#!/usr/bin/python
#
#    test-jasper.py quality assurance test script for jasper
#    Copyright (C) 2009-2014 Canonical Ltd.
#    Author:  Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: libjasper-runtime file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_data.py data jasper private/qrt/jasper.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install lsb-release <QRT-Packages> && ./test-jasper.py -v'

'''

import unittest, sys, os
import testlib, testlib_data
import tempfile

use_private = True
try:
    from private.qrt.jasper import JasperPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class JasperTests(testlib.TestlibCase):
    '''Test jasper by converting files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="jasper-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_imginfo(self):
        '''Test the imginfo utility'''

        samples = ( ('pnm', 'pnm 3 92 84 8 23184'),
                    ('ras', 'ras 3 92 84 8 23184'),
                    ('jp2', 'jp2 3 92 84 8 23184'),
                    ('jpc', 'jpc 3 92 84 8 23184'),
                    ('jpg', 'jpg 3 80 72 8 17280') )

        for infiletype, filedescription in samples:
            (rc, report) = testlib.cmd(["/usr/bin/imginfo", "-f", "./data/well-formed." + infiletype])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'imginfo returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), filedescription)
            self.assertTrue(filedescription in report, result + report)

    def test_jasper(self):
        '''Test jasper utility'''

        jpg_filetype = 'JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 80x72, frames 3'
        jpc_filetype = 'JPEG 2000 codestream'
        jp2_filetype = 'JPEG 2000 Part 1 \(JP2\)'
        bmp_filetype = 'PC bitmap, Windows 3.x format, 92 x 84 x 24'
        pnm_filetype = 'Netpbm image data, size = 92 x 84, rawbits, pixmap'

        if self.lsb_release['Release'] == 12.04:
            jpg_filetype = 'JPEG image data, JFIF standard 1.01'
            jpc_filetype = 'JPEG-2000 Code Stream Bitmap data'
            jp2_filetype = 'JPEG 2000 image data'
            pnm_filetype = 'Netpbm PPM "rawbits" image data'
        elif self.lsb_release['Release'] == 14.04:
            jpg_filetype = 'JPEG image data, JFIF standard 1.01'
            pnm_filetype = 'Netpbm PPM "rawbits" image data, size = 92 x 84'
        elif self.lsb_release['Release'] == 15.10:
            pnm_filetype = 'Netpbm PPM "rawbits" image data, size = 92 x 84'

        conversions = ( ('pnm',
                         'jp2', jp2_filetype,
                          pnm_filetype ),

                        ('jpg',
                         'jp2', jp2_filetype,
                         jpg_filetype ),

                        ('jpg',
                         'jpc', jpc_filetype,
                         jpg_filetype ),

                        ('jpg',
                         'jp2', jp2_filetype,
                         jpg_filetype ),

                        ('ras',
                         'jp2', jp2_filetype,
                         'Sun raster image data, 92 x 84, 24-bit, no colormap' ),

                        ('jp2',
                         'bmp', bmp_filetype,
                         jp2_filetype ) )


        for infiletype, outfiletype, outmimetype, remimetype in conversions:

            outfilename = os.path.join(self.tempdir, infiletype + "-converted." + outfiletype)

            (rc, report) = testlib.cmd(["/usr/bin/jasper", "--input",
                                        "./data/well-formed." + infiletype,
                                        "--output-format", outfiletype,
                                        "--output", outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the file-type to make sure it generated a valid image
            self.assertFileType(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = os.path.join(self.tempdir, infiletype + "-reconverted." + infiletype)

            (rc, report) = testlib.cmd(["/usr/bin/jasper", "--input",
                                        outfilename,
                                        "--output-format", infiletype,
                                        "--output", refilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(refilename, remimetype)

class JasperViewerTests(testlib_data.DataCommon):
    '''Test jasper by displaying images'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_data(self):
        '''Test jiv with data files'''

        if self.lsb_release['Release'] <= 10.10:
            return self._skipped("jiv utility is broken on maverick and older")

        if self.lsb_release['Release'] == 14.04:
            return self._skipped("jiv utility didn't ship in trusty")

        testlib_data.DataCommon._setUp(self)
        print "\nNOTE: Press 'q' to exit"
        for types in 'pnm', 'ppm', 'jpg', 'jp2':
            self._cmd(['jiv'], types, url=False, skip=['kubuntu-leaflet.jpg'])

    def test_samples(self):
        '''Test jiv with sample files'''

        if self.lsb_release['Release'] <= 10.10:
            return self._skipped("jiv utility is broken on maverick and older")

        if self.lsb_release['Release'] == 14.04:
            return self._skipped("jiv utility didn't ship in trusty")

        testlib_data.DataCommon._setUp(self, dir='jasper')
        print "\nNOTE: Press 'q' to exit (may take a while)"
        self._cmd(['jiv'], 'pnm', url=False, dir='jasper')


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(JasperTests))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(JasperViewerTests))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(JasperPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

