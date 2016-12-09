#!/usr/bin/python
#
#    test-python-imaging.py quality assurance test script for python-imaging
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
# QRT-Packages: python-imaging
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: libjpeg-turbo-progs libjpeg-progs
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
import PIL
from PIL import Image

try:
    from private.qrt.pythonimaging import PrivatePythonImagingTest
except ImportError:
    class PrivatePythonImagingTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class PythonImagingTest(testlib.TestlibCase, PrivatePythonImagingTest):
    '''Test python-imaging.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="qrt-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_eps(self):
        '''Test loading an eps'''

        im = Image.open("./data/well-formed.eps")
        outfilename = os.path.join(self.tempdir, "test.jpg")
        im.save(outfilename, "JPEG")

        self.assertFileType(outfilename,
                            'JPEG image data, JFIF standard 1.01')

    def test_jpg(self):
        '''Test loading a jpg'''

        im = Image.open("./data/well-formed.jpg")
        outfilename = os.path.join(self.tempdir, "test.png")
        im.save(outfilename, "PNG")

        self.assertFileType(outfilename,
            r'PNG image( data)?, 80 x 72, 8-bit/color RGB, non-interlaced')

    def test_jpg_djpeg(self):
        '''Test loading a jpg with djpeg'''

        im = Image.open("./data/well-formed.jpg")
        im.load_djpeg()
        outfilename = os.path.join(self.tempdir, "test.png")
        im.save(outfilename, "PNG")

        self.assertFileType(outfilename,
            r'PNG image( data)?, 80 x 72, 8-bit/color RGB, non-interlaced')

    def test_iptc(self):
        '''Test loading a jpg with iptc info'''
        im = Image.open("./data/withiptc.iim")

        outfilename = os.path.join(self.tempdir, "test.png")
        im.save(outfilename, "PNG")

        self.assertFileType(outfilename,
            r'PNG image( data)?, 80 x 72, 8-bit/color RGB, non-interlaced')

        info = PIL.IptcImagePlugin.getiptcinfo(im)

        self.assertTrue(info[(2, 110)] == 'Marc Deslauriers')
        self.assertTrue(info[(2, 25)] == 'Vacation')


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
