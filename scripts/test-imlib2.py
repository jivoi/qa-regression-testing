#!/usr/bin/python
#
#    test-imlib2.py quality assurance test script for imlib2
#    Copyright (C) 2008 Canonical Ltd.
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

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install file libimlib2  && ./test-imlib2.py -v'

    TODO:
     - Test more than just image loading and saving
'''

# QRT-Depends: data imlib2

import unittest, os
import testlib
import tempfile

class Imlib2Tests(testlib.TestlibCase):
    '''Test imlib2 functionality.'''


    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="imlib2-")


    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)


    def test_convert(self):
        '''Test image loading, conversion and saving'''

        # no gif or xpm write support
        conversions = ( ('xpm',
                         'png', 'PNG image data, 92 x 84, 8-bit/color RGBA, non-interlaced'),

                        ('jpg',
                         'png', 'PNG image data, 80 x 72, 8-bit/color RGB, non-interlaced'),

                        ('bmp',
                         'png', 'PNG image data, 92 x 84, 8-bit/color RGB, non-interlaced'),

                        ('gif',
                         'png', 'PNG image data, 92 x 84, 8-bit/color RGBA, non-interlaced'),

                        ('pnm',
                         'png', 'PNG image data, 92 x 84, 8-bit/color RGB, non-interlaced'),

                        ('png',
                         'jpg', 'JPEG image data, JFIF standard 1.01'),

                        ('tiff',
                         'png', 'PNG image data, 92 x 84, 8-bit/color RGBA, non-interlaced') )


        for infiletype, outfiletype, outmimetype in conversions:
            outfilename = os.path.join(self.tempdir, infiletype + "-converted." + outfiletype)

            (rc, report) = testlib.cmd(["imlib2/imlib2_convert.sh",
                                        "./data/well-formed." + infiletype,
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid image
            self.assertFileType(outfilename, outmimetype)


    def test_cve_2008_5187(self):
        '''Test for CVE-2008-5187 segfault'''

        (rc, report) = testlib.cmd(["imlib2/imlib2_convert.sh", "imlib2/CVE-2008-5187.xpm",
                                                        os.path.join(self.tempdir, "CVE-2008-5187.png")])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
            

if __name__ == '__main__':
    unittest.main()

