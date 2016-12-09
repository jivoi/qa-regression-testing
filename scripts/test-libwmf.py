#!/usr/bin/python
#
#    test-libwmf.py quality assurance test script for libwmf
#    Copyright (C) 2009-2015 Canonical Ltd.
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file libwmf-bin  && ./test-libwmf.py -v'
'''

# QRT-Depends: data private/qrt/libwmf.py
# QRT-Packages: file libwmf-bin

import unittest, sys, tempfile, os, shutil
import testlib

use_private = True
try:
    from private.qrt.libwmf import LibwmfPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibwmfTest(testlib.TestlibCase):
    '''Test libwmf.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libwmf-")
        self.current_dir = os.getcwd()
        # copy the well-formed file to the tempdir as some of the
        # libwmf tools seem to write temp files to the directory where
        # the input file resides
        shutil.copy("./data/2doorvan.wmf", self.tempdir)
        os.chdir(self.tempdir)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        os.chdir(self.current_dir)

    def _check_mime_type(self, filename, mimetype):
        '''Checks the mime type of the file specified'''

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", filename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'Mime type from file: "%s", expected: "%s"\n' % (report, mimetype)
        self.assertEquals(report.rstrip(), mimetype, result)

    def test_conversions(self):
        '''Test conversion utilities'''

        eps_mimetype = 'PostScript document text conforming DSC level 2.0, type EPS'
        fig_mimetype = 'FIG image text, version 3.2,'
        png_mimetype = 'PNG image data, 238 x 86, 8-bit/color RGBA, non-interlaced'
        svg_mimetype = 'SVG Scalable Vector Graphics image'

        if self.lsb_release['Release'] >= 14.10:
            fig_mimetype = 'FIG image text, version 3.2, ASCII text'

        conversions = ( ('wmf2eps', 'eps', eps_mimetype),
                        ('wmf2fig', 'eps', fig_mimetype),
                        ('wmf2gd',  'png', png_mimetype),
                        ('wmf2svg', 'svg', svg_mimetype) )

        for command, outfiletype, outmimetype in conversions:

            outfile = os.path.join(self.tempdir, command + outfiletype)
            (rc, report) = testlib.cmd(["/usr/bin/" + command, "-o", outfile, "2doorvan.wmf"])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid image
            self._check_mime_type(outfile, outmimetype)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibwmfTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibwmfPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
