#!/usr/bin/python
#
#    test-okular.py quality assurance test script for okular
#    Copyright (C) 2008, 2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
  NOTES:
    Need to start kdeinit4 before running the testsuite.
    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test.

  GUTSY:
    - well-formed.tiff is discolored
'''

# QRT-Depends: testlib_data.py private/qrt/pdfs.py
# QRT-Packages: okular konqueror kdelibs-bin unrar p7zip|p7zip-full unzip texlive-extra-utils

import unittest, sys
import testlib
import testlib_data

try:
    from private.qrt.pdfs import PrivatePDFTests
except ImportError:
    class PrivatePDFTests(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class TestImages(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['okular']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_gif(self):
        '''Test GIF'''
        for exe in self.exes:
            self._cmd([exe], "gif", url=False)

    def test_jpg(self):
        '''Test JPG'''
        for exe in self.exes:
            self._cmd([exe], "jpg", url=False)

    def test_png(self):
        '''Test PNG'''
        for exe in self.exes:
            self._cmd([exe], "png", url=False)

    def test_tiff(self):
        '''Test TIFF'''
        for exe in self.exes:
            self._cmd([exe], "tif", url=False)
            self._cmd([exe], "tiff", url=False)

    def test_bmp(self):
        '''Test BMP'''
        for exe in self.exes:
            self._cmd([exe], "bmp", url=False)

    def test_pnm(self):
        '''Test PNM'''
        for exe in self.exes:
            self._cmd([exe], "pnm", url=False)

    def test_xpm(self):
        '''Test XPM'''
        for exe in self.exes:
            self._cmd([exe], "xpm", url=False)

    def test_eps(self):
        '''Test EPS'''
        for exe in self.exes:
            self._cmd([exe], "eps", url=False)


class TestDocuments(testlib_data.DataCommon, PrivatePDFTests):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['okular']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_pdf(self):
        '''Test PDF'''
        for exe in self.exes:
            self._cmd([exe], "pdf")

    def test_ps(self):
        '''Test PS'''
        for exe in self.exes:
            self._cmd([exe], "ps")

    #def test_djvu(self):
    #    '''Test DJVU'''
    #    for exe in self.exes:
    #        self._cmd([exe], "djvu")

    def test_dvi(self):
        '''Test DVI'''
        for exe in self.exes:
            self._cmd([exe], "dvi")

    def test_comicbook(self):
        '''Test Comic Book archives'''
        for exe in self.exes:
            #for ext in ['cbr', 'cbz', 'cb7', 'cbt']:
            for ext in ['cbr', 'cbz']:
                self._cmd([exe], ext)

    def test_gz(self):
        '''Test PDF (gzipped)'''
        if self.lsb_release['Release'] < 8.04:
            self._skipped("'gz' not supported")
            return

        for exe in self.exes:
            self._cmd([exe], "pdf.gz")

    def test_bz2(self):
        '''Test PDF (bzip2ed)'''
        if self.lsb_release['Release'] < 8.04:
            self._skipped("'bzip2' not supported")
            return

        for exe in self.exes:
            self._cmd([exe], "pdf.bz2")

    # these don't really work on any released version of Ubuntu
    #def test_odp(self):
    #    '''Test ODP'''
    #    for exe in self.exes:
    #        self._cmd([exe], "odp")

class TestDocumentsBrowser(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['konqueror']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_pdf(self):
        '''Test PDF from browser'''
        for exe in self.exes:
            self._cmd([exe], "pdf", limit=1)

    def test_ps(self):
        '''Test PS from browser'''
        for exe in self.exes:
            self._cmd([exe], "ps", limit=1)

    def test_djvu(self):
        '''Test DJVU from browser'''
        for exe in self.exes:
            self._cmd([exe], "djvu", limit=1)

if __name__ == '__main__':
    if not testlib.is_kdeinit_running():
        sys.exit(2)

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestImages))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDocuments))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDocumentsBrowser))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
