#!/usr/bin/python
#
#    test-libreoffice.py quality assurance test script for LibreOffice
#    Copyright (C) 2008-2016 Canonical Ltd.
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
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install libreoffice
    2. ./test-libreoffice.py -v (as non-root)

  NOTES:
    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test.
'''

# QRT-Depends: testlib_data.py private/qrt/libreoffice.py
# QRT-Packages: libreoffice

import unittest, sys
import testlib_data

try:
    from private.qrt.libreoffice import PrivateLibreOfficeTest
except ImportError:
    class PrivateLibreOfficeTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TestFiles(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exe = 'libreoffice'

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def open_files(self, file_type, skip=[]):
        '''Open files of a given type'''
        self._cmd([self.exe], file_type, skip=skip)

    def test_bmp(self):
        '''Test BMP'''
        self.open_files("bmp")

    def test_emf(self):
        '''Test EMF'''
        self.open_files("emf")

    def test_gif(self):
        '''Test GIF'''
        self.open_files("gif")

    def test_jpg(self):
        '''Test JPG'''
        self.open_files("jpg")

    def test_png(self):
        '''Test PNG'''
        self.open_files("png")

    def test_tiff(self):
        '''Test TIFF'''
        self.open_files("tiff", skip=["well-formed-gray16.tiff"])

    def test_wmf(self):
        '''Test WMF'''
        self.open_files("wmf")

    def test_odp(self):
        '''Test ODP'''
        self.open_files("odp")

    def test_ods(self):
        '''Test ODS'''
        self.open_files("ods")

    def test_odt(self):
        '''Test ODT'''
        self.open_files("odt")

    def test_doc(self):
        '''Test DOC'''
        self.open_files("doc")

    def test_rtf(self):
        '''Test RTF'''
        self.open_files("rtf")

    def test_xls(self):
        '''Test XLS'''
        self.open_files("xls")

    def test_ppt(self):
        '''Test PPT'''
        self.open_files("ppt")


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFiles))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PrivateLibreOfficeTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
