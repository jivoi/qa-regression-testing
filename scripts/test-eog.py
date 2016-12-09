#!/usr/bin/python
#
#    test-eog.py quality assurance test script for Xine
#    Copyright (C) 2008 Canonical Ltd.
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
    1. apt-get -y install eog
    2. ./test-eog.py -v (as non-root)

  NOTES:
    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test.
'''

# QRT-Depends: testlib_data.py

import unittest, sys
import testlib_data

class TestImages(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['eog']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_gif(self):
        '''Test GIF'''
        for exe in self.exes:
            self._cmd([exe], "gif")

    def test_jpg(self):
        '''Test JPG'''
        for exe in self.exes:
            self._cmd([exe], "jpg")

    def test_png(self):
        '''Test PNG'''
        for exe in self.exes:
            self._cmd([exe], "png")

    def test_tiff(self):
        '''Test TIFF'''
        for exe in self.exes:
            self._cmd([exe], "tiff")


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestImages))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
