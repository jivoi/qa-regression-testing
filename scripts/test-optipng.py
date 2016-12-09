#!/usr/bin/python
#
#    test-optipng.py quality assurance test script for optipng
#    Copyright (C) 2016 Canonical Ltd.
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
# QRT-Packages: optipng
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/optipng.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

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
    from private.qrt.optipng import PrivateOptipngTest
except ImportError:
    class PrivateOptipngTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class OptipngTest(testlib.TestlibCase, PrivateOptipngTest):
    '''Test optipng.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="optipng-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_optipng(self, image, expected=0):

        (rc, report) = testlib.cmd(["/usr/bin/optipng",
                                    "-dir", self.tempdir,
                                    image])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _check_mime(self, mimetype, image="well-formed.png"):

        output_file = os.path.join(self.tempdir, image)
        self.assertFileType(output_file, mimetype)

    def test_png(self):
        '''Test png'''

        self._run_optipng("./data/well-formed.png")
        self._check_mime("PNG image data, 92 x 84, 8-bit/color RGBA, non-interlaced")

    def test_gif(self):
        '''Test gif'''

        self._run_optipng("./data/well-formed.gif")
        self._check_mime("PNG image data, 92 x 84, 8-bit colormap, non-interlaced")

    def test_bmp(self):
        '''Test bmp'''

        self._run_optipng("./data/well-formed.bmp")
        self._check_mime("PNG image data, 92 x 84, 8-bit/color RGB, non-interlaced")

    def test_pnm(self):
        '''Test pnm'''

        self._run_optipng("./data/well-formed.pnm")
        self._check_mime("PNG image data, 92 x 84, 8-bit/color RGB, non-interlaced")


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
