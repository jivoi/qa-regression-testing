#!/usr/bin/python
#
#    test-libxfont.py quality assurance test script for libxfont
#    Copyright (C) 2011 Canonical Ltd.
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
# QRT-Packages: xfonts-utils gzip
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: libxfont data

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-libxfont.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-libxfont.py -v'
'''


import unittest, sys, os, shutil, tempfile
import testlib

try:
    from private.qrt.libxfont import PrivateLibxfontTest
except ImportError:
    class PrivateLibxfontTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibxfontTest(testlib.TestlibCase, PrivateLibxfontTest):
    '''Test libxfont.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="qrt-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_mkfontdir(self):
        '''Runs mkfontdir on the temp directory'''
        (rc, report) = testlib.cmd(["/usr/bin/mkfontdir", self.tempdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _run_uncompress(self, filename):
        '''Runs uncompress on a file in the temp directory'''
        (rc, report) = testlib.cmd(["/bin/uncompress", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _run_bdftopcf(self, filename, expected=0):
        '''Runs bdftopcf on a file and puts it in the temp directory'''
        output_file = os.path.join(self.tempdir, 'output.pcf')
        (rc, report) = testlib.cmd(["/usr/bin/bdftopcf", "-o", output_file, filename])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _check_fonts_dir(self, search):
        '''Checks fonts.dir file for specific contents'''
        fonts_dir = os.path.join(self.tempdir, 'fonts.dir')
        self.assertTrue(os.path.exists(fonts_dir), "Could not find fonts.dir!")

        contents = open(fonts_dir).read()

        result = "Could not find '%s' in '%s'\n" % (search, contents)
        self.assertTrue(search in contents, result)

    def test_compressed_pcf(self):
        '''Test compressed pcf'''
        shutil.copy('./data/courR08.pcf.gz', self.tempdir)
        self._run_mkfontdir()
        self._check_fonts_dir('-adobe-courier-medium-r-normal--8-80-75-75-m-50-iso10646-1')

    def test_compressed_bdf_a(self):
        '''Test compressed bdf - manual uncompress'''
        shutil.copy('./data/courR08.bdf.Z', self.tempdir)
        self._run_uncompress('courR08.bdf.Z')
        self._run_mkfontdir()
        self._check_fonts_dir('-adobe-courier-medium-r-normal--8-80-75-75-m-50-iso10646-1')

    def test_compressed_bdf_b(self):
        '''Test compressed bdf - converted to pcf'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("Hardy's bdftopcf doesn't support compressed fonts")

        self._run_bdftopcf('./data/courR08.bdf.Z')
        self._run_mkfontdir()
        self._check_fonts_dir('-adobe-courier-medium-r-normal--8-80-75-75-m-50-iso10646-1')

    def test_cve_2011_2895(self):
        '''Test CVE-2011-2895'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("Hardy's bdftopcf doesn't support compressed fonts")

        self._run_bdftopcf('./libxfont/foo.bdf.Z', expected=1)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
