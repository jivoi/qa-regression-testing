#!/usr/bin/python
#
#    test-kdeutils.py quality assurance test script for kdeutils
#    Copyright (C) 2011 Canonical Ltd.
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

# QRT-Depends: testlib_data.py testlib_archive.py
# QRT-Packages: kdeutils

import unittest
import testlib
import testlib_archive
import testlib_data
import os
import sys

class ArkTests(testlib_data.DataCommon, testlib_archive.ArchiveCommon):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        testlib_archive.ArchiveCommon._setUp(self)
        os.chdir(self.fs_dir)

        testlib_data.DataCommon._setUp(self)
        self.exes = ['ark']

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

    def test_tar(self):
        '''Test tar archives'''
        archives = self.create_sample_tar_archives()

        for exe in self.exes:
            self._cmd([exe], "tar.gz")

            for a in archives:
                print >>sys.stdout, "%s ..." % (os.path.basename(a)),
                sys.stdout.flush()
                ext = a.split('.')[-1]
                rc, report = testlib.cmd([exe, "file://%s" % a])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

    def test_cpio(self):
        '''Test cpio archives'''
        formats = ['tar', 'ustar']
        if self.lsb_release['Release'] >= 11.10:
            formats += ['bin', 'crc', 'hpbin', 'hpodc']
        archives = self.create_sample_cpio_archives(formats)

        for exe in self.exes:
            for a in archives:
                print >>sys.stdout, "%s ..." % (os.path.basename(a)),
                sys.stdout.flush()
                ext = a.split('.')[-1]
                rc, report = testlib.cmd([exe, "file://%s" % a])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

    def test_gz(self):
        '''Test .gz'''
        for exe in self.exes:
            self._cmd([exe], "pdf.gz")

    def test_bz2(self):
        '''Test .bz2'''
        for exe in self.exes:
            self._cmd([exe], "pdf.bz2")


if __name__ == '__main__':
    if not testlib.is_kdeinit_running():
        sys.exit(2)

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ArkTests))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

