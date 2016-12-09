#!/usr/bin/python
#
#    test-cpio.py quality assurance test script for PKG
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install cpio  && ./test-cpio.py -v'

    TODO:
     There are a lot more tests that should/could be done such as:
     - file sizes
     - permissions
     - ownership
     - various cpio options
'''

# QRT-Depends: testlib_archive.py
# QRT-Packages: cpio

import unittest
import testlib
import testlib_archive
import os
import time
import sys

class CpioTests(testlib_archive.ArchiveCommon):
    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_archive.ArchiveCommon._setUp(self)

        self.formats = [ 'bin', 'odc', 'newc', 'crc', 'hpbin', 'hpodc' ]

        # cpio 2.6 doesn't write tar and ustar correctly
        if self.lsb_release['Release'] >= 7.10:
            self.formats.append("tar")
            self.formats.append("ustar")

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)

    def test_out(self):
        '''Copy out'''
        # create the archives
        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir, '-depth', '-print'], \
                                            ["cpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # get the contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # verify the contents
        for f in self.formats:
            (rc, report) = testlib.cmd(["cpio", "--list", "--quiet", \
                                        "-I", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # verify all the files are present
            sorted_report = self.clean_trailing_slash(self.sort_output(report))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive." + f, \
                                                       sorted_report)
            self.assertEquals(find_report, sorted_report, result)

    def test_out_append(self):
        '''Copy out (append)'''
        # first create the base archives
        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir], \
                                            ["cpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
        time.sleep(1)

        # add the file to the hieracrchy
        added_file = os.path.join(self.archive_root, "added1")
        testlib.create_fill(added_file, "new content")

        # get the updated contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", \
                                             os.path.join(self.archive_dir, \
                                               os.path.basename(added_file))], \
                                            ["cpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f, '-A'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            (rc, report) = testlib.cmd(["cpio", "--list", "--quiet", \
                                        "-I", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # verify all the files are present
            sorted_report = self.clean_trailing_slash(self.sort_output(report))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive." + f, \
                                                       sorted_report)
            self.assertEquals(find_report, sorted_report, result)

    def test_in(self):
        '''Copy in'''
        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create archives
        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir], \
                                            ["cpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # test the contents of the created archives
        for f in self.formats:
            testlib.recursive_rm(self.archive_dir)
            (rc, report) = testlib.cmd(["cpio", "-i", "-v", "-F", \
                                        "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            (rc, tmp) = testlib.cmd(["find", self.archive_dir])
            listing_report = self.clean_trailing_slash(self.sort_output(tmp))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive." + f, \
                                                       listing_report)
            self.assertEquals(find_report, listing_report, result)

    def test_pass(self):
        '''Copy pass'''
        destdir = "dest"
        os.mkdir(destdir)

        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # passthrough copy
        (rc, report) = testlib.cmd_pipe(["find", self.archive_dir], \
                                        ["cpio", "-p", "-v", "dest"])

        os.chdir(destdir)
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        listing_report = self.clean_trailing_slash(self.sort_output(tmp))
        result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                   destdir, listing_report)
        self.assertEquals(find_report, listing_report, result)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CpioTests))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

