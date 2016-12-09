#!/usr/bin/python
#
#    test-tar.py quality assurance test script for PKG
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install tar bzip2 file gzip && ./test-tar.py -v'

    NOTES:
     tar has a test suite enabled in the build that checks a bunch of stuff, so
     we really only need to verify some basic operations to make sure tar
     installed ok
'''

# QRT-Depends: testlib_archive.py
# QRT-Packages: tar

import unittest
import testlib
import testlib_archive
import os
import sys

class TarTests(testlib_archive.ArchiveCommon):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        testlib_archive.ArchiveCommon._setUp(self)

        self.formats = [ 'tar', 'gz', 'bz2' ]

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

    def test_basic(self):
        '''Tar create'''
        # get the contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        for f in self.formats:
            # create the archives
            compress_flags = ""
            ext = ".tar"
            type = "POSIX tar"
            if f == "gz":
                compress_flags = "z"
                ext += ".gz"
                type = "gzip compressed"
            elif f == "bz2":
                compress_flags = "j"
                ext += ".bz2"
                type = "bzip2 compressed"

            (rc, report) = testlib.cmd(["tar", compress_flags + "cf", "archive" + ext, \
                                       self.archive_dir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # verify file type
            (rc, report) = testlib.cmd(["file","archive"+ext])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            report = report.split(': ')[1]
            self.assertTrue(report.startswith(type),"Expected '%s' got '%s'" % (type,report))

            # verify the contents
            (rc, report) = testlib.cmd(["tar", "tf", "archive" + ext])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            # Drop the tar record size debugging
            report = "\n".join([x for x in report.splitlines() if x != 'tar: Record size = 8 blocks'])+"\n"

            # verify all the files are present
            sorted_report = self.clean_trailing_slash(self.sort_output(report))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive" + ext, \
                                                       sorted_report)
            self.assertEquals(find_report, sorted_report, result)

    def test_append(self):
        '''Tar append'''
        archive = "archive.tar"
        new_file = "added1"

        # Record initial directory tree
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        self.assertEquals(rc, 0, tmp)
        first_find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # Create the base archive
        (rc, report) = testlib.cmd(["tar", "cf", archive, self.archive_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # add the file to the hieracrchy
        added_file = os.path.join(self.archive_root, new_file)
        testlib.create_fill(added_file, "new content")

        # Record updated directory tree
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        self.assertEquals(rc, 0, tmp)
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # Directory trees should be different
        self.assertNotEquals(first_find_report,find_report)

        # Update tar
        (rc, report) = testlib.cmd(["tar", "uf", archive, \
                                    os.path.join(self.archive_dir, new_file)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Record tar contents
        (rc, report) = testlib.cmd(["tar", "tf", archive])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        # Drop the tar record size debugging
        report = "\n".join([x for x in report.splitlines() if x != 'tar: Record size = 8 blocks'])+"\n"
        sorted_report = self.clean_trailing_slash(self.sort_output(report))

        # Verify new tar does not match old find
        result = 'Find has:%s\n\n%s has:%s\n' % (first_find_report, \
                                                   archive, \
                                                   sorted_report)
        self.assertNotEquals(first_find_report, sorted_report, result)

        # Verify new tar does match the new find
        result = 'Find has:%s\n\n%s has:%s\n' % (find_report, \
                                                   archive, \
                                                   sorted_report)
        self.assertEquals(find_report, sorted_report, result)

    def test_extract(self):
        '''Tar extract'''
        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create archives
        for f in self.formats:
            compress_flags = ""
            ext = ".tar"
            if f == "gz":
                compress_flags = "z"
                ext += ".gz"
            elif f == "bz2":
                compress_flags = "j"
                ext += ".bz2"

            (rc, report) = testlib.cmd(["tar", compress_flags + "cf", "archive" + ext, \
                                       self.archive_dir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # test the contents of the created archives
        for f in self.formats:
            testlib.recursive_rm(self.archive_dir)
            (rc, report) = testlib.cmd(["tar", compress_flags + "xf", "archive" + ext])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            (rc, tmp) = testlib.cmd(["find", self.archive_dir])
            listing_report = self.clean_trailing_slash(self.sort_output(tmp))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive" + ext, \
                                                       listing_report)
            self.assertEquals(find_report, listing_report, result)

    def test_symlink_without_dir(self):
        '''Does not unpack through symlink to non-existing directory'''
        self.assertShellExitEquals(2, ["tar", "xf", '%s/data/bad-symlink-following-without-dir.tar' % (self.fs_dir)])
        self.assertTrue(os.path.exists('linktest'))
        self.assertFalse(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/orig/x'))

    def test_symlink_with_internal_dir(self):
        '''Unpacks through symlink to directory from archive'''
        self.assertShellExitEquals(0, ["tar", "xf", '%s/data/bad-symlink-following-with-dir.tar' % (self.fs_dir)])
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        # tar safely handles non-relative paths with symlinks
        self.assertTrue(os.path.exists('linktest/orig/x'))

    def test_symlink_with_external_dir(self):
        '''Does not unpack through symlink to directory outside of archive (CVE-2001-1267)'''
        self.assertFalse(os.path.exists('/tmp/x'))
        self.assertShellExitEquals(2, ["tar", "xf", '%s/data/bad-symlink-following-absolute-path.tar' % (self.fs_dir)])
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/link/x'))
        self.assertFalse(os.path.exists('/tmp/x'))

    def test_symlink_to_dotdot(self):
        '''Does not unpack through symlink to dot dot (CVE-2001-1267)'''
        os.mkdir('deeper')
        os.chdir('deeper')
        self.assertShellExitEquals(2, ["tar", "xf", '%s/data/bad-symlink-following-with-dotdot.tar' % (self.fs_dir)])
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/evil'))
        self.assertFalse(os.path.exists('../zomg'))

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TarTests))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

