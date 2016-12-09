#!/usr/bin/python
#
#    testlib_archive.py quality assurance test script for PKG
#    Copyright (C) 2008-2009 Canonical Ltd.
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
Classes to help with testing archives. Example usage:

#!/usr/bin/python

import unittest, subprocess, sys
import testlib
import testlib_archive

class TestFoo(testlib_archive.ArchiveCommon):
    def setUp(self):
        testlib_archive.ArchiveCommon._setUp(self)

    def tearDown(self):
        testlib_archive.ArchiveCommon._tearDown(self)

    def test_foo(self):
        \'''Test foo\'''
        ...

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFoo))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
'''

import testlib
import os
import tempfile

class ArchiveCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp')
        self.archive_dir = "test-archive"

        # create some random files to archive
        self.archive_root = os.path.join(self.tempdir, self.archive_dir)

        self.files = { 'dir1': os.path.join(self.archive_root, "dir1"), \
                       'dir2': os.path.join(self.archive_root, "dir1", \
                                                               "dir2"), \
                       'dir3': os.path.join(self.archive_root, "dir3"), \
                       'hlink1': os.path.join(self.archive_root, "hlink1"), \
                       'slink1': os.path.join(self.archive_root, "slink1"), \
                       'file1': os.path.join(self.archive_root, "file1"), \
                       'file2': os.path.join(self.archive_root, "dir1", \
                                                                "file2"), \
                       'dev2': os.path.join(self.archive_root, "dir1", "dev1")
                     }

        # dirs
        os.mkdir(self.archive_root)
        os.mkdir(self.files['dir1'])
        os.mkdir(self.files['dir2'])
        os.mkdir(self.files['dir3'])

        # files
        testlib.create_fill(self.files['file1'], "foo")
        testlib.create_fill(self.files['file2'], "bar")

        # links
        os.link(self.files['file1'], self.files['hlink1'])
        os.symlink(self.files['file2'], self.files['slink1'])

        os.chdir(self.tempdir)


    def _tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir("/tmp")
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def sort_output(self, output):
        '''Return sorted lines of output.'''
        lines = output.split('\n')
        lines.sort()
        sorted_output = '\n'.join(lines)
        return sorted_output

    def clean_trailing_slash(self, output):
        '''Remove trailing '/' from lines of output'''
        lines = []
        for line in output.split('\n'):
            lines.append(line.rstrip('/'))
        cleaned = '\n'.join(lines)
        return cleaned

    def create_sample_tar_archives(self, formats=['tar', 'gz', 'bz2']):
        '''Create tar archives'''
        # get the contents
        prev_dir = os.getcwd()
        os.chdir(self.tempdir)
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        archives = []

        for f in formats:
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

            archive_name = os.path.join(self.tempdir, "archive" + ext)
            archives.append(archive_name)
            (rc, report) = testlib.cmd(["tar", compress_flags + "cf", \
                                        archive_name, self.archive_dir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # verify file type
            (rc, report) = testlib.cmd(["file", archive_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            report = report.split(': ')[1]
            self.assertTrue(report.startswith(type),"Expected '%s' got '%s'" % (type,report))

        os.chdir(prev_dir)
        return archives

    def create_sample_cpio_archives(self, formats=['bin', 'odc', 'newc', 'crc', 'hpbin', 'hpodc', 'tar', 'ustar']):
        '''Create cpio archives'''
        archives = []
        prev_dir = os.getcwd()
        os.chdir(self.tempdir)

        # get the contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create the archives
        for f in formats:
            archive_name = os.path.join(self.tempdir, "archive." + f)
            archives.append(archive_name)
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir, '-depth', '-print'], \
                                            ["cpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        os.chdir(prev_dir)
        return archives
