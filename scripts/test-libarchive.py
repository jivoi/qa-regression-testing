#!/usr/bin/python
#
#    test-libarchive.py quality assurance test script for libarchive
#    Copyright (C) 2011-2016 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Adapted from test-tar.py and test-cpio.py
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
# QRT-Packages: bsdtar bsdcpio valgrind
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_archive.py util-linux/test.iso libarchive private/qrt/libarchive.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''

import tempfile, unittest, sys, os, shutil
import testlib
import testlib_archive

use_private = True
try:
    from private.qrt.libarchive import LibarchivePrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibarchiveTarTests(testlib_archive.ArchiveCommon):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.test_iso = os.path.join(self.fs_dir, 'util-linux/test.iso')
        testlib_archive.ArchiveCommon._setUp(self)

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libarchive-")

        self.formats = [ 'tar', 'gz', 'bz2' ]

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_basic(self):
        '''bsdtar: create'''
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

            (rc, report) = testlib.cmd(["bsdtar", compress_flags + "cf", "archive" + ext, \
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
            (rc, report) = testlib.cmd(["bsdtar", "tf", "archive" + ext])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            # Drop locale error message
            report = "\n".join([x for x in report.splitlines() if x != 'bsdtar: Failed to set default locale'])+"\n"

            # verify all the files are present
            sorted_report = self.clean_trailing_slash(self.sort_output(report))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive" + ext, \
                                                       sorted_report)
            self.assertEquals(find_report, sorted_report, result)

    def test_append(self):
        '''bsdtar: append'''
        archive = "archive.tar"
        new_file = "added1"

        # Record initial directory tree
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        self.assertEquals(rc, 0, tmp)
        first_find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # Create the base archive
        (rc, report) = testlib.cmd(["bsdtar", "cf", archive, self.archive_dir])
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
        (rc, report) = testlib.cmd(["bsdtar", "uf", archive, \
                                    os.path.join(self.archive_dir, new_file)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Record tar contents
        (rc, report) = testlib.cmd(["bsdtar", "tf", archive])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        # Drop locale error message
        report = "\n".join([x for x in report.splitlines() if x != 'bsdtar: Failed to set default locale'])+"\n"
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
        '''bsdtar: extract'''
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

            (rc, report) = testlib.cmd(["bsdtar", compress_flags + "cf", "archive" + ext, \
                                       self.archive_dir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # test the contents of the created archives
        for f in self.formats:
            testlib.recursive_rm(self.archive_dir)
            (rc, report) = testlib.cmd(["bsdtar", compress_flags + "xf", "archive" + ext])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            (rc, tmp) = testlib.cmd(["find", self.archive_dir])
            listing_report = self.clean_trailing_slash(self.sort_output(tmp))
            result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                       "archive" + ext, \
                                                       listing_report)
            self.assertEquals(find_report, listing_report, result)

    def test_issue_502(self):
        '''bsdtar: Issue 502'''

        shutil.copy(os.path.join(self.fs_dir,
                                 "libarchive/issue502/crash_dos.tar"),
                    self.tempdir)
        test_file = os.path.join(self.tempdir, "crash_dos.tar")

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["bsdtar", "-xvf", test_file])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


    def test_iso(self):
        '''bsdtar: extract iso file'''

        # verify the contents
        (rc, report) = testlib.cmd(["bsdtar", "tf", self.test_iso])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        # Drop locale error message
        report = "\n".join([x for x in report.splitlines() if x != 'bsdtar: Failed to set default locale'])+"\n"

        files_report = ".\nTESTFILE.TXT\n"

        # verify all the files are present
        result = 'test.iso has:\n%s\nbsdtar has:\n%s\n' % (files_report, \
                                                   report)
        self.assertEquals(files_report, report, result)

        # Now extract it and see if the file contents are correct
        (rc, report) = testlib.cmd(["bsdtar", "xf", self.test_iso])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(os.path.exists('./TESTFILE.TXT'), "Could not find TESTFILE.TXT!")

        contents = open('./TESTFILE.TXT').read()
        search = "This is a test file"
        result = "Couldn't find %s in %s\n" % (search, contents)
        self.assertTrue(search in contents, result)


class LibarchiveCpioTests(testlib_archive.ArchiveCommon):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.test_iso = os.path.join(self.fs_dir, 'util-linux/test.iso')
        testlib_archive.ArchiveCommon._setUp(self)

        self.formats = [ 'odc', 'newc', 'pax', 'ustar' ]

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libarchive-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_out(self):
        '''bsdcpio: Copy out'''
        # create the archives
        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir, '-depth', '-print'], \
                                            ["bsdcpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # get the contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # verify the contents
        for f in self.formats:
            (rc, report) = testlib.cmd(["bsdcpio", "--list", "--quiet", \
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
        '''bsdcpio: Copy in'''
        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create archives
        for f in self.formats:
            (rc, report) = testlib.cmd_pipe(["find", self.archive_dir], \
                                            ["bsdcpio", "-o", "-v", "-H", f, \
                                             "-F", "archive." + f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # test the contents of the created archives
        for f in self.formats:
            testlib.recursive_rm(self.archive_dir)
            (rc, report) = testlib.cmd(["bsdcpio", "-i", "-v", "-F", \
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
        '''bsdcpio: Copy pass'''
        destdir = "dest"
        os.mkdir(destdir)

        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # passthrough copy
        (rc, report) = testlib.cmd_pipe(["find", self.archive_dir], \
                                        ["bsdcpio", "-p", "-v", "dest"])

        os.chdir(destdir)
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        listing_report = self.clean_trailing_slash(self.sort_output(tmp))
        result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                   destdir, listing_report)
        self.assertEquals(find_report, listing_report, result)

    def test_cve_2015_2304_1(self):
        '''bsdcpio: CVE-2015-2304 - default mode'''

        absolute_file = "/tmp/tmp.2NBml3icHX"
        link_file = "/tmp/tmp.Vw5GphuCqU"
        relative_file = "tmp.eUPxvHvloB"

        # Make sure our test files are blown away first
        for tf in [absolute_file, link_file]:
            if os.path.exists(tf):
                os.unlink(tf)

        test_dir = os.path.join(self.tempdir, "test") 
        os.mkdir(test_dir)
        shutil.copy(os.path.join(self.fs_dir,
                                 "libarchive/CVE-2015-2304/arc.cpio"),
                    test_dir)
        test_file = os.path.join(test_dir, "arc.cpio")

        os.chdir(test_dir)
        (rc, report) = testlib.cmd(["bsdcpio", "-i", "-I", test_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        relative_path = os.path.join(self.tempdir, relative_file)

        for tf in [absolute_file, link_file, relative_path]:
            self.assertFalse(os.path.exists(tf),
                "Found %s!" % tf)

    def test_cve_2015_2304_2(self):
        '''bsdcpio: CVE-2015-2304 - insecure mode'''

        absolute_file = "/tmp/tmp.2NBml3icHX"
        link_file = "/tmp/tmp.Vw5GphuCqU"
        relative_file = "tmp.eUPxvHvloB"

        # Make sure our test files are blown away first
        for tf in [absolute_file, link_file]:
            if os.path.exists(tf):
                os.unlink(tf)

        test_dir = os.path.join(self.tempdir, "test") 
        os.mkdir(test_dir)
        shutil.copy(os.path.join(self.fs_dir,
                                 "libarchive/CVE-2015-2304/arc.cpio"),
                    test_dir)
        test_file = os.path.join(test_dir, "arc.cpio")

        os.chdir(test_dir)
        (rc, report) = testlib.cmd(["bsdcpio", "--insecure", "-i", "-I", test_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        relative_path = os.path.join(self.tempdir, relative_file)

        for tf in [absolute_file, link_file, relative_path]:
            self.assertTrue(os.path.exists(tf),
                "Didn't find %s!" % tf)

    def test_iso(self):
        '''bsdcpio: Extract iso file'''

        # verify the contents
        (rc, report) = testlib.cmd(["bsdcpio", "--list", "--quiet", \
                                    "-I", self.test_iso])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        files_report = ".\nTESTFILE.TXT\n"

        # verify all the files are present
        result = 'test.iso has:\n%s\nbsdcpio has:\n%s\n' % (files_report, \
                                                   report)
        self.assertEquals(files_report, report, result)

        # Now extract it and see if the file contents are correct
        (rc, report) = testlib.cmd(["bsdcpio", "-i", "-v", "-F", self.test_iso])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(os.path.exists('./TESTFILE.TXT'), "Could not find TESTFILE.TXT!")

        contents = open('./TESTFILE.TXT').read()
        search = "This is a test file"
        result = "Couldn't find %s in %s\n" % (search, contents)
        self.assertTrue(search in contents, result)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibarchiveTarTests))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibarchiveCpioTests))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibarchivePrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
