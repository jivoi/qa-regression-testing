#!/usr/bin/python
#
#    test-fastjar.py quality assurance test script for fastjar
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# packages required for test to run:
# QRT-Packages: fastjar file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_archive.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file fastjar  && ./test-fastjar.py -v'
'''


import unittest, sys, os
import testlib
import testlib_archive

try:
    from private.qrt.fastjar import PrivateFastjarTest
except ImportError:
    class PrivateFastjarTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class FastjarTest(testlib_archive.ArchiveCommon, PrivateFastjarTest):
    '''Test fastjar.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        testlib_archive.ArchiveCommon._setUp(self)

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

    def test_basic(self):
        '''Jar create'''
        # get the contents
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create the archives
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-cMf", "archive.jar", \
                                   self.archive_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify file type
        (rc, report) = testlib.cmd(["file","archive.jar"])
        expected = 0
        expected_type = "Zip archive data, at least v1.0 to extract"
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        report = report.split(': ')[1]
        self.assertTrue(report.startswith(expected_type),"Expected '%s' got '%s'" % (expected_type,report))

        # verify the contents
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-tf", "archive.jar"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify all the files are present
        sorted_report = self.clean_trailing_slash(self.sort_output(report))
        result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                   "archive.jar", \
                                                   sorted_report)
        self.assertEquals(find_report, sorted_report, result)

    def test_append(self):
        '''Jar append'''
        archive = "archive.jar"
        new_file = "added1"

        # Record initial directory tree
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        self.assertEquals(rc, 0, tmp)
        first_find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # Create the base archive
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-cMf", archive, self.archive_dir])
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

        # Update jar
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-uMf", archive, \
                                    os.path.join(self.archive_dir, new_file)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Record jar contents
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-tf", archive])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        sorted_report = self.clean_trailing_slash(self.sort_output(report))

        # Verify new jar does not match old find
        result = 'Find has:%s\n\n%s has:%s\n' % (first_find_report, \
                                                   archive, \
                                                   sorted_report)
        self.assertNotEquals(first_find_report, sorted_report, result)

        # Verify new jar does match the new find
        result = 'Find has:%s\n\n%s has:%s\n' % (find_report, \
                                                   archive, \
                                                   sorted_report)
        self.assertEquals(find_report, sorted_report, result)

    def test_extract(self):
        '''Jar extract'''
        # get the contents of the directory
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        find_report = self.clean_trailing_slash(self.sort_output(tmp))

        # create archive
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-cMf", "archive.jar", \
                                   self.archive_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test the contents of the created archive
        testlib.recursive_rm(self.archive_dir)
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-xf", "archive.jar"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        listing_report = self.clean_trailing_slash(self.sort_output(tmp))
        result = 'Find has:\n%s\n%s has:\n%s\n' % (find_report, \
                                                   "archive.jar", \
                                                   listing_report)
        self.assertEquals(find_report, listing_report, result)

    def test_cve_2010_0831(self):
        '''Test directory traversal (CVE-2010-0831)'''
        os.mkdir('deeper')
        os.chdir('deeper')

        # extract bad archive, this should fail
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-xf", "%s/fastjar/evil.jar" % (self.fs_dir)])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure the bad file isn't there
        self.assertFalse(os.path.exists('../badfile'))

    def test_cve_2006_3619(self):
        '''Test directory traversal (CVE-2006-3619)'''
        os.mkdir('deeper')
        os.chdir('deeper')

        # extract bad archive, this should fail
        (rc, report) = testlib.cmd(["/usr/bin/fastjar", "-xf", "%s/fastjar/evil2.jar" % (self.fs_dir)])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure the bad file isn't there
        self.assertFalse(os.path.exists('../badfile'))

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
