#!/usr/bin/python
#
#    test-dosfstools.py quality assurance test script for dosfstools
#    Copyright (C) 2016 Canonical Ltd.
#    Author: Marc Deslauriers <marcdeslauriers@canonical.com>
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
# QRT-Packages: dosfstools
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/dosfstools.py
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
import shutil
import sys
import unittest
import testlib
import tempfile

try:
    from private.qrt.dosfstools import PrivateDosfstoolsTest
except ImportError:
    class PrivateDosfstoolsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class DosfstoolsTest(testlib.TestlibCase, PrivateDosfstoolsTest):
    '''Test dosfstools.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="dosfstools-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_main(self):
        '''Test main tools'''

        image_path = os.path.join(self.tempdir, "image.img")
        mount_path = os.path.join(self.tempdir, "mount")
        os.mkdir(mount_path)

        # First, create an empty 10MB image
        rc, report = testlib.cmd(['dd', 'if=/dev/zero',
                                  'of=%s' % image_path, 'bs=1M',
                                  'count=10'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "records out"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Now create a filesystem
        rc, report = testlib.cmd(['mkdosfs', '-v',
                                  image_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "Volume ID is"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Do a fsck on it
        rc, report = testlib.cmd(['dosfsck', '-v', '-n',
                                  image_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "0 files"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Try and mount it
        rc, report = testlib.cmd(['mount', '-v',
                                  image_path, mount_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if self.lsb_release['Release'] >= 15.10:
            search = "mounted on %s" % mount_path
        else:
            search = "%s on %s type vfat (rw)" % (image_path, mount_path)
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Copy some files to it
        shutil.copy("/etc/hosts", mount_path)
        shutil.copy("/etc/resolv.conf", mount_path)

        # Unmount it
        rc, report = testlib.cmd(['umount', '-v', mount_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if self.lsb_release['Release'] >= 15.10:
            search = "%s unmounted" % mount_path
        else:
            search = "has been unmounted"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Do a fsck on it again
        rc, report = testlib.cmd(['dosfsck', '-v', '-n',
                                  image_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "2 files"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
