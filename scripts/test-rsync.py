#!/usr/bin/python
#
#    test-rsync.py quality assurance test script for rsync
#    Copyright (C) 2011-2014 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
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
# QRT-Packages: rsync
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_archive.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''


import unittest, sys, os
import testlib
import testlib_archive
import time

try:
    from private.qrt.Rsync import PrivateRsyncTest
except ImportError:
    class PrivateRsyncTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class RsyncTest(testlib_archive.ArchiveCommon, PrivateRsyncTest):
    '''Test rsync.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        testlib_archive.ArchiveCommon._setUp(self)
        self.dest_dir = "test-dest"
        self.dest_root = os.path.join(self.tempdir, self.dest_dir)
        os.mkdir(self.dest_root)

        self.rsyncd_default = "/etc/default/rsync"
        self.rsyncd_conf = "/etc/rsyncd.conf"
        self.rsyncd_secrets = "/etc/rsyncd.secrets"

        testlib.config_set(self.rsyncd_default, 'RSYNC_ENABLE', 'true',
                           spaces=False)
        testlib.config_replace(self.rsyncd_conf,
'''[test-module]
  path = %s
  auth users = *
  secrets file = %s
''' % (self.archive_root, self.rsyncd_secrets) )

        testlib.config_replace(self.rsyncd_secrets,
'''gooduser:goodpass
''')
        os.chmod(self.rsyncd_secrets, 0700)

        self.daemon = testlib.TestDaemon("/etc/init.d/rsync")
        self.daemon.force_restart()
        time.sleep(1)

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_archive.ArchiveCommon._tearDown(self)
        os.chdir(self.fs_dir)

        self.daemon.stop()
        time.sleep(1)

        testlib.config_restore(self.rsyncd_default)
        testlib.config_restore(self.rsyncd_conf)
        testlib.config_restore(self.rsyncd_secrets)

    def _create_password_file(self, password):
        password_file = os.path.join(self.tempdir, 'passwordfile.txt')
        open(password_file, 'w').write(password)
        os.chmod(password_file, 0700)
        return password_file

    def test_basic(self):
        '''Test basic functionnality'''
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        ori_report = self.clean_trailing_slash(self.sort_output(tmp))

        (rc, report) = testlib.cmd(["rsync", "-av", "--delete", \
                                   self.archive_dir + "/", self.dest_dir + "/"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify all the files are present
        (rc, tmp) = testlib.cmd(["find", self.dest_dir])
        dst_report = self.clean_trailing_slash(self.sort_output(tmp))
        dst_report = dst_report.replace(self.dest_dir, self.archive_dir)
        result = 'Original dir has:\n%s\nDest dir has:\n%s\n' % (ori_report, \
                                                   dst_report)
        self.assertEquals(ori_report, dst_report, result)

    def test_daemon(self):
        '''Test daemon'''
        (rc, tmp) = testlib.cmd(["find", self.archive_dir])
        ori_report = self.clean_trailing_slash(self.sort_output(tmp))

        password_file = self._create_password_file("goodpass")

        (rc, report) = testlib.cmd(["rsync", "--password-file",
                                    password_file, "-av", "--delete",
                                    "rsync://gooduser@localhost/test-module/",
                                    self.dest_dir + "/"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify all the files are present
        (rc, tmp) = testlib.cmd(["find", self.dest_dir])
        dst_report = self.clean_trailing_slash(self.sort_output(tmp))
        dst_report = dst_report.replace(self.dest_dir, self.archive_dir)
        result = 'Original dir has:\n%s\nDest dir has:\n%s\n' % (ori_report, \
                                                   dst_report)
        self.assertEquals(ori_report, dst_report, result)

    def test_daemon_badpass(self):
        '''Test daemon bad password'''
        password_file = self._create_password_file("badpass")

        (rc, report) = testlib.cmd(["rsync", "--password-file",
                                    password_file, "-av", "--delete",
                                    "rsync://gooduser@localhost/test-module/",
                                    self.dest_dir + "/"])
        expected = 5
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        error = 'auth failed'
        result = "Didn't find '%s' in output '%s'\n" % (error, report)
        self.assertTrue(error in report, result)

    def test_daemon_baduser(self):
        '''Test daemon bad user (CVE-2014-2855)'''
        password_file = self._create_password_file("goodpass")

        (rc, report) = testlib.cmd(["rsync", "--password-file",
                                    password_file, "-av", "--delete",
                                    "rsync://baduser@localhost/test-module/",
                                    self.dest_dir + "/"])
        expected = 5
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        error = 'auth failed'
        result = "Didn't find '%s' in output '%s'\n" % (error, report)
        self.assertTrue(error in report, result)


    def test_cve_2011_1097(self):
        '''Test CVE-2011-1097'''
        # PoC taken from https://bugzilla.samba.org/show_bug.cgi?id=7936

        for filename in [ 'src', 'src/sub' ]:
            os.mkdir(os.path.join(self.tempdir, filename))

        for filename in [ 'src/1', 'src/2', 'src/sub/file' ]:
            testlib.create_fill(os.path.join(self.tempdir, filename), "")

        (rc, report) = testlib.cmd(["rsync", "-a", "src/", "dest/"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        open('src/1', 'w').write("data")
        os.unlink('src/2')

        (rc, report) = testlib.cmd(["rsync", "-nvi", "-rc", "--delete", \
                                   "src/", "dest/"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify rsync doesn't think sub/file has changed
        result = 'Rsync thinks sub/file has changed! Report:%s\n' % report
        self.assertFalse("sub/file" in report, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
