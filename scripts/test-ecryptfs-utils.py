#!/usr/bin/python
#
#    test-ecryptfs-utils.py quality assurance test script for ecryptfs-utils
#    Copyright (C) 2015 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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
# QRT-Packages: ecryptfs-utils python-pexpect
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/ecryptfs_utils.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-ecryptfs-utils.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-ecryptfs-utils.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-ecryptfs-utils.tar.gz
    # cd /tmp/qrt-test-ecryptfs-utils ; ./install-packages ./test-ecryptfs-utils.py
    # ./test-ecryptfs-utils.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-ecryptfs-utils.py -v'
'''


import os
import subprocess
import sys
import unittest
import testlib
import string
import pexpect

import time

try:
    from private.qrt.ecryptfs_utils import PrivateEcryptfsUtilsTest
except ImportError:
    class PrivateEcryptfsUtilsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class EncryptedHomeTest(testlib.TestlibCase, PrivateEcryptfsUtilsTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test function'''
        self.user = testlib.AddUser(encrypt_home=True)

    def tearDown(self):
        '''Clean up after each test function'''
        # FIXME: Temp workaround until stale process bug (LP: #903582) is fixed
        time.sleep(1)
        testlib.cmd(['killall', '-u', self.user.login])
        time.sleep(1)

    def _login_cmd(self, command, callback=None):
        # ssh is used, rather than login, because it returns the status of the
        # last command
        child = pexpect.spawn('ssh', ['-o', 'StrictHostKeyChecking=no', '%s@localhost' % self.user.login], timeout=5)
        self.assertEqual(child.expect('.* password: '), 0)
        child.sendline(self.user.password)
        self.assertEqual(child.expect('.*\$ '), 0)
        child.sendline(string.join(command))
        if callback:
            callback(child)
        self.assertEqual(child.expect('.*\$ '), 0)
        child.sendline('exit $?')
        report = child.before + child.after

        child.wait()
        child.close()
        self.assertEqual(child.signalstatus, None)

        return child.exitstatus, report

    def _drop_caches(self, val=3):
        f = open('/proc/sys/vm/drop_caches', 'w')
        f.write('%d\n' % val)
        f.close()

    def test_login_true(self):
        '''Test logging in and running true'''
        (rc, report) = self._login_cmd(['true'])
        self.assertEqual(rc, 0, report)

    def test_login_false(self):
        '''Test logging in and running false'''
        (rc, report) = self._login_cmd(['false'])
        self.assertNotEqual(rc, 0, report)

    def test_login_whoami(self):
        '''Test logging in and running whoami'''
        (rc, report) = self._login_cmd(['whoami'])
        self.assertTrue(self.user.login in report)

    def _mv_to_encrypted_home(self, src, dst):
        '''Moves src to dst, unmounts the encrypted home dir, returns sha256sum of src'''
        (rc, report) = self._login_cmd(['cp', src, dst])
        self.assertEqual(rc, 0, report)

        (rc, sha256sum_output) = testlib.cmd(['sha256sum', src])
        self.assertEqual(rc, 0, sha256sum_output)

        # Make sure the encrypted home dir was unmounted
        if os.path.isfile(dst):
            (rc, report) = self._login_cmd(['ecryptfs-umount-private'])
            expected = 0
            if self.lsb_release['Release'] >= 15.10 and \
               'Sessions still open, not unmounting' in report:
                   expected = 1
            self.assertEqual(rc, expected, report)
            self.assertFalse(os.path.isfile(dst))

        self._drop_caches()

        return sha256sum_output.split()[0]

    def test_cp_testlib(self):
        '''Test copying testlib.py into encrypted home dir and verifying contents'''
        src = os.path.join(os.getcwd(), 'testlib.py')
        dst = os.path.join(self.user.home, 'testlib.py')
        expected = self._mv_to_encrypted_home(src, dst)

        (rc, report) = self._login_cmd(['sha256sum', dst])
        self.assertEqual(rc, 0, report)
        self.assertTrue(expected in report, '[%s] not in [%s]' % (expected, report))

    def _change_passwd_callback(self, child):
        new_password = 'a1b2c3D$' * 8

        self.assertEqual(child.expect('\(current\) UNIX password: '), 0)
        child.sendline(self.user.password)
        self.assertEqual(child.expect('Enter new UNIX password: '), 0)
        child.sendline(new_password)
        self.assertEqual(child.expect('Retype new UNIX password: '), 0)
        child.sendline(new_password)
        self.assertEqual(child.expect('passwd: password updated successfully'), 0)
        self.user.password = new_password

    def test_change_passwd(self):
        '''Test changing the wrapping password and verifying pre-existing contents'''
        src = os.path.join(os.getcwd(), 'testlib.py')
        dst = os.path.join(self.user.home, 'testlib.py')
        expected = self._mv_to_encrypted_home(src, dst)

        (rc, report) = self._login_cmd(['passwd', '-q'], self._change_passwd_callback)

        (rc, report) = self._login_cmd(['sha256sum', dst])
        self.assertEqual(rc, 0, report)
        self.assertTrue(expected in report, '[%s] not in [%s]' % (expected, report))


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(EncryptedHomeTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
