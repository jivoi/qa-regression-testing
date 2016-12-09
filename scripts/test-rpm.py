#!/usr/bin/python
#
#    test-rpm.py quality assurance test script for rpm
#    Copyright (C) 2013 Canonical Ltd.
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
# QRT-Packages: rpm
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: rpm private/qrt/rpm.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) and not
    on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-rpm.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-rpm.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-rpm.tar.gz
    # cd /tmp/qrt-test-rpm ; ./install-packages ./test-rpm.py
    # ./test-rpm.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-rpm.py

'''


import unittest, sys, os
import testlib

try:
    from private.qrt.rpm import PrivateRpmTest
except ImportError:
    class PrivateRpmTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class RpmTest(testlib.TestlibCase, PrivateRpmTest):
    '''Test rpm.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.user = testlib.TestUser()

        # Lucid fails to verify signatures, not sure why
        # skip importing the key so example rpms are still installable
        if self.lsb_release['Release'] > 10.04:
            self._import_key()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None

    def _run_rpm_as_user(self, cmd, expected = 0):
        '''Runs rpm as the test user'''
        command = ['sudo', '-H', '-u', self.user.login, 'rpm']

        # Lucid needs a few more options
        if self.lsb_release['Release'] == 10.04:
            command += ['--force-debian', '--dbpath', os.path.join(self.user.home, '.rpmdb')]

        rc, report = testlib.cmd(command + cmd)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _import_key(self):
        '''Imports test gpg key into user rpm keyring'''
        self._run_rpm_as_user(['--import', './rpm/mdeslaur.asc'])

    def test_rpm_signature(self):
        '''Test rpm signature'''

        if self.lsb_release['Release'] == 10.04:
            return self._skipped("Ubuntu 10.04 doesn't verify signatures")

        self._run_rpm_as_user(['-K', './rpm/hello-1.0-1.src.rpm'])

    def test_no_signature(self):
        '''Test rpm with no signature'''
        self._run_rpm_as_user(['-K', './rpm/hello-nosign-1.0-1.src.rpm'])

    def test_broken_rpm_signature(self):
        '''Test broken rpm signature'''
        self._run_rpm_as_user(['-K', './rpm/hello-brokensign-1.0-1.src.rpm'],
                           expected = 1)

    def test_rpm_extraction(self):
        '''Test rpm extraction'''
        self._run_rpm_as_user(['-ivh', './rpm/hello-1.0-1.src.rpm'])

        contents = [ ('SOURCES/hello-1.0.tar.gz', 'b718a835936fd2f6c8855f210c4789a1'),
                     ('SPECS/hello.spec',         '1ffb0f2ae09490879c3694fffe8edb41') ]

        for filepath, checksum in contents:
            fullpath = os.path.join(self.user.home, 'rpmbuild', filepath)

            result = "Could not find '%s' file!" % fullpath
            self.assertTrue(os.path.exists(fullpath), result)

            new_cksum = testlib.get_md5(fullpath)
            result = "Checksum didn't match for '%s' file!" % fullpath
            self.assertEquals(checksum, new_cksum, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
