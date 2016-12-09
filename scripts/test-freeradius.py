#!/usr/bin/python
#
#    test-freeradius.py quality assurance test script for freeradius
#    Copyright (C) 2009-2014 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
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
# QRT-Packages: freeradius
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'lucid':
        schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release freeradius  && ./test-freeradius.py -v'

'''


import unittest, sys, tempfile, os, socket, time, subprocess
import testlib

try:
    from private.qrt.freeradius import PrivateFreeradiusTest
except ImportError:
    class PrivateFreeradiusTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class FreeradiusTest(testlib.TestlibCase, PrivateFreeradiusTest):
    '''Test FreeRadius.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.daemon = testlib.TestDaemon("/etc/init.d/freeradius")
        self.tmpdir = tempfile.mkdtemp(prefix='freeradius-', dir='/tmp')
        self.auth_approved = "code 2"
        self.auth_denied = "code 3"

        # Add a default user
        self.users_file = "/etc/freeradius/users"
        self.test_user = "testuser"
        self.test_pass = "testpassword"
        config_line = '%s Cleartext-Password := "%s"' % (self.test_user, self.test_pass)
        testlib.config_replace(self.users_file, config_line, append=True)

        # Enable Unix auth
        self.default_site = "/etc/freeradius/sites-available/default"
        testlib.config_replace(self.default_site, "", append=True)
        subprocess.call(['sed', '-i', 's/^#\tunix/\tunix/', self.default_site])

        # Create a test user
        self.user = testlib.TestUser()

        self._restart_daemon()

    def tearDown(self):
        '''Clean up after each test_* function'''

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        testlib.config_restore(self.users_file)
        testlib.config_restore(self.default_site)

        self.user = None

    def _restart_daemon(self):
        # On saucy and later, must use upstart job
        if self.lsb_release['Release'] >= 13.10:
            testlib.cmd(['stop', 'freeradius'])
            time.sleep(0.5)
            rc, report = testlib.cmd(['start', 'freeradius'])
            time.sleep(0.5)
            expected = 0
        else:
            rc, report = self.daemon.restart()
            expected = True

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


    def _test_auth(self, username, password, expected_string, expected_rc=0):
        '''Tests authentication'''

        handle, tmpname = testlib.mkstemp_fill("User-Name=%s,Password=%s" % (username, password), dir=self.tmpdir)

        # can't use radtest as there's no way to set a timeout or number of retries
        rc, report = testlib.cmd(['/usr/bin/radclient', '-4', '-r', '2', '-f', tmpname, '-s', 'localhost:1812', 'auth', 'testing123'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        result = 'Could not find %s in output: %s\n' % (expected_string, report)
        self.assertTrue(expected_string in report, result)


    def test_valid_user(self):
        '''Test a valid user'''

        self._test_auth(self.test_user, self.test_pass, self.auth_approved)

    def test_invalid_user(self):
        '''Test an invalid user'''

        self._test_auth('xxubuntuxx', 'xxrocksxx', self.auth_denied, 1)

    def test_unix_user(self):
        '''Test a unix user'''

        self._test_auth(self.user.login, self.user.password, self.auth_approved)

    def test_unix_user_disabled_pass(self):
        '''Test a unix user with disabled password'''

        subprocess.call(['passwd', '-q', '-e', self.user.login])
        # Hrm, this works for some reason.
        self._test_auth(self.user.login, self.user.password, self.auth_approved)

    def test_unix_user_expired_pass(self):
        '''Test a unix user with expired password'''

        # This tests CVE-2011-4966

        # gah! Yes, this is crazy.
        subprocess.call(['sed', '-i',
                         r's/^%s:\([^:]*\).*$/%s:\1:10000:0:10:7:::/' % (self.user.login,
                                                                         self.user.login),
                         '/etc/shadow'])

        self._test_auth(self.user.login, self.user.password, self.auth_denied, expected_rc = 1)

    def test_unix_user_expired_account(self):
        '''Test a unix user with expired account'''

        # gah! Yes, this is crazy.
        subprocess.call(['sed', '-i',
                         r's/^%s:\([^:]*\).*$/%s:\1:10000:0::7::10001:/' % (self.user.login,
                                                                            self.user.login),
                         '/etc/shadow'])

        self._test_auth(self.user.login, self.user.password, self.auth_denied, expected_rc = 1)


    def test_cve_2009_3111(self):
        '''Test CVE-2009-3111'''

        # This is same as CVE-2003-0967
        # PoC from here: http://marc.info/?l=bugtraq&m=106944220426970

        # Send a crafted packet
        kaboom = "\x01\x01\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x02"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('localhost', 1812))
        s.send(kaboom)
        s.close()
        time.sleep(1)

        # See if it still works
        self._test_auth(self.test_user, self.test_pass, self.auth_approved)

if __name__ == '__main__':
    # simple
    unittest.main()
