#!/usr/bin/python
#
#    test-opie.py quality assurance test script for opie
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
# QRT-Packages: opie-client opie-server python-pam libpam-opie python-pexpect
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: opie
# QRT-Privilege: root
# QRT-Deprecated: 11.10

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release opie-client opie-server python-pam libpam-opie python-pexpect && ./test-opie.py -v'
'''

import unittest, subprocess, sys, os, pexpect, time, PAM
import testlib

use_private = True
try:
    from private.qrt.opie import OpiePrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class OpieTest(testlib.TestlibCase):
    '''Test opie.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.secret = "UbuntuRocks!"
        self.opiekeys = "/etc/opiekeys"
        self.opie_pam = "/etc/pam.d/opie"
        self.long_username = "12345678901234567890123456789012345"

        # If there's no database file, create one so it gets purged
        # properly when the test script ends.
        if not os.path.exists(self.opiekeys):
            subprocess.call(['touch',self.opiekeys])
        testlib.config_replace(self.opiekeys,"")

        # Create the pam config file
        open(self.opie_pam, 'w').write('''auth	sufficient	pam_unix.so
auth 	sufficient	pam_opie.so 
auth	required	pam_deny.so
''')

        # Create a system user with an opie key
        self.user = testlib.TestUser()
        (self.opie_user,self.opie_seq,self.opie_seed) = self._create_opie()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None
        testlib.config_restore(self.opiekeys)
        if os.path.exists(self.opie_pam):
            os.unlink(self.opie_pam)

    def _create_opie(self):
        child = pexpect.spawn('su -c "opiepasswd -f -c" %s' % self.user.login)
        time.sleep(0.2)
        child.expect('Enter new secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(self.secret)
        time.sleep(0.2)
        child.expect('Again new secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(self.secret)
        time.sleep(0.2)
        child.expect('ID [^\s]* OTP key is [^\s]* [^\s]*', timeout=5)
        report = child.after
        child.expect(pexpect.EOF, timeout=5)
        child.close(force=True)

        user = report.split(' ')[1]
        seq  = report.split(' ')[5]
        seed = report.split(' ')[6]
        opiekeys_search = "%s %04d %s" % (user,int(seq),seed)

        # See if the username is valid
        result = "Username %s doesn't match %s!" % (self.user.login,user)
        self.assertTrue(user == self.user.login, result)

        # See if it got set in the opiekeys file
        result = "Couldn't find user %s in opiekeys file!" % user
        self.assertTrue(opiekeys_search in file(self.opiekeys).read(), result)

        return (user,seq,seed)

    def _get_otp(self, req, seed):
        child = pexpect.spawn('opiekey %s %s' % (req, seed))
        time.sleep(0.2)
        child.expect('Enter secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(self.secret)
        time.sleep(0.2)
        child.expect(pexpect.EOF, timeout=5)
        otp = child.before
        child.close(force=True)
        return otp.strip()

    def _pam_callback(self, auth, query_list, userData):
        '''Callback for pam'''
        resp = []

        for i in range(len(query_list)):
            query, type = query_list[i]
            if type == PAM.PAM_PROMPT_ECHO_OFF:
                # If we get a password prompt, just send an empty string so we
                # can get the opie query string
                if "Password:" in query:
                    val = ""
                    resp.append((val, 0))
                elif "otp-md5" in query:
                    # We've got the string, let's get a valid OTP
                    val = self._get_otp(query.split(' ')[1], query.split(' ')[2])
                    resp.append((val, 0))
            else:
                return None

        return resp

    def test_lp569292(self):
        '''Test opiepasswd valid seed bug (LP: #569292)'''

        new_secret = "UbuntuRules!"

        # Change password and validate the seed
        child = pexpect.spawn('su -c "opiepasswd -f -c" %s' % self.user.login)
        time.sleep(0.2)
        child.expect('Enter old secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(self.secret)
        time.sleep(0.2)
        child.expect('Enter new secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(new_secret)
        time.sleep(0.2)
        child.expect('Again new secret pass phrase:', timeout=5)
        time.sleep(0.2)
        child.sendline(new_secret)
        time.sleep(0.2)
        child.expect('ID [^\s]* OTP key is [^\s]* [^\s]*', timeout=5)
        report = child.after
        child.expect(pexpect.EOF, timeout=5)
        child.close(force=True)
        seed = report.split(' ')[6]

        result = "Seed %s looks like it was truncated!" % seed
        self.assertTrue(len(seed) >= 6, result)

    def test_pam_authentication(self):
        '''Test pam authentication'''

        service = 'opie'

        auth = PAM.pam()
        auth.start(service)

	auth.set_item(PAM.PAM_USER, self.user.login)
        auth.set_item(PAM.PAM_CONV, self._pam_callback)

        auth.authenticate()
        auth.acct_mgmt()

    def test_cve_2010_1938_opie(self):
        '''Test CVE-2010-1938 in opie'''

        (rc, report) = testlib.cmd(["/usr/bin/opieinfo", self.long_username])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + report)

    def test_cve_2010_1938_pam_opie(self):
        '''Test CVE-2010-1938 in pam_opie'''

        # We use an external helper here so our main script doesn't
        # segfault
        child = pexpect.spawn('./opie/pamtest.py %s' % self.long_username)
        time.sleep(0.2)
        child.expect('Password:', timeout=5)
        time.sleep(0.2)
        child.sendline("")
        time.sleep(0.2)
        child.expect('.*, Response:', timeout=5)
        time.sleep(0.2)
        child.sendline("")
        time.sleep(0.2)
        child.close(force=True)


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpieTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpiePrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
