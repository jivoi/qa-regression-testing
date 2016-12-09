#!/usr/bin/python
#
#    test-openssh.py quality assurance test script for PKG
#    Copyright (C) 2010-2016 Canonical Ltd.
#    Author: Steve Beattie <sbeattie@ubuntu.com>
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
# QRT-Packages: openssh-server openssh-client python-pexpect
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/openssh.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-PKG.py -v'
'''

import unittest, sys, os
import testlib
import pexpect
import shutil
import re
import time

use_private = True
try:
    from private.qrt.openssh import PrivateOpenSSHTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class OpenSSHTest(testlib.TestlibCase):
    '''Test both openssh server and client.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        self.sshd_config = '/etc/ssh/sshd_config'
        self.sshd_rsa_private_keyfile = '/etc/ssh/ssh_host_rsa_key'
        self.sshd_rsa_private_key = \
'''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs7PQMZkt6/s3ibdNW6C4ZUr6k1uSE0XZ5RK2cfdh0Ug1+DkJ
Rp8WTdsIKOVY69No1k3zKGm7EFvx5JhmSXxFcPqMj1/+NYw+JeT8q18JzPrhvEmI
KhP3+ydW+B+6w8PP2uEIpOS9OX7ISQgsgJ2J2M48aP2aAkdAjtO61JepJ6d+UHtD
cFyRS7P/17/o1QfWalAgbdLpZuq0eguRedVO6OTugTLu96g3w7Tk7watLO0GRStG
PlXRNRyZW4ER6xnUrG5lbEYICTYISA5yLSYBb3TTPyfQv6flD9SD64Xa8kgktGkD
AbMx7wa6BiRMeshNM+uFRJ/ZimcAKdUJMyYf4QIDAQABAoIBAQCt+W+eFQZ4aAYk
temWw8rBhg2BjC2nqwCA3dT0EOQKkTZu0glA7dPSHDOSJDgqV8ovb9fxUCticyGE
hmbAzicMcgSS6gRaIyQn28EiyCfc4yaX+zhwRFTYOgXgwhc2X+Rjq2mK+kiX2T5e
NiOfgOVrmH6zxpHLkt/VZvaByzJgyA2deH3KT9W/O+Mm52dDaer3ZKNKy/orpxbo
Ip4SbNIEdTylX9DoBZQzn6AKBkc/S8Qok3xGT/uM/mbj2IruwHwrkFURYQyzbcmQ
jDX1T3AJz92+LbiW8kKw8uODfoVdxv91ooTmST4z6izU6shpNGsHOHtV/rsOfvGs
H/fNYqSBAoGBAO9ULRjWeWcyMO/M+dLc4z4+LQ4QWPMVChuxjNVKIX4HycrXbIo4
uEZYhIDYDW7tIJp7Jp4YPzpbAGQldR//3EW3Pr9t4e7Y7TT2EDutNpFn+2a+cr2J
Qn+k0aO458V0vNXofpThIPyZppCF6y2ass/LG/RrIx+4XeIhprFzFlmtAoGBAMA4
Wc5GCaPbh+URejTptbE/WCBolUgt6gMDuEMvwVrdRJSP/7HTy5SdCzEExn8S86AY
S3TBGq5c5Pa+S8vuGXWaVidsVr4tf50yNTBkmyMazzi8cM+q0BHWFqT5L5+wbfpW
ahS+vidFhoF+1jK14Gg4WMVfZubDX4aiRYC44s2FAoGAfgU3/eUpZhKCvDKVtdfD
/Mlmlgo7nDwO54g1XTY8ro1RT3Lh32KAfeIsW1/oqulICrAgJI0l9gdnDFTA+MmU
Zk1YSBqHJmqpdQLAh3vsyOIU+gP8jRsSnf3eubQqrsmKiaRzytdEtF3/3Af4Tzov
P8V2gdxMUW6WWPVZPgUY1r0CgYBoerilnAAFZn/5DITmWdn+W7Xk97Ocpgg6Vz1C
l6R7ZSWvso2C9OIFB09b94KE86IkdNAeyA9ekvOJAmpkkCiaeac2inajrEtfADlU
8no4nIviBNs0pV2vNDTeuusd22IL3giO+haVdf7kSDLZIW62d1oY/gAKkktL/MvW
aagtmQKBgFQJ8FhBmSU/pkl5cRLEySwFWv/SvK7/VPBB1KDnbqAFC3YV1J2EIghL
7Rq/s93NCBweb97e5SgH/IBPpWnlXzRGL5ApmwXuoPzp7PZokgw7Tv4X8SSjaOmP
ITfOx9KgntLukRe860E+CbkBxEhPD+2+GhtXL0d21o4JoS/YQb80
-----END RSA PRIVATE KEY-----
'''
        self.sshd_rsa_public_key = \
'''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzs9AxmS3r+zeJt01boLhlSvqTW5ITRdnlErZx92HRSDX4OQlGnxZN2wgo5Vjr02jWTfMoabsQW/HkmGZJfEVw+oyPX/41jD4l5PyrXwnM+uG8SYgqE/f7J1b4H7rDw8/a4Qik5L05fshJCCyAnYnYzjxo/ZoCR0CO07rUl6knp35Qe0NwXJFLs//Xv+jVB9ZqUCBt0ulm6rR6C5F51U7o5O6BMu73qDfDtOTvBq0s7QZFK0Y+VdE1HJlbgRHrGdSsbmVsRggJNghIDnItJgFvdNM/J9C/p+UP1IPrhdrySCS0aQMBszHvBroGJEx6yE0z64VEn9mKZwAp1QkzJh/h root@localhost
'''
        testlib.config_replace(self.sshd_rsa_private_keyfile, self.sshd_rsa_private_key)
        testlib.config_replace(self.sshd_rsa_private_keyfile + ".pub", self.sshd_rsa_public_key)

        self._restart_daemon()

        # create a user to log in via ssh
        self.user = testlib.TestUser()
        self.other_user = testlib.TestUser()
        self._create_ssh_dir(self.user)
        self._create_ssh_dir(self.other_user)

    def _create_ssh_dir(self, user):
        '''Creates a .ssh dir'''
        os.mkdir(user.home + "/.ssh", 0700)
        os.chown(user.home + "/.ssh", user.uid, user.gid)
        testlib.create_fill(user.home + "/.ssh/known_hosts",
                            "localhost,127.0.0.1 " + self.sshd_rsa_public_key)
        os.chown(user.home + "/.ssh/known_hosts", user.uid, user.gid)

    def _restart_daemon(self):

        if self.lsb_release['Release'] >= 15.04:
            rc, report = testlib.cmd(['systemctl', 'restart', 'ssh'])
            time.sleep(3)
        else:
            rc, report = testlib.cmd(['restart', 'ssh'])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _cmd_as_user(self, cmd):
        _cmd = ['sudo', '-i', '-u', self.user.login]
        _cmd.extend(cmd)
        return _cmd

    def run_ssh_cmd(self, cmd, use_password=True, other_user=False):

        if other_user == False:
            password = self.user.password
        else:
            password = self.other_user.password

        command = self._cmd_as_user(cmd)
        child = pexpect.spawn(command.pop(0), command, timeout=5)
        if use_password:
            ret = child.expect('password:');
            child.sendline(password)
        else:
            ret = child.expect('Enter passphrase.*:');
            child.sendline(self.privkey_pass)
        out = [line.strip('\r\n') for line in child.readlines()]
        child.close()
        # kill first line of output
        out.pop(0)

        return [child.exitstatus, out]

    def generate_ssh_keys(self, keytype='rsa', password=None):
        if not password:
            self.privkey_pass = testlib.random_string(8)
        else:
            self.privkey_pass = password
        command = self._cmd_as_user(["ssh-keygen", "-q", "-N", self.privkey_pass, '-t', keytype, '-f', self.user.home + "/.ssh/id_" + keytype])
        expected = 0
        rc, cmp_out = self.shell_cmd(command)
        self.assertEquals(expected, rc, cmp_out)

    def modify_sshd_config(self, items):
        '''take a list of key:value pairs and insert/replace into the sshd config'''

        contents = ""
        found = {}
        for line in file(self.sshd_config):
            for item in items.keys():
                if re.search("^\s*%s\s+" % (item), line):
                    found[item] = True
                    line = "%s %s\n" %(item, items[item])
                contents += line
        for item in items.keys():
            if not item in found.keys():
                contents += "%s %s\n" %(item, items[item])

        testlib.config_replace(self.sshd_config, contents)
        self._restart_daemon()

    def _simple_ssh_login(self, extra_args=None, use_password=True):
        expected = 0
        rc, cmp_out = self.shell_cmd(['cat', '/etc/lsb-release'])
        self.assertEquals(expected, rc, cmp_out)

        command = ['ssh']
        if extra_args:
            command.extend(extra_args)
        command.extend(['-x', 'localhost', 'cat', '/etc/lsb-release'])
        rc, out = self.run_ssh_cmd(command, use_password=use_password)
        self.assertEquals(expected, rc, out)
        self.assertEquals(cmp_out.splitlines(), out, out)


    def tearDown(self):
        '''Clean up after each test_* function'''

        testlib.config_restore(self.sshd_rsa_private_keyfile)
        testlib.config_restore(self.sshd_rsa_private_keyfile + ".pub")
        testlib.config_restore(self.sshd_config)
        self._restart_daemon()
        time.sleep(0.5)
        self.user = None
        self.other_user = None

    def test_00_sshd_listening(self):
        '''Test to ensure ssh is running'''
        self.assertTrue(testlib.check_port(22, 'tcp'))

    def test_10_simple_ssh_login(self):
        '''Test simple ssh login'''
        self._simple_ssh_login()

    def test_simple_ssh_login_compression(self):
        '''Test ssh login with compression'''
        self._simple_ssh_login(extra_args=['-C'])

    def test_simple_ssh_login_blowfish(self):
        '''Test ssh login with blowfish cipher'''

        if self.lsb_release['Release'] >= 15.04:
            return self._skipped("Skipped: No blowfish support in later releases")

        self._simple_ssh_login(extra_args=['-o', 'Ciphers=blowfish-cbc'])

    def test_simple_authorized_key_login(self):
        '''Test ssh authorized key login (rsa)'''

        self.generate_ssh_keys()
        shutil.copy2(self.user.home + "/.ssh/id_rsa.pub", self.user.home + "/.ssh/authorized_keys")

        self._simple_ssh_login(use_password=False)

    def test_simple_authorized_key_login_dsa(self):
        '''Test ssh authorized key login (dsa)'''

        self.generate_ssh_keys(keytype="dsa")
        shutil.copy2(self.user.home + "/.ssh/id_dsa.pub", self.user.home + "/.ssh/authorized_keys")

        if self.lsb_release['Release'] >= 16.04:
            return self._skipped("Skipped: No DSA support in later releases")

        self._simple_ssh_login(use_password=False)

    def test_no_passwords_login_authorized_keys(self):
        '''Test ssh login nopassword's w/authorized key'''

        self.modify_sshd_config({"PasswordAuthentication": "no"})
        self.generate_ssh_keys()
        shutil.copy2(self.user.home + "/.ssh/id_rsa.pub", self.user.home + "/.ssh/authorized_keys")

        self._simple_ssh_login(use_password=False)

    def test_server_side_ciphers(self):
        '''Test sshd restricted cipher set'''

        self.modify_sshd_config({"Ciphers": "aes256-cbc,blowfish-cbc"})
        self._simple_ssh_login()

    def test_no_agreed_upon_ciphers(self):
        '''Test when client and server can't agree on a cipher'''

        self.modify_sshd_config({"Ciphers": "aes256-cbc,blowfish-cbc"})

        command = self._cmd_as_user(['ssh', '-o', 'Ciphers=aes128-cbc', '-x', 'localhost', 'cat', '/etc/lsb-release'])
        child = pexpect.spawn(command.pop(0), command, timeout=5)
        try:
            ret = child.expect('no matching cipher found');
        except pexpect.TIMEOUT:
            self.assertTrue(False, "Didn't get expected 'no matching cipher found' message")
        finally:
            child.close()

    def test_no_zero_knowledge_auth_clientside_support(self):
        '''Test clientside zero knowledge (aka J-PAKE) support'''

        '''At some point in the future, support this will get enabled
           by upstream, and thus the testcase will need to change'''

        if self.lsb_release['Release'] >= 14.04:
            return self._skipped("Skipped: Need to fix for recent releases")

        command = self._cmd_as_user(['ssh', '-o', 'ZeroKnowledgePasswordAuthentication=yes', '-x', 'localhost', 'cat', '/etc/lsb-release'])
        child = pexpect.spawn(command.pop(0), command, timeout=5)
        try:
            ret = child.expect('Unsupported option "ZeroKnowledgePasswordAuthentication"');
        except pexpect.TIMEOUT:
            self.assertTrue(False, "Didn't get expected 'Unsupported option' message")
        ret = child.expect('password:');
        child.sendline(self.user.password)

        out = [line.strip('\r\n') for line in child.readlines()]
        child.close()
        # kill first line of output
        out.pop(0)

        expected = 0
        self.assertEquals(expected, child.exitstatus, out)

    def test_sshd_no_priv_sep(self):
        '''Test sshd with privilege seperation disabled'''

        self.modify_sshd_config({"UsePrivilegeSeparation": "no"})
        self._simple_ssh_login()

    def test_sshd_no_default_sshv1_support(self):
        '''Test sshv1 is disabled by default for sshd'''

        command = self._cmd_as_user(['ssh', '-1', '-x', 'localhost', 'cat', '/etc/lsb-release'])
        child = pexpect.spawn(command.pop(0), command, timeout=5)
        try:
            ret = child.expect('Protocol major versions differ:');
        except pexpect.TIMEOUT:
            self.assertTrue(False, "Didn't get expected 'Protocol major versions differ:' message")
        finally:
            child.close()

    def test_simple_root_login(self):
        '''Test ssh login to root'''

        self.modify_sshd_config({"PermitRootLogin": "yes"})
        self.generate_ssh_keys()
        if os.path.exists("/root/.ssh"):
            testlib.config_copydir("/root/.ssh")
            root_ssh_exists = True
        else:
            os.mkdir("/root/.ssh", 0700)
            root_ssh_exists = False

        shutil.copy2(self.user.home + "/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")
        os.chown("/root/.ssh/authorized_keys", 0, 0)

        try:
	        expected = 0
	        rc, out = self.run_ssh_cmd(['ssh', '-x', 'root@localhost', 'id', '-u'], use_password=False)
	        self.assertEquals(expected, rc, out)
	        self.assertEquals(["0"], out, out)

        finally:
	        testlib.recursive_rm("/root/.ssh")
	        if root_ssh_exists:
	            testlib.config_restore("/root/.ssh")

    def test_simple_deny_root_login(self):
        '''Test deny ssh login to root'''

        self.modify_sshd_config({"PermitRootLogin": "no"})
        self.generate_ssh_keys()
        if os.path.exists("/root/.ssh"):
            testlib.config_copydir("/root/.ssh")
            root_ssh_exists = True
        else:
            os.mkdir("/root/.ssh", 0700)
            root_ssh_exists = False

        shutil.copy2(self.user.home + "/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys")
        os.chown("/root/.ssh/authorized_keys", 0, 0)

        try:
            expected = 1
            rc, out = self.run_ssh_cmd(['ssh', '-x', 'root@localhost', 'id', '-u'], use_password=False)
            self.assertEquals(expected, rc, out)
            #self.assertEquals(["0"], out, out)
        except pexpect.TIMEOUT:
            pass
        else:
            self.assertNotEquals(["0"], out, out)
        finally:
            testlib.recursive_rm("/root/.ssh")
            if root_ssh_exists:
                testlib.config_restore("/root/.ssh")

    def test_no_passwords_login_rejection(self):
        '''Test ssh login rejection w/password'''

        self.modify_sshd_config({"PasswordAuthentication": "no"})
        #os.chown(self.user.home + "/.ssh/authorized_keys", self.user.uid, self.user.gid)

        expected = 0
        rc, cmp_out = self.shell_cmd(['cat', '/etc/lsb-release'])
        self.assertEquals(expected, rc, cmp_out)

        try:
            expected = 1
            rc, out = self.run_ssh_cmd(['ssh', 'localhost', 'cat', '/etc/lsb-release'])
            self.assertEquals(expected, rc, out)
        except pexpect.EOF:
            pass

    def test_sendenv(self):
        '''Test ssh SendEnv with whitelisted variable'''

        # Ubuntu comes with "AcceptEnv LANG LC_*" by default, so use that
        magic = 'ubunturocks'
        match = ["LC_QRT='%s'" % magic]

        try:
            expected = 0
            # We use grep here because trying to escape the $ is a PITA
            # and behaves differently on older releases for some reason
            rc, out = self.run_ssh_cmd(['env', 'LC_QRT=%s' % magic, 'ssh',
                                        '-o', 'SendEnv=LC_QRT',
                                        '-l', self.other_user.login,
                                        'localhost', 'set | grep LC_QRT'],
                                        other_user=True)
            self.assertEquals(expected, rc, out)
            error = "Variable '%s' didn't match expected '%s'!" % (out, match)
            self.assertEquals(out, match, error)
        except pexpect.EOF:
            pass

    def test_sendenv_deny(self):
        '''Test ssh SendEnv with non-whitelisted variable'''

        magic = 'ubunturocks'
        match = ["NWL_QRT='%s'" % magic]

        try:
            expected = 1
            rc, out = self.run_ssh_cmd(['env', 'NWL_QRT=%s' % magic, 'ssh',
                                        '-o', 'SendEnv=NWL_QRT',
                                        '-l', self.other_user.login,
                                        'localhost', 'set | grep NWL_QRT'],
                                        other_user=True)
            self.assertEquals(expected, rc, out)
            error = "Variable '%s' matched expected '%s'!" % (out, match)
            self.assertNotEquals(out, match, error)
        except pexpect.EOF:
            pass

    def test_cve_2016_0777(self):
        '''Test CVE-2016-0777'''

        command = ['ssh', '-v', '-o', 'PasswordAuthentication=no', '-x',
                   'localhost', 'cat', '/etc/lsb-release']
        rc, out = self.shell_cmd(self._cmd_as_user(command))

        # See if we've connected
        self.assertTrue("Connection established" in out,
                        "Couldn't establish connection in '%s'" % out)
        # Make sure roaming is disabled
        self.assertFalse("Roaming not allowed by server" in out,
                         "Roaming isn't disabled in '%s'" % out)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenSSHTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PrivateOpenSSHTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
