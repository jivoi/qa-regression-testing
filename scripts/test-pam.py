#!/usr/bin/python
#
#    test-pam.py quality assurance test script for pam
#    Copyright (C) 2011 Canonical Ltd.
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
# QRT-Packages: python-pexpect
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) and not
    on a production machine. While efforts are made to make these tests
    non-destructive, there is no guarantee this script will not alter the
    machine. You have been warned.

    A pam update that introduces ABI changes may break cron. The cron test
    in this script will attempt to run a cron job to make sure it is still
    functional. In order for this test to be accurate, the cron daemon must
    have been started with the original pam packages, and left running
    without a reboot or a restart after the pam packages have been updated.

    How to run in a clean VM:
    $ sudo apt-get -y install lsb-release <QRT-Packages> && sudo ./test-pam.py -v'
'''


import unittest, subprocess, sys, os, time, stat, tempfile
import pexpect
import testlib

try:
    from private.qrt.Pam import PrivatePamTest
except ImportError:
    class PrivatePamTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PamTest(testlib.TestlibCase, PrivatePamTest):
    '''Test pam.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.pam_su = "/etc/pam.d/su"
        self.pam_login = "/etc/pam.d/login"
        self.user = testlib.TestUser(shell="/bin/bash")
        self.userB = testlib.TestUser(shell="/bin/bash")
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        self.cronfile = "/etc/cron.d/testlib-crontest"
        if os.path.exists(self.cronfile):
            os.unlink(self.cronfile)

    def tearDown(self):
        '''Clean up after each test_* function'''

        # clean up mail file and maildir
        for username in (self.user.login, self.userB.login):
            mail_dir = os.path.join('/var/mail', username)
            if os.path.exists(mail_dir):
                if stat.S_ISREG(os.lstat(mail_dir).st_mode):
                    os.unlink(mail_dir)
                else:
                    testlib.recursive_rm(mail_dir)

        # clean up cron file
        if os.path.exists(self.cronfile):
            os.unlink(self.cronfile)

        self.user = None
        self.userB = None
        testlib.config_restore(self.pam_su)
        testlib.config_restore(self.pam_login)

    def _login(self, password, extra_command=None):
        sent_command = False
        child = pexpect.spawn('login')
        while 1:
            # 'Login incorrect' needs to come before the login prompt because we'll match both
            rc = child.expect([pexpect.TIMEOUT, '.*Login incorrect', '.* (?i)login: ', '(?i)password: ', '.*\$ ', pexpect.EOF], timeout=10)
            if rc == 0: # Timeout
                report = str(child.before) + str(child.after)
                break
            if rc == 1: # Login incorrect
                report = child.before + child.after
                break
            if rc == 2: # Login prompt
                child.sendline(self.user.login)
            if rc == 3: # Password prompt
                child.sendline(password)
            if rc == 4: # Command prompt
                if extra_command != None and sent_command == False:
                    child.sendline(extra_command)
                    sent_command = True
                else:
                    child.sendline('exit')
                    report = child.before + child.after
                    break
            if rc == 5: # EOF
                report = child.before
                break

        child.close(force=True)
        return rc, report

    def _double_su(self, userA, userB, password, command):
        sent_command = False
        second_user = False
        child = pexpect.spawn('su - ' + userA)
        while 1:
            # 'Login incorrect' needs to come before the login prompt because we'll match both
            rc = child.expect([pexpect.TIMEOUT, '(?i)password: ', '.*\$ '], timeout=10)
            if rc == 0: # Timeout
                report = child.before + child.after
                break
            if rc == 1: # Password prompt
                child.sendline(password)
            if rc == 2: # Command prompt
                if second_user == False:
                    child.sendline('su - ' + userB)
                    second_user = True
                elif sent_command == False:
                    child.sendline(command)
                    sent_command = True
                else:
                    child.sendline('exit')
                    report = child.before + child.after
                    break

        child.close(force=True)
        return rc, report

    def _get_mail(self, username):
        rc, report = testlib.cmd(['su', '-', username, '-c', 'exit'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        return report

    def test_login(self):
        '''Test login'''
        expected = 4
        rc, report = self._login(self.user.password)
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

    def test_bad_login(self):
        '''Test bad login'''
        expected = 1
        rc, report = self._login('foo')
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

    def test_pam_env(self):
        '''Test pam_env module'''

        # Trusty and higher no longer default to user env files
        if self.lsb_release['Release'] >= 14.04:
            testlib.config_replace(self.pam_login, "", True)
            subprocess.call(['sed', '-i',
                's/pam_env.so readenv=1/pam_env.so readenv=1 user_readenv=1/',
                 self.pam_login])

        open(os.path.join(self.user.home, '.pam_environment'),'w').write("QRT=qrtuser")

        expected = 4
        rc, report = self._login(self.user.password, extra_command="echo $QRT")
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

        self._word_find(report, "qrtuser")

    def test_cve_2010_3435_1(self):
        '''Test CVE-2010-3435 - pam_env'''

        # Create a file only readable by root and symlink to it
        root_file = '/etc/qrtbad.txt'
        open(root_file,'w').write("QRT=qrtroot")
        os.chmod(root_file, 0400)
        os.symlink(root_file, os.path.join(self.user.home, '.pam_environment'))

        expected = 4
        rc, report = self._login(self.user.password, extra_command="echo $QRT")
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

        self._word_find(report, "qrtroot", invert=True)

    def test_cve_2011_3148(self):
        '''Test CVE-2011-3148 - pam_env'''

        # Trusty and higher no longer default to user env files
        if self.lsb_release['Release'] >= 14.04:
            testlib.config_replace(self.pam_login, "", True)
            subprocess.call(['sed', '-i',
                's/pam_env.so readenv=1/pam_env.so readenv=1 user_readenv=1/',
                 self.pam_login])

        bad_line = " " * 256 + "\\"
        big_bad_line = bad_line * 4 + "A" * 256
        big_bad_file = big_bad_line + "\nQRT=qrttest"

        open(os.path.join(self.user.home, '.pam_environment'),'w').write(big_bad_file)

        expected = 4
        rc, report = self._login(self.user.password, extra_command="echo $QRT")
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

        self._word_find(report, "qrttest")

    def test_cve_2011_3149(self):
        '''Test CVE-2011-3149 - pam_env'''

        # Trusty and higher no longer default to user env files
        if self.lsb_release['Release'] >= 14.04:
            testlib.config_replace(self.pam_login, "", True)
            subprocess.call(['sed', '-i',
                's/pam_env.so readenv=1/pam_env.so readenv=1 user_readenv=1/',
                 self.pam_login])

        evil_filler = '''EVIL_FILLER_255 DEFAULT=''' + "B" * 255 + '''
EVIL_FILLER_256 DEFAULT=${EVIL_FILLER_255}B
EVIL_FILLER_1024 DEFAULT=${EVIL_FILLER_256}${EVIL_FILLER_256}${EVIL_FILLER_256}${EVIL_FILLER_256}
EVIL_FILLER_8191 DEFAULT=${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_1024}${EVIL_FILLER_256}${EVIL_FILLER_256}${EVIL_FILLER_256}${EVIL_FILLER_255}
EVIL_OVERFLOW_DOS DEFAULT=${EVIL_FILLER_8191}AAAA
'''
        big_bad_file = evil_filler + "\nQRT=qrttest"

        open(os.path.join(self.user.home, '.pam_environment'),'w').write(big_bad_file)

        expected = 5
        rc, report = self._login(self.user.password, extra_command="echo $QRT")
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

    def test_pam_xauth(self):
        '''Test pam_xauth module'''

        contents = "session optional pam_xauth.so"
        testlib.config_replace(self.pam_su, contents, True)

        # Make sure the test user doesn't inherit ours when we su -
        if 'XAUTHORITY' in os.environ:
            del os.environ['XAUTHORITY']

        # Create a bogus xauth file for the first user
        rc, report = testlib.cmd(['su', '-', self.user.login, '-c', 'xauth add localhost:0 . 123456'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure $DISPLAY is set
        testlib.config_replace(os.path.join(self.user.home, ".bashrc"), "export DISPLAY=localhost:0", True)

        # Do the insanity
        rc, report = self._double_su(self.user.login, self.userB.login, self.userB.password, 'xauth list')
        self._word_find(report, "123456")

        # Validate permissions
        rc, report = self._double_su(self.user.login, self.userB.login, self.userB.password, 'ls -al .xauth*')
        self._word_find(report, "-rw------- 1 %s %s" % (self.userB.login, self.userB.login))

    def test_cve_2011_3628(self):
        '''Test CVE-2011-3628 - pam_motd'''

        contents = "session optional pam_motd.so"
        testlib.config_replace(self.pam_su, contents, True)

        user_bindir = os.path.join(self.user.home, 'bin')
        user_hackfile = os.path.join(self.user.home, 'hackfile')
        user_evil_env = os.path.join(user_bindir, 'env')
        user_evil_run_parts = os.path.join(user_bindir, 'run-parts')
        os.mkdir(user_bindir)

        # run-parts in original version, env in incomplete fix
        open(user_evil_env, 'w').write("touch %s" % user_hackfile)
        os.chmod(user_evil_env, 0755)
        open(user_evil_run_parts, 'w').write("touch %s" % user_hackfile)
        os.chmod(user_evil_run_parts, 0755)

        expected = 2
        rc, report = self._double_su(self.user.login, self.userB.login, self.userB.password, command="ls -l %s" % user_hackfile)
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

        self._word_find(report, "No such file")

    def test_pam_mail(self):
        '''Test pam_mail module'''

        testlib.config_replace(self.pam_su, "", True)
        subprocess.call(['sed', '-i', 's/pam_mail.so nopen/pam_mail.so standard/', self.pam_su])

        # make sure we don't have any mail right now
        report = self._get_mail(self.user.login)
        self._word_find(report, "You have", invert=True)
        self._word_find(report, "No mail.", invert=True)

        # Create a bogus mail file
        user_mail_file = os.path.join('/var/mail', self.user.login)
        testlib.cmd(['touch', user_mail_file])

        # We shouldn't have new mail
        report = self._get_mail(self.user.login)
        self._word_find(report, "You have", invert=True)
        self._word_find(report, "No mail.")

        # Append to the file to create some new mail
        open(user_mail_file,'w').write("Thisisnewmail")
        report = self._get_mail(self.user.login)
        self._word_find(report, "You have")
        self._word_find(report, "No mail.", invert=True)

    def test_cve_2010_3435_2(self):
        '''Test CVE-2010-3435 - pam_mail'''

        testlib.config_replace(self.pam_su, "", True)
        subprocess.call(['sed', '-i', 's/pam_mail.so nopen/pam_mail.so standard/', self.pam_su])

        # Create some bogus maildir mail
        user_mail_dir = os.path.join('/var/mail', self.user.login)
        user_mail_dir_new = os.path.join(user_mail_dir, 'new')
        os.mkdir(user_mail_dir)
        os.mkdir(user_mail_dir_new)
        testlib.cmd(['touch', os.path.join(user_mail_dir_new, 'bogusmail1')])
        testlib.cmd(['touch', os.path.join(user_mail_dir_new, 'bogusmail2')])

        # su to the user to get the "new mail" message
        report = self._get_mail(self.user.login)
        self._word_find(report, "You have")
        self._word_find(report, "No mail.", invert=True)

        # Now, remove permissions and try again
        os.chmod(user_mail_dir, 0400)
        report = self._get_mail(self.user.login)
        self._word_find(report, "You have", invert=True)
        self._word_find(report, "No mail.")

    def test_cron(self):
        '''Test that cron still works'''

        # Create cron file and script
        script = os.path.join(self.tmpdir, "test.sh")
        works = os.path.join(self.tmpdir, "it_works")
        contents = '''#!/bin/sh
set -e
touch %s
''' % (works)
        testlib.create_fill(script, contents, mode=0755)

        contents = "* * * * *	root	%s\n" % (script)
        testlib.create_fill(self.cronfile, contents)

        # Wait for result
        timeout = 130
        print "\n  Waiting for result from cron (max %d seconds)..." % (timeout)

        while (timeout > 0):
            if(os.path.exists(works)):
                break
            else:
                timeout -= 5
                time.sleep(5)

        self.assertTrue(os.path.exists(works), "'%s' does not exist" % (works))

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
