#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    test-shadow.py quality assurance test script for shadow
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: python-pexpect language-pack-en
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install python-pexpect && ./test-shadow.py -v'

    NOTE: pexpect on dapper seems to suffer from timing issues (which is why
          all the time.sleep(0.2) are in place)
'''

import unittest, sys
import testlib
import pexpect
import time
import crypt
import os
import re

class LoginTest(testlib.TestlibCase):
    '''Test login package functionality'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None

    def _test_login(self, password):
        child = pexpect.spawn('login')
        time.sleep(0.2)
        child.expect('.* (?i)login: ', timeout=5)
        time.sleep(0.2)
        child.sendline(self.user.login)
        time.sleep(0.2)
        child.expect('(?i)password: ', timeout=5)
        time.sleep(0.2)
        rc = child.sendline(password)
        time.sleep(0.2)
        try:
            i = child.expect('.*\$', timeout=5)
            time.sleep(0.2)
            child.sendline('exit')
        except:
            pass

        time.sleep(0.2)
        child.kill(0)
        return rc

    def test_login(self):
        '''Test login'''
        expected = 9
        rc = self._test_login(self.user.password)
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

    def test_bad_login(self):
        '''Test bad login'''
        expected = 4
        rc = self._test_login('foo')
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

    def test_faillog(self):
        '''Test faillog'''
        rc, report = testlib.cmd(['faillog', '-a'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['faillog', '-u', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Couldn't find 'Failures' in report"
        self.assertTrue('Failures' in report, result + report)

    def test_lastlog(self):
        '''Test lastlog'''

        # First, simulate a login...
        expected = 9
        rc = self._test_login(self.user.password)
        self.assertEquals(rc, expected, "login returned %d (!=%d)" %(rc,expected))

        # Now validate the user was seen
        rc, report = testlib.cmd(['lastlog'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Couldn't find 'Latest' in report"
        self.assertTrue('Latest' in report, result + report)
        self.assertTrue(re.search('\n%s +pts/' % (self.user.login), report), "Did not see %s:\n" % (self.user.login) + report)
        self.assertFalse(re.search('\nnobody +pts/', report), "Saw 'nobody' unexpectedly:\n" + report)

    def test_newgrp(self):
        '''Test newgrp'''
        child = pexpect.spawn('newgrp daemon')
        time.sleep(0.2)
        child.expect('.*# ', timeout=5)
        time.sleep(0.2)
        child.sendline('id')
        time.sleep(0.2)
        child.expect('.*# ', timeout=5)
        time.sleep(0.2)
        report = child.after
        child.kill(0)

        result = "Couldn't find 'daemon' in report:\n"
        self.assertTrue('daemon' in report, result + report)

    def test_su(self):
        '''Test su'''
        rc, report = testlib.cmd(['su', '-c', 'ls /', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if self.lsb_release['Release'] == 6.06:
            rc, report = testlib.cmd(['su', '-c', 'ls /', self.user.login])
        else:
            rc, report = testlib.cmd(['su', '-l', '-c', 'ls /', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['su', '-m', '-c', 'ls /', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_sg(self):
        '''Test sg'''
        rc, report = testlib.cmd(['sg', 'daemon', '-c', 'ls /'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


class PasswdTest(testlib.TestlibCase):
    '''Test passwd package functionality'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        os.environ['LANG'] = 'en_US.UTF-8'
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None

    def test_chage(self):
        '''Test chage'''
        rc, report = testlib.cmd(['chage', '-l', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Couldn't find 'expires' in report"
        self.assertTrue('expires' in report, result + report)

        rc, report = testlib.cmd(['chage', '-d', '2006-01-01', \
                                  '--inactive', '14', \
                                  '--mindays', '42', \
                                  '--maxdays', '43', \
                                  '--warndays', '44', \
                                  '-E', '2020-01-02',
                                  self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['chage', '-l', self.user.login])
        for i in ['Jan 01','Jan 02','Feb 13','Feb 27','42','43','44']:
            result = "Couldn't find '%s' in report" % (i)
            self.assertTrue(i in report, result + report)

        rc, report = testlib.cmd(['chage', '-E', '-1', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['chage', '-l', self.user.login])
        result = "Couldn't find 'never' in report"
        self.assertTrue('never' in report, result + report)

    def test_passwd(self):
        '''Test passwd'''
        rc, report = testlib.cmd(['chage', '-d', '2006-01-01', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['passwd', \
                                  '--inactive', '14', \
                                  '--mindays', '42', \
                                  '--maxdays', '43', \
                                  '-w', '44', \
                                  self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['chage', '-l', self.user.login])
        for i in ['Jan 01','Feb 13','Feb 27','42','43','44']:
            result = "Couldn't find '%s' in report" % (i)
            self.assertTrue(i in report, result + report)

        password = testlib.random_string(8,lower=False)
        child = pexpect.spawn('passwd ' + self.user.login)
        time.sleep(0.2)
        child.expect('.* (?i)password: ', timeout=5)
        time.sleep(0.2)
        child.sendline(password)
        time.sleep(0.2)
        child.expect('.* (?i)password: ', timeout=5)
        time.sleep(0.2)
        child.sendline(password)
        time.sleep(0.2)
        rc = child.expect('.* successfully', timeout=5)
        time.sleep(0.2)
        self.assertEquals(rc, expected, "passwd returned %d" %(rc))

        child.kill(0)

        child = pexpect.spawn('login')
        time.sleep(0.2)
        child.expect('.* (?i)login: ', timeout=5)
        time.sleep(0.2)
        child.sendline(self.user.login)
        time.sleep(0.2)
        child.expect('(?i)password: ', timeout=5)
        time.sleep(0.2)
        rc = child.sendline(password)
        time.sleep(0.2)
        try:
            i = child.expect('.*\$', timeout=5)
            time.sleep(0.2)
            child.sendline('exit')
        except:
            expected = 9
            self.assertEquals(rc, expected, "login returned %d" %(rc))

        time.sleep(0.2)
        child.kill(0)

    def test_expiry(self):
        '''Test expiry'''
        rc, report = testlib.cmd(['expiry', '-c'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_grpck(self):
        '''Test grpck'''
        rc, report = testlib.cmd(['grpck','-r']) # don't prompt for fixes
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_pwck(self):
        '''Test pwck'''
        rc, report = testlib.cmd(['pwck', '-qr'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # FIXME: add a negative test for corrupted /etc/passwd entry

    def _perform_chfn(self, login, opt_f, opt_r, opt_w, opt_h, opt_o, expected=0):
        rc, report = testlib.cmd(['chfn', '-f', opt_f, '-r', opt_r, '-w', opt_w, '-h', opt_h, '-o', opt_o, login])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['grep', '^%s:' % (login), '/etc/passwd'])
        for i in [opt_f, opt_r, opt_w, opt_h, opt_o]:
            if expected == 0:
                result = "Couldn't find '%s' in /etc/passwd!\n" % (i)
            else:
                result = "Found '%s' in /etc/passwd!\n" % (i)
            self.assertEquals(expected == 0, i in report, result + report)

    def test_chfn(self):
        '''Test chfn'''
        self._perform_chfn(self.user.login, 'abcdef', 'ghijkl', '777-8888', '555-6666', 'mnopqr')

    def test_chfn_locale_sanity(self):
        '''Make sure that chfn cannot include special characters (CVE-2011-0721)'''

        # Non-ASCII support was added in shadow 4.1.2
        expected = 0
        if self.lsb_release['Release'] <= 8.04:
            expected = 1
        self._perform_chfn(self.user.login, 'éä młowczaj ůōṫ', '1hijkl', '177-8888', '155-6666', '1nopqr', expected=expected)

        self._perform_chfn(self.user.login, ':::', '2hijkl', '277-8888', '255-6666', '2nopqr', expected=1)
        self._perform_chfn(self.user.login, '1\n2', '3hijkl', '377-8888', '355-6666', '3nopqr', expected=1)


    def test_chsh(self):
        '''Test chsh'''
        rc, report = testlib.cmd(['chsh', '-s', '/bin/sh', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['tail', '-1', '/etc/passwd'])
        result = "Couldn't find '/bin/sh' in report"
        self.assertTrue('/bin/sh' in report, result + report)

    def test_pwconv(self):
        '''Test pwconv'''
        str = self.user.login + ":x:"

        rc, report = testlib.cmd(['pwunconv'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['tail', '-1', '/etc/passwd'])
        result = "Found '%s' in report" % (str)
        self.assertFalse(str in report, result + report)

        rc, report = testlib.cmd(['pwconv'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['tail', '-1', '/etc/passwd'])
        result = "Couldn't find '%s' in report" % (str)
        self.assertTrue(str in report, result + report)

    def test_grpconv(self):
        '''Test grpconv'''
        str = "daemon:x:"

        rc, report = testlib.cmd(['grpunconv'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['cat', '/etc/group'])
        result = "Found '%s' in report" % (str)
        self.assertFalse(re.search('^%s' % (str), report, re.MULTILINE), result + report)

        rc, report = testlib.cmd(['grpconv'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['cat', '/etc/group'])
        result = "Couldn't find '%s' in report" % (str)
        self.assertTrue(re.search('^%s' % (str), report, re.MULTILINE), result + report)


class UserTest(testlib.TestlibCase):
    '''Test user* package functionality'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.login = 't' + testlib.random_string(7,lower=False)
        self.assertFalse(testlib.login_exists(self.login))

        self.salt = testlib.random_string(2)
        self.password = testlib.random_string(8,lower=False)
        self.crypted = crypt.crypt(self.password, self.salt)

        rc, report = testlib.cmd(['useradd', \
                                  '-c', 'Buddy %s' % (self.login), \
                                  '-p', self.crypted, \
                                  '-m', \
                                  '-G', 'adm', \
                                  '-s', '/bin/sh', \
                                  self.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if testlib.login_exists(self.login):
            testlib.cmd(['userdel', '-f', '-r', self.login])
        self.user = None

    def test_useradd(self):
        '''Test useradd/del/mod'''
        rc, report = testlib.cmd(['useradd', '-D'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['tail', '-1', '/etc/passwd'])
        result = "Couldn't find '/bin/sh' in report"
        self.assertTrue('/bin/sh' in report, result + report)

        rc, report = testlib.cmd(['cat', '/etc/group'])
        result = "Couldn't find '%s' in report in adm group" % (self.login)
        self.assertTrue(re.search('^adm:.*%s$' % (self.login), report, re.MULTILINE), result + report)

        rc, report = testlib.cmd(['cat', '/etc/passwd'])
        result = "Couldn't find '%s:' in report" % (self.login)
        self.assertTrue(self.login in report, result + report)

        rc, report = testlib.cmd(['cat', '/etc/group'])
        result = "Couldn't find '%s:' in report" % (self.login)
        self.assertTrue(self.login in report, result + report)

        home = os.path.join("/home", self.login)
        self.assertTrue(os.path.isdir(home))
        self.assertTrue(os.path.exists(os.path.join(home, '.bashrc')))

        rc, report = testlib.cmd(['usermod', '-s', '/bin/bash', self.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        rc, report = testlib.cmd(['tail', '-1', '/etc/passwd'])
        result = "Couldn't find '/bin/bash' in report"
        self.assertTrue('/bin/bash' in report, result + report)

        # useradd on karmic and newer (possibly older releases as well) does not
        # create an empty /var/mail/ mailbox
        if not os.path.exists('/var/mail/' + self.login):
            open('/var/mail/' + self.login, 'a').close()

        rc, report = testlib.cmd(['userdel', '-f', '-r', self.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['cat', '/etc/passwd'])
        result = "Couldn't find '%s:' in report" % (self.login)
        self.assertFalse(self.login in report, result + report)

        rc, report = testlib.cmd(['cat', '/etc/group'])
        result = "Couldn't find '%s:' in report" % (self.login)
        self.assertFalse(self.login in report, result + report)

        self.assertFalse(os.path.isdir(home))
        self.assertFalse(os.path.exists(os.path.join(home, '.bashrc')))


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LoginTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PasswdTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UserTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
