#!/usr/bin/python
#
#    test-procmail.py quality assurance test script for procmail
#    Copyright (C) 2014 Canonical Ltd.
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
# QRT-Packages: procmail
# QRT-Depends: procmail

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    ### TODO: ###
    * This only currently tests the formail tool, should add tests for the
      actual procmail binary also.
'''


import os
import subprocess
import sys
import unittest
import testlib

try:
    from private.qrt.procmail import PrivateProcmailTest
except ImportError:
    class PrivateProcmailTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class ProcmailTest(testlib.TestlibCase, PrivateProcmailTest):
    '''Test procmail.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpname = None

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpname):
            os.unlink(self.tmpname)

    def _run_formail(self, contents, split=False, expected=0, search=None):
        '''Test formail tool'''

        handle, self.tmpname = testlib.mkstemp_fill(contents)

        if split == True:
            command = ['formail', '-s']
        else:
            command = ['formail']

        rc, report = testlib.cmd(command, stdin=handle)

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != None:
            result = 'Could not find "%s" in output "%s"\n' % (search, report)
            self.assertTrue(search in report, result)

    def test_cve_2014_3618_1(self):
        '''Test CVE-2014-3618 Part 1'''

        contents = '''From a@a Tue Mar 19 12:12:12 2013
Message-ID: <a@example.com"
From: aaaaaaaaaaaaaaaaa <nobody@example.com"
To: <nobody@example.com"

a
'''

        self._run_formail(contents = contents,
                          search = contents)

    def test_cve_2014_3618_2(self):
        '''Test CVE-2014-3618 Part 2'''

        contents = '''From a@a Tue Mar 19 12:12:12 2013
Message-ID: <a@example.com>
From: aaaaaaaaaaaaaaaaa <nobody@example.com>
To: <nobody@example.com>

a
'''

        self._run_formail(contents = contents,
                          search = contents)

    def test_cve_2014_3618_3(self):
        '''Test CVE-2014-3618 Part 3'''

        contents = '''From a@a Tue Mar 19 12:12:12 2013
Message-ID: "a@example.com>
From: aaaaaaaaaaaaaaaaa "nobody@example.com>
To: "nobody@example.com>

a
'''

        self._run_formail(contents = contents,
                          search = contents)

    def test_cve_2014_3618_4(self):
        '''Test CVE-2014-3618 Part 4'''

        contents = open('./procmail/CVE-2014-3618/mbox').read()

        self._run_formail(contents = contents,
                          split = True,
                          search = contents)


if __name__ == '__main__':

    print >>sys.stderr, "Please also consider running test-postfix.py and test-dovecot.py"

    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
