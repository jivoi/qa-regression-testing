#!/usr/bin/python
#
#    test-python-pam.py quality assurance test script for python-pam
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: python-pam
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: python-pam
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-python-pam.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-python-pam.py -v'
'''


import unittest, sys, PAM
import testlib

try:
    from private.qrt.pythonpam import PrivatePythonpamTest
except ImportError:
    class PrivatePythonpamTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PythonpamTest(testlib.TestlibCase, PrivatePythonpamTest):
    '''Test python-pam.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        # Create a system user key
        self.user = testlib.TestUser()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None

    def _pam_callback(self, auth, query_list, userData):
        '''Callback for pam'''
        resp = []

        for i in range(len(query_list)):
            query, type = query_list[i]
            if type == PAM.PAM_PROMPT_ECHO_OFF:
                if "Password:" in query:
                    val = self.user.password
                    resp.append((val, 0))
            else:
                return None

        return resp

    def test_pam_authentication(self):
        '''Test pam authentication'''

        service = 'passwd'

        auth = PAM.pam()
        auth.start(service)

	auth.set_item(PAM.PAM_USER, self.user.login)
        auth.set_item(PAM.PAM_CONV, self._pam_callback)

        auth.authenticate()
        auth.acct_mgmt()

    def test_cve_2011_1502(self):
        '''Test CVE-2012-1502'''

        # We use an external helper here so our main script doesn't
        # segfault
        (rc, report) = testlib.cmd(['./python-pam/pamtest.py', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
