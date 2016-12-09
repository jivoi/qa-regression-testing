#!/usr/bin/python
#
#    test-dash.py quality assurance test script for dash
#    Copyright (C) 2009 Canonical Ltd.
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

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release  && ./test-dash.py -v'
'''
# QRT-Privilege: root

import unittest, sys, os
import testlib

class DashTest(testlib.TestlibCase):
    '''Test Dash.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_double_profile_root(self):
        '''Test dash parsing profile twice under root'''

        roothome = os.environ.get('HOME','/')
        self.assertEquals(roothome, "/root", "Root user's home directory is not '/root': '%s'" % (roothome))
        os.chdir(roothome)

        rc, report = testlib.cmd(['/bin/dash', '-l', '-c', 'pwd'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Didn't find '%s' in report: " % system_string
        self.assertTrue(system_string in report, result + report)

        result = "Incorrect number of '%s' in report: " % root_string
        self.assertTrue(report.count(root_string) == 1, result + report)

    def test_double_profile_user(self):
        '''Test dash parsing profile twice under a regular user'''

        os.chdir(test_user.home)

        rc, report = testlib.cmd(['su', '-c', '/bin/dash -l -c pwd', test_user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Didn't find '%s' in report: " % system_string
        self.assertTrue(system_string in report, result + report)

        result = "Incorrect number of '%s' in report: " % user_string
        self.assertTrue(report.count(user_string) == 1, result + report)

if __name__ == '__main__':
    ## Set up

    system_string = "This is /etc/profile"
    root_string = "This is /root/.profile"
    user_string = "This is /home/user/.profile"

    # Create a test user
    test_user = testlib.TestUser()

    # Change /etc/profile
    testlib.config_replace('/etc/profile','''
echo "%s"
''' % system_string, append=True)

    # Change the user's profile
    testlib.config_replace(test_user.home + '/.profile','''
echo "%s"
''' % user_string, append=True)

    # Change root's profile
    testlib.config_replace('/root/.profile','''
echo "%s"
''' % root_string, append=True)

    mydir = os.getcwd()

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DashTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    # Clean up
    print 'clean up'
    test_user = None
    testlib.config_restore('/etc/profile')
    testlib.config_restore('/root/.profile')

    os.chdir(mydir)

    if not rc.wasSuccessful():
        sys.exit(1)
