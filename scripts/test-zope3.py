#!/usr/bin/python
#
#    test-zope3.py quality assurance test script for zope3
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
# packages required for test to run:
# QRT-Packages: elinks zope3
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends:
# QRT-Deprecated: 10.04

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release elinks zope3  && ./test-zope3.py -v'

    TODO: Actually test zope functionnality.
'''


import os
import subprocess
import sys
import time
import unittest

import testlib

try:
    from private.qrt.zope3 import PrivateZope3Test
except ImportError:
    class PrivateZope3Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class Zope3Test(testlib.TestlibCase, PrivateZope3Test):
    '''Test zope3.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.zope_instance = "/var/lib/zope3/instance/testinstance"
        self.zope_zdaemon = os.path.join(self.zope_instance, 'etc/zdaemon.conf')
        self.zope_logfile = os.path.join(self.zope_instance, 'log/z3.log')
        self.zope_transcriptfile = os.path.join(self.zope_instance, 'log/transcript.log')
        self.zope_port = '8080'
        self.zope_admin_user = "adminuser"
        self.zope_admin_pass = testlib.random_string(12)
        self.daemon = testlib.TestDaemon("/etc/init.d/zope3")

        # Make sure we're stopped
        rc, result = self.daemon.stop()

        # Empty out the instance directory if it already exists
        if os.path.exists(self.zope_instance):
            testlib.recursive_rm(self.zope_instance)

        # Create the instance
        (rc, report) = testlib.cmd(['/usr/lib/zope3/bin/mkzopeinstance', '-d', self.zope_instance,
                                    '-u', self.zope_admin_user + ':' + self.zope_admin_pass,
                                    '--service-port=' + self.zope_port, '-m', 'Plain Text'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Work around bug #356137 in jaunty
        if self.lsb_release['Release'] == 9.04:
            subprocess.call(['sed', '-i', 's/^define ZOPE_USER/%define ZOPE_USER/', self.zope_zdaemon])

        # Start the instance
        rc, result = self.daemon.start()

        report = 'Init script reported no instances found.\n'
        self.assertFalse('no instances found' in result, result + report)
        time.sleep(2)

    def tearDown(self):
        '''Clean up after each test_* function'''
        rc, result = self.daemon.stop()

        # Empty out the instance directory
        if os.path.exists(self.zope_instance):
            testlib.recursive_rm(self.zope_instance)

    def _word_find(self, report, content, invert=False):
        '''Check for a specific string'''
        if invert:
            warning = 'Found "%s"\n' % content
            self.assertTrue(content not in report, warning + report)
        else:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(content in report, warning + report)

    def _test_url(self, url="http://localhost/", content="", invert=False):
        '''Test the given url'''
        report = self._get_page(url)

        if content != "":
            self._word_find(report, content, invert)

    def _get_page(self, url="http://localhost/"):
        '''Get contents of given url'''
        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-dump', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def test_aa_logfiles(self):
        '''Make sure logfiles look ok'''
        log_success = 'HTTP:localhost:' + self.zope_port + ' Server started.'
        log_file = open(self.zope_logfile).read()
        report = "Could not find '%s' in log file: %s\n" % (log_success, log_file)
        self.assertTrue(log_success in log_file, report)

        transcript_file = open(self.zope_transcriptfile).read()
        report = "Found 'Traceback' in transcript file: %s\n" % transcript_file
        self.assertFalse('Traceback' in transcript_file, report)

    def test_connection(self):
        '''Test web page'''
        url = 'http://localhost:' + self.zope_port + '/'
        auth_url = 'http://' + self.zope_admin_user + ':' + self.zope_admin_pass + '@localhost:' + self.zope_port + '/'

        self._test_url(url, 'User: Unauthenticated User')
        self._test_url(auth_url, 'User: Manager')

if __name__ == '__main__':
    # simple
    unittest.main()
