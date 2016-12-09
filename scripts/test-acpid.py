#!/usr/bin/python
#
#    test-acpid.py quality assurance test script for acpid
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
# QRT-Packages: acpid
# QRT-Privilege: root

'''

  This test script needs to be run in a VM.

  How to run:
    $ sudo apt-get -y install lsb-release acpid
    $ sudo ./test-acpid.py -v
    
    Simulate acpid events by suspending and shutting down VM

  TODO:
    find a way to simulate and script acpid events

'''

import unittest, sys, os, stat
import testlib

use_private = True
try:
    from private.qrt.acpid import AcpidPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class AcpidTest(testlib.TestlibCase):
    '''Test acpid.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.daemon = testlib.TestDaemon("/etc/init.d/acpid")

        # Assume we're running.
        #self.daemon.stop()
        #self.daemon.start()

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_daemon(self):
        '''Test if daemon is running'''
        if self.lsb_release['Release'] <= 8.04:
            print "Dapper through Hardy don't have 'status' in the acpid init script"
            return True
        rc, result = self.daemon.status()
        self.assertTrue(rc, result)

    def test_socket(self):
        '''Test if socket is present'''
        acpid_socket = '/var/run/acpid.socket'
        
        self.assertTrue(os.path.exists(acpid_socket), "/var/run/acpid.socket doesn't exist")
        sb = os.stat(acpid_socket)
        self.assertTrue(stat.S_ISSOCK(sb.st_mode), '/var/run/acpid.socket is not a socket')

    def test_acpi_listen(self):
        '''Test acpi_listen tool'''
        rc, report = testlib.cmd(['/usr/bin/acpi_listen', '-t', '3'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # TODO: have tester press power button, etc and check for things like
        #button/power PWRF 00000080 00000001
        # etc

if __name__ == '__main__':
    # more configurable

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AcpidTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(AcpidPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
