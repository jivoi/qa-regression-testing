#!/usr/bin/python
#
#    test-openslp.py quality assurance test script for PKG
#    Copyright (C) 2011 Canonical Ltd.
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
# QRT-Packages: slpd slptool
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-openslp.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-openslp.py -v'
'''


import unittest, sys, os
import testlib

try:
    from private.qrt.Openslp import PrivateOpenslpTest
except ImportError:
    class PrivateOpenslpTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class OpenslpTest(testlib.TestlibCase, PrivateOpenslpTest):
    '''Test OpenSLP.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.server_initscript = "/etc/init.d/slpd"
        self.server_pidfile = "/var/run/slpd.pid"
        self.server_binary = "/usr/sbin/slpd"

        self.daemon = testlib.TestDaemon(self.server_initscript)
        self.daemon.restart()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.daemon.stop()

    def _query_slptool(self, command, query, search):
        '''Checks the result of a slptool query'''

        (rc, report) = testlib.cmd(["/usr/bin/slptool", command, query])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'Could not find "%s" in "%s".\n' % (search, report)
        self.assertTrue(search in report, result)

    def test_daemon(self):
        '''Test if slpd daemon is running'''
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.server_binary), self.server_pidfile))

    def test_slptool(self):
        '''Test if slptool locates server'''

        self._query_slptool("findsrvs", "service:service-agent", "service:service-agent://127.0")

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
