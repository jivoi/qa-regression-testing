#!/usr/bin/python
#
#    test-usbmuxd.py quality assurance test script for usbmuxd
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: usbmuxd
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: usbmuxd/
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install usbmuxd && sudo ./test-usbmuxd.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release usbmuxd && ./test-usbmuxd.py -v'
'''


import unittest, sys, os
import pwd
import re
import testlib

try:
    from private.qrt.usbmuxd import PrivateUsbmuxdTest
except ImportError:
    class PrivateUsbmuxdTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class UsbmuxdTest(testlib.TestlibCase, PrivateUsbmuxdTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.pidfile = "/var/run/usbmuxd.pid"
        self.socket = "/var/run/usbmuxd"
        self.user = "usbmux"
        self.exe = "/usr/sbin/usbmuxd"
        self.unpriv_user = None

	# usbmuxd normally starts via udev if a device is plugged in. Start it
        # here instead
        self._kill_and_clean()

        rc, report = testlib.cmd([self.exe, '-U', self.user, '-v', '-v'])
        expected = 0
        self.assertEquals(expected, rc, "Got error code '%d':\n%s" % (rc, report))

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._kill_and_clean()
        self.unpriv_user = None

    def _kill_and_clean(self):
        '''Kill usbmuxd and cleanup'''
        testlib.cmd(['killall', os.path.basename(self.exe)])
        testlib.cmd(['killall', '-9', os.path.basename(self.exe)])
        for f in [self.pidfile, self.socket]:
            if os.path.exists(f):
                os.unlink(f)

    def test_daemon(self):
        '''Test daemon'''
        testlib.check_pidfile(self.exe, self.pidfile)

    def test_privileges(self):
        '''Test daemon'''
        testlib.check_pidfile(self.exe, self.pidfile)

        fd = open(self.pidfile, 'r')
        pid = fd.readline().rstrip('\n')
        fd.close()

        status = "/proc/%d/status" % int(pid)
        self.assertTrue(os.path.exists(status), "could not find '%s'" % status)

        uid = pwd.getpwnam(self.user)[2]

        lines = open(status).read()
        dropped = False
        for line in lines.splitlines():
            if re.search(r'^Uid:\s+%d\s+' % uid, line):
                dropped = True
        self.assertTrue(dropped, "did not drop privileges to '%s (%d)':\n%s" % (self.user, uid, lines))

    def test_devices(self):
        '''Test devices'''
        self.unpriv_user = testlib.TestUser()
        client = os.path.abspath('./usbmuxd/usbmux.py')

        # TODO: would be nice to plug in a device during this time and check
        # for it
        rc, report = testlib.cmd(['su', '-', self.unpriv_user.login, '-c', client])
        expected = 0
        self.assertEquals(expected, rc, "Got error code '%d':\n%s" % (rc, report))
        for s in ['Waiting for devices', 'Devices:']:
            result = "Could not find '%s' in report:\n%s" % (s, report)
            self.assertTrue(s in report, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UsbmuxdTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
