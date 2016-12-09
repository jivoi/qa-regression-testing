#!/usr/bin/python
#
#    test-libfs.py quality assurance test script for libfs
#    Copyright (C) 2013 Canonical Ltd.
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
# QRT-Packages: xfs x11-xfs-utils
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
    $ ./make-test-tarball test-libfs.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-libfs.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-libfs.tar.gz
    # cd /tmp/qrt-test-libfs ; ./install-packages ./test-libfs.py
    # ./test-libfs.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-libfs

'''


import unittest, sys, os, time
import testlib

try:
    from private.qrt.Libfs import PrivateLibfsTest
except ImportError:
    class PrivateLibfsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibfsTest(testlib.TestlibCase, PrivateLibfsTest):
    '''Test libfs.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.pidfile = "/var/run/xfs/xfs.pid"
        self.exe = "/usr/bin/xfs"
        self.font_server = "unix/:7100"

        self.daemon = testlib.TestDaemon("/etc/init.d/xfs")
        self._restart_daemon()

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _start_daemon(self):
        '''Start daemon'''
        self.assertTrue(self.daemon.start())

    def _stop_daemon(self):
        '''Stop daemon'''
        self.assertTrue(self.daemon.stop())

    def _restart_daemon(self):
        '''Restart daemon'''
        self.assertTrue(self.daemon.restart())

    def test_aa_xfs_daemon(self):
        '''Test xfs daemon'''
        self._stop_daemon()
        time.sleep(1)
        self.assertFalse(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))
        self._start_daemon()
        time.sleep(1)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))
        self._restart_daemon()
        time.sleep(1)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

    def test_fslsfonts(self):
        '''Test fslsfonts'''
        (rc, report) = testlib.cmd(["/usr/bin/fslsfonts",
                                    "-server", self.font_server])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Could not find 'fixed' font in report: '%s'" % report
        self.assertTrue("fixed" in report, result)

        result = "Could not find 'bitstream charter-bold' font in report: '%s'" % report
        self.assertTrue("bitstream charter-bold" in report, result)

    def test_fslsfonts_ll(self):
        '''Test fslsfonts with -ll'''
        (rc, report) = testlib.cmd(["/usr/bin/fslsfonts",
                                    "-server", self.font_server,
                                    "-ll", "fixed"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Could not find 'FOUNDRY\tMisc' in report: '%s'" % report
        self.assertTrue("FOUNDRY\tMisc" in report, result)

        result = "Could not find 'COPYRIGHT\tPublic domain font.' font in report: '%s'" % report
        self.assertTrue("COPYRIGHT\tPublic domain font." in report, result)

    def test_xfsinfo(self):
        '''Test xfsinfo'''
        (rc, report) = testlib.cmd(["/usr/bin/xfsinfo",
                                    "-server", self.font_server])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        server_name = "name of server:\t%s" % self.font_server

        result = "Could not find '%s' in report: '%s'" % (server_name, report)
        self.assertTrue(server_name in report, result)

        result = "Could not find 'X.Org Foundation' in report: '%s'" % report
        self.assertTrue("X.Org Foundation" in report, result)

    def test_showfont(self):
        '''Test showfont'''
        (rc, report) = testlib.cmd(["/usr/bin/showfont",
                                    "-server", self.font_server,
                                    "-fn", "fixed"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Could not find 'FOUNDRY\tMisc' in report: '%s'" % report
        self.assertTrue("FOUNDRY\tMisc" in report, result)

        result = "Could not find 'COPYRIGHT\tPublic domain font.' font in report: '%s'" % report
        self.assertTrue("COPYRIGHT\tPublic domain font." in report, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
