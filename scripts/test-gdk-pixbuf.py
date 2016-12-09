#!/usr/bin/python
#
#    test-gdk-pixbuf.py quality assurance test script for gdk-pixbuf
#    Copyright (C) 2015 Canonical Ltd.
#    Author: Steve Beattie <steve.beattie@canonical.com>
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
# QRT-Packages: libgdk-pixbuf2.0-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/gdk-pixbuf.py gdk-pixbuf
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-gdk-pixbuf.py -v'
'''


import os
import subprocess
import sys
import unittest
import testlib

try:
    from private.qrt.gdkpixbuf import PrivateGDKPixbufTest
except ImportError:
    class PrivateGDKPixbufTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class GDKPixbufTest(testlib.TestlibCase, PrivateGDKPixbufTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('gdk-pixbuf')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _run_test(self, file):
        expected = 0
        self.assertShellExitEquals(expected, ["./test-gdk-pixbuf", file])

    def test_00_make(self):
        '''Fake test to compile'''
        self.announce("gcc %s" % (self.gcc_version))
        self.assertShellExitEquals(0, ["make","clean"])
        self.assertShellExitEquals(0, ["make"])

    def test_CVE_2015_7673_DoS_tga(self):
        self._run_test("CVE-2015-7673-DoS.tga")

    def test_CVE_2015_7673_overflow_tga(self):
        self._run_test("CVE-2015-7673-overflow.tga")

    def test_CVE_2015_7674_gif(self):
        self._run_test("CVE-2015-7674.gif")


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
