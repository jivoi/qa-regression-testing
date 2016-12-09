#!/usr/bin/python
#
#    test-libxcursor.py quality assurance test script for libxcursor
#    Copyright (C) 2013 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com
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
# QRT-Packages: file x11-apps
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: libxcursor

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-libxcursor.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-libxcursor.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-libxcursor.tar.gz
    # cd /tmp/qrt-test-libxcursor ; ./install-packages ./test-libxcursor.py
    # ./test-libxcursor.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

'''


import unittest, sys, os, shutil, tempfile
import testlib

try:
    from private.qrt.Libxcursor import PrivateLibxcursorTest
except ImportError:
    class PrivateLibxcursorTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibxcursorTest(testlib.TestlibCase, PrivateLibxcursorTest):
    '''Test libxcursor.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libxcursor-")
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_xcursorgen(self):
        '''Test xcursorgen'''

        outfilename = os.path.join(self.tempdir, 'click.output')

        shutil.copy('./libxcursor/click.cursor', self.tempdir)
        shutil.copy('./libxcursor/click.png', self.tempdir)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["/usr/bin/xcursorgen",
                                    "click.cursor",
                                    outfilename])

        os.chdir(self.current_dir)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let's check the mime-type to make sure it generated a valid image
        self.assertFileType(outfilename, "X11 cursor")


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
