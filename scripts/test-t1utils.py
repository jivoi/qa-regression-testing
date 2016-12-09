#!/usr/bin/python
#
#    test-t1utils.py quality assurance test script for t1utils 
#    Copyright (C) 2015 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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
# QRT-Packages: t1utils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_data.py private/qrt/t1utils.py

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
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-t1utils.py -v'
'''


import os
import subprocess
import sys
import unittest
import testlib, testlib_data

try:
    from private.qrt.t1utils import PrivateT1utilsTest
except ImportError:
    class PrivateT1utilsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class T1utilsTest(testlib_data.DataCommon):
    '''Test t1utils'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.tmpdir = self.cp_data_to_tmpdir('pfb')

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_pfb_disassembly(self):
        '''Test PFB disassembly'''
        for f in self.files:
            if not f.endswith('.pfb'):
                continue
            pfb = os.path.join(self.tmpdir, f)
            (rc, report) = testlib.cmd(['t1disasm', pfb, '/dev/null'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(T1utilsTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
