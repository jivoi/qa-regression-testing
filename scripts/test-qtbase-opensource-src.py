#!/usr/bin/python
#
#    test-qtbase-opensource-src.py quality assurance test script
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
# QRT-Packages: build-essential g++ qtbase5-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: qtbase-opensource-src

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
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import os
import subprocess
import sys
import unittest
import shutil
import tempfile
import testlib


try:
    from private.qrt.qtbase import PrivateQtbaseTest
except ImportError:
    class PrivateQtbaseTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class QtbaseTest(testlib.TestlibCase, PrivateQtbaseTest):
    '''Test qtbase-opensource-src.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='qrt-qtbase', dir='/tmp')
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_CVE_2013_4549(self):
        '''Test CVE-2013-4549'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2013-4549.c")
        binary = os.path.join(self.tmpdir, "CVE-2013-4549")
        shutil.copy('./qtbase-opensource-src/CVE-2013-4549/CVE-2013-4549.c', source)
        shutil.copy('./qtbase-opensource-src/CVE-2013-4549/1-levels-nested-dtd.xml', self.tmpdir)
        shutil.copy('./qtbase-opensource-src/CVE-2013-4549/2-levels-nested-dtd.xml', self.tmpdir)
        shutil.copy('./qtbase-opensource-src/CVE-2013-4549/internal-entity-polynomial-attribute.xml', self.tmpdir)

        pkg_config = testlib.get_pkgconfig_flags(['Qt5Xml'])
        rc, report = testlib.cmd(['g++', source, '-o', binary, '-fPIE'] + pkg_config)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(self.tmpdir)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
