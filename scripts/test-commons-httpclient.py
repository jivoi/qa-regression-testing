#!/usr/bin/python
#
#    test-commons-httpclient.py quality assurance test script for commons-httpclient
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
# QRT-Packages: libcommons-httpclient-java default-jre-headless junit default-jdk dpkg-dev patch
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/commons-httpclient.py commons-httpclient/

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-commons-httpclient.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-commons-httpclient.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-commons-httpclient.tar.gz
    # cd /tmp/qrt-test-commons-httpclient ; ./install-packages ./test-commons-httpclient.py
    # ./test-commons-httpclient.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-commons-httpclient.py

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import os
import subprocess
import sys
import unittest
import testlib
import tempfile
import glob

try:
    from private.qrt.CommonsHttpclient import PrivateCommonsHttpclientTest
except ImportError:
    class PrivateCommonsHttpclientTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class CommonsHttpclientTest(testlib.TestlibCase, PrivateCommonsHttpclientTest):
    '''Test commons-httpclient.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='test-commons-httpclient', dir='/tmp')
        self.topdir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _download_and_chdir_to_sources(self):
        os.chdir(self.tmpdir)
        self.assertShellExitEquals(0, ['apt-get', 'source', '--allow-unauthenticated', 'commons-httpclient'])
        os.chdir(glob.glob('commons-httpclient-*')[0])

    def _apply_patch_to_include_all_tests(self):
        patch = os.path.join(self.topdir, 'commons-httpclient/really-test-all.patch')
        self.assertShellExitEquals(0, ['patch', '-p1', '-i', patch])

    def test_unit_tests(self):
        '''Run the in-tree unit tests'''
        self._download_and_chdir_to_sources()
        self._apply_patch_to_include_all_tests()
        os.chdir('src/test')

        class_path = '.:/usr/share/java/commons-httpclient.jar:/usr/share/java/junit.jar'
        self.assertShellExitEquals(0, ['javac', '-encoding', 'ISO8859-1', '-cp', class_path, 'org/apache/commons/httpclient/TestAll.java'])

        rc, report = testlib.cmd(['java', '-cp', class_path, 'junit.textui.TestRunner', 'org.apache.commons.httpclient.TestAll'])
        self.assertEquals(0, rc, report)
        self.assertFalse("FAILURES!!!" in report, report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CommonsHttpclientTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
