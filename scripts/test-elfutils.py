#!/usr/bin/python
#
#    test-elfutils.py quality assurance test script for elfutils
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
# QRT-Packages: elfutils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: elfutils private/qrt/elfutils.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-elfutils.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-elfutils.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-elfutils.tar.gz
    # cd /tmp/qrt-test-elfutils ; ./install-packages ./test-elfutils.py
    # ./test-elfutils.py -v

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
import testlib
import errno

try:
    from private.qrt.Pkg import PrivateElfutilsTest
except ImportError:
    class PrivateElfutilsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class ElfutilsTest(testlib.TestlibCase, PrivateElfutilsTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _force_unlink(self, path):
        try:
            os.unlink(path)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

    def test_cve_2014_9447(self):
        '''Test CVE-2014-9447'''
        bad_path = '/qrt-test-CVE-2014-9447'

        self._force_unlink(bad_path)
        rc, report = testlib.cmd(['eu-ar', '-xv', './elfutils/CVE-2014-9447/test.a'])

        exists = os.path.exists(bad_path)
        self._force_unlink(bad_path)
        self.assertFalse(exists, "Found '%s'" % (bad_path))

        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ElfutilsTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
