#!/usr/bin/python
#
#    test-lxc.py quality assurance test script for lxc
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
# QRT-Packages: lxc lxc-tests
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends: private/qrt/lxc.py
# privilege required for the test to run (remove line if running as
# user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-lxc.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-lxc.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-lxc.tar.gz
    # cd /tmp/qrt-test-lxc ; ./install-packages ./test-lxc.py
    # ./test-lxc.py -v
'''

import fnmatch
import os
import sys
import unittest
import testlib

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class LXCUpstreamTests(testlib.TestlibCase, PrivatePkgTest):
    '''LXC's upstream tests based on the lxc-tests package'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _check(self, test_bin):
        expected = 0
        rc, report = testlib.cmd([test_bin])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


def setup_testcases():
    bins = os.listdir('/usr/bin/')
    for test in fnmatch.filter(bins, 'lxc-test-*'):
        def stub_test(self, test_bin=test):
            self._check(test_bin)
        stub_test.__doc__ = "test %s" % (test)
        setattr(LXCUpstreamTests, 'test_%s' % (test), stub_test)

if __name__ == '__main__':
    # simple
    testlib.require_root()
    setup_testcases()
    unittest.main()
