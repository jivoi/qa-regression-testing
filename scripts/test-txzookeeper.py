#!/usr/bin/python
#
#    test-txzookeeper.py quality assurance test script for txzookeeper
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: python-txzookeeper zookeeperd
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/Txzookeeper.py
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-txzookeeper.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-txzookeeper.py -v'
'''


import unittest, subprocess, sys, os
import testlib
import tempfile

try:
    from private.qrt.Txzookeeper import PrivateTxzookeeperTest
except ImportError:
    class PrivateTxzookeeperTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TxzookeeperTest(testlib.TestlibCase, PrivateTxzookeeperTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.tests = "/usr/share/pyshared/txzookeeper"
        self.zookeeper_path = "/usr/share/java"

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_testsuite(self):
        '''Test testsuite'''
        # useful for testing (ie get shell after setUp())
        #subprocess.call(['bash'])
        self.assertTrue(os.path.isdir(self.tests), "Could not find '%s'" % self.tests)
        testlib.cmd(['cp', '-a', self.tests, self.tmpdir])
        os.chdir(os.path.join(self.tmpdir, os.path.basename(self.tests)))
        os.environ["ZOOKEEPER_PATH"] = self.zookeeper_path
        rc, report = testlib.cmd(['trial', os.path.basename(self.tests)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse("FAIL" in report, "Found 'FAIL' in report:\n%s" % report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TxzookeeperTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
