#!/usr/bin/python
#
#    test-pyopenssl.py quality assurance test script for pyopenssl
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
# QRT-Packages: python-openssl python3-openssl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-pyopenssl.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-pyopenssl.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-pyopenssl.tar.gz
    # cd /tmp/qrt-test-pyopenssl ; ./install-packages ./test-pyopenssl.py
    # ./test-pyopenssl.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-pyopenssl

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-pyopenssl.py -v'
'''


import unittest, subprocess, sys, os, tempfile
import testlib

try:
    from private.qrt.Pyopenssl import PrivatePyopensslTest
except ImportError:
    class PrivatePyopensslTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PyopensslTest(testlib.TestlibCase, PrivatePyopensslTest):
    '''Test pyopenssl.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.python2_test_dir = '/usr/share/pyshared/OpenSSL/test/'
        self.python3_test_dir = '/usr/lib/python3/dist-packages/OpenSSL/test/'

        self.tmpdir = tempfile.mkdtemp(prefix='testlib-pyopenssl', dir='/tmp')
        self.topdir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _run_test(self, test, python_version=2):
        '''Run a test from the test suite'''

        if python_version == 3:
            cmd = ['python3', os.path.join(self.python3_test_dir, test)]
        else:
            cmd = ['python', os.path.join(self.python2_test_dir, test)]

        os.chdir(self.tmpdir)
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure the test finished OK
        result = 'Did not find "OK" at the end of report: "%s"\n' % report
        self.assertEquals(report[-3:-1], 'OK', result)


    def test_crypto(self):
        '''Test crypto'''
        self._run_test('test_crypto.py')

    def test_rand(self):
        '''Test rand'''
        self._run_test('test_rand.py')

    def test_ssl(self):
        '''Test ssl'''
        self._run_test('test_ssl.py')

    def test_crypto_python3(self):
        '''Test crypto - python 3'''

        if self.lsb_release['Release'] < 12.10:
            return self._skipped("No python 3 version available")

        self._run_test('test_crypto.py', 3)

    def test_rand_python3(self):
        '''Test rand - python 3'''

        if self.lsb_release['Release'] < 12.10:
            return self._skipped("No python 3 version available")

        self._run_test('test_rand.py', 3)

    def test_ssl_python3(self):
        '''Test ssl - python 3'''

        if self.lsb_release['Release'] < 12.10:
            return self._skipped("No python 3 version available")

        self._run_test('test_ssl.py', 3)

    def test_cve_2013_4314(self):
        '''Test CVE-2013-4314'''
        # This just makes sure the CVE-2013-4314 test is part of the
        # test suite we run
        test_file = os.path.join(self.python2_test_dir, 'test_crypto.py')
        contents = open(test_file).read()

        test_string = 'nulbyteSubjectAltNamePEM'
        result = 'Did not find CVE-2013-4314 test in test suite!\n'
        self.assertTrue(test_string in contents, result)

    def test_cve_2013_4314_python3(self):
        '''Test CVE-2013-4314 - python 3'''

        if self.lsb_release['Release'] < 12.10:
            return self._skipped("No python 3 version available")

        # This just makes sure the CVE-2013-4314 test is part of the
        # test suite we run
        test_file = os.path.join(self.python3_test_dir, 'test_crypto.py')
        contents = open(test_file).read()

        test_string = 'nulbyteSubjectAltNamePEM'
        result = 'Did not find CVE-2013-4314 test in test suite!\n'
        self.assertTrue(test_string in contents, result)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
