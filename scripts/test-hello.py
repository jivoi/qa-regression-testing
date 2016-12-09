#!/usr/bin/python
# coding: utf-8
#
#    test-PKG.py quality assurance test script for PKG
#    Copyright (C) 2012 Canonical Ltd.
#    Author: 
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
# QRT-Packages: hello

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


import unittest, sys
import testlib

class HelloTest(testlib.TestlibCase):
    '''Tests to ensure the hello program greets politely'''

    def setUp(self):
        '''Set up prior to each test_* function'''
	pass

    def tearDown(self):
        '''Clean up after each test_* function'''
	pass

    def test_hello(self):
        '''Test hello'''
	rc, report = testlib.cmd(['/usr/bin/hello'])
	expected = 0
	result = 'Got exit code %d, expected %d\n' % (rc, expected)
	self.assertEquals(expected, rc, result + report)
	self.assertEquals("Hello, world!\n", report, report)

    def test_oldschool(self):
        '''Test hello -t'''
	rc, report = testlib.cmd(['/usr/bin/hello', '-t'])
	expected = 0
	result = 'Got exit code %d, expected %d\n' % (rc, expected)
	self.assertEquals(expected, rc, result + report)
	self.assertEquals("hello, world\n", report, report)

    def test_russian(self):
        '''Test hello -g привет'''
	rc, report = testlib.cmd(['/usr/bin/hello', '-g', 'привет'])
	expected = 0
	result = 'Got exit code %d, expected %d\n' % (rc, expected)
	self.assertEquals(expected, rc, result + report)
	self.assertEquals("привет\n", report, report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
