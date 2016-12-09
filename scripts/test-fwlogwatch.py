#!/usr/bin/python
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
# QRT-Packages: fwlogwatch
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/Pkg.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

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


import unittest, sys, os
import testlib

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PkgTest(testlib.TestlibCase, PrivatePkgTest):
    '''Test fwlogwatch.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
	f=open('in', 'wb')
	f.write("Apr 18 18:05:37 rack1 kernel: [ 1690.227087] fw: IN=" +
			" OUT=eth0 SRC=166.78.158.192 DST=72.14.183.239" +
			" LEN=76 TOS=0x00 PREC=0xC0 TTL=64 ID=0 DF" +
			" PROTO=UDP SPT=123 DPT=123 LEN=56")
	f.close()
	f=open('out.check', 'wb')
	f.write("""First packet log entry: Apr 18 18:05:37, last: Apr 18 18:05:37.
All entries were logged by the same host: "rack1".
All entries are from the same chain: "fw: ".
All entries have the same target: "-".
All entries are from the same interface: "".

1 packet from 166.78.158.192 to 72.14.183.239
""")
	f.close()


    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_early_boot_msg(self):
        '''Test fwlogwatch on messages logged shortly after boot'''
        # useful for testing (ie get shell after setUp())
	(rc, report) = testlib.cmd(['fwlogwatch', '-o', 'out', 'in'])
	expected = 0
	result = 'Got exit code %d, expected %d\n' % (rc, expected)
	self.assertEquals(expected, rc, result + report)

	os.system("tail -7 out > out.trimmed")
	(rc, report) = testlib.cmd(['cmp', 'out.check', 'out.trimmed'])
	expected = 0
	result = 'Got exit code %d, expected %d\n' % (rc, expected)
	self.assertEquals(expected, rc, result + report)
        

if __name__ == '__main__':
    # simple
    unittest.main()
