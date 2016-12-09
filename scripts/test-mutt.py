#!/usr/bin/python
#
#    test-mutt.py quality assurance test script for PKG
#    Copyright (C) 2014 Canonical Ltd.
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
# QRT-Packages: mutt
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: mutt
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-mutt.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-mutt.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-mutt.tar.gz
    # cd /tmp/qrt-test-mutt ; ./install-packages ./test-mutt.py
    # ./test-mutt.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-mutt.py

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-mutt.py -v'
'''


import os
import subprocess
import sys
import unittest
import tempfile
import testlib

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class PkgTest(testlib.TestlibCase, PrivatePkgTest):
    '''Test mutt.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.tempdir is not None and os.path.exists(self.tempdir):
            os.rmdir(self.tempdir)

    def test_CVE_2014_0467(self):
        '''CVE-2014-0467 reproducer'''
        # useful for testing (ie get shell after setUp())
        #subprocess.call(['bash'])
        rc, report = testlib.cmd(['mutt',
                                  '-f', 'mutt/CVE-2014-0467/mutt_killing_message_from_DebianBTS',
                                  '-F', 'mutt/CVE-2014-0467/muttrc',
                                  '-e', 'set folder=%s; exec exit' % (self.tempdir)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2014_9116(self):
        '''CVE-2014-9116 reproducer'''
        # testcase from
        # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=771125
        rc, report = testlib.cmd(['mutt',
                                  '-f', 'mutt/CVE-2014-9116/mutt-crasher-db771125.mbox',
                                  '-F', '/dev/null',
                                  '-e', 'set folder=%s; set weed=no; exec display-message exit exit' % (self.tempdir)])
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
