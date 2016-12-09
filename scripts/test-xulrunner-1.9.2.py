#!/usr/bin/python
#
#    test-xulrunner-1.9.2.py quality assurance test script for xulrunner-1.9.2
#    Copyright (C) 2011 Canonical Ltd.
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
# QRT-Packages: xulrunner-1.9.2 xulrunner-1.9.2-testsuite
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/xul192.py
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import unittest, sys, os
import glob
import testlib

try:
    from private.qrt.xul192 import PrivateXulTest
except ImportError:
    class PrivateXulTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class XulTest(testlib.TestlibCase, PrivateXulTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_testsuite(self):
        '''Test testsuite'''
        skipped = [
                   'NormalizationTest',
                   'TestGtkEmbedChild',
                   'TestGtkEmbedNotebook',
                   'TestGtkEmbedSocket',
                   'TestBlockingProcess',
                   'TestOOM',
                   'TestRegistrationOrder',
                  ]

        xuldir = os.path.dirname(os.path.realpath("/usr/bin/xulrunner-1.9.2"))
        exe = os.path.join(xuldir, "run-mozilla.sh")

        tests = glob.glob("%s/*est*" % xuldir)
        tests.sort()
        print ""
        for t in tests:
            if not os.path.isfile(t):
                continue

            testname = os.path.basename(t)
            print " %s:" % (testname),
            if testname in skipped:
                print "skipped"
                continue

            url = 'http://www.ubuntu.com'
            expected = 0
            altrc = 255

            args = [exe, t]
            if testname == "TestURLParser":
                 args.append('-noauth')

            if testname == "TestURLParser" or testname == "TestStandardURL":
                 args.append(url)
            elif testname == "TestQuickReturn":
                 expected = 42
            elif testname == "TestCallTemplates":
                 expected = -11

            rc, report = testlib.cmd([exe, t])
            result = 'Got exit code %d, expected %d for \'%s\'\n' % (rc, expected, " ".join(args))
            self.assertTrue(rc == expected or rc == altrc, result + report)
            print "ok"

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
