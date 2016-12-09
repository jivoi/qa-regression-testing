#!/usr/bin/python
#
#    test-libxslt.py quality assurance test script for libxslt
#    Copyright (C) 2012-2013 Canonical Ltd.
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
# QRT-Packages: xsltproc
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: libxslt
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-libxslt.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-libxslt.py -v'

'''


import unittest, sys, os, tempfile, glob
import testlib

try:
    from private.qrt.Libxslt import PrivateLibxsltTest
except ImportError:
    class PrivateLibxsltTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibxsltTest(testlib.TestlibCase, PrivateLibxsltTest):
    '''Test libxslt.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        #self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libxslt-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        #if os.path.exists(self.tempdir):
        #    testlib.recursive_rm(self.tempdir)

    def _call_xsltproc(self, xsl, xml, output=None, expected_rc = 0):
        '''Call xsltproc and check for a specific output'''

        rc, report = testlib.cmd(['xsltproc', xsl, xml])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        # This generates output files, useful for adding a new test suite
        #if not os.path.isfile(output):
        #    open(output, 'w').write(report)
        #    return

        if output != None:
            expected_output = open(output).read()

            result = "Output '%s' doesn't match report '%s'" % (expected_output, report)
            self.assertTrue(expected_output == report, result)

    def test_transform_1(self):
        '''Test transform 1'''

        self._call_xsltproc('./libxslt/transform.xsl',
                            './libxslt/data.xml',
                            './libxslt/result.txt')

    def test_transform_2(self):
        '''Test transform 2'''

        self._call_xsltproc('./libxslt/transform2.xsl',
                            './libxslt/data2.xml',
                            './libxslt/result2.txt')

    def test_transform_3(self):
        '''Test transform 3'''

        self._call_xsltproc('./libxslt/transform3.xsl',
                            './libxslt/data3.xml',
                            './libxslt/result3.txt')

    def test_nist_testsuite(self):
        '''Test NIST testsuite'''
        skipped = []

        xuldir = os.path.dirname(os.path.realpath("/usr/bin/xulrunner-1.9.2"))
        exe = os.path.join(xuldir, "run-mozilla.sh")

        tests = glob.glob("./libxslt/NIST/*.xsl")
        tests.sort()
        print ""
        for t in tests:
            if not os.path.isfile(t):
                continue

            testname = os.path.basename(t).split('.')[0]

            # xsl file with no xml file
            if not os.path.exists('./libxslt/NIST/' + testname + '.xml'):
                continue

            print " %s:" % (testname),
            if testname in skipped:
                print "skipped"
                continue

            self._call_xsltproc('./libxslt/NIST/' + testname + '.xsl',
                                './libxslt/NIST/' + testname + '.xml',
                                './libxslt/NIST/' + testname + '.txt')

            print "ok"

    def test_cve_2012_6139_1(self):
        '''Test CVE-2012-6139 Part 1'''

        self._call_xsltproc('./libxslt/CVE-2012-6139/crash_document.xsl',
                            './libxslt/data.xml',
                            expected_rc = 10)

    def test_cve_2012_6139_2(self):
        '''Test CVE-2012-6139 Part 2'''

        self._call_xsltproc('./libxslt/CVE-2012-6139/crash_xsl_key.xsl',
                            './libxslt/data.xml',
                            expected_rc = 5)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
