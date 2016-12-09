#!/usr/bin/python
#
#    test-tidy.py quality assurance test script for tidy
#    Copyright (C) 2015 Canonical Ltd.
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
# QRT-Packages: tidy valgrind
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

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


import os
import subprocess
import sys
import unittest
import testlib
import tempfile

try:
    from private.qrt.tidy import PrivateTidyTest
except ImportError:
    class PrivateTidyTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class TidyTest(testlib.TestlibCase, PrivateTidyTest):
    '''Test tidy.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="tidy-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_tidy(self, contents, check_res=None, check_out=None,
                  valgrind=False, expected = 0):
        '''Run tidy on some contents'''

        input_file = os.path.join(self.tempdir, "input.html")
        output_file = os.path.join(self.tempdir, "input.html")

        file(input_file,'w').write(contents)

        command = []

        if valgrind:
            command.extend(["/usr/bin/valgrind", "--error-exitcode=100"])

        command.extend(["/usr/bin/tidy", "-o", output_file, input_file])

        #print "running command: '%s'" % command

        (rc, report) = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if check_res:
            result = "Couldn't find '%s' in report: %s\n" % (check_res, report)
            self.assertTrue(check_res in report, result)

        if check_out:
            output = file(output_file).read()
            result = "Couldn't fine '%s' in output: '%s'\n" % (check_out, output)
            self.assertTrue(check_out in output, result)

    def test_missing_tag(self):
        '''Test a missing tag'''

        html = '''   <h1>heading
   <h2>subheading</h3>'''

        search = "<h1>heading</h1>"

        self._run_tidy(html, check_out = search, expected = 1)


    def test_cve_2015_5522_1(self):
        '''Test CVE-2015-5522 Part 1'''

        html = ("\x3c\x61\x20\x62\x3d\x3c\x61\x20\x3c\x3f\x78\x6d\x0d"
                "\x3f\x3e\x62\x3d\x22\x63\x22\x47\x20\x68\x72\x65\x66"
                "\x3d\x22\x12\x22\xbb")

        search = 'attribute "href" lacks value'

        self._run_tidy(html, check_res = search, expected = 1)

    def test_cve_2015_5522_2(self):
        '''Test CVE-2015-5522 Part 2'''

        html = ("\x3c\x61\x20\x62\x3d\x3c\x61\x20\x3c\x3f\x78\x6d\x0d"
                "\x3f\x3e\x62\x3d\x22\x63\x22\x47\x20\x68\x72\x65\x66"
                "\x3d\x22\x12\x22\xbb")

        search = 'attribute "href" lacks value'

        self._run_tidy(html, check_res = search, valgrind = True,
                       expected = 1)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
