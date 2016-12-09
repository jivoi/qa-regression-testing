#!/usr/bin/python
#
#    test-pcre3.py quality assurance test script for pcre3
#    Copyright (C) 2015-2016 Canonical Ltd.
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
# QRT-Packages: pcregrep valgrind
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
    from private.qrt.pcre3 import PrivatePcre3Test
except ImportError:
    class PrivatePcre3Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class Pcre3Test(testlib.TestlibCase, PrivatePcre3Test):
    '''Test pcre3.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="pcre3-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_pcregrep(self, regex, contents, check=None, valgrind=False,
                      expected = 0):
        '''Check a regex with pcregrep'''

        temp_file = os.path.join(self.tempdir, "tempfile")
        file(temp_file,'w').write(contents)

        command = []

        if valgrind:
            command.extend(["/usr/bin/valgrind", "--error-exitcode=100"])

        command.extend(["/usr/bin/pcregrep", regex, temp_file])

        #print "running command: '%s'" % command

        (rc, report) = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if check:
            result = "Couldn't find '%s' in report: %s\n" % (check, report)
            self.assertTrue(check in report, result)

    def test_a_simple_regex(self):
        '''Test a simple regex'''

        self._run_pcregrep("i?a", contents="thisisatest", check="thisisatest")
        self._run_pcregrep("i?b", contents="thisisatest", expected=1)

    def test_cve_2014_8964(self):
        '''Test CVE-2014-8964'''

        if self.lsb_release['Release'] == 12.04:
            expected = 2
        elif self.lsb_release['Release'] == 14.04:
            expected = 1
        elif self.lsb_release['Release'] == 16.04:
            expected = 2
        else:
            expected = 0

        self._run_pcregrep("((?=(?(?=(?(?=(?(?=())))*))))){2}",
                           contents="a", valgrind=True, expected=expected)

    def test_cve_2015_2325(self):
        '''Test CVE-2015-2325'''

        if self.lsb_release['Release'] == 12.04:
            expected = 2
        elif self.lsb_release['Release'] == 14.04:
            expected = 1
        else:
            expected = 0

        self._run_pcregrep("((?2){0,1999}?(b(?2)c)){0,2}",
                           contents="AAAAAAAAA",
                           expected=expected)

        self._run_pcregrep("((?2){0,1999}?(b(?2)c)){0,2}",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=expected)

        self._run_pcregrep("((?2){0,1999}())?",
                           contents="AAAAAAAAA",
                           expected=expected)

        self._run_pcregrep("((?2){0,1999}())?",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=expected)

        self._run_pcregrep("/(((a\2)|(a*)\g<-1>))*a?/BZ",
                           contents="AAAAAAAAA",
                           expected=1)

        self._run_pcregrep("/(((a\2)|(a*)\g<-1>))*a?/BZ",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=1)

    def test_cve_2015_2326(self):
        '''Test CVE-2015-2326'''

        if self.lsb_release['Release'] == 12.04:
            expected = 2
        else:
            expected = 1

        self._run_pcregrep(r"/((?i)(?+1)a(a|b\1))\s+\1/",
                           contents="AAAAAAAAA",
                           expected=expected)

        self._run_pcregrep(r"/((?+1)(\1))/",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=expected)

        self._run_pcregrep(r"/((?i)(?+1)a(a|b\1))\s+\1/",
                           contents="AAAAAAAAA",
                           expected=expected)

        self._run_pcregrep(r"/((?+1)(\1))/",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=expected)

        self._run_pcregrep(r"/((?+1)(\1))/BZ",
                           contents="ADLAB",
                           expected=expected)

        self._run_pcregrep(r"/((?+1)(\1))/BZ",
                           contents="ADLAB",
                           valgrind=True,
                           expected=expected)

    def test_cve_2015_3210(self):
        '''Test CVE-2015-3210'''

        self._run_pcregrep(r"(?J)(?'d'(?'d'\g{d}))",
                           contents="AAAAAAAAA",
                           expected=1)

        self._run_pcregrep(r"(?J)(?'d'(?'d'\g{d}))",
                           contents="AAAAAAAAA",
                           valgrind=True,
                           expected=1)

    def test_cve_2015_5073(self):
        '''Test CVE-2015-5073'''

        self._run_pcregrep(r"/(?=di(?<=(?1))|(?=(.))))/",
                           contents="AAAAAAAAA",
                           check="unmatched parentheses",
                           expected=2)

        self._run_pcregrep(r"/(?=di(?<=(?1))|(?=(.))))/",
                           contents="AAAAAAAAA",
                           check="unmatched parentheses",
                           valgrind=True,
                           expected=2)

    def test_cve_2014_9769(self):
        '''Test CVE-2014-9769'''

        self._run_pcregrep(r'\/(?:(?:s(?:ystem\/(?:logs|engine)\/[^\x2f]+?'
'|e(?:rv(?:au|er)|ct)|gau\/.*?|alam|ucks|can|ke)|p(?:lugins\/content\/vote'
'\/\.ssl\/[a-z0-9]|(?:rogcicic|atr)ic|osts?\/[a-z0-9]+)|(?=[a-z]*[0-9])(?='
'[0-9]*[a-z])(?!setup\d+\.exe$)[a-z0-9]{5,10}|a(?:d(?:min\/images\/\w+|obe'
')|(?:sala|kee)m|live)|(?:i(?:mage\/flags|nvoice)|xml\/load)\/[^\x2f]+|d(?'
':o(?:c(?:\/[a-z0-9]+)?|ne)|bust)|m(?:edia\/files\/\w+|arch)|~.+?\/\.[^\x2f'
']+\/.+?|c(?:onfig|hris|alc)|u(?:swinz\w+|pdate)|Ozonecrytedserver|w(?:or'
'[dk]|insys)|fa(?:cture|soo)|n(?:otepad|ach)|k(?:be|ey|is)|(?:tes|ve)t|Arf'
'Btxz|office|yhaooo|[a-z]|etna|link|\d+)\.exe$|(?:(?=[a-z0-9]*?[3456789][a'
'-z0-9]*?[3456789])(?=[a-z0-9]*?[h-z])[a-z0-9]{3,31}\+|PasswordRecovery|Re'
'moveWAT|Dejdisc|Host\d+|Msword)\.exe)',
                           contents="/a/eaa",
                           expected=1)

    def test_cve_2015_2328(self):
        '''Test CVE-2015-2328'''

        if self.lsb_release['Release'] == 12.04:
            expected = 2
        else:
            expected = 1

        self._run_pcregrep(r"/((?(R)a|(?1)))*/",
                           contents="AAAAAAAAA",
                           expected=expected)



if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
