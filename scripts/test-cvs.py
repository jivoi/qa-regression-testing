#!/usr/bin/python
#
#    test-cvs.py quality assurance test script for cvs
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: cvs
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-cvs.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-cvs.py -v'
'''


import unittest, subprocess, sys, os
import tempfile, time
import testlib

try:
    from private.qrt.Cvs import PrivateCvsTest
except ImportError:
    class PrivateCvsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class CvsTest(testlib.TestlibCase, PrivateCvsTest):
    '''Test cvs.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="cvs-")
        self.test_repo = os.path.join(self.tempdir, 'testrepo')
        self.working_dir = os.path.join(self.tempdir, 'workingdir')
        self.test_file = os.path.join(self.working_dir, "test-cvs.py")

        os.mkdir(self.test_repo)
        os.mkdir(self.working_dir)

        self.current_dir = os.getcwd()

        # Set up default test repo
        self.run_cvs("init")
        self.run_cvs("import", ["-m", "Initial commit", "MyRepo",
                                "TestSoft", "START"], change_dir=False)
        self.run_cvs("checkout", ["-d", self.working_dir, "MyRepo"])

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def run_cvs(self, command, arguments=None, change_dir=True, expected=0):
        '''Runs the cvs command'''
        cmd = []

        cmd.extend(["cvs", "-d", self.test_repo, command])

        if arguments:
            cmd.extend(arguments)

        if change_dir == True:
            os.chdir(self.working_dir)

        (rc, report) = testlib.cmd(cmd)

        if change_dir == True:
            os.chdir(self.current_dir)

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def word_find(self, report, content, invert=False):
        '''Check for a specific string'''
        if invert == False:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(content in report, warning + report)
        else:
            warning = 'Found "%s"\n' % content
            self.assertFalse(content in report, warning + report)

    def test_00_list(self):
        '''Test svn list'''
        result = self.run_cvs("rls", ["MyRepo"])
        self.word_find(result, "test-cvs.py")

    def test_01_content(self):
        '''Test if content matches'''

        (rc, report) = testlib.cmd(["/usr/bin/diff", '-q', "./test-cvs.py",
                                    self.test_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_02_modify(self):
        '''Test modifying contents'''

        commit_log = "This is a test commit."

        # If we do this too quick, our file has the same timestamp
        time.sleep(2)

        # Modify our file
        subprocess.call(['sed', '-i', 's/test/xylophone/g', self.test_file])

        # Check the status
        result = self.run_cvs("status", ["test-cvs.py"])
        self.word_find(result, "Locally Modified")

        # Commit
        self.run_cvs('commit', ['-m', commit_log])

        # Check the status
        result = self.run_cvs("status", ["test-cvs.py"])
        self.word_find(result, "Up-to-date")

        # Update
        result = self.run_cvs("update")
        self.word_find(result, "cvs update: Updating")

        # Check the log
        result = self.run_cvs("log")
        self.word_find(result, commit_log)

    def test_03_annotate(self):
        '''Test annotate command'''
        result = self.run_cvs("annotate", [self.test_file])
        self.word_find(result, "xylophone")


if __name__ == '__main__':
    # simple
    testlib.require_nonroot()
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
