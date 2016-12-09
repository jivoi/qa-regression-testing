#!/usr/bin/python
#
#    test-bash.py quality assurance test script for bash
#    Copyright (C) 2014 Canonical Ltd.
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
# QRT-Packages: bash

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.
'''


import os
import subprocess
import sys
import unittest
import testlib
import tempfile
import datetime

try:
    from private.qrt.bash import PrivateBashTest
except ImportError:
    class PrivateBashTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class BashTest(testlib.TestlibCase, PrivateBashTest):
    '''Test bash.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="qrt-")
        self.cwd = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.cwd)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _write_script(self, filename, data):
        '''Writes out a shell script into the temporary directory'''

        fullname = os.path.join(self.tempdir, filename)
        f = open(fullname, 'w')
        f.write("#!/bin/bash\n%s" % data)
        f.close()
        os.chmod(fullname, 0755)
        return fullname

    def _check_script_results(self, script, results=None, expected=None, args=[], invert=False):
        '''Run a bash script, check if results contain text'''

        rc, report = testlib.cmd(['/bin/bash'] + args + [script])

        if expected != None:
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        if results != None:
            if invert == False:
                warning = 'Could not find "%s"\n' % results
                self.assertTrue(results in report, warning + report)
            else:
                warning = 'Found "%s"\n' % results
                self.assertFalse(results in report, warning + report)

    def test_basic(self):
        '''Test basic script'''

        test_string = "hello world!"

        script = self._write_script('basic.sh', 'echo "%s"' % test_string)
        self._check_script_results(script, test_string)

    def test_cve_2014_6271_1(self):
        '''Test CVE-2014-6271 - no prefix/suffix'''

        script = self._write_script('6271test1.sh', '''
env x='() { :;}; echo vulnerable'  bash -c "echo this is a test"
''')

        self._check_script_results(script, 'vulnerable', invert=True)

    def test_cve_2014_6271_2(self):
        '''Test CVE-2014-6271 - old suffix'''

        script = self._write_script('6271test2.sh', '''
env "BASH_FUNC_x()"='() { :;}; echo vulnerable'  bash -c "echo this is a test"
''')

        self._check_script_results(script, 'vulnerable', invert=True)

    def test_cve_2014_6271_3(self):
        '''Test CVE-2014-6271 - new suffix'''

        script = self._write_script('6271test3.sh', '''
env "BASH_FUNC_x%%"='() { :;}; echo vulnerable'  bash -c "echo this is a test"
''')

        self._check_script_results(script, 'vulnerable', invert=True)


    def test_cve_2014_7169(self):
        '''Test CVE-2014-7169'''

        year = datetime.date.today().strftime('%Y')
        contents = '''
env -i  X='() { (a)=>\\' bash -c 'echo date'; cat echo
        '''

        script = self._write_script('7169test.sh', contents)

        os.chdir(self.tempdir)
        self._check_script_results(script, year, invert=True)

    def test_cve_2014_6277_1(self):
        '''Test CVE-2014-6277 - old suffix'''

        script = self._write_script('6277test1.sh', '''
env "BASH_FUNC_foo()"='() { x() { _; }; x() { _; } <<a; }' bash -c :
''')

        self._check_script_results(script, expected=0)

    def test_cve_2014_6277_2(self):
        '''Test CVE-2014-6277 - new suffix'''

        script = self._write_script('6277test2.sh', '''
env "BASH_FUNC_foo%%"='() { x() { _; }; x() { _; } <<a; }' bash -c :
''')

        self._check_script_results(script, expected=0)

    def test_cve_2014_6278_1(self):
        '''Test CVE-2014-6278 - old suffix'''

        script = self._write_script('6278test1.sh', '''
env "BASH_FUNC_foo()"='() { _; } >_[$($())] { cat /etc/hosts; }' bash -c :
''')

        self._check_script_results(script, 'localhost', invert=True)

    def test_cve_2014_6278_2(self):
        '''Test CVE-2014-6278 - new suffix'''

        script = self._write_script('6278test2.sh', '''
env "BASH_FUNC_foo%%"='() { _; } >_[$($())] { cat /etc/hosts; }' bash -c :
''')

        self._check_script_results(script, 'localhost', invert=True)

    def test_cve_2014_7186(self):
        '''Test CVE-2014-7186'''

        amount = 20

        contents = "bash -c 'true"

        for x in range(amount):
            contents += " <<EOF"

        contents += "'\n"

        script = self._write_script('7186test.sh', contents)

        self._check_script_results(script, expected=1)

    def test_cve_2014_7187(self):
        '''Test CVE-2014-7187'''

        contents = ""

        # lucid's bash only supports 127 of them
        if self.lsb_release['Release'] == 10.04:
            amount = 127
        else:
            amount = 200

        for x in range(amount):
            contents += "for x%s in ; do :\n" % x
        for x in range(amount):
            contents += "done\n"

        script = self._write_script('7187test.sh', contents)

        self._check_script_results(script, expected=0)

    def test_function_def_1(self):
        '''Test function def hardening - no prefix/suffix'''

        test_string = '"hello" "hello"'
        result = "hello hello"

        script = self._write_script('func1.sh', '''
env foo='() { echo %s; }' bash -c 'foo'
''' % test_string)

        self._check_script_results(script, result, invert=True)

    def test_function_def_2(self):
        '''Test function def hardening - using export -f'''

        test_string = '"hello" "hello"'
        result = "hello hello"

        script = self._write_script('func2.sh', '''
function foo { echo %s; };export -f foo;bash -c 'foo'
''' % test_string)

        self._check_script_results(script, result)

    def test_function_def_3(self):
        '''Test function def hardening - old suffix'''

        test_string = '"hello" "hello"'
        result = "hello hello"

        # This was the original suffix which ultimately got changed
        # by the official upstream patch
        script = self._write_script('func3.sh', '''
env BASH_FUNC_foo\\(\\)='() { echo %s; }' bash -c 'foo'
''' % test_string)

        self._check_script_results(script, result, invert=True)

    def test_function_def_4(self):
        '''Test function def hardening - new suffix'''

        test_string = '"hello" "hello"'
        result = "hello hello"

        script = self._write_script('func3.sh', '''
env BASH_FUNC_foo%%%%='() { echo %s; }' bash -c 'foo'
''' % test_string)

        self._check_script_results(script, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
