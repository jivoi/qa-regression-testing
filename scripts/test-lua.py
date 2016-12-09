#!/usr/bin/python
#
#    test-lua.py quality assurance test script for lua
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

exe = ""

try:
    from private.qrt.lua import PrivateLuaTest
except ImportError:
    class PrivateLuaTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class LuaTest(testlib.TestlibCase, PrivateLuaTest):
    '''Test lua.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="lua-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_script(self, contents, expected=0, search=None, args=[]):

        script = os.path.join(self.tempdir, "test.lua")
        testlib.create_fill(script, contents, mode=0755)

        rc, report = testlib.cmd([exe, script])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != None:
            result = 'Could not find "%s" in output "%s"\n' % (search, report)
            self.assertEquals(search, report, result)

    def test_hello(self):
        '''Test hello world'''

        self._run_script('''
io.write("Hello world!\\n")
''', search= "Hello world!\n")

    def test_cve_2014_5461(self):
        '''Test CVE-2014-5461'''

        self._run_script('''
function f(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10,
           p11, p12, p13, p14, p15, p16, p17, p18, p19, p20,
           p21, p22, p23, p24, p25, p26, p27, p28, p29, p30,
           p31, p32, p33, p34, p35, p36, p37, p38, p39, p40,
           p41, p42, p43, p44, p45, p46, p48, p49, p50, ...)
  local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14
end

f()
io.write("Test done!\\n")
''', search= "Test done!\n")


if __name__ == '__main__':

    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        print >>sys.stderr, "Please specify the name of the binary to test (eg 'lua5.1 or 'lua5.2')"
        sys.exit(1)

    exe = sys.argv[1]

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LuaTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
