#!/usr/bin/python
#
# ***********************************************************************
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# THIS TEST SCRIPT MAY CAUSE YOUR SYSTEM TO PANIC OR HANG IF A TEST FAILS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ***********************************************************************
#
#    test-kernel-panic.py quality assurance test script for kernel panics
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: build-essential libkeyutils-dev
# packages where more than one package can satisfy a runtime requirement:
# +++ NOTE ++++
# gcc-multilib must be an alternate because it does not exist on armel
# for releases older than oneiric
# QRT-Alternates: gcc-multilib
# files and directories required for the test to run:
# QRT-Depends: kernel-panic

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install build-essential libc6-dev-i386 && ./test-kernel-panic.py -v'
'''

import os
import sys
import time
import unittest
import testlib

try:
    from private.qrt.KernelPanic import PrivateKernelPanicTest
except ImportError:
    class PrivateKernelPanicTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class KernelPanicTest(testlib.TestlibCase, PrivateKernelPanicTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('kernel-panic')
        os.system("sync")
        os.system("sync")

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def test_too_early_vsyscall(self):
        '''The vsyscall entries are created too early (CVE-2010-0307)'''
        if self.dpkg_arch != 'amd64':
            self._skipped('amd64 only')
            return

        os.chdir('CVE-2010-0307')
        self.assertShellExitEquals(0, ["make",'clean'])
        self.assertShellExitEquals(0, ["make",'test'])

    def test_cve_2013_2094(self):
        '''test linux kernel perf out-of-bounds access (CVE-2013-2094)'''
        if self.dpkg_arch != 'amd64':
            self._skipped('test works on amd64 only')
            return

        os.chdir('CVE-2013-2094')
        self.assertShellExitEquals(0, ["make",'clean'])
        self.assertShellExitEquals(0, ["make",'test'])

    def test_cve_2015_7550(self):
        '''test linux kernel keyctl race (CVE-2015-7550)'''

        os.chdir('CVE-2015-7550')
        self.assertShellExitEquals(0, ["make", 'clean'])
        self.assertShellExitEquals(0, ["make", 'all'])

        print ""
        full = 100000
        started = time.time()
        for i in range(0,full+1):
            if (i % 1000 == 0):
                taken = time.time() - started
                eta = ""
                if i>0:
                    per_chunk = float(taken) / float(i)
                    remaining = int(per_chunk * full) - taken
                    eta = " (eta: %dmin %dsec)   " % (remaining / 60, remaining % 60)
                sys.stdout.write("\r\t%d/%d%s" % (i, full, eta))
                sys.stdout.flush()
            self.assertShellExitEquals(0, ['./cve-2015-7550'])

if __name__ == '__main__':
    # simple
    unittest.main()
