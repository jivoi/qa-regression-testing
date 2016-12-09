#!/usr/bin/python
#
#    kernel.py regression testing script for kernel stuff
#
#    Copyright (C) 2009-2014 Canonical Ltd.
#    Authors:
#      Steve Beattie <sbeattie@ubuntu.com>
#      Kees Cook <kees@ubuntu.com>
#      Marc Deslauriers <marc.deslauriers@canonical.com>
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
# TODO:
#  - kernel capabilities tests (positive and negative)
#  - kernel keyring tests (LTP?)
#  - IPC tests
#
# QRT-Packages: build-essential sudo
# =!= NOTE =!=
# gcc-multilib must be an alternate because it does not exist on armel
# for releases older than oneiric
# QRT-Alternates: gcc-multilib

# QRT-Depends: kernel private/linux private/qrt/kernel.py

import unittest
import os
import testlib

try:
    from private.qrt.kernel import PrivateKernelTest
except ImportError:
    class PrivateKernelTest(object):
        '''Empty class'''

class KernelSecurityTest(testlib.TestlibCase):
    '''Test kernel for non-security-feature regressions'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('kernel')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    # All, duh
    def test_00_make(self):
        '''Build helper tools'''

        self.announce("gcc %s" % (self.gcc_version))
        self.assertShellExitEquals(0, ["make","clean"])
        self.assertShellExitEquals(0, ["make"])

    def test_10_bad_syscall_returns_ENOSYS(self):
        '''syscall(666666) returns ENOSYS (LP: #339743)'''

        expected = 0
        if self.dpkg_arch not in ['i386', 'amd64']:
            self._skipped("only i386")
            expected = 127

        os.chdir('bad-syscall')
        self.assertShellExitEquals(expected, ["./bad-syscall"])

    def test_inotify_leak(self):
        '''inotify does not leak descriptors (LP: #485556)'''

        expected = 0
        if self.lsb_release['Release'] < 8.04:
            self._skipped("only Hardy and later")
            expected = 127

        os.chdir('inotify')
        self.assertShellExitEquals(expected, ["./inotify-leak"])

    def test_memmove(self):
        '''memmove does not leak bytes (CVE-2010-0415)'''

        os.chdir('memmove')
        name = 'randomize_va_space'
        sysctl = '/proc/sys/kernel/%s' % (name)
        with open(sysctl) as fh:
            value = int(fh.read())
        self.assertNotEqual(value, 0, "%s must be non-zero for this test" % (sysctl))
        rc, report = testlib.cmd(["./exp_sieve",name,'4'])
        if rc != 1:
            self.assertEquals(rc, 0, report)
            output = report.splitlines().pop().strip()
            self.assertTrue(output in ['00 00 00 00','ff ff ff ff'], report)

    def test_guard_page_split(self):
        '''Make sure the stack guard page does not split the stack on mlock'''

        expected = 0
        os.chdir('guard-page')
        self.assertShellExitEquals(expected, ["./split-stack"])

    def test_stacksignal_memleak(self):
        '''Kernel memory does not leak to userspace in signalstack (CVE-2009-2847)'''

        expected = 0
        os.chdir('signalstack')
        self.assertShellExitEquals(expected, ["./signal-stack"])

    def test_compat_syscall(self):
        '''Kernel correctly filters compat syscalls (CVE-2010-3301)'''

        os.chdir('compat')
        self.assertShellOutputContains("UID 0,", ["./CVE-2010-3301"], invert=True)

    def test_compat_alloc_userspace(self):
        '''Kernel correctly calls access_ok on compat_alloc_userspace (CVE-2010-3081)'''

        if self.lsb_release['Release'] == 14.04:
            return self._skipped("Skipped: FTBFS on Trusty's GCC")

        os.chdir('compat')
        self.assertShellExitEquals(1, ['./CVE-2010-3081'])


# other things to test...
#~~~~~~~~~~~~~~~~~~~~~~~~
# ... ?

if __name__ == '__main__':
    testlib.require_nonroot()
    unittest.main()
