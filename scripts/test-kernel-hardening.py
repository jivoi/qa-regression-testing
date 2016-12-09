#!/usr/bin/python
#
#    test-kernel-hardening.py quality assurance test script for kernel-hardening.
#    These tests aren't in test-kernel-security.py yet because they're not in the
#    mainline or Ubuntu kernels.
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
# QRT-Packages: sudo
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/KernelHardening.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install sudo && ./test-kernel-hardening.py -v'
'''


import unittest, sys, os, tempfile, shutil
import testlib

try:
    from private.qrt.KernelHardening import PrivateKernelHardeningTest
except ImportError:
    class PrivateKernelHardeningTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class KernelHardeningTest(testlib.TestlibCase, PrivateKernelHardeningTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('kernel-hardening')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def skip_test_chroot_pwd(self):
        '''Current working directory is updated when using chroot()'''

        # So, I'm convinced that chroot isn't a security measure.  Proper
        # containers are the only real way to do this, with appropriate
        # CAP-dropping, etc.  There are so many ways to escape chroot that it
        # isn't worth the effort to break POSIX to fix them (pwd, /proc/*/cwd,
        # fchdir, PTRACE).  Focus should be spent on getting proper containers
        # working well.
        # http://lkml.indiana.edu/hypermail/linux/kernel/0709.3/0721.html

        os.chdir('chroot')
        tmpdir = tempfile.mkdtemp(prefix='chroot-pwd-')
        self.assertNotEquals(os.path.abspath('.'),tmpdir)
        self.assertShellOutputEquals('/\n', ['./chroot-pwd',tmpdir])

        # Clean up
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
