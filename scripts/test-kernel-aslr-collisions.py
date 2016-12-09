#!/usr/bin/python
#
#    test-kernel-aslr-collisions.py quality assurance test script for kernel-aslr-collisions
#    Copyright (C) 2010, 2015 Canonical Ltd.
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
# QRT-Packages: build-essential
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: kernel-aslr-collisions

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install exim4 && ./test-kernel-aslr-collisions.py -v'
'''


import unittest, subprocess, sys, os, resource, time
import testlib

try:
    from private.qrt.KernelASLRCollisions import PrivateKernelASLRCollisionsTest
except ImportError:
    class PrivateKernelASLRCollisionsTest(object):
        '''Empty class'''
    #print >>sys.stdout, "Skipping private tests"

class KernelASLRCollisionsTest(testlib.TestlibCase, PrivateKernelASLRCollisionsTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('kernel-aslr-collisions')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def test_00_make(self):
        '''Build helper tools'''

        self.announce("gcc %s" % (self.gcc_version))
        self.assertShellExitEquals(0, ["make","clean"])
        self.assertShellExitEquals(0, ["make"])

    def test_01_randomize_vaspace(self):
        '''Kernel is randomizing VA space'''
        self.assertNotEquals(0, int(file('/proc/sys/kernel/randomize_va_space').read()))

    def test_02_stack_limit(self):
        '''Process stack is normal size'''
        stack = resource.getrlimit(resource.RLIMIT_STACK)
        self.assertEquals(8192*1024, stack[0])
        self.assertEquals(-1, stack[1])

    def test_stack_collision(self):
        # This appears to have only been an issue after mmap randomization (hardy->jaunty)
        # and only on amd64, for some reason.
        '''Check if stack crashes into mmap in 100,000 execs (amd64 only?) (LP: #504164)'''
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
            self.assertShellExitEquals(0, ['./aslr-crash'])

    def test_brk_collision(self):
        # This appears to have only been an issue with nx-emu (non-pae i386 karmic)
        '''Check if brk crashes into mmap in 10,000 execs (i386, nx-emu only) (LP: #452175)'''
        devnull = open('/dev/null','w')
        for i in range(0,10000):
            self.assertShellExitEquals(0, ['./explode-brk'])

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(KernelASLRCollisionsTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
