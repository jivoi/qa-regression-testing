#!/usr/bin/python
#
#    test-glibc.py regression testing script for glibc bug regressions.
#
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: build-essential php5-cli iputils-ping
# =!= NOTE =!=
# gcc-multilib must be an alternate because it does not exist on armel
# for releases older than oneiric
# QRT-Alternates: gcc-multilib
# QRT-Depends: glibc

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install build-essential gcc-multilib && ./test-glibc.py -v'
'''

import unittest, glob
import os
import testlib
import time

class GlibcTest(testlib.TestlibCase):
    '''Test glibc bug regressions'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.listener = None
        self.fs_dir = os.path.abspath('.')
        os.chdir('glibc')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        if self.listener != None and self.listener != 0:
            try:
                os.kill(self.listener, 15)
            except:
                pass
        self.listener = None

    def _libpath(self, name):
        return "/".join(self.path_libc.split('/')[0:-1]) + "/%s" % (name)

    def _cmd_timeout(self, cmd, timeout=10):
        '''Run a command, wait a bit and if the executable is still
           running, kill it.
        '''

        self.listener = os.fork()
        if self.listener == 0:
            os.execv(cmd, [cmd])
            sys.exit(0)

        pidfile = "/proc/%s" % self.listener

        # Now, wait for the process to exit, or the timeout
        while timeout > 0:
            pid, status = os.waitpid(self.listener, os.WNOHANG)
            return_code = status >> 8   # return code is upper byte
            signal = status & 0x7f      # status is lower 7 bits
            if not os.path.exists(pidfile):
                self.listener = None
                return signal, return_code
            timeout -= 1
            time.sleep(1)

        # If we've made it here, we need to kill it
        try:
            os.kill(self.listener, 15)
        except:
            pass

        pid, status = os.waitpid(self.listener, 0)
        return_code = status >> 8   # return code is upper byte
        signal = status & 0x7f      # status is lower 7 bits
        self.listener = None

        return signal, return_code

    # All, duh
    def test_00_make(self):
        '''Build helper tools'''

        self.announce("gcc %s" % (self.gcc_version))
        self.assertShellExitEquals(0, ["make","clean"])
        self.assertShellExitEquals(0, ["make"])

    # All releases
    def test_getdents64_padding(self):
        '''Calling getdents64 does not over-pad (LP: #392501)'''

        os.chdir('getdents')
        self.assertShellExitEquals(0, ["make","test"])

    def test_strfmon_overflow(self):
        '''strfmon does not have integer overflows (CVE-2008-1391)'''

        if self.dpkg_arch == 'amd64':
            self._skipped('32bit only')
            return

        self.assertShellExitEquals(0, ['php','-r','money_format("%1073741821i",1);'])
        self.assertShellExitEquals(0, ['php','-r','money_format("%#1073741821i",1);'])
        self.assertShellExitEquals(0, ['php','-r','money_format("%.1073741821i",1);'])
        self.assertShellOutputEquals("hi 1.23", ['php','-r','echo money_format("hi %1.2i",1.23);'])

    def test_d_tag_underflow(self):
        '''ELF header parser does not underflow (CVE-2010-0830)'''

        ld = glob.glob(self._libpath('ld-2.*.so'))[0]
        expected = 0
        if self.dpkg_arch != 'i386':
            expected = 1
            self._skipped('x86_32 only')

        self.assertShellExitEquals(expected, [ld,'--verify','./okay.elf']);
        # This ELF has had the SYMTAB tag (0x00000005) replaced with 0xFEEDBEEF
        self.assertShellExitEquals(expected, [ld,'--verify','./corrupted.elf']);

    def test_bad_strstr(self):
        '''strstr broken for some inputs on pre-SSE4 machines (LP: #655463)'''

        os.chdir('strstr')
        self.assertShellExitEquals(0, ["./test"])

    def test_bad_static_strspan(self):
        '''static strspan causes SIGILL (LP: #615953)'''

        os.chdir('strspn')
        self.assertShellExitEquals(0, ["./test"])
        self.assertShellExitEquals(0, ["./test-static"])

    def test_bad_static_getaddrinfo(self):
        '''static getaddrinfo triggers pagesize assert (LP: #672352)'''

        os.chdir('getaddrinfo')
        self.assertShellExitEquals(0, ["./pagesize-abort"])

        if self.lsb_release['Release'] >= 14.04:
            expected = 254
        else:
            expected = 0

        self.assertShellExitEquals(expected, ["./pagesize-abort-static"])

    def test_crypt(self):
        '''test crypt(3) to ensure it returns sane results'''

        os.chdir('crypt')
        self.assertShellExitEquals(0, ["./test-crypt", "des"])
        self.assertShellExitEquals(0, ["./test-crypt", "md5"])
        self.assertShellExitEquals(0, ["./test-crypt", "sha256"])
        self.assertShellExitEquals(0, ["./test-crypt", "sha256-10000"])
        self.assertShellExitEquals(0, ["./test-crypt", "sha512"])
        self.assertShellExitEquals(0, ["./test-crypt", "sha512-10000"])
        # FIXME, blowfish isn't supported, come up with a reasonable
        # test here
        #self.assertShellExitEquals(0, ["./test-crypt", "blowfish"])

    def test_tavis_ldaudit(self):
        '''LD_AUDIT does not load arbitrary libraries for setuid programs (CVE-2010-3856)'''

        os.chdir("origin")
        self.assertShellExitEquals(0, ["./ld_audit.sh"])

    def test_sscanf_always_realloc(self):
        '''sscanf mistakenly always calls realloc() (LP: #1028038)'''

        os.chdir('sscanf')
        self.assertShellExitEquals(0, ["./lp1028038"])

    def test_vfprintf_cve_2012_3404(self):
        '''vfprintf buffer overflow (CVE-2012-3404)'''

        os.chdir('vfprintf')
        self.assertShellExitEquals(0, ["./cve-2012-3404"])

    def test_vfprintf_cve_2012_3406(self):
        '''vfprintf buffer overflow (CVE-2012-3406)'''

        os.chdir('vfprintf')
        self.assertShellExitEquals(0, ["./cve-2012-3406"])

    def test_strtod_cve_2012_3480(self):
        '''strtod integer overflow (CVE-2012-3480)'''

        os.chdir('strtod')
        self.assertShellExitEquals(0, ["./cve-2012-3480"])

    def test_strcoll_cve_2012_4412(self):
        '''strcoll integer overflow (CVE-2012-4412)'''

        # This test segfaults when vulnerable, but consumes massive
        # resources when not
        os.chdir('strcoll')
        signal, rc = self._cmd_timeout("./cve-2012-4412")

        # Should not segfault
        self.assertNotEqual(signal, 11)
        # Should either end cleanly, or we killed it
        self.assertTrue(signal in [ 0, 15 ])

    def test_strcoll_cve_2012_4424(self):
        '''strcoll stack overflow (CVE-2012-4424)'''

        # This test segfaults when vulnerable, but consumes massive
        # resources when not
        os.chdir('strcoll')
        signal, rc = self._cmd_timeout("./cve-2012-4424")

        # Should not segfault
        self.assertNotEqual(signal, 11)
        # Should either end cleanly, or we killed it
        self.assertTrue(signal in [ 0, 9, 15 ])

    def test_strcoll_sanity(self):
        '''strcoll sanity check'''

        os.chdir('strcoll')
        self.assertShellExitEquals(0, ["./strcoll-test"])

    def test_regex_cve_2013_0242(self):
        '''regex buffer overflow (CVE-2013-0242)'''

        # This test consumes resources when vulnerable
        os.chdir('regex')
        signal, rc = self._cmd_timeout("./cve-2013-0242")

        # Should exit cleanly
        self.assertEqual(signal, 0)

    def test_malloc_cve_2013_4332_1(self):
        '''malloc heap corruption (CVE-2013-4332) Part 1'''

        # This test consumes resources when vulnerable
        os.chdir('malloc')
        signal, rc = self._cmd_timeout("./cve-2013-4332-1")

        # Should exit cleanly
        self.assertEqual(signal, 0)

    def test_malloc_cve_2013_4332_2(self):
        '''malloc heap corruption (CVE-2013-4332) Part 2'''

        # This test consumes resources when vulnerable
        os.chdir('malloc')
        signal, rc = self._cmd_timeout("./cve-2013-4332-2")

        # Should exit cleanly
        self.assertEqual(signal, 0)

    def test_malloc_cve_2013_4332_3(self):
        '''malloc heap corruption (CVE-2013-4332) Part 3'''

        # This test consumes resources when vulnerable
        os.chdir('malloc')
        signal, rc = self._cmd_timeout("./cve-2013-4332-3")

        # Should exit cleanly
        self.assertEqual(signal, 0)

    def test_getaddrinfo_cve_2013_4357(self):
        '''getaddrinfo stack overflow (CVE-2013-4357)'''

        if self.lsb_release['Release'] < 14.10:
            expected = 248
        else:
            expected = 0

        os.chdir('getaddrinfo')
        self.assertShellExitEquals(expected, ["./CVE-2013-4357", "150000000"])


if __name__ == '__main__':
    # CVE-2010-3856 test fails if we're running as root
    testlib.require_nonroot()

    unittest.main()
