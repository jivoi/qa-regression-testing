#!/usr/bin/python
#
#    glibc-security.py regression testing script for glibc internal
#    security features
#
#    Copyright (C) 2008-2009 Canonical Ltd.
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
# QRT-Packages: build-essential
# QRT-Depends: glibc-security
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install build-essential  && ./test-glibc-security.py -v'
'''

import unittest
import os
import testlib

class GlibcSecurityTest(testlib.TestlibCase):
    '''Test glibc security features'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('glibc-security')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    # All, duh
    def test_00_make(self):
        '''Build helper tools'''

        self.announce("gcc %s" % (self.gcc_version))
        self.assertShellExitEquals(0, ["make","clean"])
        self.assertShellExitEquals(0, ["make"])

    # All releases
    def test_11_heap_protector(self):
        '''glibc heap protection'''

        self.assertShellExitEquals(0, ["./heap",'safe'])
        self.assertShellExitEquals(-6, ["./heap",'unsafe'])

    # All releases (got fixed in Intrepid)
    def test_11_sprintf_unmangled(self):
        '''sprintf not pre-truncated with -D_FORTIFY_SOURCE=2'''
        expected = 0
        if self.lsb_release['Release'] == 8.04:
            self._skipped("Hardy known broken")
            expected = 1
        self.assertShellExitEquals(expected, ["./sprintf"])

    # All releases
    def test_12_glibc_pointer_obfuscation(self):
        '''glibc pointer obfuscation'''

        # glibc implementation of PTR_MANGLE/PTR_DEMANGLE
        #
        # locate values via:
        #  cd glibc-*
        #  fakeroot debian/rules patch
        #  cd build-tree/glibc-*
        #  grep -R JB_PC sysdeps/ | grep define

        expected = 0
        jb_pc = '-1'
        jb_unenc = '-1' # unencrypted isn't stable
        if self.dpkg_arch == 'i386' or self.dpkg_arch == 'lpia':
            jb_pc = '5'
            #jb_unenc = '1'
        elif self.dpkg_arch == 'amd64':
            jb_pc = '7'
            #jb_unenc = '0'
        elif self.dpkg_arch == 'armel':
            self._skipped("not on ARM")
            expected = 2

        if self.lsb_release['Release'] < 7.04:
            self._skipped("only Edgy and later")
            expected = 100

        self.assertShellExitEquals(2, ["./ptr-enc",'-1','-1'])
        self.assertShellExitEquals(200, ["./ptr-enc",'-2','-2'])
        self.assertShellExitEquals(expected, ["./ptr-enc",jb_pc,jb_unenc])

    # Precise and later (glibc 2.15+)
    def test_13_select_overflow(self):
        '''select macros detect overflow with -D_FORTIFY_SOURCE=2'''
        expected = -6
        if self.lsb_release['Release'] < 12.04:
            self._skipped("only Precise and later")
            expected = 4
        self.assertShellExitEquals(0, ["./select", "200"])
        self.assertShellExitEquals(expected, ["./select", "1500"])
        self.assertShellExitEquals(expected, ["./select", "-100"])

    # Is this really glibc?  I guess it is since it's crypt() kinda...
    def test_41_passwd_hashes(self):
        '''Password hashes'''

        expected = 'sha512'
        pattern = '$6$'
        if self.lsb_release['Release'] < 8.10:
            expected = 'md5'
            pattern = '$1$'
        self.announce(expected)

        seen = None
        pam_file = None
        for pam_path in ['/etc/pam.d/common-password', '/etc/pam.d/system-auth']:
            if os.path.exists(pam_path):
                pam_file = pam_path
                break
        self.assertTrue(pam_file != None, "Cannot find pam password config file")
        for line in file(pam_file):
            if line.startswith('password') and 'pam_unix.so' in line:
                if expected in line:
                    seen = True
                else:
                    seen = False
                break
        self.assertTrue(seen!=None,"pam_unix.so line not found in %s" % (pam_file))
        self.assertTrue(seen,"%s argument not found in %s" % (expected, pam_file))

        rc, output = self.shell_cmd(['cut','-d:','-f2','/etc/shadow'])
        self.assertEquals(rc,0,"Got %d (expected %d):\n%s" % (rc, 0, output))
        seen = False
        star = False
        for hash in output.splitlines():
            if hash.startswith(pattern):
                seen = True
            if hash == '*':
                star = True
        self.assertTrue(star,"'*' locked password not found in /etc/shadow:\n%s" % (output))
        self.assertTrue(seen,"%s hash not found in /etc/shadow:\n%s" % (expected, output))

    # Edgy and newer
    def test_80_stack_guard_exists(self):
        '''Stack guard exists'''

        rc_expected = 0
        if self.lsb_release['Release'] < 6.10:
            self._skipped("only Edgy and later")
            rc_expected = 1

        rc, one  = testlib.cmd(["./guard"])
        self.assertEqual(rc, rc_expected, one)

    # Edgy and newer
    def test_81_stack_guard_leads_zero(self):
        '''Stack guard leads with zero byte'''

        rc_expected = 0
        expected = True
        if self.lsb_release['Release'] < 6.10:
            self._skipped("only Edgy and later")
            rc_expected = 1
        # This should not be: https://bugs.launchpad.net/bugs/413278
        #if self.lsb_release['Release'] > 9.04:
        #    expected = False
        #    self._skipped("stopped in Jaunty+")

        rc, one  = testlib.cmd(["./guard"])
        self.assertEqual(rc, rc_expected, one)
        if rc_expected == 0:
            # Try three times just to avoid randomized luck
            self.assertEqual(one.startswith('00 '), expected, one)
            rc, two  = testlib.cmd(["./guard"])
            self.assertEqual(rc, rc_expected, two)
            self.assertEqual(two.startswith('00 '), expected, two)
            rc, three  = testlib.cmd(["./guard"])
            self.assertEqual(rc, rc_expected, three)
            self.assertEqual(three.startswith('00 '), expected, three)

    # Intrepid and newer
    def test_82_stack_guard_randomized(self):
        '''Stack guard is randomized'''

        rc_expected = 0
        if self.lsb_release['Release'] < 6.10:
            # Only Edgy and later can run this test
            rc_expected = 1

        expected = True
        # Fixed for Hardy in 2.7-10ubuntu5 from -proposed
        if self.lsb_release['Release'] < 8.04:
            self._skipped("only Hardy and later")
            expected = False

        rc, one  = testlib.cmd(["./guard"])
        self.assertEqual(rc, rc_expected, one)

        if rc_expected == 0:
            rc, two  = testlib.cmd(["./guard"])
            self.assertEqual(rc, rc_expected, two)
            rc, three = testlib.cmd(["./guard"])
            self.assertEqual(one != two and one != three and two != three, expected, one + two + three)

    # Karmic and newer
    def test_90_abort_msg(self):
        '''Retains assert()/*_chk() message'''

        self.announce(self.path_libc)

        # Not strictly security, but good to check for anyway.
        expected = True
        if self.lsb_release['Release'] < 9.10:
            # Only Karmic and later are expected to have this
            self._skipped("only Karmic and later")
            expected = False

        rc, out = testlib.cmd(["readelf","-s",self.path_libc])
        self.assertEqual(rc, 0, out)
        self.assertEqual(expected, ' __abort_msg@@' in out, out)

# other things to test...
#~~~~~~~~~~~~~~~~~~~~~~~~
# ... ?

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
