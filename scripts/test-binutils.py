#!/usr/bin/python
#
#    test-binutils.py quality assurance test script for binutils
#    Copyright (C) 2015 Canonical Ltd.
#    Author:  Steve Beattie <steve.beattie@canonical.com>
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
# QRT-Packages: binutils binutils-multiarch
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends: private/qrt/binutils.py binutils

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


import difflib
import os
import resource
import subprocess
import sys
import tempfile
import testlib
import unittest

try:
    from private.qrt.binutils import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class BinutilsTest(testlib.TestlibCase, PrivatePkgTest):
    '''Test binutils-multiarch.'''

    strings_bin = '/usr/bin/strings'
    objdump_bin= '/usr/bin/objdump'
    readelf_bin= '/usr/bin/readelf'
    objcopy_bin= '/usr/bin/objcopy'

    def setUp(self):
        '''Set up prior to each test_* function'''

        # some of these tests can consume all memory. Try to prevent that.
        resource.setrlimit(resource.RLIMIT_AS, (2 ** 32, 2 ** 32))
        self.fs_dir = os.path.abspath('.')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _test_strings(self, filename, expected=0):
        '''Helper function to wrap testing whether strings segvs'''
        rc, report = testlib.cmd([self.strings_bin, filename])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _test_objdump(self, filename, expected=0):
        '''Helper function to wrap testing whether objdump segvs'''
        rc, report = testlib.cmd([self.objdump_bin, '-x', filename])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _test_readelf(self, filename, expected=0):
        '''Helper function to wrap testing whether objdump segvs'''
        rc, report = testlib.cmd([self.readelf_bin, '-a', filename])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def skip_if_lucid(self, expected=0, fortify_caught=False):
        '''backporting the necessary fixes for the bz17512 crashers for
           lucid required pulling in too many prerequisite commits. :(
           Skip those tests on lucid.'''

        if self.lsb_release['Release'] <= 10.04:
            self._skipped('no backport for lucid')
            expected = -11
            # fortify printf checks catch some of the overflows
            if fortify_caught:
                expected = -6

        return expected

    def test_CVE_2014_8484_1(self):
        '''Test for CVE-2014-8484 (first example)'''
        self._test_strings('binutils/CVE-2014-8484/stringme')

    def test_CVE_2014_8484_2(self):
        '''Test for CVE-2014-8484 (second example)'''
        self._test_strings('binutils/CVE-2014-8484/string2')

    def test_CVE_2014_8485_1(self):
        '''Test for CVE-2014-8485 (first example)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17510#c0'''
        self._test_strings('binutils/CVE-2014-8485/strings-bfd-badptr')

    def test_CVE_2014_8485_2(self):
        '''Test for CVE-2014-8485 (second example)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17510#c2'''
        self._test_strings('binutils/CVE-2014-8485/strings-bfd-badptr2')

    def test_CVE_2014_8501_1(self):
        '''Test for CVE-2014-8501 (maxvals.exe)'''

        '''Origin: https://github.com/radare/radare2-regressions/tree/master/bins/pe'''
        self._test_strings('binutils/CVE-2014-8501/maxvals.exe')

    def test_CVE_2014_8501_2(self):
        '''Test for CVE-2014-8501 (dllmaxvals.dll)'''

        '''Origin: https://github.com/radare/radare2-regressions/tree/master/bins/pe'''
        self._test_strings('binutils/CVE-2014-8501/dllmaxvals.dll')

    def test_CVE_2014_8502_1(self):
        '''Test for CVE-2014-8502 (first)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c5'''
        self._test_objdump('binutils/CVE-2014-8502/objdump-pe-crasher')

    def test_CVE_2014_8502_2(self):
        '''Test for CVE-2014-8502 (second)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c4'''
        self._test_objdump('binutils/CVE-2014-8502/objdump-elf-crasher', expected=1)

    def test_CVE_2014_8502_3(self):
        '''Test for CVE-2014-8502 (third)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c16'''
        self._test_objdump('binutils/CVE-2014-8502/objdump-pe-crasher2')

    def test_CVE_2014_8503_ihex(self):
        '''Test for CVE-2014-8503 (ihex)'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c33'''
        self._test_objdump('binutils/CVE-2014-8503/ihex-stack-overflow.ihex', expected=1)

    def test_CVE_2014_8504(self):
        '''Test for CVE-2014-8504'''

        '''Origin: http://lcamtuf.coredump.cx/strings-stack-overflow'''
        self._test_strings('binutils/CVE-2014-8504/strings-stack-overflow')

    def test_CVE_2014_8738(self):
        '''Test for CVE-2014-8738'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17533#c0'''
        self._test_objdump('binutils/CVE-2014-8738/test.a', expected=1)

    def test_bz17512_c49_01(self):
        '''Test for bz17512 comment 49 crasher 01'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid(1, fortify_caught=True)
        self._test_objdump('binutils/bz17512/17512c49-078-4396-0.004', expected)

    def test_bz17512_c49_02(self):
        '''Test for bz17512 comment 49 crasher 02'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-221-1874-0.004')

    def test_bz17512_c49_03(self):
        '''Test for bz17512 comment 49 crasher 03'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-070-7351-0.004', expected)

    def test_bz17512_c49_04(self):
        '''Test for bz17512 comment 49 crasher 04'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-17961-0.004')

    def test_bz17512_c49_05(self):
        '''Test for bz17512 comment 49 crasher 05'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-272-2488-0.004')

    def test_bz17512_c49_06(self):
        '''Test for bz17512 comment 49 crasher 06'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-070-2541-0.004')

    def test_bz17512_c49_07(self):
        '''Test for bz17512 comment 49 crasher 07'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-9239-0.004')

    def test_bz17512_c49_08(self):
        '''Test for bz17512 comment 49 crasher 08'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-078-13914-0.004', expected)

    def test_bz17512_c49_09(self):
        '''Test for bz17512 comment 49 crasher 09'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-1318-0.004')

    def test_bz17512_c49_10(self):
        '''Test for bz17512 comment 49 crasher 10'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-272-1434-0.004')

    def test_bz17512_c49_11(self):
        '''Test for bz17512 comment 49 crasher 11'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-116-1071-0.004', expected)

    def test_bz17512_c49_12(self):
        '''Test for bz17512 comment 49 crasher 12'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-079-5460-0.004', expected)

    def test_bz17512_c49_13(self):
        '''Test for bz17512 comment 49 crasher 13'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-078-16876-0.004', expected)

    def test_bz17512_c49_14(self):
        '''Test for bz17512 comment 49 crasher 14'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid(1, fortify_caught=True)
        self._test_objdump('binutils/bz17512/17512c49-079-16424-0.004', expected)

    def test_bz17512_c49_15(self):
        '''Test for bz17512 comment 49 crasher 15'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-222-6942-0.004')

    def test_bz17512_c49_16(self):
        '''Test for bz17512 comment 49 crasher 16'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-070-13551-0.004')

    def test_bz17512_c49_17(self):
        '''Test for bz17512 comment 49 crasher 17'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-118-944-0.004', expected)

    def test_bz17512_c49_18(self):
        '''Test for bz17512 comment 49 crasher 18'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-13482-0.004')

    def test_bz17512_c49_19(self):
        '''Test for bz17512 comment 49 crasher 19'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-079-8998-0.004', expected)

    def test_bz17512_c49_20(self):
        '''Test for bz17512 comment 49 crasher 20'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-087-5683-0.004')

    def test_bz17512_c49_21(self):
        '''Test for bz17512 comment 49 crasher 21'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-4195-0.004')

    def test_bz17512_c49_22(self):
        '''Test for bz17512 comment 49 crasher 22'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-116-1767-0.004', expected)

    def test_bz17512_c49_23(self):
        '''Test for bz17512 comment 49 crasher 23'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-222-8288-0.004')

    def test_bz17512_c49_24(self):
        '''Test for bz17512 comment 49 crasher 24'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-277-185-0.004')

    def test_bz17512_c49_25(self):
        '''Test for bz17512 comment 49 crasher 25'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-093-3968-0.004', expected)

    def test_bz17512_c49_26(self):
        '''Test for bz17512 comment 49 crasher 26'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-154-6305-0.004', expected)

    def test_bz17512_c49_27(self):
        '''Test for bz17512 comment 49 crasher 27'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-085-6046-0.004', expected)

    def test_bz17512_c49_28(self):
        '''Test for bz17512 comment 49 crasher 28'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-1458-0.004')

    def test_bz17512_c49_29(self):
        '''Test for bz17512 comment 49 crasher 29'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-101-8438-0.004', expected)

    def test_bz17512_c49_30(self):
        '''Test for bz17512 comment 49 crasher 30'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-6268-0.004')

    def test_bz17512_c49_31(self):
        '''Test for bz17512 comment 49 crasher 31'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = self.skip_if_lucid()
        self._test_objdump('binutils/bz17512/17512c49-079-8380-0.004', expected)

    def test_bz17512_c49_32(self):
        '''Test for bz17512 comment 49 crasher 32'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-221-1445-0.004')

    def test_bz17512_c49_33(self):
        '''Test for bz17512 comment 49 crasher 33'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        self._test_objdump('binutils/bz17512/17512c49-065-2592-0.004', expected=1)

    def test_bz17512_c49_34(self):
        '''Test for bz17512 comment 49 crasher 34'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c49'''
        expected = 0
        # unsupported format on 12.04 and older
        if self.lsb_release['Release'] <= 12.04:
            expected = 1
        self._test_objdump('binutils/bz17512/17512c49-179-6986-0.004', expected)

    # Ugh, the next four tests still trip a buffer overflow, even with
    # the binutils 2.25 release. However, they all get caught by the
    # fortify source printf protections, so expect this behavior.
    def test_bz17512_c91_id000001(self):
        '''Test for bz17512 comment 91 crasher id:000001'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c91'''
        self._test_objdump('binutils/bz17512/17512c91-id000001', -6)

    def test_bz17512_c91_id000009(self):
        '''Test for bz17512 comment 91 crasher id:000009'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c91'''
        self._test_objdump('binutils/bz17512/17512c91-id000009', -6)

    def test_bz17512_c91_id000033(self):
        '''Test for bz17512 comment 91 crasher id:000033'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c91'''
        self._test_objdump('binutils/bz17512/17512c91-id000033', -6)

    def test_bz17512_c91_id000787(self):
        '''Test for bz17512 comment 91 crasher id:000787'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17512#c91'''
        self._test_objdump('binutils/bz17512/17512c91-id000787', -6)

    def test_bz17531_c00(self):
        '''Test for bz17531 comment 00 readelf crasher'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17531#c0'''
        expected = self.skip_if_lucid()
        self._test_readelf('binutils/bz17531/readelf-crash-01', expected)

    def test_bz17531_c06_01(self):
        '''Test for bz17531 comment 06 readelf crasher 01'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17531#c6'''
        self._test_readelf('binutils/bz17531/17531c6-001-1222-0.004')

    def test_bz17531_c06_02(self):
        '''Test for bz17531 comment 06 readelf crasher 01'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17531#c6'''
        self._test_readelf('binutils/bz17531/17531c6-012-10414-0.004')

    def test_bz17531_c06_03(self):
        '''Test for bz17531 comment 06 readelf crasher 01'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17531#c6'''
        self._test_readelf('binutils/bz17531/17531c6-012-1555-0.004')

    def test_bz17531_c06_04(self):
        '''Test for bz17531 comment 06 readelf crasher 01'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17531#c6'''
        self._test_readelf('binutils/bz17531/17531c6-037-31-0.004')

    def test_lp1477350(self):
        '''Test to ensure objcopy doesn't segfault writing pecoff files'''

        '''Origin: https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1477350'''
        expected = 0
        os.chdir('binutils/lp1477350')
        rc, report_default = testlib.cmd(['make', 'clean', 'all', 'OBJCOPY=%s' % self.objcopy_bin])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report_default)
        testlib.cmd(['make', 'clean'])

    def test_hardened_strings(self):
        '''Test whether strings avoids using libbfd by default'''

        # strings -a/--all does not use libbfd, strings --data
        # does. The default behavior should be --all, as libbfd is
        # unsafe to use on untrusted input.

        expected = 0
        binary = '/bin/true'
        rc, report_default = testlib.cmd([self.strings_bin, binary])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report_default)

        rc, report_all = testlib.cmd([self.strings_bin, '-a', binary])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report_all)

        diff = difflib.unified_diff(report_default.splitlines(1), report_all.splitlines(1))
        result = '"strings" and "strings -a" should return the same output, ' \
                 'but did not. Differences are:" \n%s' % (''.join(diff))
        self.assertEquals(report_all, report_default, result)

class BinutilsSingleTest(BinutilsTest):
    '''Test binutils (the single arch package).'''

    strings_bin = '/usr/bin/strings.single'
    objdump_bin = '/usr/bin/objdump.single'
    readelf_bin = '/usr/bin/readelf.single'
    objcopy_bin = '/usr/bin/objcopy.single'

class BinutilsPathsTest(testlib.TestlibCase):
    '''Tests for binutils issues related to paths'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.tempdir = tempfile.mkdtemp(prefix='binutils-')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_CVE_2014_8737_strip(self):
        '''Test strip for CVE-2014-8737'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17552'''
        bad_archive_contents = '!<arch>\n{0:<48}{1:<10d}`\n../file\n{2:<48}{3:<10d}`\n'.format('//', 8, '/0', 0)
        bad_archive = os.path.join(self.tempdir, 'cve-2014-8737.a')
        testlib.create_fill(bad_archive, bad_archive_contents)

        victim_file = os.path.join(self.tempdir, 'file')
        testlib.create_fill(victim_file, 'Please don\'t hurt me\n')

        os.chdir(self.tempdir)

        expected = 1
        rc, report = testlib.cmd(['/usr/bin/strip', bad_archive])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(os.path.exists(victim_file), 'strip deleted %s; output was:\n%s' %(victim_file, report))

    def test_CVE_2014_8737_ar(self):
        '''Test ar for CVE-2014-8737'''

        '''Origin: https://sourceware.org/bugzilla/show_bug.cgi?id=17552'''
        bad_archive_contents = '!<arch>\n{0:<48}{1:<10d}`\n../file\n{2:<48}{3:<10d}`\n'.format('//', 8, '/0', 0)
        bad_archive = os.path.join(self.tempdir, 'cve-2014-8737.a')
        testlib.create_fill(bad_archive, bad_archive_contents)

        victim_file = os.path.join(self.tempdir, 'file')
        victim_contents = 'Please don\'t hurt me\n'
        testlib.create_fill(victim_file, victim_contents)

        subdir = os.path.join(self.tempdir, 'dir')
        os.mkdir(subdir)
        os.chdir(subdir)

        expected = 0
        rc, report = testlib.cmd(['/usr/bin/ar', 'xv', bad_archive])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(os.path.exists(victim_file), 'strip deleted %s; output was:\n%s' %(victim_file, report))
        try:
            with open(victim_file, 'r') as f:
                new_contents = f.read()
        except IOError as e:
            self.fail('Unable to open victim \'%s\': %s' %(victim_file, str(e)))
        result = 'expected file contents:\n%s\nactual file contents:\n%s\n' %(victim_contents, new_contents)
        self.assertEquals(victim_contents, new_contents, result + report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
