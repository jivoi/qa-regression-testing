#!/usr/bin/python
#
#    gcc-security.py regression testing script for GCC
#    security features (and some glibc features too)
#
#    Copyright (C) 2009-2011 Canonical Ltd.
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
# QRT-Depends: gcc-security built-binaries

'''
    Cannot run as root.
'''

import unittest, subprocess
import os
import testlib

class GccSecurityTest00(testlib.TestlibCase):
    '''Test gcc security feature availability'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('gcc-security')
        self.mode = 'available'
        # Get short gcc version
        self.gcc_version_short = testlib.get_gcc_version(self.get_makefile_compiler(), full=False)
        self.gcc_version_minor = float('.'.join(self.gcc_version_short.split('.')[0:2]))

    def tearDown(self):
        '''Clean up after each test_* function'''

        self.make_clean()
        os.chdir(self.fs_dir)

    def test_00_clean(self):
        '''Fresh build tree'''
        self.announce('Makefile uses gcc %s' % (self.gcc_version_short))
        self.make_clean()

    default_modes = ['strcpy', 'memcpy', 'sprintf', 'read', 'getcwd', 'nada']

    # Generic glibc abort handler test
    def _test_overflow_handling(self, base_exec, abort_string, stack_protector=False, modes=default_modes):
        '''Generic tester for glibc aborts'''

        expected = True
        if self.lsb_release['Release'] < 8.10:
            self._skipped("only Intrepid and later")
            return

        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': expected,
                  }
        map_list = [ base_exec + '-off', base_exec + '-on' ]
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        for target in map_list:
            self.make_target(target)
            for mode in modes:
                traces = ['sprintf']
                if self.dpkg_arch != 'amd64' or self.lsb_release['Release'] < 14.04:
                    # 14.04 stopped having read_chk show up in backtraces on amd64
                    traces += ['read']
                if self.dpkg_arch != 'amd64' and self.lsb_release['Release'] != 12.04:
                    # amd64 does not resolve this in backtrace for some reason
                    # nor does i386 on precise
                    traces += ['strcpy']

                if mode != 'nada':
                    # check non-overflow case
                    cmd = ['./%s' % (target),mode,'A' * 40]
                    rc, output = self.shell_cmd(cmd)
                    self.assertEquals(rc, 0)

                # stop when we hit either SIGABRT or SIGSEGV, whichever
                # comes first to detect the overflow needed to trigger
                # protections without wrecking the backtrace as well.
                # http://sourceware.org/bugzilla/show_bug.cgi?id=12189
                # Step in max-word-width steps to avoid partially
                # overwriting the saved-pc with a valid .text location.
                for size in range(50,100,8):
                    cmd = ['./%s' % (target),mode,'A' * size]
                    rc, output = self.shell_cmd(cmd)
                    if rc in [-6,-11] or mode == 'nada':
                        self.announce("%s:%d" % (mode, size))
                        break

                # short-circuit on the "invalid mode" test
                if mode == 'nada':
                    self.assertEquals(rc, 2)
                    continue
                # clean up generated temp dirs
                if mode == 'getcwd':
                    dir = output.strip().splitlines().pop(0)
                    self.assertTrue(dir.startswith("/"),dir)
                    if os.path.exists(dir):
                        os.rmdir(dir)
                # If the crash is caught by glibc, it is an abort,
                # otherwise it is an uncontrolled segmentation fault.
                rc_expected = -6
                if not mapping[target]:
                    rc_expected = -11
                self.assertEquals(rc, rc_expected, 'rc(%d) != %d: %s\n' % (rc, rc_expected, " ".join(cmd)) + output)
                wanted = '*** %s ***: ./%s terminated\n' % (abort_string, target)
                self.assertEquals(wanted in output, mapping[target], "'%s' %s in output of '%s':\n%s" % (wanted, ['NOT','is'][mapping[target]], " ".join(cmd),output))

                # Backtrace expected?
                backtrace_expected = mapping[target]
                if self.dpkg_arch == 'armel' or \
                   (self.lsb_release['Release'] > 12.04 and stack_protector):
                    backtrace_expected = False
                has_backtrace = '(__fortify_fail+0x' in output
                self.assertEquals(has_backtrace, backtrace_expected, "%s:\n%s" % (" ".join(cmd),output))
                if not has_backtrace:
                    continue
                # Look for specific backtrace details
                chk_expected = mapping[target] and not stack_protector
                if not mode in traces:
                    chk_expected = False
                wanted = '(__%s_chk+0x' % (mode)
                self.assertEquals(wanted in output, chk_expected, "'%s' %s in output from '%s':\n%s" % (wanted, ['NOT','is'][chk_expected], " ".join(cmd),output))

    # Intrepid and later
    # Edgy and later
    def test_10_stack_protector(self):
        '''Stack protector'''

        self._test_overflow_handling('stack-protector', 'stack smashing detected', stack_protector=True)

    def test_11_stack_protector_strong(self):
        '''Stack protector strong'''

        # only Utopic and gcc-4.9 or later
        if self.lsb_release['Release'] < 14.10:
            self._skipped("only Utopic and later")
            return

        self._test_overflow_handling('stack-protector-strong', 'stack smashing detected', stack_protector=True, modes=['memcpy', 'nada'])

    # Intrepid and later
    def test_20_relro(self):
        '''GNU_RELRO ELF section generated'''

        expected = True
        if self.lsb_release['Release'] < 8.10:
            self._skipped("only Intrepid and later")
            expected = False

        base_exec = 'relro'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-default': expected,
                  }
        map_list = [ base_exec + '-off', base_exec + '-on' ]
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        for target in map_list:
            self.make_target(target)
            rc, output = self.shell_cmd(['readelf','-l',target])
            self.assertEquals(rc, 0, output)
            self.assertTrue(mapping[target] == ('GNU_RELRO' in output), output)

    # Intrepid and later
    # Technically, this run-time test is actually a glibc test...
    def test_21_format_security(self):
        '''Format security checked at compile and runtime'''

        default_expected = True
        abort_expected = True
        if self.lsb_release['Release'] < 8.10:
            self._skipped("only Intrepid and later")
            default_expected = False
        if self.lsb_release['Release'] < 8.04:
            abort_expected = False

        base_exec = 'format-security'
        mapping = { base_exec + '-off': False,
                    base_exec + '-on': True,
                    base_exec + '-equal2': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [ base_exec + '-off', base_exec + '-on', base_exec + '-equal2']
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        for target in map_list:
            output = self.make_target(target)
            self.assertEqual('warning: format not a string literal' in output, mapping[target], output)
            cmd = ['./%s'%(target),'%x%x%x%n%n%n%n']
            rc, output = self.shell_cmd(cmd)
            # If the crash is caught by stack-protector, it is an abort,
            # otherwise it is an uncontrolled segmentation fault.
            rc_expected = -11
            if mapping[target] and abort_expected:
                rc_expected = -6
            self.assertEquals(rc, rc_expected, 'rc(%d) != %d: %s\n' % (rc, rc_expected, " ".join(cmd)) + output)
            wanted = '*** %n in writable segment detected ***\n'
            self.assertEquals(wanted in output, mapping[target] and abort_expected, "'%s' in output of '%s':\n" % (wanted, " ".join(cmd)) + output)

    def test_40_format_warnings(self):
        '''gcc -Wformat works when requested'''

        default_expected = True
        if self.lsb_release['Release'] < 14.04:
            self._skipped("-Wformat only on by default in trusty and later")
            default_expected = False

        base_exec = 'format'
        mapping = { base_exec + '-off': False,
                    base_exec + '-equal0': False,
                    base_exec + '-on': True,
                    base_exec + '-equal1': True,
                    base_exec + '-equal2': True,
                    base_exec + '-extra-args-on': True,
                    base_exec + '-default': default_expected,
                  }
        map_list = [ base_exec + '-off', base_exec + '-equal0', base_exec + '-on', base_exec + '-equal1',  base_exec + '-equal2', base_exec + '-extra-args-on']
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        for target in map_list:
            # only interested in make warnings, no crashes occur
            output = self.make_target(target)
            self.assertEqual('warning: too many arguments for format' in output, mapping[target], output)

    def _test_warnings(self, base_exec, warning, expected_funcs, unexpected_funcs, compiles=True, rc_wanted=0):
        '''Unchecked return values generate warnings'''

        default_expected = True
        abort_expected = True
        if self.lsb_release['Release'] < 8.10:
            self._skipped("only Intrepid and later")
            default_expected = False
        if self.lsb_release['Release'] < 8.04:
            abort_expected = False

        mapping = { base_exec + '-off': False,
                base_exec + '-on': True,
                base_exec + '-default': default_expected,
              }
        map_list = [ base_exec + '-off', base_exec + '-on' ]
        if self.mode == 'by-default':
            map_list = [ base_exec + '-default' ]
        for target in map_list:
            compile_rc = 0
            if not compiles and mapping[target]:
                compile_rc = 2
            output = self.make_target(target, expected=compile_rc)
            for func in expected_funcs + unexpected_funcs:
                wanted = warning % (func)
                self.assertEqual(wanted in output, func in expected_funcs and mapping[target], "'%s' (%d, %s) in output of %s:\n" % (wanted, mapping[target], ", ".join(expected_funcs), target) + output)

            if not compiles:
                continue
            cmd = ['./%s'%(target), 'blah blah blah']
            rc, output = self.shell_cmd(cmd)
            rc_expected = rc_wanted
            if rc_expected == -11 and mapping[target] and abort_expected:
                rc_expected = -6
            self.assertEquals(rc, rc_expected, 'rc(%d) != %d: %s\n' % (rc, rc_expected, " ".join(cmd)) + output)
            self.assertEquals('ok\n' in output, True, "%s:\n" % (" ".join(cmd)) + output)

    # Intrepid and later
    # Technically, this is a glibc compile-time test...
    def test_22_warn_unchecked(self):
        '''Unchecked return values generate warnings'''

        expected_funcs = ['write','system']
        unexpected_funcs = ['open']
        if self.lsb_release['Release'] < 8.04:
            self.announce("-all")
            unexpected_funcs += expected_funcs
            expected_funcs = []
        else:
            if self.lsb_release['Release'] < 9.04:
                self.announce("+fwrite")
                expected_funcs += ['fwrite']
            else:
                self.announce("-fwrite")
                unexpected_funcs += ['fwrite']


        self._test_warnings('warn-unchecked', "warning: ignoring return value of '%s', declared with attribute warn_unused_result", expected_funcs, unexpected_funcs)

    # Intrepid and later
    # Technically, this is a glibc run-time test...
    def test_23_buffer_overflow_protection(self):
        '''Buffer overflow protection'''

        self._test_overflow_handling('buffer-overflow', 'buffer overflow detected')

    # Technically, this is a glibc compile-time test...
    def test_24_missing_mode(self):
        '''Missing open mode when using O_CREAT warning'''

        compiles = False
        rc = None
        old_expected_funcs = ['__open_missing_mode']
        expected_funcs = []
        unexpected_funcs = ['mongoose']
        if self.lsb_release['Release'] > 8.04:
            self.announce("has warnings")
            expected_funcs += old_expected_funcs
        else:
            self.announce("no warnings")
            unexpected_funcs += old_expected_funcs
        if self.lsb_release['Release'] < 8.10:
            self.announce("compiles")
            compiles = True
            rc = -11

        self._test_warnings('missing-mode', "error: call to '%s' declared with attribute error: open with O_CREAT in second argument needs 3 arguments", expected_funcs, unexpected_funcs, compiles=compiles, rc_wanted=rc)

    # Technically, this is a glibc compile-time test...
    def test_25_static_buffer_read_check(self):
        '''Static read vs buffer size warning'''

        compiles = False
        rc = None
        new_expected_funcs = ['__read_chk_warn']
        expected_funcs = []
        unexpected_funcs = ['mongoose']
        if self.lsb_release['Release'] > 8.04:
            self.announce("has warnings")
            expected_funcs += new_expected_funcs
        else:
            self.announce("no warnings")
            unexpected_funcs += new_expected_funcs

        if self.lsb_release['Release'] < 8.10:
            self.announce("compiles")
            compiles = True
            rc = -11

        self._test_warnings('missing-mode', "warning: call to '%s' declared with attribute warning: read called with bigger length than size of the destination buffer", expected_funcs, unexpected_funcs, compiles=compiles, rc_wanted=rc)

    # Technically, this is a glibc compile-time test...
    def test_26_static_buffer_check(self):
        '''Static copy vs buffer size warning'''

        compiles = False
        rc = None
        new_expected_funcs = ['__builtin___memcpy_chk','__builtin___snprintf_chk']
        expected_funcs = []
        unexpected_funcs = ['mongoose']
        if self.lsb_release['Release'] > 7.10:
            self.announce("has warnings")
            expected_funcs += new_expected_funcs
        else:
            self.announce("no warnings")
            unexpected_funcs += new_expected_funcs

        if self.lsb_release['Release'] < 8.10:
            self.announce("compiles")
            compiles = True
            rc = -11

        self._test_warnings('missing-mode', "warning: call to %s will always overflow destination buffer", expected_funcs, unexpected_funcs, compiles=compiles, rc_wanted=rc)

    def test_30_stack_protector_all(self):
        '''gcc -fstack-protector-all works when requested (LP: #691722)'''

        expected = 0
        if self.lsb_release['Release'] < 11.04:
            self.announce("unfixed prior to Natty")
            expected = 1

        target = 'stack-protector-all'
        self.make_target(target)
        # Only care about stack protector
        cmd = ['../built-binaries/hardening-check','-qpfrb',target]
        self.assertShellExitEquals(expected, cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, msg="Hardening check failed for -fstack-protector-all:")


# Secondary class that enables all the "by default" tests so features can
# be separated from their "by default"-ness.  (i.e. ask the question "is
# Dapper's gcc even capable of feature XYZ?" separate from "is that feature
# enabled by default in Dapper?")
class GccSecurityTest01(GccSecurityTest00):
    '''Test gcc security features available'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        GccSecurityTest00.setUp(self)
        self.announce('by default')
        self.mode = 'by-default'


# other things to test...
#~~~~~~~~~~~~~~~~~~~~~~~~
# ... ?

if __name__ == '__main__':
    testlib.require_nonroot()
    unittest.main()
