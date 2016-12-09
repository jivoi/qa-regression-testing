#!/usr/bin/env python
#
#    kernel-security.py regression testing script for kernel and
#    security features
#
#    Copyright (C) 2008-2016 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Steve Beattie <steve.beattie@canonical.com>
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
# QRT-Packages: build-essential sudo gdb gawk libcap-dev
# QRT-Packages: linux-headers-`UNAME-R`
# QRT-Alternates: libcap2-bin libcap-bin
# QRT-Alternates: e2fslibs-dev
# QRT-Alternates: gcc-multilib
# QRT-Privilege: root
#
# 6.06 dapper 2.6.15
# 6.10 edgy 2.6.18
# 7.04 feisty 2.6.20
# 7.10 gutsy 2.6.22 (is this wrong? was it .23?)
# 8.04 hardy 2.6.24
# 8.10 intrepid 2.6.27
# 9.04 jaunty 2.6.28
# 9.10 karmic 2.6.31
# 10.04 lucid 2.6.32
# 10.10 maverick 2.6.35
# 11.04 natty 2.6.38
# 11.10 oneiric 3.0.0
# 12.04 precise 3.2.0
# ...
# 14.04 trusty 3.13
# ...
# 15.10 wily 4.2
# 16.04 xenial 4.4
# 16.10 yakkety 4.6?

'''
    This expects to be run under sudo, or at least running as root, with
    the "SUDO_USER" environment variable set to a non-root user.
'''

# QRT-Depends: kernel-security private/qrt/kernel_security.py

import gzip
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest

import testlib

try:
    from private.qrt.kernel_security import PrivateKernelSecurityTest
except ImportError:
    class PrivateKernelSecurityTest(object):
        '''Empty class'''


class KernelSecurityTest(testlib.TestlibCase):
    '''Test kernel security features'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('kernel-security')

        self.arm_archs = ['armel', 'armhf']

        self.aslr_archs = ['i386', 'amd64', 'ppc64el', 'arm64', 's390x']
        if self.kernel_at_least('2.6.35'):
            self.aslr_archs += ['armel', 'armhf']

        self.seccomp_filter_archs = list()
        if self.kernel_at_least('3.0') and not self.kernel_at_least('3.2'):
            self.seccomp_filter_archs += ['i386', 'amd64']

        self.module_ronx_archs = ['i386', 'amd64', 's390x']

        self.sysctl = dict()
        self.sysctl['hardlink'] = 'kernel/yama/protected_nonaccess_hardlinks'
        self.sysctl['symlink'] = 'kernel/yama/protected_sticky_symlinks'
        if self.kernel_at_least('3.6'):
            self.sysctl['hardlink'] = 'fs/protected_hardlinks'
            self.sysctl['symlink'] = 'fs/protected_symlinks'

        self.__config_lines = None

        with open("/proc/cpuinfo") as proc_cpuinfo:
            self.cpu_flags = [x[x.find(': ') + 2:] for x in proc_cpuinfo if x.startswith('flags\t')]
        if len(self.cpu_flags) != 0:
            self.cpu_flags = self.cpu_flags[0].split(' ')

        # Record current stack rlimit
        self.old_stack_limit = resource.getrlimit(resource.RLIMIT_STACK)

        # Prepare for per-test teardowns
        self.teardowns = []

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

        # Restore any changes to stack rlimit
        resource.setrlimit(resource.RLIMIT_STACK, self.old_stack_limit)

        # Handle per-test teardowns
        for func in self.teardowns:
            func()

    def _get_sym(self, sym):
        '''Find a kernel symbol from System.map'''
        systemmap = '/boot/System.map-%s' % (self.kernel_version)
        for line in open(systemmap):
            addr, kind, name = line.strip().split()
            if name == sym:
                return addr
        self.assertTrue(False, "Could not find '%s' in '%s'" % (sym, systemmap))

    # Clean up all builds here, and make them on a per-test basis.
    def test_000_make(self):
        '''Prepare to build helper tools'''

        self.announce("%s" % (self.gcc_version))
        # Something might be keeping "gawk" from being the default AWK
        # implementation, so make sure it is set for the kernel build.
        self.assertShellExitEquals(0, ["update-alternatives",
                                       "--set", "awk", "/usr/bin/gawk"])
        self.assertShellExitEquals(0, ["make", "clean"])

    # Feisty(?) and newer
    def test_010_proc_maps(self):
        '''/proc/$pid/maps is correctly protected (CVE-2013-2929)'''

        expected = 0
        if not self.kernel_at_least('2.6.22'):
            self._skipped("only Feisty and later")
            expected = 1

        os.chdir('proc-maps')
        self.assertShellExitEquals(0, ["make"])
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], "./maps-protection.py", "-v"])

    def test_025_kaslr(self):
        '''kernel ASLR enabled'''

        # FIXME: at runtime, kaslr currently is disabled because it
        # conflicts with hibernate and Ubuntu enables hibernate in its
        # kernel config. When that is fixed upstream, then we can add
        # a runtime test to ensure that kaslr is actually in effect.
        expected = 'y'
        if not self.kernel_at_least('3.16.0'):
            self._skipped("kaslr is only utopic and later")
            expected = None
        elif self.dpkg_arch not in ['i386', 'amd64']:
            self._skipped("kaslr is x86 only")
            expected = None
        self.assertEqual(self._get_config('RANDOMIZE_BASE'), expected)

    # Hardy and newer
    def test_030_mmap_min(self):
        '''Low memory allocation respects mmap_min_addr'''

        wanted = 65536
        if self.dpkg_arch in self.arm_archs or self.dpkg_arch == 'arm64':
            wanted = 32768
        self.announce("%d" % (wanted))
        if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
            # Karmic's EC2 has:
            #  CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
            #  CONFIG_LSM_MMAP_MIN_ADDR=65536
            self.announce("weird: Karmic EC2")
            wanted = 4096

        expected = 0
        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = 1
            mmap_limit = 0
        else:
            mmap_limit = self._test_sysctl_value('vm/mmap_min_addr', wanted, "is wine or qemu-kvm-extras-static installed?")

        os.chdir('min-addr')
        self.assertShellExitEquals(0, ["make"])

        # Karmic's ec2 reports the wrong value in mmap_min_addr, but enforces 65536.
        if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
            wanted = 65536

        # Test minimum is enforced
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], "./low-mmap", '%d' % (wanted)])

        # Test that zero is still possible
        self.assertShellExitEquals(1, ["./zero-possible", '%d' % (mmap_limit)], msg="Unable to allocate zero-page when mmap_min_addr set to 0!\n")

        # MMAP_PAGE_ZERO is cleared unconditionally (CVE-2009-1895)
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], "./mappage0", '%d' % (wanted)])

    # Gutsy and newer
    def test_031_apparmor(self):
        '''AppArmor loaded'''

        expected = True
        if not self.kernel_at_least('2.6.22'):
            self._skipped("only Gutsy and later")
            expected = False
        else:
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.31'):
                self._skipped("on ARM only Lucid and later")
                expected = False
        self.assertEqual(os.path.exists('/sys/kernel/security/apparmor'), expected)

    # Hardy and newer
    def test_031_seccomp(self):
        '''PR_SET_SECCOMP works'''

        expected = -9
        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = 10
        else:
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.35'):
                self._skipped("not available on ARM")
                expected = 10
            if self.dpkg_arch == 'arm64' and \
               not self.kernel_at_least('3.19.0'):
                self._skipped("not available on ARM64")
                expected = 10
            if self.kernel_version.endswith('-ec2') or self.kernel_version.endswith('-virtual') or self.kernel_version.endswith('-xen'):
                self._skipped('LP: #725089')
                return

        os.chdir('seccomp')
        self.assertShellExitEquals(0, ["make"])
        self.assertShellExitEquals(expected, ["./seccomp"])

    # Hardy and newer
    def test_032_dev_kmem(self):
        '''/dev/kmem not available'''

        expected = 6  # No such device
        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = 14  # Bad address
        if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
            self._skipped("ignored on Karmic EC2")
            expected = 14  # Bad address
        if not self.kernel_at_least('2.6.22'):
            expected = 1  # Operation not permitted on Gutsy

        self.assertShellExitEquals(0, ["./errno-read.py", '/dev/zero', '4096'])

        dir = tempfile.mkdtemp(prefix='kmem-')
        kmem = os.path.join(dir,'kmem')
        self.assertShellExitEquals(0, ['/bin/mknod', kmem, 'c', '1', '2'])
        self.assertTrue(os.path.exists(kmem))
        self.assertShellExitEquals(expected, ["./errno-read.py", kmem, '4096'])
        os.unlink(kmem)
        os.rmdir(dir)

    # Jaunty and newer
    def test_033_syn_cookies(self):
        '''SYN cookies is enabled'''

        expected = 1
        if not self.kernel_at_least('2.6.28'):
            self._skipped("only Jaunty and later")
            expected = 0

        self._test_sysctl_value('net/ipv4/tcp_syncookies', expected)

    # All kernels
    def test_040_pcaps(self):
        # FIXME: tighten the check to make sure more caps can't be added/lost
        '''init's CAPABILITY list is clean'''

        getpcaps = None
        for item in ['/sbin/getpcaps', '/usr/sbin/getpcaps']:
            if os.path.exists(item):
                getpcaps = item
        self.assertTrue(getpcaps is not None, "getpcaps missing (please install libcap-bin)")

        okay_removed = ['cap_sys_module', 'cap_sys_rawio', 'cap_setpcap']
        required_removed = []
        # CONFIG_SECURITY_FILE_CAPABILITIES was removed in 2.6.33
        if not self.kernel_at_least('2.6.33'):
            required_removed = ['cap_setpcap']

        rc, output = self.shell_cmd([getpcaps, '1'])
        self.assertEqual(rc, 0, output)
        # Capabilities for `1': =ep cap_sys_module,cap_sys_rawio-ep
        self.assertTrue(output.startswith("Capabilities"), output)

        parts = output.strip().split(': ', 1)[1].split()
        self.assertTrue(len(parts) == 1 or len(parts) == 2, output)
        caps_removed = []
        if len(parts) == 1:
            self.assertEqual(parts[0], '=ep', output)
        elif len(parts) == 2:
            self.assertTrue(parts[0] == '=ep' or parts[0] == '=', output)
            if parts[1].endswith('-ep') or parts[1].endswith('-e'):
                caps_removed = parts[1].split('-',1)[0].split(',')
            elif parts[1].endswith('+ep') or parts[1].endswith('+e'):
                # if cap list has +ep, we need to figure out which caps,
                # if any have been dropped; we do this be enumerating
                # all available caps and searching for each one in the
                # list of granted caps
                caps_added = parts[1].split('+',1)[0].split(',')
                all_caps = testlib.enumerate_capabilities()
                for cap in all_caps:
                    if cap not in caps_added:
                        caps_removed.append(cap)
            else:
                raise self.failureException('Unknown capabilities suffix: %s' % output)

        okay = True
        for cap in required_removed:
            if cap not in caps_removed:
                okay = False
            else:
                caps_removed.remove(cap)
        for cap in caps_removed:
            if cap not in okay_removed:
                okay = False

        self.assertTrue(okay, "init capability mismatch (removals required: %s; removals okay: %s) -- got: %s" % (",".join(required_removed), ",".join(okay_removed), output))

    # Hardy and newer
    def test_050_personality(self):
        '''init missing READ_IMPLIES_EXEC'''
        # This is really only a concern for ia32, but it doesn't hurt to
        # check all architectures.  READ_IMPLIES_EXEC causes all PROT_READ
        # mmap calls to silently gain PROT_EXEC as well.  PROT_EXEC can also
        # be gained via ELF headers (readelf -l BIN).

        # ARM64 currently has READ_IMPLIES_EXEC set, see LP: #1501645

        expected = False
        if self.dpkg_arch == 'i386' and not self.kernel_at_least('2.6.24'):
            self._skipped("only non-i386 or Hardy and later")
            expected = True

        if not os.path.exists('/proc/1/personality'):
            self.announce("heap check")
            # So, there doesn't seem to be a way to query personality bits
            # prior to Jaunty.  As a work-around, we can examine the [heap]
            # section of init and verify that it lacks "x".
            rc, output = self.shell_cmd(['cat','/proc/1/maps'])
            self.assertEqual(rc,0,"Got %d (expected %d):\n%s" % (rc, 0, output))
            heap_exec = None
            for line in output.splitlines():
                line = line.strip()
                if '[heap]' in line:
                    perms = line.split(' ')[1]
                    if len(perms)==4 and perms[0] == 'r' and perms[1] == 'w':
                        if perms[2] == 'x':
                            heap_exec = True
                        else:
                            heap_exec = False
            self.assertEqual(heap_exec, expected, "Heap executable?  Got %d (expected %d):\n%s" % (heap_exec, expected, output))
        else:
            self.announce("/proc/1/personality")
            rc, output = self.shell_cmd(['cat','/proc/1/personality'])
            self.assertEqual(rc,0,"Got %d (expected %d):\n%s" % (rc, 0, output))
            expected = '00000000'
            # ARM sets ADDR_LIMIT_32BIT
            if self.dpkg_arch in self.arm_archs:
                expected = '00800000'

            output = output.strip()
            self.assertEqual(output, expected, "/proc/1/personality contains %s (expected %s)" % (output, expected))

    # All kernels
    def test_060_nx(self):
        '''NX bit is working'''

        has_nx_flag = 'nx' in self.cpu_flags

        # Start by assuming fully functional NX hardware.
        stack_expected = expected = -11
        emulated = False
        if self.lsb_release['Distributor ID'] == "Ubuntu":
            if self.dpkg_arch == 'i386':
                if self._test_config('X86_PAE'):
                    if not has_nx_flag:
                        # i386, PAE, without NX hardware
                        if not self.kernel_at_least('2.6.31') or \
                           self.lsb_release['Release'] > 12.04:
                            # without NX emulation
                            self._skipped("CPU is not NX capable")
                            stack_expected = expected = 0
                        else:
                            # with NX emulation
                            self.announce("NX emulation, PIE-bss/data unsafe")
                            emulated = True
                    else:
                        # i386, PAE, with NX hardware
                        pass
                elif not self.kernel_at_least('2.6.31') or \
                     self.lsb_release['Release'] > 12.04:
                    # i386, no PAE, without NX emulation
                    self._skipped("Kernel lacks NX emulation")
                    stack_expected = expected = 0
                else:
                    # i386, no PAE, with NX emulation
                    self.announce("NX emulation, PIE-bss/data unsafe")
                    emulated = True
            elif self.dpkg_arch == 'amd64':
                if not has_nx_flag:
                    # x86_64 (PAE), without NX hardware
                    self._skipped("CPU is not NX capable")
                    stack_expected = expected = 0
                else:
                    # x86_64 (PAE), with NX hardware
                    pass
            elif self.dpkg_arch == 'arm64':
                # this is LP: #1501645
                self._skipped("ARM64 has READ_IMPLIES_EXEC personality set")
                # stack is still no-exec
                expected = 0
            elif self.dpkg_arch == 's390x':
                # Need to figure out nx-test assembly code for s390x
                # s390 has no dedicated RETURN code, usually it's an
                # unconditional branch to the contents of R14
                self._skipped("need to figure out return assembly code for s390x")
                return

        os.chdir('nx')
        self.assertShellExitEquals(0, ["make"])

        self.assertShellExitEquals(0, ["./nx-test", "mmap-exec"])
        self.assertShellExitEquals(expected, ["./nx-test", "data"])
        self.assertShellExitEquals(expected, ["./nx-test", "bss"])
        self.assertShellExitEquals(stack_expected, ["./nx-test", "stack"])
        self.assertShellExitEquals(expected, ["./nx-test", "brk"])
        self.assertShellExitEquals(expected, ["./nx-test", "mmap"])

        rie_expected = 0
        if self.dpkg_arch == 'ppc64el':
            # On ppc64el, marking stack executable doesn't imply that
            # all other sections will be executable
            rie_expected = -11

        # These will all work since READ_IMPLIES_EXEC gets set
        self.assertShellExitEquals(0, ["./nx-test-rie", "mmap-exec"])
        self.assertShellExitEquals(0, ["./nx-test-rie", "stack"])
        self.assertShellExitEquals(rie_expected, ["./nx-test-rie", "data"])
        self.assertShellExitEquals(rie_expected, ["./nx-test-rie", "bss"])
        self.assertShellExitEquals(rie_expected, ["./nx-test-rie", "brk"])
        self.assertShellExitEquals(rie_expected, ["./nx-test-rie", "mmap"])

        # Should always work sanely when PIE
        self.assertShellExitEquals(0, ["./nx-test-pie", "mmap-exec"])
        self.assertShellExitEquals(stack_expected, ["./nx-test-pie", "stack"])
        self.assertShellExitEquals(expected, ["./nx-test-pie", "mmap"])
        self.assertShellExitEquals(expected, ["./nx-test-pie", "brk"])
        # Can fail with emulation + PIE
        if emulated:
            for region in ['data','bss']:
                failed = False
                for i in range(0,50):
                    rc, out = self.shell_cmd(["./nx-test-pie", region])
                    if rc == 0:
                        failed = True
                        break
                self.assertTrue(failed == emulated, "Emulation unexpectedly never failed %s region" % (region))
        else:
            self.assertShellExitEquals(expected, ["./nx-test-pie", "data"])
            self.assertShellExitEquals(expected, ["./nx-test-pie", "bss"])

    # All kernels
    def test_061_guard_page(self):
        '''Userspace stack guard page exists (CVE-2010-2240)'''

        os.chdir('guard-page')
        self.assertShellExitEquals(0, ["make"])

        # behavior changed in 3.19 kernel with:
        # commit 9c145c56d0c8a0b62e48c8d71e055ad0fb2012ba
        # Author: Linus Torvalds <torvalds@linux-foundation.org>
        # Date:   Thu Jan 29 11:15:17 2015 -0800
        #     vm: make stack guard page errors return VM_FAULT_SIGSEGV rather than SIGBUS
        expected_signals = [-signal.SIGSEGV, -signal.SIGBUS]

        self.assertShellExitIn(expected_signals, ["./guard-page"])

    def _open_config(self):
        name = "/proc/config.gz"
        if os.path.exists(name):
            return gzip.open(name, "r")
        for name in ["/boot/config-%s" % (self.kernel_version),
                     "/boot/config"]:
            if os.path.exists(name):
                return open(name, "r")
        self.assertTrue(False, "Could not locate kernel configuration")

    def _config_lines(self):
        # Return cached config list or open and read it.
        if self.__config_lines == None:
            config_fh = self._open_config()
            self.__config_lines = config_fh.readlines()
            config_fh.close()
        return self.__config_lines

    def _get_config(self, name):
        '''Report a specific CONFIG_ option in the running kernel config'''
        for line in self._config_lines():
            if line.startswith('CONFIG_%s=' % (name)):
                return line.split('=',1)[1].strip()
        return None

    def _test_config(self, name):
        '''Look for a specific CONFIG_ option being enabled in the running kernel config'''
        setting = self._get_config(name)
        if setting == 'y' or setting == 'm':
            return True
        return False

    def test_070_config_brk(self):
        '''CONFIG_COMPAT_BRK disabled'''

        expected = False
        self.assertEqual(self._test_config('COMPAT_BRK'), expected)

    # Hardy and newer, but is a negative test so will pass on earlier
    def test_070_config_devkmem(self):
        '''CONFIG_DEVKMEM disabled'''

        expected = False
        if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
            self._skipped("ignored on Karmic EC2")
            expected = True

        self.assertEqual(self._test_config('DEVKMEM'), expected)

    # All releases
    def test_070_config_seccomp(self):
        '''CONFIG_SECCOMP enabled'''

        expected = 'y'
        if self.dpkg_arch in self.arm_archs and \
           not self.kernel_at_least('2.6.38'):
            expected = None
            self._skipped("ignored ARM before 2.6.38")
        if self.dpkg_arch == 'arm64' and \
           not self.kernel_at_least('3.19.0'):
            expected = None
            self._skipped("ignored ARM64 before 3.19.0")
        self.assertEqual(self._get_config('SECCOMP'), expected)

    # All releases
    def test_070_config_syn_cookies(self):
        '''CONFIG_SYN_COOKIES enabled'''
        self.assertEqual(self._get_config('SYN_COOKIES'), 'y')

    # All releases
    # FIXME: it'd be nice to test in a more direct fashion
    def test_070_config_security(self):
        '''CONFIG_SECURITY enabled'''
        self.assertEqual(self._get_config('SECURITY'), 'y')

    # All releases
    # FIXME: it'd be nice to test in a more direct fashion
    def test_070_config_security_selinux(self):
        '''CONFIG_SECURITY_SELINUX enabled'''
        expected = 'y'
        if self.dpkg_arch in self.arm_archs and \
           not self.kernel_at_least('2.6.31'):
            self._skipped("on ARM only Lucid and later")
            expected = None
        self.assertEqual(self._get_config('SECURITY_SELINUX'), expected)

    # Everything except i386 Gutsy
    def test_072_config_compat_vdso(self):
        '''CONFIG_COMPAT_VDSO disabled'''

        expected = False
        if self.lsb_release['Release'] == 7.10 and self.dpkg_arch == 'i386':
            self._skipped("i386 Gutsy broken")
            expected = True

        self.assertEqual(self._test_config('COMPAT_VDSO'), expected)

    # Gutsy and newer
    # FIXME: actually attempt to load a module that has a rwx data area
    def test_072_config_debug_rodata(self):
        '''CONFIG_DEBUG_RODATA enabled'''

        expected = True
        # Enabled in a security update for pre-Intrepid
        if not self.kernel_at_least('2.6.22'):
            self._skipped("only Gutsy and later")
            expected = False
        else:
            # Arch-specific
            if self.dpkg_arch not in (['i386','amd64'] + self.arm_archs + ['arm64']):
                self._skipped("only x86 and ARM")
                expected = False
            # Hardy Xen doesn't have it?
            if self.lsb_release['Release'] == 8.04 and \
               self.kernel_version.endswith('-xen'):
                self._skipped("ignored on Hardy Xen")
                expected = False

        self.assertEqual(self._test_config('DEBUG_RODATA'), expected)

    # Natty and newer
    # FIXME: it'd be nice to test in a more direct fashion
    def test_072_config_debug_set_module_ronx(self):
        '''CONFIG_DEBUG_SET_MODULE_RONX enabled'''

        expected = True
        if not self.kernel_at_least('2.6.38'):
            self._skipped("only Natty and later")
            expected = False
        elif self.dpkg_arch not in self.module_ronx_archs:
            self._skipped("only x86")
            expected = False
        if self._get_config('MODULES') == None:
            self._skipped("non-modular")
            expected = False

        self.assertEqual(self._test_config('DEBUG_SET_MODULE_RONX'), expected)

    # Hardy and newer (Gutsy was a direct patch)
    def test_072_config_security_apparmor(self):
        '''CONFIG_SECURITY_APPARMOR enabled'''

        self.assertEqual(self._get_config('SECURITY_APPARMOR'), 'y')
        self.assertEqual(self._get_config('DEFAULT_SECURITY_APPARMOR'), 'y')
        self.assertEqual(self._get_config('SECURITY_APPARMOR_BOOTPARAM_VALUE'), '1')

    # Hardy and newer
    def test_072_config_strict_devmem(self):
        '''CONFIG_STRICT_DEVMEM enabled'''

        nonpromisc = False
        strict = True
        if not self.kernel_at_least('2.6.27'):
            strict = False
            if self.kernel_at_least('2.6.24'):
                # named "NONPROMISC_DEVMEM" in Hardy
                nonpromisc = True
            else:
                self._skipped("only Hardy and later")
        else:
            # Arch-specific
            if self.dpkg_arch not in ['i386', 'amd64', 'armel', 'armhf', 'arm64', 'ppc64el', 's390x']:
                self._skipped("x86, ppc64, and ARM only")
                strict = False
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.38'):
                self._skipped("only 2.6.38 and later for ARM")
                strict = False
            if self.dpkg_arch == 'arm64' and \
               not self.kernel_at_least('3.16.0'):
                self._skipped("only 3.16 and later for ARM64")
                strict = False

        self.assertEqual(self._test_config('NONPROMISC_DEVMEM'), nonpromisc)
        self.assertEqual(self._test_config('STRICT_DEVMEM'), strict)

    def test_072_strict_devmem(self):
        '''/dev/mem unreadable for kernel memory'''

        os.chdir('mem')
        target = None
        if self.kernel_is_ubuntu:
            self.assertShellExitEquals(0, ["make"])

            # Find a value to test in memory.
            self.shell_cmd(["rmmod","signpost"])
            self.assertShellExitEquals(0, ["insmod","signpost/signpost.ko"])
            with open("/proc/signpost_phys") as signpost_phys:
                target = int(signpost_phys.read(), 16)
            with open("/proc/signpost_value") as signpost_value:
                value  = int(signpost_value.read(), 16)
            self.assertEqual(value, 0xfeedface)
            self.announce("using %s" % (hex(target)))
        else:
            self.assertShellExitEquals(0, ["make", "readmem"])

        expected = [0]
        # FIXME: why does this work on Dapper??
        if not self.kernel_at_least('2.6.15'):
            self._skipped("only Dapper, Karmic and later")
            expected = [5]
        else:
            # Arch-specific
            if self.dpkg_arch not in ['i386', 'amd64', 'armel', 'armhf', 'arm64', 'ppc64el', 's390x']:
                self._skipped("x86, ARM, and ppc64el only")
                expected = [5]
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.38'):
                self._skipped("only 2.6.38 and later for ARM")
                expected = [4]
            if self.dpkg_arch == 'arm64' and \
               not self.kernel_at_least('3.16.0'):
                self._skipped("only 3.16 and later for ARM64")
                expected = [4]
            # Xen and EC2 are weird. -virtual seems okay, though
            # Since EC2 /dev/mem behavior appears to depend at least partially on the
            # Xen _host_, we need to treat "ok" and "reads 0s" as okay.
            if self.kernel_version.endswith('-xen') or self.kernel_version.endswith('-ec2'):
                if self.lsb_release['Release'] == 8.04:
                    self.announce("weird on Hardy Xen")
                    expected = [0, 6]
                elif self.lsb_release['Release'] == 9.10:
                    self.announce("weird on Karmic EC2")
                    expected = [0, 6]
                elif self.lsb_release['Release'] == 10.04:
                    self.announce("weird on Lucid EC2")
                    expected = [0, 6]

        cmd = ['./readmem']
        if target:
            cmd += [hex(target)]
        rc, output = self.shell_cmd(cmd)
        self.announce("exit code %d" % (rc))
        self.assertTrue(rc in expected, 'exit code: %d (wanted %s). Output:\n%s' % (rc, ", ".join(["%d" % (x) for x in expected]), output))
        if target:
            self.assertShellExitEquals(0, ["rmmod","signpost"])


    # Intrepid and newer
    # FIXME: it'd be nice to test in a more direct fashion
    def test_073_config_security_file_capabilities(self):
        '''CONFIG_SECURITY_FILE_CAPABILITIES enabled'''

        expected = True
        if not self.kernel_at_least('2.6.27') or self.kernel_at_least('2.6.35'):
            # Maverick and later have it always on
            self._skipped("only Intrepid through Lucid")
            expected = False

        self.assertEqual(self._test_config('SECURITY_FILE_CAPABILITIES'), expected)

    # FIXME: add direct capability testing

    # Intrepid and newer
    # FIXME: it'd be nice to test in a more direct fashion
    def test_073_config_security_smack(self):
        '''CONFIG_SECURITY_SMACK enabled'''

        expected = 'y'
        if not self.kernel_at_least('2.6.27'):
            self._skipped("only Intrepid and later")
            expected = None
        self.assertEqual(self._get_config('SECURITY_SMACK'), expected)

    # FIXME: it'd be nice to test in a more direct fashion
    def test_073_config_security_tomoyo(self):
        '''CONFIG_SECURITY_TOMOYO enabled'''
        self.assertEqual(self._get_config('SECURITY_TOMOYO'), 'y')

    # Jaunty and newer
    def test_074_config_security_default_mmap_min_addr(self):
        '''CONFIG_DEFAULT_MMAP_MIN_ADDR'''

        # Min expectation, based on architecture
        expected = '65536'
        # for arm64, see LP: #1415481
        if self.dpkg_arch in self.arm_archs or self.dpkg_arch == 'arm64':
            expected = '32768'
        if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
            # Karmic's EC2 has:
            #  CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
            #  CONFIG_LSM_MMAP_MIN_ADDR=65536
            self.announce("weird: Karmic EC2")
            expected = '4096'

        config = 'DEFAULT_MMAP_MIN_ADDR'
        if not self.kernel_at_least('2.6.24'):
            config = 'SECURITY_' + config
            self.announce(config)

        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = None
            if self.kernel_at_least('2.6.21'):
                # Existed, but was still set to 0
                expected = '0'
        else:
            self.announce(expected)

        self.assertEqual(self._get_config(config), expected)

    # Karmic and newer
    def test_075_config_stack_protector(self):
        '''CONFIG_CC_STACKPROTECTOR set'''

        expected = 'y'
        if not self.kernel_at_least('2.6.31'):
            if self.lsb_release['Release'] == 8.04 and self.dpkg_arch == 'amd64':
                pass
            else:
                self._skipped("only Hardy amd64 or Karmic and later")
                expected = None
        else:
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.35'):
                self._skipped("not available on ARM before 10.10")
                expected = None
            if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
                self._skipped("ignored on Karmic EC2")
                expected = None
            if self.dpkg_arch in ['powerpc', 'ppc64', 'ppc64el']:
                self._skipped("not available on powerpc")
                expected = None
            if self.dpkg_arch in ['s390x']:
                self._skipped("not available on s390x")
                expected = None

        self.assertEqual(self._get_config('CC_STACKPROTECTOR'), expected)

    def test_076_config_security_acl_ext3(self):
        '''CONFIG_EXT3_FS_SECURITY set (LP: #1295948)'''

        # if CONFIG_EXT4_USE_FOR_EXT23, then we can rely on the
        # CONFIG_EXT4_FS_SECURITY check
        if self.kernel_at_least('4.3'):
            self._skipped("4.3 and later are only ext4 for ext3")
        elif self._test_config('EXT4_USE_FOR_EXT23'):
            self._skipped("Kernel is configured to use ext4 for ext3")
        else:
            self.assertTrue(self._test_config('EXT3_FS_SECURITY'), 'CONFIG_EXT3_FS_SECURITY is not set')

    def test_076_config_security_acl_ext4(self):
        '''CONFIG_EXT4_FS_SECURITY set (LP: #1295948)'''
        self.assertTrue(self._test_config('EXT4_FS_SECURITY'), 'CONFIG_EXT4_FS_SECURITY is not set')

    def test_077_config_security_ecryptfs(self):
        '''CONFIG_ECRYPT_FS is set'''
        self.assertTrue(self._test_config('ECRYPT_FS'))

    # Taken from strongSwan wiki:
    # http://wiki.strongswan.org/projects/strongswan/wiki/KernelModules
    def test_077_config_security_ipsec(self):
        '''Config options for IPsec'''
        configs = ['XFRM_USER', 'NET_KEY', 'INET', 'IP_ADVANCED_ROUTER',
                   'IP_MULTIPLE_TABLES', 'INET_AH', 'INET_ESP', 'INET_IPCOMP',
                   'INET_XFRM_MODE_TRANSPORT', 'INET_XFRM_MODE_TUNNEL',
                   'INET_XFRM_MODE_BEET', 'IP_MULTIPLE_TABLES', 'INET_AH',
                   'INET_ESP', 'INET_IPCOMP', 'INET_XFRM_MODE_TRANSPORT',
                   'INET_XFRM_MODE_TUNNEL', 'INET_XFRM_MODE_BEET', 'IPV6',
                   'INET6_AH', 'INET6_ESP', 'INET6_IPCOMP',
                   'INET6_XFRM_MODE_TRANSPORT', 'INET6_XFRM_MODE_TUNNEL',
                   'INET6_XFRM_MODE_BEET', 'IPV6_MULTIPLE_TABLES', 'NETFILTER',
                   'NETFILTER_XTABLES', 'NETFILTER_XT_MATCH_POLICY']
        for c in configs:
            self.assertTrue(self._test_config(c), 'CONFIG_%s is not set' % (c))

    # Karmic and newer
    def test_082_stack_guard_kernel(self):
        '''Kernel stack guard'''

        expected = True
        if not self.kernel_at_least('2.6.31'):
            self._skipped("only Karmic and later")
            expected = False
        else:
            if self.dpkg_arch in self.arm_archs and \
               not self.kernel_at_least('2.6.35'):
                self._skipped("not available on ARM before 10.10")
                expected = False
            if self.lsb_release['Release'] == 9.10 and self.kernel_version.endswith('-ec2'):
                self._skipped("ignored on Karmic EC2")
                expected = False
            if self.dpkg_arch in ['powerpc', 'ppc64', 'ppc64el']:
                self._skipped("not available on powerpc")
                expected = False
            if self.dpkg_arch in ['s390x']:
                self._skipped("not available on s390x")
                expected = False
        if self._get_config('MODULES') == None:
            self.announce("cannot check, non-modular")
            # Fall back to config test...
            self.assertTrue(self._get_config('CC_STACKPROTECTOR'))
            expected = False

        module = ""
        for m in ['fs/befs/befs.ko', 'crypto/tcrypt.ko', 'fs/cifs/cifs.ko',
                  'net/ipv4/netfilter/arp_tables.ko',
                  'net/bridge/netfilter/ebtables.ko']:
            m = os.path.join('/lib/modules/%s/kernel/' % (self.kernel_version), m)
            if os.path.exists(m):
                module = m
                break
        if expected:
            self.assertTrue(module, 'Could not find a suitable kernel module to test')

        rc, out = testlib.cmd(['readelf', '-s', module])
        if expected:
            self.assertEqual(rc, 0, out)
        self.assertEqual(expected, ' UND __stack_chk_fail\n' in out, '__stack_chk_fail missing from kernel (tested befs.ko)')

    # Karmic and newer
    def test_090_module_blocking(self):
        '''Sysctl to disable module loading exists'''

        expected = True
        if not self.kernel_at_least('2.6.31'):
            self._skipped("only Karmic and later")
            expected = False
        if self._get_config('MODULES') == None:
            self._skipped("non-modular")
            expected = False

        self.assertEqual(os.path.exists('/proc/sys/kernel/modules_disabled'), expected)

    def _check_symlinks(self, sticky, hardened=None):
        '''Performs the symlink following checks, either in sticky or non-sticky dir'''

        attacker = testlib.TestUser()
        noob = testlib.TestUser()

        # Validate we have three separate uids
        self.assertTrue(0 != attacker.uid)
        self.assertTrue(0 != noob.uid)
        self.assertTrue(attacker.uid != noob.uid)

        # Verify sudo is actually working to change euid
        self.assertShellOutputContains('(%s) ' % (attacker.login), ['sudo','-u',attacker.login,'id'])
        self.assertShellOutputContains('(%s) ' % (noob.login), ['sudo','-u',noob.login,'id'])

        # create testdir dir
        tmpdir = tempfile.mkdtemp(prefix='symlinks-')
        mode = 0o777
        if sticky:
            mode |= 0o1000
        os.chmod(tmpdir, mode)

        # Validate stickiness
        drop = os.path.join(tmpdir, 'remove.me')
        with open(drop, 'w') as drop_fh:
            drop_fh.write('I can be deleted in a non-sticky directory')
        if not hardened:
            hardened = False
            if sticky:
                expected = True
        expected = 0
        if sticky:
            expected = 1
        self.assertShellExitEquals(expected, ['sudo','-u',attacker.login,'rm','-f',drop])
        self.assertEqual(sticky, os.path.exists(drop))

        # create world-readable target file
        message = 'sekrit\n'
        target = os.path.join(tmpdir, 'target')
        with open(target, 'w') as target_fh:
            target_fh.write(message)
        os.chmod(target, 0o644)

        # create symlinks to it as different users
        root_symlink = os.path.join(tmpdir, 'root.link')
        attacker_symlink = os.path.join(tmpdir, 'attacker.link')
        noob_symlink = os.path.join(tmpdir, 'noob.link')

        os.symlink(target, root_symlink)
        self.assertShellExitEquals(0, ['sudo','-u',attacker.login,'ln','-s',target,attacker_symlink])
        self.assertShellExitEquals(0, ['sudo','-u',noob.login,'ln','-s',target,noob_symlink])

        # Validate the link ownerships
        self.assertEqual(os.lstat(root_symlink).st_uid, 0)
        self.assertEqual(os.lstat(attacker_symlink).st_uid, attacker.uid)
        self.assertEqual(os.lstat(noob_symlink).st_uid, noob.uid)

        ### READING

        # Verify each user can see the target file contents directly
        self.assertShellOutputEquals(message, ['cat',target])
        self.assertShellOutputEquals(message, ['sudo','-u',attacker.login,'cat',target])
        self.assertShellOutputEquals(message, ['sudo','-u',noob.login,'cat',target])

        # Verify that users via their own symlink can read the file
        self.assertShellOutputEquals(message, ['cat',root_symlink])
        self.assertShellOutputEquals(message, ['sudo','-u',noob.login,'cat',noob_symlink])
        self.assertShellOutputEquals(message, ['sudo','-u',attacker.login,'cat',attacker_symlink])

        # Verify that each user can read the file via the root symlink (dir owner)
        self.assertShellOutputEquals(message, ['cat', root_symlink])
        self.assertShellOutputEquals(message, ['sudo','-u',attacker.login,'cat',root_symlink])
        self.assertShellOutputEquals(message, ['sudo','-u',noob.login,'cat',root_symlink])

        # Verify non-root users cannot read obvious unreadable files
        self.assertShellOutputContains('root', ['sudo','-u',noob.login,'cat','/etc/shadow'], invert=True)
        self.assertShellOutputContains('root', ['sudo','-u',attacker.login,'cat','/etc/shadow'], invert=True)

        # Verify users via a different user's symlink cannot read the file if sticky and hardened
        self.assertShellOutputEquals(message, ['sudo','-u',noob.login,'cat',attacker_symlink], invert=sticky and hardened)
        self.assertShellOutputEquals(message, ['sudo','-u',attacker.login,'cat',noob_symlink], invert=sticky and hardened)
        self.assertShellOutputEquals(message, ['cat',attacker_symlink], invert=sticky and hardened)
        self.assertShellOutputEquals(message, ['cat',noob_symlink], invert=sticky and hardened)

        ### WRITING

        # Verify users can write to the file directly
        os.unlink(target)
        self.assertShellExitEquals(0, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % target])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % target])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['dd','if=/bin/dd','of=%s' % target])
        self.assertTrue(os.path.exists(target))

        # Verify users can write to the file via symlink to create target
        os.unlink(target)
        self.assertShellExitEquals(0, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % noob_symlink])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % attacker_symlink])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['dd','if=/bin/dd','of=%s' % root_symlink])
        self.assertTrue(os.path.exists(target))

        # Verify non-root users can not write to the direct file
        self.assertShellExitEquals(1, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % target])
        self.assertShellExitEquals(1, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % target])

        # Verify non-root users can not write to the symlink file
        self.assertShellExitEquals(1, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % noob_symlink])
        self.assertShellExitEquals(1, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % attacker_symlink])

        # CREATING

        # Verify non-root users can not create files to the symlink target
        # when crossing uid
        expected=0
        if sticky and hardened:
            expected=1
        os.unlink(target)
        self.assertShellExitEquals(expected, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % attacker_symlink])
        if os.path.exists(target):
            os.unlink(target)
        self.assertShellExitEquals(expected, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % noob_symlink])
        if os.path.exists(target):
            os.unlink(target)
        self.assertShellExitEquals(expected, ['dd','if=/bin/dd','of=%s' % noob_symlink])
        if os.path.exists(target):
            os.unlink(target)
        self.assertShellExitEquals(expected, ['dd','if=/bin/dd','of=%s' % attacker_symlink])
        if os.path.exists(target):
            os.unlink(target)

        # Verify users can create file through root's symlink
        self.assertShellExitEquals(0, ['sudo','-u',noob.login,'dd','if=/bin/dd','of=%s' % root_symlink])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['sudo','-u',attacker.login,'dd','if=/bin/dd','of=%s' % root_symlink])
        self.assertTrue(os.path.exists(target))
        os.unlink(target)
        self.assertShellExitEquals(0, ['dd','if=/bin/dd','of=%s' % root_symlink])
        self.assertTrue(os.path.exists(target))

        # Clean up
        shutil.rmtree(tmpdir, ignore_errors=True)

    def tearDown_091_symlink_following_in_sticky_directories(self):
        self.set_sysctl_value(self.sysctl['symlink'], 1)

    def test_091_symlink_following_in_sticky_directories(self):
        '''Symlinks not followable across differing uids in sticky directories'''

        expected = True
        if not self.kernel_at_least('2.6.35'):
            self._skipped("only Maverick and later")
            expected = False
        elif not os.path.exists(self.sysctl['symlink']) and \
             not self._test_config('SECURITY_YAMA') and \
             not self.kernel_at_least('3.5'):
            self._skipped("built without Yama")
            expected = False

        if expected:
            self.teardowns.append(self.tearDown_091_symlink_following_in_sticky_directories)
            self._test_sysctl_value(self.sysctl['symlink'], 1)
        self._check_symlinks(sticky=False, hardened=expected)
        self._check_symlinks(sticky=True, hardened=expected)
        if expected:
            self.set_sysctl_value(self.sysctl['symlink'], 0)
        self._check_symlinks(sticky=False, hardened=False)
        self._check_symlinks(sticky=True, hardened=False)
        if expected:
            self.set_sysctl_value(self.sysctl['symlink'], 1)

    def _check_hardlinks(self, hardened=True):
        expected = 0
        if hardened:
            expected = 1

        tmpdir = tempfile.mkdtemp(prefix='hardlinks-')
        self.assertShellExitEquals(0, ['chown',os.environ['SUDO_USER'],tmpdir])

        secret = tempfile.NamedTemporaryFile(prefix="secret-")
        evil = '%s/evil' % (tmpdir)
        not_evil = '%s/not-evil' % (tmpdir)
        # Allow hardlink to self files
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'touch','%s/mine' % (tmpdir)])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/mine' % (tmpdir),'%s/okay' % (tmpdir)])

        # Disallow hardlink to unreadable files
        self.assertShellExitEquals(expected, ['sudo','-u',os.environ['SUDO_USER'],'ln',secret.name,evil])
        if os.path.exists(evil):
            os.unlink(evil)

        # Disallow hardlink to only writable files
        self.assertShellExitEquals(0, ['chmod','a+r',secret.name])
        self.assertShellExitEquals(expected, ['sudo','-u',os.environ['SUDO_USER'],'ln',secret.name,evil])
        if os.path.exists(evil):
            os.unlink(evil)

        # Allow hardlinkg to readable and writable files
        self.assertShellExitEquals(0, ['chmod','a+w',secret.name])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'ln',secret.name,not_evil])
        os.unlink(not_evil)

        # Disallow hardlinks to non-regular files
        self.assertShellExitEquals(0, ['mknod','-m','0666','%s/null' % (tmpdir),'c','1','3'])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'cat','%s/null' % (tmpdir)])
        self.assertShellExitEquals(expected, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/null' % (tmpdir),evil])
        if os.path.exists(evil):
            os.unlink(evil)

        # allow hardlinks to owned non-regular files
        self.assertShellExitEquals(0, ['chown',os.environ['SUDO_USER'],'%s/null' % (tmpdir)])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/null' % (tmpdir),not_evil])
        os.unlink(not_evil)

        # allow hardlinks to owned setuid files
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'chmod','u+s','%s/mine' % (tmpdir)])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/mine' % (tmpdir),not_evil])
        os.unlink(not_evil)

        # Disallow hardlinks to non-owned setuid files
        self.assertShellExitEquals(0, ['touch','%s/root-setuid' % (tmpdir)])
        self.assertShellExitEquals(0, ['chmod','u+s','%s/root-setuid' % (tmpdir)])
        self.assertShellExitEquals(expected, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/root-setuid' % (tmpdir),evil])
        if os.path.exists(evil):
            os.unlink(evil)

        # allow hardlinks to owned exec setgid files
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'chmod','g+sx','%s/mine' % (tmpdir)])
        self.assertShellExitEquals(0, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/mine' % (tmpdir),not_evil])
        os.unlink(not_evil)

        # Disallow hardlinks to non-owned exec setgid files
        self.assertShellExitEquals(0, ['touch','%s/root-setgid' % (tmpdir)])
        self.assertShellExitEquals(0, ['chmod','g+sx','%s/root-setgid' % (tmpdir)])
        self.assertShellExitEquals(expected, ['sudo','-u',os.environ['SUDO_USER'],'ln','%s/root-setgid' % (tmpdir),evil])
        if os.path.exists(evil):
            os.unlink(evil)

        # Can link with CAP_FOWNER
        self.assertShellExitEquals(0, ['ln','%s/null' % (tmpdir),'%s/root-null' % (tmpdir)])

        shutil.rmtree(tmpdir, ignore_errors=True)

    def tearDown_092_hardlink_restriction(self):
        self.set_sysctl_value(self.sysctl['hardlink'], 1)

    def test_092_hardlink_restriction(self):
        '''Hardlink disallowed for unreadable/unwritable sources'''

        expected = True
        if not self.kernel_at_least('2.6.35'):
            self._skipped("only Maverick and later")
            expected = False
        elif not os.path.exists(self.sysctl['hardlink']) and \
             not self._test_config('SECURITY_YAMA') and \
             not self.kernel_at_least('3.5'):
            self._skipped("built without Yama")
            expected = False

        if expected:
            self.teardowns.append(self.tearDown_092_hardlink_restriction)
            self._test_sysctl_value(self.sysctl['hardlink'], 1)
        self._check_hardlinks(hardened=expected)
        if expected:
            self.set_sysctl_value(self.sysctl['hardlink'], 0)
        self._check_hardlinks(hardened=False)
        if expected:
            self.set_sysctl_value(self.sysctl['hardlink'], 1)

    def test_093_ptrace_restriction(self):
        '''ptrace allowed only on children or declared processes'''

        expected = 0
        if not self.kernel_at_least('2.6.35'):
            self._skipped("only Maverick and later")
            expected = 1
        elif not self._test_config('SECURITY_YAMA') and \
             not self.kernel_at_least('3.3'):
            self._skipped("built without Yama")
            expected = 1

        cmd = ['sudo', '-u', os.environ['SUDO_USER'], 'bash', '-x', './ptrace-restrictions.sh']
        if self.kernel_at_least('3.2'):
            cmd += ['--any']
        else:
            self.announce("skipping PR_SET_PTRACER_ANY")

        os.chdir('ptrace')
        self.assertShellExitEquals(0, ["make"])
        shelltimeout = testlib.TimeoutFunction(self.assertShellExitEquals, 10)
        try:
            with open("/dev/null") as dev_null:
                shelltimeout(expected, cmd, stdin=dev_null)
        except:
            # try to run this again if it timed out. haven't been able to
            # track down the cause yet.
            self.announce("timeout, backing off")
            time.sleep(5)
            # back off with a longer timeout, this may be needed for panda
            shelltimeout = testlib.TimeoutFunction(self.assertShellExitEquals, 60)
            shelltimeout(expected, cmd, stdin=open("/dev/null"))

    def test_093_ptrace_restriction_parent_via_thread(self):
        '''ptrace of child works from parent threads (LP: #737676)'''

        if not self.kernel_at_least('2.6.35'):
            self._skipped("only Maverick and later")
        expected = 0

        os.chdir('ptrace')
        # Works from main process
        self.assertShellExitEquals(0, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '0', '1'])
        # Works from thread
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '0', '0'])

    def test_093_ptrace_restriction_prctl_via_thread(self):
        '''prctl(PR_SET_PTRACER) works from threads (LP: #729839)'''

        # on a failure "2" is seen
        expected = 0
        os.chdir('ptrace')
        # Works from main process
        self.assertShellExitEquals(0, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '1', '1'])
        # Works from thread
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '2', '1'])

    def test_093_ptrace_restriction_extras(self):
        '''ptrace from thread on tracee that used prctl(PR_SET_PTRACER)'''

        # on a failure "2" is seen
        expected = 0
        os.chdir('ptrace')
        # prctl from main process
        self.assertShellExitEquals(0, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '1', '0'])
        # prctl from thread
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], './thread-prctl', '2', '0'])

    def test_094_rare_net_autoload(self):
        '''rare network modules do not autoload'''

        proto = {   'ax25': 3,
                    'netrom': 6,
                    'x25': 9,
                    'rose': 11,
                    'decnet': 12,
                    'econet': 19,
                    'rds': 21,
                    'af_802154': 36,
                }
        # try AF_INET for the positive case
        raised = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        except Exception as detail:
            raised = True
        finally:
            s.close()

        self.assertFalse(raised, msg="AF_INET not loadable")

        if self.lsb_release['Release'] < 11.04:
            self._skipped("only Natty and later")
            return

        for af in proto:
            # Dapper's python 2.4 doesn't have "with", so this is a bit ugly...
            raised = False
            try:
                # unload module before attempting to open the socket for
                # it, to ensure we have a clean environment. We do't
                # care about the result of the cmd because it will fail
                # as modules are dropped from the kernel entirely
                testlib.cmd(['modprobe', '-r', af])
                socket.socket(proto[af], socket.SOCK_STREAM, 0)
            except Exception as detail:
                self.assertTrue(isinstance(detail, socket.error), msg=af)
                self.assertEqual(detail.errno, 97, msg=af)
                raised = True
            self.assertTrue(raised, msg=af)

    def _read_twice(self, filename, transform, expected, check=None):
        '''Return contents of a file as root and regular user'''

        if not os.path.exists(filename):
            self._skipped("No %s" % (filename))
            return

        cmd = ['cat', filename]
        rc, root = self.shell_cmd(cmd)
        self.assertEqual(rc, 0, root)

        cmd = ['sudo', '-u', os.environ['SUDO_USER']] + cmd
        rc, regular = self.shell_cmd(cmd)
        self.assertEqual(rc, 0, regular)

        if check and check not in root:
            self._skipped("No '%s' in root's %s" % (check, filename))
            return
        if check and check not in regular:
            self._skipped("No '%s' in user's %s" % (check, filename))
            return

        # Make sure root can read it
        try:
            address = transform(root)
        except:
            self.assertTrue(False, "transformation failed on root-read data from %s:\n%s" % (filename, root))
        self.assertFalse(0 == int(address, 16), "%s: root saw %s" % (filename, address))

        # ... and regular user can't
        try:
            address = transform(regular)
        except:
            self.assertTrue(False, "transformation failed on user-read data from %s:\n%s" % (filename, root))
        self.assertEqual(expected, 0 == int(address, 16), "%s: user saw %s" % (filename, address))

        return root, regular

    # Check for %pK abilities
    def test_095_kernel_symbols_acl(self):
        '''/proc/sys/kernel/kptr_restrict is enabled'''

        # It's a default in the kernel in the 2.6.38 series only, otherwise
        # it's enforced vi procps sysctls.
        if self.lsb_release['Release'] > 10.10 or \
           (self.kernel_at_least('2.6.38') and not self.kernel_at_least('3.0')):
            expected = 1
            exists = 1
        else:
            expected = 0
            exists = 0
            if self.kernel_at_least('2.6.38'):
                exists = 1
            self._skipped("only Natty and later")

        self._test_sysctl_value('kernel/kptr_restrict', expected, exists=exists)

    def _check_pK_files(self, expected):
        '''Actually performs the file checks for pK-wiped values'''

        def _split_proc_modules(x):
            line = x.splitlines().pop().split()
            ret = line.pop()
            if ret.startswith('(') and ret.endswith(')'):
                # Module is tainted so we'll have to pop off the taint flag
                # field to get the address
                ret = line.pop()
            return ret

        if os.path.exists('/proc/kallsyms'):
            self._read_twice('/proc/kallsyms',
                             lambda x: x.splitlines().pop().split()[0],
                             expected)
        if os.path.exists('/proc/modules') and not testlib.is_empty_file('/proc/modules'):
            root, regular = \
            self._read_twice('/proc/modules',
                             _split_proc_modules,
                             expected)
            module = root.splitlines().pop().split()[0].strip()
            self._read_twice('/sys/module/%s/sections/.text' % (module),
                             lambda x: x.splitlines().pop().split().pop(),
                             expected)
        # Make sure a timer is running
        sleeper = subprocess.Popen(['sleep', '120'])
        self._read_twice('/proc/timer_list',
                         lambda x: [y.split().pop() for y in x.splitlines()
                                    if 'base:' in y][0],
                         expected, check='base:')
        self._read_twice('/proc/timer_list',
                         lambda x: [y.split().pop(1).split('<')[1].split('>')[0]
                                    for y in x.splitlines()
                                    if re.search('#[0-9]+: <', y)][0],
                         expected)
        os.kill(sleeper.pid, 9)

        def __self_stack_filter(content):
            # on s390x, the first line of /proc/self/stack will
            # sometimes be '(null)' which has a 000 address, causing a
            # false negative
            x = content.splitlines()
            if x[0].split()[1] == '(null)':
                return x[1].split()[0][2:-2]
            else:
                return x[0].split()[0][2:-2]

        self._read_twice('/proc/self/stack',
                         __self_stack_filter,
                         expected)

        self._read_twice('/proc/net/tcp',
                         lambda x: x.splitlines()[1].split()[11],
                         expected)

    def tearDown_095_kernel_symbols_missing(self):
        self.set_sysctl_value('kernel/kptr_restrict', 1)

    # Check for %pK abilities
    def test_095_kernel_symbols_missing(self):
        '''kernel addresses in kallsyms and modules are zeroed out'''

        # It's a default in the kernel in the 2.6.38 series only, otherwise
        # it's enforced vi procps sysctls.
        if self.lsb_release['Release'] > 10.10 or \
           (self.kernel_at_least('2.6.38') and not self.kernel_at_least('3.0')):
            expected = True
        else:
            expected = False
            self._skipped("only Natty and later")

        if expected:
            self.set_sysctl_value('kernel/kptr_restrict', 1)
            self.teardowns.append(self.tearDown_095_kernel_symbols_missing)
        self._check_pK_files(expected)
        if expected:
            # Validate that disabling the feature restores kernel pointers
            self.set_sysctl_value('kernel/kptr_restrict', 0)
            self._check_pK_files(False)
            self.set_sysctl_value('kernel/kptr_restrict', 1)

    def test_096_boot_symbols_unreadable(self):
        '''kernel addresses in /boot are not world readable'''

        expected = 0
        if not self.kernel_at_least('2.6.38'):
            self._skipped("only Natty and later")
            expected = 0o044
        mask = 0o044

        # Check something readable just to be sure
        name = '/proc/cpuinfo'
        self.assertEqual(os.stat(name).st_mode & mask, 0o044, name)
        # Check something unreadable just to be sure
        name = '/proc/kpagecount'
        self.assertEqual(os.stat(name).st_mode & mask, 0o000, name)

        # Make sure kernel files are either missing or unreadable.
        for base in ['System.map', 'vmcoreinfo', 'vmlinuz']:
            for name in ['/%s' % (base),
                         '/boot/%s-%s' % (base, self.kernel_version)]:
                if not os.path.exists(name):
                    continue
                self.assertEqual(os.stat(name).st_mode & mask, expected, '%s is world readable' % (name))

    # FIXME: merge proc and boot file perm checks
    def test_096_proc_entries_unreadable(self):
        '''sensitive files in /proc are not world readable'''

        expected = 0
        if self.lsb_release['Release'] < 11.04:
            self._skipped("only Natty and later")
            expected = 0o044
        mask = 0o044

        # Check something readable just to be sure
        name = '/proc/uptime'
        self.assertEqual(os.stat(name).st_mode & mask, 0o044, name)
        # Check something unreadable just to be sure
        name = '/proc/kcore'
        if not os.path.exists(name):
            # if kcore is missing, fall back to kmsg, should be 400 too
            name = '/proc/kmsg'
        self.assertEqual(os.stat(name).st_mode & mask, 0o000, name)

        name = '/proc/slabinfo'
        if self.kernel_version.endswith('-goldfish') or \
           self.kernel_version.endswith('-maguro') or \
           self.kernel_version.endswith('-mako') or \
           self.kernel_version.endswith('-manta') or \
           self.kernel_version.endswith('-flo'):
            # On Touch, the Android init.rc chowns slabinfo to 0440 and chmods
            # it to root:log. The log uid/gid is 1007 which, unfortunately,
            # overlaps with the traditional Ubuntu user uid/gid range but the
            # phablet uid/gid is 32011.
            expected = 0o040
            self.assertEqual(os.stat(name).st_gid, 1007, '%s is not group owned by Android\'s log user' % (name))
        self.assertEqual(os.stat(name).st_mode & mask, expected, '%s is world readable' % (name))

    def test_100_keep_acpi_method_disabled(self):
        '''/sys/kernel/debug/acpi/custom_method stays disabled'''

        # If debugfs isn't known to the kernel, this is an okay state
        with open('/proc/filesystems') as proc_filesystems:
            filesystems = proc_filesystems.read()
            if '\tdebugfs\n' not in filesystems:
                self._skipped('No debugfs')
                return

        # Since it exists, it must be mounted to test for custom_method
        self.assertTrue(os.path.exists('/sys/kernel'))
        kernel = os.lstat('/sys/kernel')
        self.assertTrue(os.path.exists('/sys/kernel/debug'))
        debug = os.lstat('/sys/kernel/debug')
        needs_umount = False
        if kernel.st_dev == debug.st_dev:
            self.assertShellExitEquals(0, ["mount", "-t", "debugfs", "none", "/sys/kernel/debug"])
            needs_umount = True
            debug = os.lstat('/sys/kernel/debug')
        # Make sure /sys/kernel and /sys/kernel/debug are separate filesystems
        self.assertTrue(kernel.st_dev != debug.st_dev)

        # Make sure acpi/custom_method does not exist
        custom_method_exists = os.path.exists('/sys/kernel/debug/acpi/custom_method')
        if needs_umount:
            self.assertShellExitEquals(0, ["umount", "/sys/kernel/debug"])
        self.assertFalse(custom_method_exists)

    def test_101_proc_fd_leaks(self):
        '''/proc/$pid/ DAC bypass on setuid (CVE-2011-1020)'''

        bad = { 'auxv':    'AT_BASE:',
                'syscall': ' 0x',
                'stack':   '[<',
              }

        expected = True

        os.chdir('proc-leaks')
        for name in bad.keys():
            # If it's not there, it can't leak, so skip missing ones
            # not present in earlier kernels.
            if not os.path.exists('/proc/self/%s' % (name)):
                continue
            self.assertShellOutputContains(bad[name], ['sudo', '-u', os.environ['SUDO_USER'], "sh", "-c", "echo '' | ./dac-bypass.py %s" % (name)], invert=expected)

    def test_110_seccomp_filter(self):
        '''seccomp_filter works'''

        # FIXME: these tests are based on an outdated api from
        # when seccomp was in development, and are only useful for
        # testing the 3.1ish era kernel. An improved set of tests
        # to exercise seccomp filtering would likely incorporate
        # https://github.com/redpig/seccomp before or after it goes
        # upstream into the kernel.

        expected = 0
        if self.dpkg_arch not in self.seccomp_filter_archs:
            self._skipped("only x86 on 3.0 kernel")
            expected = 1

        os.chdir('seccomp_filter')
        self.assertShellExitEquals(0, ["make"])
        shelltimeout = testlib.TimeoutFunction(self.assertShellExitEquals, 30)
        shelltimeout(expected, ["./seccomp_tests"])

    def test_120_smep_works(self):
        '''SMEP works'''

        if 'smep' not in self.cpu_flags:
            self._skipped("CPU does not support SMEP")
            return

        os.chdir('smep')
        if self.kernel_is_ubuntu:
            self.assertShellExitEquals(0, ["make"])

            # Find a value to test in memory.
            self.shell_cmd(["rmmod", "execuser"])
            self.assertShellExitEquals(0, ["insmod", "execuser/execuser.ko"])
            # TODO: Magic goes here.
            self._skipped("unfinished test")
            self.assertShellExitEquals(0, ["rmmod", "execuser"])
        else:
            self._skipped("only on Ubuntu")

    def test_130_kexec_disabled_00_proc(self):
        '''kexec_disabled sysctl supported'''

        expected = 0
        exists = True
        if not self.kernel_at_least('3.11'):
            self._skipped("kexec disable sysctl did not exist before trusty")
            expected = 1
            exists = False

        # ARM64 does not currently support kexec.
        if self._test_config('KEXEC') == False:
            self._skipped("kexec config not enabled")
            expected = 1
            exists = False

        self._test_sysctl_value('kernel/kexec_load_disabled', expected, exists=exists)

    taint_exception_table = {
        'spl': 'O',
        'zavl': 'PO',
        'zcommon': 'PO',
        'zfs': 'PO',
        'znvpair': 'PO',
        'zunicode': 'PO',
    }

    def _is_tainted(self, module, taint_field):
        '''checks for tainted module, with some known exceptions'''

        # no taint field at all
        if not (taint_field.startswith('(') and taint_field.endswith(')')):
            return False

        # drop first and last characters ('(' and ')')
        taint_value = taint_field[1:-1]

        # check for TAINT_CRAP
        if taint_value == 'C':
            return False

        # check in the exception table
        if module in self.taint_exception_table and self.taint_exception_table[module] == taint_value:
            return False

        # Son, we gots us an unexpectedly tainted kernel module here.
        return True

    def test_140_kernel_modules_not_tainted(self):
        '''kernel modules are not marked with a taint flag (especially 'E' for TAINT_UNSIGNED_MODULE)'''
        modules = '/proc/modules'

        if not os.path.exists(modules) or testlib.is_empty_file(modules):
            self._skipped('%s does not exist' % modules)

        with open(modules, 'r') as fh:
            for line in fh:
                fields = line.split()
                last_field = fields[-1]
                # Fail if the module is tainted. The one exception is TAINT_CRAP
                # (C), which is used to indicate the module comes from the staging
                # tree.
                if self._is_tainted(fields[0], last_field):
                    self.fail('Module \'%s\' is tainted: %s' % (fields[0], last_field))

    def test_020_aslr_00_proc(self):
        '''ASLR enabled'''

        expected = 2
        if not self.kernel_at_least('2.6.27'):
            self._skipped("boolean on Hardy and earlier")
            expected = 1

        self._test_sysctl_value('kernel/randomize_va_space', expected)

    def _test_aslr_rekey(self, area, target, name):
        '''Verify that CVE-2009-3238 is fixed'''
        self.announce("%s rekey" % (name))
        failures = 0
        report = ""
        for count in range(0, 100):
            rc, output = self.shell_cmd(['./%s' % (target), 'rekey', area, '--verbose'])
            if rc != 0:
                failures += 1
                report = "%s:\n%s" % (name, output)
        # Allow a 4-in-100 chance of repeated ASLR position on rekey, since
        # that's double the max value seen in practice.
        if failures <= 4:
            return 0, report
        return 1, report

    def _test_aslr_exec(self, area, expected, target, name):
        self.announce(name)
        self.assertShellExitEquals(expected, ["./%s" % (target), area, "--verbose"], msg="%s:\n" % name)
        rc, report = self._test_aslr_rekey(area, target, name)
        self.assertEqual(expected, rc, report)

    def _test_aslr_all(self, area, expected, environment):
        target = "aslr"
        name = "%s native" % (environment)
        self._test_aslr_exec(area, expected, target, name)

        # ppc64el doesn't have a 32bit abi, even though CONFIG_COMPAT is enabled
        if self._test_config('COMPAT') == False or self.dpkg_arch in ['ppc64el']:
            return
        target = "aslr32"
        name = "%s COMPAT" % (environment)
        self._test_aslr_exec(area, expected, target, name)

    def _test_aslr(self, area, expected):
        os.chdir('aslr')
        build = ["make"]
        self.assertShellExitEquals(0, build)

        self._test_aslr_all(area, expected, "default")

        # These tests run last since they change the rlimit that is restored
        # during per-test tearDown.
        # http://hmarco.org/bugs/CVE-2016-3672-Unlimiting-the-stack-not-longer-disables-ASLR.html
        resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        self._test_aslr_all(area, expected, "unlimited stack")

    # Dapper has stack
    def test_020_aslr_dapper_stack(self):
        '''ASLR of stack'''

        self._test_aslr('stack', 0)

    # Dapper i386 has mmap, libs
    def test_021_aslr_dapper_mmap(self):
        '''ASLR of mmap'''

        expected = 0
        if self.dpkg_arch != 'i386' and not self.kernel_at_least('2.6.20'):
            self._skipped("only i386 or Feisty and later")
            expected = 1
        else:
            # Arch-specific
            if self.dpkg_arch not in self.aslr_archs:
                self._skipped("only x86 (and armel after 10.04)")
                expected = 1

        self._test_aslr('mmap', expected)

    def test_021_aslr_dapper_libs(self):
        '''ASLR of libs'''

        expected = 0
        if self.dpkg_arch != 'i386' and not self.kernel_at_least('2.6.20'):
            self._skipped("only i386 or Feisty and later")
            expected = 1
        else:
            # Arch-specific
            if self.dpkg_arch not in self.aslr_archs:
                self._skipped("only x86 (and ARM 10.10 and later")
                expected = 1

        self._test_aslr('libs', expected)

    # Hardy has all but brk
    def test_022_aslr_hardy_text(self):
        '''ASLR of text'''

        expected = 0
        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = 1
        else:
            # Arch-specific
            if self.dpkg_arch not in self.aslr_archs:
                self._skipped("only x86 (and ARM 10.10 and later)")
                expected = 1

        self._test_aslr('text', expected)

    def test_022_aslr_hardy_vdso(self):
        '''ASLR of vdso'''

        expected = 0
        if not self.kernel_at_least('2.6.24'):
            self._skipped("only Hardy and later")
            expected = 1
        else:
            # Arch-specific
            if self.dpkg_arch not in ['i386', 'amd64', 'ppc64el', 'arm64', 's390x']:
                self._skipped("only x86, ppc64el, arm64, and s390x")
                expected = 1

        self._test_aslr('vdso', expected)

    # Intrepid and newer have all
    def test_022_aslr_intrepid_brk(self):
        '''ASLR of brk'''

        expected = 0
        if not self.kernel_at_least('2.6.27'):
            self._skipped("only Intrepid and later")
            expected = 1
        else:
            # Arch-specific
            if self.dpkg_arch not in self.aslr_archs:
                self._skipped("only x86 (and ARM after 10.04)")
                expected = 1

        self._test_aslr('brk', expected)

    # Wily and newer have mmap/pie split ASLR
    def test_023_aslr_wily_pie(self):
        '''ASLR of text vs libs'''

        expected = 0
        if not self.kernel_at_least('4.1'):
            self._skipped("only Wily and later")
            expected = 1
            # disabling for now, it's hitting a false positive on older
            # kernels
            return

        self._test_aslr('pie', expected)

    def test_150_privileged_user_namespaces(self):
        '''test whether user namespaces work at all (with root)'''

        os.chdir('userns')

        self.assertShellExitEquals(0, ["make"])
        self.assertShellExitEquals(0, ['./userns', '-U'])

    def test_150_unprivileged_user_namespaces(self):
        '''test whether user namespaces work as unprivileged user'''

        os.chdir('userns')
        expected = 0

        if not self.kernel_at_least('3.8'):
            self._skipped("unprivileged user ns was not allowed before trusty")
            expected = 1

        self.assertShellExitEquals(0, ["make"])
        self.assertShellExitEquals(expected, ['sudo', '-u', os.environ['SUDO_USER'], './userns', '-U'])

    def test_150_sysctl_disables_unpriv_userns(self):
        '''unprivileged_userns_clone sysctl supported'''

        expected = 1
        exists = True
        if not self.kernel_at_least('3.11'):
            self._skipped("unprivileged user ns disable sysctl did not exist before trusty")
            expected = 0
            exists = False

        self._test_sysctl_value('kernel/unprivileged_userns_clone', expected, exists=exists)

    def test_151_sysctl_disables_bpf_unpriv_userns(self):
        '''unprivileged_bpf_disabled sysctl supported'''

        expected = 0
        exists = True
        if not self.kernel_at_least('4.4'):
            self._skipped("unprivileged bpf disable sysctl did not exist before xenial")
            expected = 1
            exists = False

        self._test_sysctl_value('kernel/unprivileged_bpf_disabled', expected, exists=exists)

    def test_152_sysctl_disables_apparmor_unpriv_userns(self):
        '''unprivileged_userns_apparmor_policy sysctl supported'''

        expected = 0
        exists = True
        if not self.kernel_at_least('4.4'):
            self._skipped("unprivileged apparmor disable sysctl did not exist before xenial")
            expected = 1
            exists = False

        self._test_sysctl_value('kernel/unprivileged_userns_apparmor_policy', expected, exists=exists)

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
