#!/usr/bin/python
#
#    test-kernel-root-operations.py regression testing script for kernel
#
#    Copyright (C) 2010 Canonical Ltd.
#    Authors:
#      Jamie Strandboge <jamie@ubuntu.com>
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
# QRT-Packages: iptables
# QRT-Depends:

import unittest
import testlib

try:
    from private.qrt.kernel_root_ops import PrivateKernelRootOpsTest
except ImportError:
    class PrivateKernelRootOpsTest(object):
        '''Empty class'''

class KernelSecurityTest(testlib.TestlibCase):
    '''Test kernel for regressions for privileged commands'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        # make sure iptables modules are loaded
        # needed for modinfo and lsmod tests
        rc, report = testlib.cmd(["iptables", "-L", "-n"])
        expected = 0
        self.assertEquals(rc, 0, report)

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _lsmod(self):
        '''lsmod'''
        rc, report = testlib.cmd(["lsmod"])
        expected = 0
        self.assertEquals(rc, 0, report)
        return report

    def _modinfo(self, module):
        '''modinfo'''
        rc, report = testlib.cmd(["modinfo", module])
        expected = 0
        self.assertEquals(rc, 0, report)
        return report

    def _modprobe(self, module):
        '''modprobe'''
        rc, report = testlib.cmd(["modprobe", module])
        expected = 0
        self.assertEquals(rc, 0, report)
        return report

    def _rmmod(self, module, fail_ok=False):
        '''rmmod'''
        rc, report = testlib.cmd(["rmmod", module])
        expected = 0
        if fail_ok and rc != expected:
            print " WARN: could not rmmod '%s'" % (module)
            return None
        else:
            self.assertEquals(rc, 0, report)
        return report

    def _word_find(self,report,name,invert=False):
        '''Check for a specific string'''
        if invert:
            warning = 'Found "%s"\n' % name
            self.assertFalse(name in report, warning + report)
        else:
            warning = 'Could not find "%s"\n' % name
            self.assertTrue(name in report, warning + report)

    def test_lsmod(self):
        '''Test lsmod'''
        report = self._lsmod()
        self._word_find(report, "ip_tables")

    def test_modinfo(self):
        '''Test modinfo'''
        report = self._modinfo("ip_tables")
        self._word_find(report, "Netfilter")

    def test_module(self):
        '''Test module loading/unloading'''
        self._modprobe("befs")
        report = self._lsmod()
        self._word_find(report, "befs")

        self._rmmod("befs")
        report = self._lsmod()
        self._word_find(report, "befs", invert=True)

    def test_updated_modules(self):
        '''Test modules touched in security/proposed updates'''
        modules = []
        if not self.kernel_at_least("3.5"):
            modules.append('econet')

        print ""
        for m in modules:
            print " %s:" % m
            print "  modinfo...",
            report = self._modinfo(m)
            print "ok"

            print "  modprobe...",
            self._modprobe(m)
            report = self._lsmod()
            self._word_find(report, m)
            print "ok"

            print "  rmmod...",
            result = self._rmmod(m, fail_ok=True)
            report = self._lsmod()
            if result == None:
                self._word_find(report, m)
                print "ok (still loaded)"
            else:
                self._word_find(report, m, invert=True)
                print "ok"

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
