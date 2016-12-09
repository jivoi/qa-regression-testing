#!/usr/bin/python
#
#    test-libvirt-lxc.py quality assurance test script for libvirt-lxc
#    Copyright (C) 2012 Canonical Ltd.
#    Author: Serge Hallyn <serge.hallyn@canonical.com>
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
'''
    run this on precise and later only
    This script will create an lxc container, define a libvirt-lxc
    container based on its rootfs, then test start, console, stop
    and undefine.
'''

# QRT-Packages: python-pexpect build-essential libvirt-bin lxc
# QRT-Privilege: root

import unittest, sys
import testlib
import os
import pexpect

class LibvirtLxcTest(testlib.TestlibCase):
    '''Test libvirt-lxc'''

    xml = 'libvirt/lxc.xml'
    vmname = 'qatest'
    rootfs = 'libvirt/lxc-rootfs'

    xmltext = '''
<domain type='lxc'>
  <name>qatest</name>
  <memory>332768</memory>
  <os>
    <type>exe</type>
    <init>/sbin/init</init>
  </os>
  <vcpu>1</vcpu>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <filesystem type='mount'>
      <source dir="''' + os.getcwd() + '''/libvirt/lxc-rootfs"/>
      <target dir='/'/>
    </filesystem>
    <interface type='network'>
      <source network='default'/>
    </interface>
    <console type='pty' />
  </devices>
</domain>
    '''
    xmltext2 = '''
<domain type='lxc'>
  <name>qatest</name>
  <memory>332768</memory>
  <os>
    <type>exe</type>
    <init>/sbin/init</init>
  </os>
  <vcpu>1</vcpu>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <filesystem type='mount'>
      <source dir="/var/lib/lxc/qrt-base/rootfs"/>
      <target dir='/'/>
    </filesystem>
    <interface type='network'>
      <source network='default'/>
    </interface>
    <console type='pty' />
  </devices>
</domain>
    '''

    def setUp(self):
        '''Set up prior to each test_* function'''
        if not os.path.exists('/var/lib/lxc/qrt-base'):
            cmd = [ 'lxc-create', '-t', 'ubuntu', '-n', 'qrt-base' ]
            rc, report = testlib.cmd(cmd)
            expected=0
            result = 'Failed to have lxc create the base container\n'
            self.assertTrue(rc == expected, result + report)

        if False:
            if not os.path.exists(self.rootfs):
                print >> sys.stdout, "  downloading test container rootfs"
                sys.stdout.flush()
                testlib.cmd(['bash', './libvirt/get_lxc_rootfs.sh'])
        if not os.path.exists(self.xml):
            f = open(self.xml, "w")
            if False:
                f.write(self.xmltext)
            else:
                f.write(self.xmltext2)
            f.close()

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_simple_create(self):
        '''Test container creation'''
        testlib.cmd(['virsh', '-c', 'lxc://', 'undefine', self.xml])
        rc, report = testlib.cmd(['virsh', '-c', 'lxc://', 'define', self.xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

    def test_simple_list(self):
        '''Test container listing'''
        cmd = [ 'virsh', '-c', 'lxc://', 'list', '--all' ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        abort_tests = True
        result = "Could not find '%s'\n" % self.vmname
        self.assertTrue(self.vmname in report, result + str(report))
        abort_tests = False

    def test_simple_start(self):
        '''Test container start'''
        cmd = [ 'virsh', '-c', 'lxc://', 'start', self.vmname ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

    def test_simple_started_list(self):
        '''Test container listing (with container running)'''
        cmd = [ 'virsh', '-c', 'lxc://', 'list' ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        result = "Could not find '%s'\n" % self.vmname
        self.assertTrue(self.vmname in report, result + str(report))

    def test_simple_started_console(self):
        '''Test container console'''
        rc = True
        child = pexpect.spawn('virsh -c lxc:// console %s' % (self.vmname), timeout=5)
        if child.expect('.* (?i)login:', timeout=30) != 0:
            rc = False
        child.kill(0)
        self.assertTrue(rc == True, "Did not receive a login prompt\n");

    def test_simple_stop(self):
        '''Test container stop'''
        cmd = [ 'virsh', '-c', 'lxc://', 'destroy', self.vmname ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

    def test_simple_undefine(self):
        '''Test container undefine'''
        cmd = [ 'virsh', '-c', 'lxc://', 'undefine', self.vmname ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

    def test_simple_undefined_list(self):
        '''Test list with container undefined - should return error'''
        cmd = [ 'virsh', '-c', 'lxc://', 'list', '--all' ]
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        result = "Did not expect to find '%s'\n" % self.vmname
        self.assertTrue(self.vmname not in report, result + str(report))

def destroy_base_container():
    cmd = [ "lxc-destroy", "-n", "qrt-base" ]
    testlib.cmd(cmd)

if __name__ == '__main__':
    # simple
    if os.getuid() != 0:
        print >>sys.stderr, "Need to be root to run this test"
        sys.exit(1)
    unittest.main()
    destroy_base_container()
