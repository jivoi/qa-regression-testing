#!/usr/bin/python
#
#    test-libvirt.py quality assurance test script for libvirt
#    Copyright (C) 2008-2016 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
    How to run in a virtual machine:
    $ sudo apt-get -y install libvirt-bin qemu-kvm netcat-openbsd python-pexpect kvm-pxe virtinst
    or on xenial+
    $ sudo apt-get -y install libvirt-bin qemu-kvm netcat-openbsd python-pexpect ipxe-qemu virtinst
    $ sg libvirtd
    $ sudo ./test-libvirt.py setup-network # if this fails, see below
    $ sudo ./test-libvirt.py -v

    This will run libvirt inside of a virtual machine (eg kvm/libvirt) and
    test its functionality.

    Because the guest libvirt uses the same network settings as the host
    libvirt, need to change the guest libvirt to use a different network. Do
    this within the virtual machine guest (must run these as root or be in the
    'libvirtd' group and connecting to qemu:///system to do this):
    # virsh net-list               # should show the default network
    # virsh net-dumpxml default | sed -e "s#192.168.122.#192.168.123.#g" -e "s#^Connecting.*##g" > net.xml
    # virsh net-destroy default
    # virsh net-undefine default
    # virsh net-define ./net.xml
    # /etc/init.d/libvirt-bin stop
    # killall dnsmasq
    # /etc/init.d/libvirt-bin start
    # virsh net-dumpxml default    # should show the network is changed
    # virsh net-list               # should show the default network

    Can connect to this guest libvirt from the host machine with:
    $ virsh -c qemu+ssh://root@<libvirt guest hostname or ip>/system list

    The above can also be achieved by performing (broken on maverick):
    $ sudo ./test-libvirt.py setup-network

    NOTES:
      Gutsy must be run as non-root

      Hardy and higher will lose networking until adjust the default libvirt
      network when the host uses the same default network (see above)

      Hardy needs both kvm and qemu, Jaunty needs, kvm, Karmic and higher need
      qemu-kvm. FIXME: several hardy test are currently broken as a result of
      the migration away from libvirt-aa-secdriver.sh.

      If you interrupt the test halfway, you might need to clean up and reset
      the test environment. One way to do this is to run "./test-libvirt reset"

    TODO for migration away from libvirt-aa-secdriver.sh:
     - USB tests (eg analog for libvirt-apparmor.sh foo usb:2,3)
     - remote tests (eg analog for libvirt-apparmor.sh foo remote:192.168.122.203
'''

# QRT-Packages: libvirt-bin netcat-openbsd python-pexpect virtinst python-ipaddr python-requests openssh-client openssh-server
# QRT-Alternates: qemu:!lucid qemu:!precise qemu:!quantal qemu-kvm:!lucid kvm:lucid python-virtinst:lucid kvm-pxe:lucid ipxe-qemu:!lucid ipxe-qemu:!precise ipxe-qemu:!quantal
# QRT-Depends: libvirt/

import unittest, subprocess, sys
import testlib

import glob
import os
import pexpect
import re
import shutil
import tempfile
import time
import xml.dom.minidom
import errno

abort_tests = False	# emergency bailout
aborted_tests = 0
remotemachine = ''
copy_image = False
qemu_user = None
qemu_savetmpdir = None

def checksecmodel(txt):
    dom = xml.dom.minidom.parseString(txt)
    for n in dom.getElementsByTagName('secmodel'):
        for y in n.getElementsByTagName('model')[0].childNodes:
            if y.data != 'dac' and y.data != 'none':
                return True
    return False

def do_start_libvirtd():
    ubuntu_version = testlib.manager.lsb_release["Release"]
    if ubuntu_version >= 16.10:
        testlib.cmd(['sudo', 'systemctl', 'start', 'libvirtd.service'])
    elif ubuntu_version >= 15.10:
        testlib.cmd(['/usr/sbin/service', 'libvirt-bin', 'start'])
    else:
        testlib.cmd(['sudo', '/etc/init.d/libvirt-bin', 'start'])

def do_stop_libvirtd():
    ubuntu_version = testlib.manager.lsb_release["Release"]
    if ubuntu_version >= 16.10:
        testlib.cmd(['sudo', 'systemctl', 'stop', 'libvirtd.service'])
    elif ubuntu_version >= 15.10:
        testlib.cmd(['/usr/sbin/service', 'libvirt-bin', 'stop'])
    else:
        testlib.cmd(['sudo', '/etc/init.d/libvirt-bin', 'stop'])

class LibvirtTestCommon(testlib.TestlibCase):
    '''Common functionality for libvirt test classes'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.connect_uri = "qemu:///system"
        if self.lsb_release['Release'] == 7.10:
            self.connect_uri = "qemu:///session"

        self.default_net_name = "default"
        self.default_net = "192.168.123"
        self.test_net = "192.168.124"
        self.test_net_name = "fakenet"
        if self.lsb_release['Release'] >= 12.04:
            testlib.cmd(['ln', '-s', '/usr/bin/qemu-system-x86_64', '/usr/bin/qemu'])

        self.vmtarball = "libvirt/qatest.tar.bz2"
        self.vmxml = "libvirt/qatest/qatest.xml"
        self.vmimg = "libvirt/qatest/qatest.img"
        self.vmqcow2 = "libvirt/qatest/qatest-bs.qcow2"
        self.vmpristine = "libvirt/qatest/qatest-pristine.qcow2"
        self.vm_name = "qatest-i386"
        self.vm_virtinst_name = "qatest-virtinst"

        self.tmpdir = tempfile.mkdtemp(dir='/tmp')

        self.pool_name = "qrt-test-pool"
        self.pool_dir = os.path.join(self.tmpdir, "pool")
        self.vol_img = os.path.join(self.pool_dir, "vol.img")
        self.vol_bs_img = os.path.join(self.pool_dir, "bs.img")
        if self.lsb_release['Release'] > 14.10:
            self._aa_allow_tempdir()

        self.pidfile = "/var/run/libvirtd.pid"
        self.qemuconf = "/etc/libvirt/qemu.conf"

        # These can be tweaked in test classes which use one time setups
        self.clear_qemuconf = True
        self.undefine_qemu = True
        self.reinstate_apparmor = True

        self.qemuimg_exe = "qemu-img"
        if self.lsb_release['Release'] < 9.10:
            rc, output = testlib.cmd(['which', 'kvm-img'])
            if rc == 0:
                self.qemuimg_exe = "kvm-img"

        if not os.path.exists(self.vmxml) and not os.path.exists(self.vmimg):
            if os.path.exists(self.vmtarball):
                print >>sys.stdout, "  untarring '%s'  " % (self.vmtarball)
                sys.stdout.flush()
                testlib.cmd(['tar', '-C', 'libvirt', '-jxf', self.vmtarball])

                # update path in xml file
                subprocess.call(['sed', '-i', "s#<source file='/.*'/>#<source file='" + os.path.join(os.getcwd(), self.vmimg) + "'/>#g", self.vmxml])

                # add scsi controller if 15.10 >
                if self.lsb_release['Release'] >= 15.10:
                    subprocess.call(['sed', '-i', "s#<devices>#<devices>\\n    <controller type=\'scsi\' model=\'virtio-scsi\'/>#g", self.vmxml])

            else:
                raise ValueError, "Couldn't find '%s'" % (self.vmtarball)

        if not os.path.exists(self.vmpristine):
            print >>sys.stdout, "  creating qcow2 '%s' from '%s'" % (self.vmpristine, self.vmimg)
            rc, report = testlib.cmd([self.qemuimg_exe, 'convert', '-f', 'raw', self.vmimg, '-O', 'qcow2', self.vmpristine])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(self.vmpristine), "Could not find '%s'" % (self.vmpristine))

        if not os.path.exists(self.vmqcow2):
            print >>sys.stdout, "  creating qcow backingstore '%s'" % (self.vmimg)
            if self.lsb_release['Release'] < 9.10:
                # qemu-img < 0.11 doesn't support '-F'
                rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-b', os.path.join(os.getcwd(), self.vmpristine), '-f', 'qcow2', self.vmqcow2])
            else:
                rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-F', 'qcow2', '-b', os.path.join(os.getcwd(), self.vmpristine), '-f', 'qcow2', self.vmqcow2])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(self.vmqcow2), "Could not find '%s'" % (self.vmqcow2))

        if self.lsb_release['Release'] == 7.10:
            # Gutsy doesn't have a default network
            rc, report = testlib.cmd(['uuidgen'])
            uuid = report.strip()
            tmp = '''<network>
  <name>default</name>
  <uuid>%s</uuid>
  <forward mode="nat"/>
  <bridge name="virbr0" stp="on" forwardDelay="0" />
  <ip address="%s.1" netmask="255.255.255.0">
    <dhcp>
      <range start="%s.2" end="%s.254" />
    </dhcp>
  </ip>
</network>
''' % (uuid, self.default_net, self.default_net, self.default_net)

            handle, name = testlib.mkstemp_fill(tmp)
            testlib.cmd(['virsh', '-c', self.connect_uri, 'net-define', name])
            os.unlink(name)

        # we never restart libvirtd, so make sure it didn't disappear during setup
        self.assertTrue(testlib.check_pidfile('libvirtd', self.pidfile))

    def _aa_allow_tempdir(self):
        fh = open('/etc/apparmor.d/abstractions/libvirt-qemu', 'r')
        lines = fh.readlines()
        fh.close()
        contents = ""

        for line in lines:
            try:
                idx = line.index("deny /tmp/")
                line = "  /tmp/{,**} rw,\n"
            except:
                pass
            try:
                idx = line.index("deny /var/tmp/")
                line = "  /var/tmp/{,**} rw,\n"
            except:
                pass
            contents += "%s" % (line)
        testlib.config_replace('/etc/apparmor.d/abstractions/libvirt-qemu', contents, False)
        testlib.cmd(['cp', '-f', '/etc/apparmor.d/abstractions/libvirt-qemu', '/tmp/q1'])

        self._restart_daemon()

    def _tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists('/etc/apparmor.d/abstracations/libvirt-qemu'):
            testlib.config_restore('/etc/apparmor.d/abstracations/libvirt-qemu')
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

        if self.lsb_release['Release'] >= 12.04:
            testlib.cmd(['rm', '-f', '/usr/bin/qemu'])

        if self.clear_qemuconf:
            testlib.config_restore(self.qemuconf)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        testlib.cmd(['virsh', '-c', self.connect_uri, 'net-undefine', self.test_net_name])
        if self.undefine_qemu:
            for n in [self.vm_name, self.vm_virtinst_name]:
                testlib.cmd(['virsh', '-c', self.connect_uri, 'destroy', n])
                testlib.cmd(['virsh', '-c', self.connect_uri, 'undefine', n])
        if self.lsb_release['Release'] == 7.10:
            testlib.cmd(['virsh', '-c', self.connect_uri, 'net-undefine', self.default_net_name])

        for v in [self.vol_img, self.vol_bs_img]:
            testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-delete', v])
        testlib.cmd(['virsh', '-c', 'qemu:///session', 'pool-destroy', "%s-session" % self.pool_name])
        testlib.cmd(['virsh', '-c', 'qemu:///session', 'pool-undefine', "%s-session" % self.pool_name])
        testlib.cmd(['virsh', '-c', 'qemu:///system', 'pool-destroy', self.pool_name])
        testlib.cmd(['virsh', '-c', 'qemu:///system', 'pool-undefine', self.pool_name])

        # we never restart libvirtd, so make sure it didn't disappear during our test
        self.assertTrue(testlib.check_pidfile('libvirtd', self.pidfile))

        if self.reinstate_apparmor:
            # Make sure the apparmor profile is loaded, as this is the default
            # configuration in Ubuntu.
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'capabilities'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            if '<model>apparmor</model>' not in report:
                testlib.cmd(['aa-enforce', '/etc/apparmor.d/usr.sbin.libvirtd'])
                self._restart_daemon()

    def _get_domuuid(self, uri, vm_name):
        '''Get uuid of domain'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'domuuid', vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            uuid = report.splitlines()[1].strip()
        return uuid

    def _get_config(self, fn, option):
        '''Get option from config file'''
        fh = open(fn, 'r')
        lines = fh.readlines()
        fh.close()

        key = ''
        val = ''
        found = False
        for line in lines:
            key = line.split()[0]
            if key == option:
                val = line.split()[2]
                break

        return (key, val)

    def _update_config(self, fn, config_strings):
        '''Update config file with the config_strings'''
        for s in config_strings:
            fh = open(fn, 'r')
            lines = fh.readlines()
            fh.close()
            contents = ""

            found = False
            for line in lines:
                start = s.split()[0]
                if line.startswith(start):
                    contents += "# %s" % (line)
                    contents += "%s\n" % (s)
                    found = True
                    continue
                contents += "%s" % (line)
            if not found:
                contents += "%s\n" % (s)
            testlib.config_replace(self.qemuconf, contents, False)

        self._restart_daemon()

    def _dumpxml_vm(self, uri, vm_name):
        '''Dump XML of VM'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'dumpxml', vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        result = "'%s' not in report" % (vm_name)
        self.assertTrue(vm_name in report, result + report)
        return report

    def _define_vm(self, uri, vm_name, xml):
        '''Define VM'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'define', xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', uri, 'list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (vm_name)
        self.assertTrue(vm_name in report, result + report)

    def _undefine_vm(self, uri, vm_name):
        '''Undefine VM'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'undefine', vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', uri, 'list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' in report" % (vm_name)
        self.assertFalse(vm_name in report, result + report)

    def _stop_daemon(self):
        '''Stop libvirtd daemon'''
        if self.lsb_release['Release'] >= 15.10:
            do_stop_libvirtd()
            time.sleep(5)
        else:
            do_stop_libvirtd()
            time.sleep(1)
            testlib.cmd(['killall', '-9', 'libvirtd'])

    def _start_daemon(self):
        '''Start libvirtd daemon'''
        do_start_libvirtd()
        time.sleep(3)
        self.assertTrue(testlib.check_pidfile('libvirtd', '/var/run/libvirtd.pid'))
        # throwaway command that blocks until libvirt comes up
        rc, report = testlib.cmd(['virsh', 'capabilities'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _restart_daemon(self):
        '''Restart libvirtd daemon'''
        self._stop_daemon()
        self._start_daemon()

    def _start_vm(self, uri, vm_name):
        '''Start VM'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'start', vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', uri, 'list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (vm_name)
        self.assertTrue(vm_name in report, result + report)

    def _destroy_vm(self, uri, vm_name):
        '''Destroy VM'''
        rc, report = testlib.cmd(['virsh', '-c', uri, 'destroy', vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', uri, 'list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' in report" % (vm_name)
        self.assertFalse(vm_name in report, result + report)

    def _run_qemu_command_and_kill_vm(self, cmd):
        '''Run a qemu command. This function is total crack as we have to
           stop libvirt, connect to the console, send the qemu command,
	   destroy the machine, the start libvirt. I think I just threw up a
           little in my mouth. *bleck*

           Do not use this command unless forced at gunpoint.
        '''
        error = False
        error_str = ""
        monitor = os.path.join("/var/lib/libvirt/qemu", self.vm_name + ".monitor")
        self.assertTrue(os.path.exists(monitor), "Monitor '%s' does not exist" % monitor)
        self._stop_daemon()

        # clean up as best we can...
        subprocess.call(['rm', '-f', '/var/run/libvirt/libvirt-sock*'])
        subprocess.call(['rm', '-f', '/var/run/libvirt/qemu/%s*' % self.vm_name])

        if os.path.exists(monitor):
            report = ""
            child = pexpect.spawn('nc -U %s' % (monitor))
            try:
                child.expect('\(qemu\) ', timeout=5)
            except:
                error = True
                error_str += "no output from 'nc'"
            try:
                child.sendline(cmd)
                child.expect('\(qemu\) ', timeout=5)
                report = child.before
            except:
                error = True
                error_str += "no output from 'nc' after sending '%s'" % (cmd)

            if not error:
		# Now kill the machine, since there is no way to get libvirt to
		# get libvirt to reattach. If you know of one, please, *please*
                # adjust this function.
                try:
                    child.sendline('quit')
                except:
                    error = True
                    error_str += "error sending 'quit'"
            child.close(force=True)
        else:
            error = True
            error_str += "Monitor '%s' does not exist after killing libvirtd"

        # Ok, the machine is dead. Remove the monitor, then crank up libvirt
        if os.path.exists(monitor):
            os.unlink(monitor)
        self._start_daemon()

        self.assertFalse(error, error_str)
        return report

    def _get_libvirtd_pid(self):
        '''Get libvirt pid'''
        try:
            fd = open(self.pidfile, 'r')
            pid = fd.readline().rstrip('\n')
            fd.close()
        except:
            self.assertTrue(False, "could not get pid in '%s'" % self.pidfile)

        self.assertTrue(testlib.check_pid('libvirtd', pid), 'libvirtd is not running')
        return pid

    def _setup_storage_pool(self, pool_name, pool_dir, pool_uuid, connect_uri):
        '''Setup a storage pool'''
        if self.lsb_release['Release'] < 9.04:
            self._skipped("< 9.04 does not support storage pools")
            return False

        pool_xml = os.path.join(self.tmpdir, "pool.xml")
        os.mkdir(pool_dir)

        # define the storage pool
        contents = '''<pool type='dir'>
  <name>%s</name>
  <uuid>%s</uuid>
  <capacity>0</capacity>
  <allocation>0</allocation>
  <available>0</available>
  <source>
  </source>
  <target>
    <path>%s</path>
    <permissions>
      <mode>0700</mode>
      <owner>0</owner>
      <group>0</group>
    </permissions>
  </target>
</pool>
''' % (pool_name, pool_uuid, pool_dir)
        testlib.create_fill(pool_xml, contents)
        rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'pool-define', pool_xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'pool-start', pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Pool %s started" % pool_name
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)

        rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'pool-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search_re = "%s.* active" % pool_name
        result = "Could not find '%s':\n" % (search_re)
        self.assertTrue(re.search(search_re, report), result + report)


class LibvirtTestCommonWithAbort(LibvirtTestCommon):
    '''LibvirtTestCommon, but skip tests when abort_tests is True'''
    def run(self, result=None):
        '''Run test with option to abort everything'''
        global abort_tests
        global aborted_tests
        if abort_tests:
            aborted_tests += 1
            return

        unittest.TestCase.run(self, result)


class LibvirtTest(LibvirtTestCommon):
    '''Tests for general libvirt functionality'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_daemon(self):
        '''Test daemon is running'''
        self.assertTrue(testlib.check_pidfile('libvirtd', '/var/run/libvirtd.pid'))

    def test_netlist(self):
        '''Test net-list'''
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (self.default_net_name)
        self.assertTrue(self.default_net_name in report, result + report)

        result = "nonexistent in report"
        self.assertFalse('nonexistent' in report, result + report)

    def test_net(self):
        '''Test net functions'''
        self.xmltmp = os.path.join(self.tmpdir, "net.xml")

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-dumpxml', 'default'], None, stderr=subprocess.PIPE, stdout=file(self.xmltmp, 'w'))
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['uuidgen'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        uuid = report.strip()

        subprocess.call(['sed', '-i', 's/' + self.default_net + '/' + self.test_net + '/g', self.xmltmp])
        subprocess.call(['sed', '-i', 's#<name>' + self.default_net_name + '</name>#<name>' + self.test_net_name + '</name>#g', self.xmltmp])
        subprocess.call(['sed', '-i', 's#<uuid>.*</uuid>#<uuid>' + uuid + '</uuid>#g', self.xmltmp])
        subprocess.call(['sed', '-i', 's#virbr0#virbr1#g', self.xmltmp])

        # define it
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-define', self.xmltmp])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (self.test_net_name)
        self.assertTrue(self.test_net_name in report, result + report)

        # start
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-start', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (self.test_net_name)
        self.assertTrue(self.test_net_name in report, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-dumpxml', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (self.test_net)
        self.assertTrue(self.test_net in report, result + report)

        # test net autostart
        for ans in ['yes', 'no']:
            args = ['virsh', '-c', self.connect_uri, 'net-autostart', self.test_net_name]
            if ans == "no":
                args.append("--disable")

            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list', '--all'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            found = False
            err = "'%s' not found for autostart\n" % (ans)
            for line in report.splitlines():
                if re.match('.*' + self.test_net_name + '.*' + ans, line):
                    found = True

            self.assertTrue(found, err + report)

        # net-uuid
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-uuid', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Could not find '%s' in report\n" % uuid
        self.assertTrue(uuid in report, result + report)

        # net-name
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-name', uuid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Could not find '%s' in report\n" % self.test_net_name
        self.assertTrue(self.test_net_name in report, result + report)

        # net-destroy after define
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-destroy', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("destroyed" in report, "Could not find 'destroyed' in report\n" + report)

        # undefine it
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-undefine', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' in report" % (self.test_net_name)
        self.assertFalse(self.test_net_name in report, result + report)

        # net-create
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-create', self.xmltmp])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("created" in report, "Could not find 'created' in report\n" + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' not in report" % (self.test_net_name)
        self.assertTrue(self.test_net_name in report, result + report)

        # net-destroy after create
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-destroy', self.test_net_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("destroyed" in report, "Could not find 'destroyed' in report\n" + report)

        # net-undefine after create
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-undefine', self.test_net_name])
        #expected = 0
        #result = 'Got exit code %d, expected %d\n' % (rc, expected)
        #self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'net-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'%s' in report" % (self.test_net_name)
        self.assertFalse(self.test_net_name in report, result + report)


    def test_vm(self):
        '''Test VM functions'''
        # define it
        self._define_vm(self.connect_uri, self.vm_name, self.vmxml)

        # test autostart
        for ans in ['enable', 'disable']:
            args = ['virsh', '-c', self.connect_uri, 'autostart', self.vm_name]
            if ans == "disable":
                args.append("--disable")

            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            if self.lsb_release['Release'] <= 8.04:
                if ans == "enable":
                    self.assertTrue(' marked as autostarted' in report, report)
                else:
                    self.assertTrue('unmarked as autostarted' in report, report)
            else:
                rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'dominfo', self.vm_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                found = False
                err = "'%s' not found for autostart\n" % (ans)
                for line in report.splitlines():
                    if re.match('Autostart.*' + ans, line):
                        found = True

                self.assertTrue(found, err + report)

        if self.lsb_release['Release'] == 7.10:
            self._skipped("Not starting/destroying on Gutsy")
        else:
            # start it
            self._start_vm(self.connect_uri, self.vm_name)

            # destroy it
            self._destroy_vm(self.connect_uri, self.vm_name)

        # undefine it
        self._undefine_vm(self.connect_uri, self.vm_name)

    def test_fd_leaks(self):
        '''Test file descriptor leaks (LP: #567392)'''
        self._define_vm(self.connect_uri, self.vm_name, self.vmxml)

        pid = self._get_libvirtd_pid()

	# Start and stop a VM once, to make sure libvirt is all setup right.
        # Subsequent stops and starts should not leak any FDs
        self._start_vm(self.connect_uri, self.vm_name)
        self._destroy_vm(self.connect_uri, self.vm_name)

        rc, before_report = testlib.cmd(['ls', '-1', "/proc/%s/fd" % pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + before_report)

        self._start_vm(self.connect_uri, self.vm_name)

        rc, during_report = testlib.cmd(['ls', '-1', "/proc/%s/fd" % pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + during_report)

        self._destroy_vm(self.connect_uri, self.vm_name)

        # Whoa, Nelly!
        time.sleep(2)

        rc, after_report = testlib.cmd(['ls', '-1', "/proc/%s/fd" % pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + after_report)

        if before_report != after_report:
            before = os.path.join(self.tmpdir, 'before')
            after = os.path.join(self.tmpdir, 'after')
            testlib.create_fill(before, before_report)
            testlib.create_fill(after, after_report)
            rc, report = testlib.cmd(["/usr/bin/diff", before, after])
            summary = ""
            for line in report.splitlines():
                if line.startswith('<'):
                    fd = line.split()[1]
                    summary += "missing: %s %s" % (fd, os.readlink(os.path.join("/proc/%s/fd" % pid, fd)))
                elif line.startswith('>'):
                    fd = line.split()[1]
                    summary += "leaked: %s %s" % (fd, os.readlink(os.path.join("/proc/%s/fd" % pid, fd)))

            self.assertTrue(before_report == after_report, "FD leak!\nBefore:\n%s\nAfter:\n%s\nSummary:\n%s" % (before_report, after_report, summary))

    def test_enforce_image_format(self):
        '''Test enforce image format'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("%s does not use enforcing format" % (self.lsb_release['Release']))

        self.xmltmp = os.path.join(self.tmpdir, "vm.xml")
        for t in ['raw', 'qcow2']:
            if os.path.exists(self.xmltmp):
                os.unlink(self.xmltmp)

            disk = os.path.join(os.getcwd(), self.vmimg)
            if t == "qcow2":
                disk = os.path.join(os.getcwd(), self.vmpristine)

            shutil.copy(self.vmxml, self.xmltmp)
            subprocess.call(['sed', '-i', "s#<source file=.*#<source file='" + disk + "'/>#g", self.xmltmp])

            # define image, then see if it has type defined
            self._define_vm(self.connect_uri, self.vm_name, self.xmltmp)
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'dumpxml', self.vm_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))

            if self.lsb_release['Release'] >= 10.04:
		# Upstream defaults to 'raw' if type is not specified in the
		# XML. Our patch for 9.10 just makes sure that qemu-img
                # specifies it, so don't check the XML there.
                search = "<driver name='qemu' type='raw'/>"

                # Later versions of libvirt don't output "type='raw'"
                if self.lsb_release['Release'] < 10.10:
                    result = 'Could not find \"%s\" in report:\n' % search
                    self.assertTrue(search in report, result + report)

                if t != "raw":
                    search = "<driver name='qemu' type='%s'/>" % t
                    result = 'Found \"%s\" in report:\n' % search
                    self.assertFalse(search in report, result + report)
                    search = "<driver name='qemu'/>"
                    self.assertFalse(search in report, result + report)

            self._undefine_vm(self.connect_uri, self.vm_name)

            # Make sure new machines get the format specified when using
            # -drive. Ubuntu 9.04 and lower does not have
            # domxml-from-native
            qemu_args = os.path.join(self.tmpdir, "qemu.args")
            contents = '''LC_ALL=C PATH=/bin:/usr/sbin:/sbin:/bin QEMU_AUDIO_DRV=none /usr/bin/qemu -S -M pc -m 512 -smp 1 -name foo -boot c -drive file=%s,if=virtio,index=0,boot=on,format=%s -net none serial none -parallel none -usb
''' % (disk, t)
            testlib.create_fill(qemu_args, contents)
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-from-native', 'qemu-argv', qemu_args])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))

            # Later versions of libvirt don't output "type='raw'"
            if t == 'raw' and self.lsb_release['Release'] >= 11.04:
                continue
            search = "<driver name='qemu' type='%s'/>" % t
            result = "Could not find '%s' in:\n" % (search)
            self.assertTrue(search in report, result + report)

    def test_domxml_to_native(self):
        '''Test domxml-to-native'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("%s does not have 'domxml-to-native'" % (self.lsb_release['Release']))
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-to-native', 'qemu-argv', self.vmxml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        search = "-name %s" % (self.vm_name)
        self.assertTrue(search, "Could not find '%s' in:\n%s" % (search, report))

        search = "-drive file=%s" % (self.vmimg)
        self.assertTrue(search, "Could not find '%s' in:\n%s" % (search, report))

        search = "-net nic"
        self.assertTrue(search, "Could not find '%s' in:\n%s" % (search, report))

        search = "-vnc 127"
        self.assertTrue(search, "Could not find '%s' in:\n%s" % (search, report))

    def test_domxml_from_native(self):
        '''Test domxml-from-native'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("%s does not have 'domxml-from-native'" % (self.lsb_release['Release']))
        qemu_args = os.path.join(self.tmpdir, "qemu.args.old")
        contents = '''LC_ALL=C PATH=/bin HOME=/home/test USER=test LOGNAME=test /usr/bin/qemu -S -M pc -m 214 -smp 1 -nographic -monitor pty -no-acpi -boot c -hda /dev/HostVG/QEMUGuest1 -net none -serial none -parallel none -usb
'''
        testlib.create_fill(qemu_args, contents)
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-from-native', 'qemu-argv', qemu_args])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        for search in ["<domain type='qemu'", "<name>", "<uuid>", "<memory( unit='KiB')?>219136</memory>", "<currentMemory( unit='KiB')?>219136</currentMemory>", "<vcpu( placement='static')?>1</vcpu>", "<os>", "<type arch=", "<boot dev=", "qemu</emulator>", "<disk type=", "device='disk'>", "<source dev='/dev/HostVG/QEMUGuest1'/>", "<target dev="]:
            result = "Could not find '%s' in:\n" % (search)
            self.assertTrue(re.search(search, report), result + report)

        qemu_args = os.path.join(self.tmpdir, "qemu.args.new")
        contents = '''LC_ALL=C PATH=/bin:/usr/sbin:/sbin:/bin QEMU_AUDIO_DRV=none /usr/bin/qemu -S -M pc -m 512 -acpi -smp 2 -name foo -boot c -drive file=/tmp/nonexistent,if=virtio,index=0,boot=on,format=qcow2 -net none serial none -parallel none -usb
'''
        testlib.create_fill(qemu_args, contents)
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-from-native', 'qemu-argv', qemu_args])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        for search in ["<domain type='qemu'", "<name>", "<uuid>", "<memory( unit='KiB')?>524288</memory>", "<currentMemory( unit='KiB')?>524288</currentMemory>", "<vcpu( placement='static')?>2</vcpu>", "<os>", "<type arch=", "<features>", "<acpi/>", "<boot dev=", "qemu</emulator>", "<disk type='file' device='disk'>", "<driver name='qemu' type='qcow2'/>", "<source file='/tmp/nonexistent'/>", "<target dev=", "<input type='mouse'", "<graphics type='", "<video>"]:
            result = "Could not find '%s' in:\n" % (search)
            self.assertTrue(re.search(search,report), result + report)

    def test_storage_pools(self):
        '''Test storage pools'''
        if self.lsb_release['Release'] < 9.04:
            return self._skipped("< 9.04 does not support storage pools")
        pool_xml = os.path.join(self.tmpdir, "pool.xml")

        vol_xml = os.path.join(self.tmpdir, "vol.xml")

        vol_pristine_img = os.path.join(self.pool_dir, "pristine.img")
        vol_bs_xml = os.path.join(self.tmpdir, "bs.xml")
        vol_bs_name = os.path.basename(self.vol_bs_img)

        os.mkdir(self.pool_dir)

        # define the storage pool
        contents = '''<pool type='dir'>
  <name>%s</name>
  <uuid>4a458219-9b8b-2af0-77b8-adebf563f5fa</uuid>
  <capacity>0</capacity>
  <allocation>0</allocation>
  <available>0</available>
  <source>
  </source>
  <target>
    <path>%s</path>
    <permissions>
      <mode>0700</mode>
      <owner>0</owner>
      <group>0</group>
    </permissions>
  </target>
</pool>
''' % (self.pool_name, self.pool_dir)
        testlib.create_fill(pool_xml, contents)

        print "\n  pool-define"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-define', pool_xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        # see if the storage pool showed up
        print "  pool-list"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search_re = "%s.*inactive" % self.pool_name
        result = "Could not find '%s':\n" % (search_re)
        self.assertTrue(re.search(search_re, report), result + report)

        # start the storage pool
        print "  pool-start"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-start', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Pool %s started" % self.pool_name
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search_re = "%s.* active" % self.pool_name
        result = "Could not find '%s':\n" % (search_re)
        self.assertTrue(re.search(search_re, report), result + report)

        # set the pool to autostart
        print "  pool-autostart"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-autostart', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search_re = "%s.*active.*yes" % self.pool_name
        result = "Could not find '%s':\n" % (search_re)
        self.assertTrue(re.search(search_re, report), result + report)

        # list the volumes (should not be there)
        print "  vol-list"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-list', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = vol_bs_name
        result = "Could not find '%s':\n" % (search)
        self.assertFalse(search in report, result + report)

        # create the raw volume
        contents = '''<volume>
  <name>%s</name>
  <key>%s</key>
  <allocation>0</allocation>
  <capacity unit="M">10</capacity>
  <target>
    <path>%s</path>
    <format type='raw'/>
    <permissions>
      <owner>0744</owner>
      <group>0744</group>
      <mode>0744</mode>
    </permissions>
  </target>
</volume>
''' % (os.path.basename(self.vol_img), self.vol_img, self.vol_img)
        testlib.create_fill(vol_xml, contents)

        print "  vol-create"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-create', self.pool_name, vol_xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        self.assertTrue(os.path.exists(self.vol_img), "Could not find '%s'" % self.vol_img)

        # verify the volume was added to the pool
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-list', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = os.path.basename(self.vol_img)
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)


        # AppArmor blocks these on Karmic (LP: #470636)
        # create the pristine qcow2 image (the backing store needs to be
        # already created)
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', 'qcow2', vol_pristine_img, '10M'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(os.path.exists(vol_pristine_img), "Could not find '%s'" % (vol_pristine_img))

        bs_fmt = "qcow2"
        if self.lsb_release['Release'] < 9.10:
            # needed for vol-create on Jaunty for some reason
            bs_fmt = "raw"

        # create the volume with a backingstore
        contents = '''<volume>
  <name>%s</name>
  <key>%s</key>
  <allocation>0</allocation>
  <capacity unit="M">10</capacity>
  <target>
    <path>%s</path>
    <format type='%s'/>
    <permissions>
      <owner>0744</owner>
      <group>0744</group>
      <mode>0744</mode>
    </permissions>
  </target>
  <backingStore>
    <path>%s</path>
    <format>qcow2</format>
    <permissions>
      <owner>0744</owner>
      <group>0744</group>
      <mode>0744</mode>
    </permissions>
  </backingStore>
</volume>
''' % (vol_bs_name, self.vol_bs_img, self.vol_bs_img, bs_fmt, vol_pristine_img)
        testlib.create_fill(vol_bs_xml, contents)

        print "  vol-create (with backing store)"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-create', self.pool_name, vol_bs_xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        self.assertTrue(os.path.exists(self.vol_bs_img), "Could not find '%s'" % self.vol_bs_img)

        # verify the volume with a backingstore was added to the pool
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-list', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = vol_bs_name
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)

        print "  vol-path"
        for v in [self.vol_img, self.vol_bs_img]:
            #if self.lsb_release['Release'] == 9.10 and v == vol_pristine_img:
            #    continue
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-path', v])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))
            result = "Could not find '%s':\n" % (v)
            self.assertTrue(v in report, result + report)

        print "  vol-delete"
        for v in [self.vol_img, self.vol_bs_img]:
            # This doesn't work in 1.2.21 or with CVE-2015-5247 fix
            # Not sure if this is an upstream regression
            if self.lsb_release['Release'] in [15.10, 16.04]:
                continue
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-delete', v])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))
            search = '%s deleted' % v
            result = "Could not find '%s':\n" % (search)
            self.assertTrue(search in report, result + report)
            self.assertFalse(os.path.exists(v), "Found '%s'" % v)


        print "  pool-destroy"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-destroy', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = '%s destroyed' % self.pool_name
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)

        print "  pool-undefine"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-undefine', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'pool-list', '--all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = self.pool_name
        result = "Found '%s':\n" % (search)
        self.assertFalse(search in report, result + report)

    def test_emulators(self):
        '''Test emulators'''
        print ""
        for i in ["kvm", "kqemu", "qemu"]:
            print "  %s... " % i,
            sys.stdout.flush()
            if (i == "kvm" and not os.path.exists("/dev/kvm")) or (i == "kqemu" and not os.path.exists("/dev/kqemu")):
                print "skipping ('/dev/%s' does not exist)" % i
                continue
            tmpxml = os.path.join(self.tmpdir, "tmp.xml")
            shutil.copy(self.vmxml, tmpxml)

            if i == "kvm":
                subprocess.call(['sed', '-i', "-e", "s#<domain type=.*#<domain type='kvm'>#", "-e", "s#<emulator>.*#<emulator>/usr/bin/kvm</emulator>#", tmpxml])
            elif i == "kqemu":
                subprocess.call(['sed', '-i', "-e", "s#<domain type=.*#<domain type='kqemu'>#", "-e", "s#<emulator>.*#<emulator>/usr/bin/qemu</emulator>#", tmpxml])
            else:
                subprocess.call(['sed', '-i', "-e", "s#<domain type=.*#<domain type='qemu'>#", "-e", "s#<emulator>.*#<emulator>/usr/bin/qemu</emulator>#", tmpxml])

            self._define_vm(self.connect_uri, self.vm_name, tmpxml)
            self._start_vm(self.connect_uri, self.vm_name)
            self._destroy_vm(self.connect_uri, self.vm_name)
            self._undefine_vm(self.connect_uri, self.vm_name)


class LibvirtTestVirtinst(LibvirtTestCommon):
    '''Tests for virtinst functionality'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_virt_install_cdrom(self):
        '''Test virt-install --cdrom'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("TODO: fix test on '%s'" % (self.lsb_release['Release']))

        # We aren't going to do a full install here, but we are going to
        # try out virt-install and make sure it did a few things right
        memory = 64

        # libvirt runs as libvirt-qemu:kvm in maverick and later
        if self.lsb_release['Release'] > 10.04:
            os.chmod(self.tmpdir, 0770)
            subprocess.call(['chgrp', 'kvm', self.tmpdir])

        print ""
        for install_type in ['file', 'pool']:
            for connect_uri in [ 'qemu:///system', 'qemu:///session' ]:
                disk = ""
                disk_args = ""
                virtinst_search = ['Creating domain']
                dumpxml_search = [self.vm_virtinst_name, '''<memory( unit='KiB')?>%d</memory>''' % (memory * 1024), "<boot dev='cdrom'/>"]
                if install_type == 'file':
                    disk = os.path.join(self.tmpdir, "%s.img" % (self.vm_virtinst_name))
                    disk_args = 'path=%s,size=.01' % (disk)
                    if self.lsb_release['Release'] < 14.10:
                        virtinst_search.append('Creating storage')
                    # Later versions of libvirt don't output "type='raw'"
                    if self.lsb_release['Release'] < 11.04:
                        dumpxml_search.append("<driver name='qemu' type='raw'")

                    if os.path.exists(disk):
                        os.unlink(disk)
                else:
                    if self.lsb_release['Release'] < 9.04:
                        self._skipped("< 9.04 does not support storage pools")
                        continue

                    pool_name = self.pool_name
                    pool_dir = "%s-system" % (self.pool_dir)
                    pool_uuid = "4a458219-9b8b-2af0-77b8-adebf563f5fa"
                    if connect_uri == 'qemu:///session':
                        pool_name = "%s-session" % (self.pool_name)
                        pool_dir = "%s-session" % (self.pool_dir)
                        pool_uuid = "4a458219-9b8b-2af0-77b8-adebf563f5fb"

                    print " setting up %s for %s (%s)" % (os.path.basename(pool_dir), self.vm_virtinst_name, connect_uri)
                    self._setup_storage_pool(pool_name, pool_dir, pool_uuid, connect_uri)

                    if self.lsb_release['Release'] > 14.04:
                        disk = os.path.join(pool_dir, "%s.qcow2" % (self.vm_virtinst_name))
                    else:
                        disk = os.path.join(pool_dir, "%s.img" % (self.vm_virtinst_name))
                    disk_args = 'pool=%s,size=.01,format=qcow2' % (pool_name)
                    virtinst_search.append('Allocating ')
                    dumpxml_search.append("<driver name='qemu' type='qcow2'")

                dumpxml_search.append(" file='%s'" % (disk))

                print " virt-install %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
                rc, report = testlib.cmd(['virt-install', '--connect=%s' % connect_uri, '--wait=0', '--force', '--name', self.vm_virtinst_name, '--ram=%d' % (memory), '--disk', disk_args, '--cdrom=/dev/zero'])

                for s in virtinst_search:
                    result = "Could not find '%s' in:\n" % s
                    self.assertTrue(s in report, result + report)
                time.sleep(3)

                # Verify the storage was created
                self.assertTrue(os.path.exists(disk), "Could not find '%s'" % disk)

                print " dumpxml %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'dumpxml', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))
                for s in dumpxml_search:
                    result = "Could not find '%s' in:\n" % s
                    self.assertTrue(re.search(s, report), result + report)

                print " destroy %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'destroy', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))

                print " undefine %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'undefine', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))

    def test_virt_install_location(self):
        '''Test virt-install --location'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("TODO: fix test on '%s'" % (self.lsb_release['Release']))

        # We aren't going to do a full install here, but we are going to
        # try out virt-install and make sure it did a few things right
        memory = 64
        location = "http://archive.ubuntu.com/ubuntu/dists/xenial/main/installer-i386/"
        connect_uri = ''

        # libvirt runs as libvirt-qemu:kvm in maverick and later
        if self.lsb_release['Release'] > 10.04:
            os.chmod(self.tmpdir, 0770)
            subprocess.call(['chgrp', 'kvm', self.tmpdir])

        print ""
        for install_type in ['file', 'pool']:
            disk = ""
            disk_args = ""

            virtinst_path = "/var/lib/libvirt/boot"
            if install_type == 'pool':
                r = self.lsb_release['Release']
                if r >= 11.10 and r <= 14.04:
                    virtinst_path = "%s/.virtinst/boot" % os.environ["HOME"]
                elif r > 14.04:
                    virtinst_path = "%s/.cache/virt-manager/boot" % os.environ["HOME"]

            virtinst_search = ['Creating domain',
                               'Retrieving file linux',
                               'Retrieving file initrd']
            if self.lsb_release['Release'] < 16.04:
                virtinst_search += ['Retrieving file MANIFEST']

            dumpxml_search = [self.vm_virtinst_name,
                              '''<memory( unit='KiB')?>%d</memory>''' % (memory * 1024),
                              '<kernel>%s/virtinst-linux' % virtinst_path,
                              '<initrd>%s/virtinst-initrd' % virtinst_path,
                              '<cmdline>method=%s' % location]

            if install_type == 'file':
                disk = os.path.join(self.tmpdir, "%s.img" % (self.vm_virtinst_name))
                disk_args = 'path=%s,size=.01' % (disk)
                connect_uri = 'qemu:///system'
            else:
                if self.lsb_release['Release'] < 9.04:
                    self._skipped("< 9.04 does not support storage pools")
                    continue

                connect_uri = 'qemu:///session'
                pool_name = self.pool_name
                pool_name = "%s-session" % (self.pool_name)
                pool_dir = "%s-session" % (self.pool_dir)
                pool_uuid = "4a458219-9b8b-2af0-77b8-adebf563f5fb"

                print " setting up %s for %s (%s)" % (os.path.basename(pool_dir), self.vm_virtinst_name, connect_uri)
                self._setup_storage_pool(pool_name, pool_dir, pool_uuid, connect_uri)

                if self.lsb_release['Release'] > 14.04:
                    disk = os.path.join(pool_dir, "%s.qcow2" % (self.vm_virtinst_name))
                else:
                    disk = os.path.join(pool_dir, "%s.img" % (self.vm_virtinst_name))
                disk_args = 'pool=%s,size=.01,format=qcow2' % (pool_name)
                dumpxml_search.append("<driver name='qemu' type='qcow2'")

            dumpxml_search.append(" file='%s'" % (disk))

            if self.lsb_release['Release'] > 14.04:
                dname = os.environ['HOME']
                for d in [ "/.cache", "/virt-manager", "/boot" ]:
                    dname += d
                    try:
                        os.mkdir(dname)
                    except os.error, e:
                        if e.errno != errno.EEXIST:
                            raise
                    os.chmod(dname, 0755)

            print " virt-install %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
            print " (downloading from %s)" % location
            rc, report = testlib.cmd(['virt-install', '--connect=%s' % connect_uri, '--wait=0', '--force', '--name', self.vm_virtinst_name, '--ram=%d' % (memory), '--disk', disk_args, '--location=%s' % (location)])

            for s in virtinst_search:
                result = "Could not find '%s' in:\n" % s
                self.assertTrue(s in report, result + report)
            time.sleep(3)

            # Verify the storage was created
            self.assertTrue(os.path.exists(disk), "Could not find '%s'" % disk)

            print " dumpxml %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
            rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'dumpxml', self.vm_virtinst_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))
            for s in dumpxml_search:
                result = "Could not find '%s' in:\n" % s
                self.assertTrue(re.search(s, report), result + report)

            print " destroy %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
            rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'destroy', self.vm_virtinst_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))

            print " undefine %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, install_type)
            rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'undefine', self.vm_virtinst_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + str(report))

    def test_virt_install_import(self):
        '''Test virt-install --import'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("TODO: fix test on '%s'" % (self.lsb_release['Release']))

        # We aren't going to do a full install here, but we are going to
        # try out virt-install and make sure it did a few things right
        memory = 64

        # libvirt runs as libvirt-qemu:kvm in maverick and later
        if self.lsb_release['Release'] > 10.04:
            os.chmod(self.tmpdir, 0770)
            subprocess.call(['chgrp', 'kvm', self.tmpdir])

        print ""
        for connect_uri in [ 'qemu:///system', 'qemu:///session' ]:
            for disk_type in ['raw', 'qcow2']:
                disk = os.path.join(os.getcwd(), self.vmimg)
                disk_extra_args = ""
                if disk_type == 'qcow2':
                    disk = os.path.join(os.getcwd(), self.vmpristine)
                    if self.lsb_release['Release'] >= 10.04:
                        # Karmic and earlier do not support --import with
                        # 'format='. Lucid and later add it for
                        # CVE-2010-223[7-9]
                        disk_extra_args = ",format=%s" % disk_type

                virtinst_search = []
                if self.lsb_release['Release'] < 11.04:
                    virtinst_search.append('Guest installation complete')
                    virtinst_search.append('restarting guest')
                else:
                    virtinst_search.append('Domain creation completed')

                dumpxml_search = [self.vm_virtinst_name,
                                  '''<memory( unit='KiB')?>%d</memory>''' % (memory * 1024),
                                  " file='%s'" % (disk)]

                if self.lsb_release['Release'] >= 10.04:
                    # Later versions of libvirt don't output "type='raw'"
                    if disk_type == 'raw' and self.lsb_release['Release'] < 11.04:
                        dumpxml_search.append("<driver name='qemu' type='%s'" % disk_type)

                print " virt-install %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, disk_type)
                rc, report = testlib.cmd(['virt-install', '--connect=%s' % connect_uri, '--wait=0', '--force', '--name', self.vm_virtinst_name, '--ram=%d' % (memory), '--disk', "%s%s" % (disk, disk_extra_args), '--import'])

                for s in virtinst_search:
                    result = "Could not find '%s' in:\n" % s
                    self.assertTrue(s in report, result + report)
                time.sleep(3)

                print " dumpxml %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, disk_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'dumpxml', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))
                for s in dumpxml_search:
                    result = "Could not find '%s' in:\n" % s
                    self.assertTrue(re.search(s, report), result + report)

                print " destroy %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, disk_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'destroy', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))

                print " undefine %s (%s, %s)" % (self.vm_virtinst_name, connect_uri, disk_type)
                rc, report = testlib.cmd(['virsh', '-c', connect_uri, 'undefine', self.vm_virtinst_name])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))


class LibvirtTestMigrate(LibvirtTestCommon):
    '''Tests for libvirt migrate functionality'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    # Note that in order for this to work to a remote host, we must obviously
    # set up passwordless ssh keys
    def test_migrate(self):
        '''Test migrate functions'''

        global remotemachine
        global copy_image

        if self.lsb_release['Release'] < 9.04:
            return self._skipped("< 9.04 not supported")

        self._define_vm(self.connect_uri, self.vm_name, self.vmxml)
        self._start_vm(self.connect_uri, self.vm_name)

        #remotemachine = "localhost"  # XXX gotta find a way to pass this in ???
        print "remotemachine is " + remotemachine
        if remotemachine == '':
            remotemachine = "localhost"

        if copy_image and remotemachine != 'localhost' and remotemachine != '127.0.0.1':
            fname=os.path.join(os.getcwd(), self.vmimg)
            dirname=os.path.dirname(fname)
            rc, report = testlib.cmd(['ssh', 'root@%s' % remotemachine, 'mkdir', '-p', dirname])
            self.assertEquals(rc, 0, 'Error creating dirname %s on remote host %s' % (dirname, remotemachine))
            rc, report = testlib.cmd(['scp', self.vmimg, 'root@%s:%s' % (remotemachine, fname)])
            self.assertEquals(rc, 0, 'Error copying %s to host %s' % (self.vmimg, remotemachine))

        remote = "qemu+ssh://%s/session" % remotemachine
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'migrate', '--live', self.vm_name, remote])
        # now, how do we test whether it's there?
        if remotemachine != 'localhost' and remotemachine != '127.0.0.1':
            expected=0
        else:
            expected=1

        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'list'])
        self.assertEquals(rc, expected, 'Expected %d running vms, found %d' % (expected, rc))

        if expected == 1:
            self._destroy_vm(self.connect_uri, self.vm_name)
        else:
            # make sure it's running on the remote machine, then erase it
            cmd = ['ssh', remotemachine, '--', 'virsh', 'list', '|', 'grep', self.vm_name]
            rc,report = testlib.cmd(cmd)
            self.assertEquals(rc, 0, 'Machine not properly running after migration')
            testlib.cmd(['ssh', remotemachine, 'virsh', 'destroy', self.vm_name])


class LibvirtTestVirshCommon(LibvirtTestCommonWithAbort):
    '''Common functionality for virsh tests'''
    def _setUp(self, uri, user, group, skip_apparmor):
        '''Generic test setup'''
        global qemu_savetmpdir

        self.kvm_user = user
        self.kvm_group = group
        self.qemu_uri = uri
        self.skip_apparmor = skip_apparmor
        self.usb = None
        self.remote = None
        self.vm_uuid = ""

        LibvirtTestCommon._setUp(self)

        self.clear_qemuconf = False
        self.undefine_qemu = False
        self.reinstate_apparmor = False

        if qemu_savetmpdir:
            self.qemu_saved_state = os.path.join(qemu_savetmpdir, "state")

        self.qemu_tmpdir = tempfile.mkdtemp(dir='/tmp')
        self.qemu_origxml = os.path.join(self.qemu_tmpdir, "orig.xml")
        xml = re.sub("pc-[0-9.]*", "pc", re.sub('\n', '', open(self.vmxml).read()))
        open(self.qemu_origxml, 'w').write(xml)

        self.qemu_xml = os.path.join(self.qemu_tmpdir, "vm.xml")

        if self.qemu_uri == "qemu:///session":
            # strip out the network line from qemu:///session
            xml = re.sub("<interface type='network'>.*</interface>", "", re.sub('\n', '', open(self.qemu_origxml).read()))
            open(self.qemu_xml, 'w').write(xml)
        else:
            shutil.copy(self.qemu_origxml, self.qemu_xml)

        if qemu_user != None:
            # if the vm is defined, then get the domuuid
            rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s dumpxml %s' % (qemu_user.login, self.qemu_uri, self.vm_name)])
            if rc == 0:
                rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, self.vm_name)])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                self.vm_uuid = report.splitlines()[0].strip()
                if self.lsb_release['Release'] < 10.04:
                    self.vm_uuid = report.splitlines()[1].strip()

            testlib.cmd(['chown', '-R', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.qemu_tmpdir])
            os.chmod(self.qemu_tmpdir,0770)

        self.logfile = "/var/log/kern.log"
        if os.path.exists("/var/log/audit/audit.log"):
            self.logfile = "/var/log/audit/audit.log"

    def _tearDown(self):
        '''Tear down method'''
        global abort_tests
        global qemu_user
        if abort_tests:
            print >>sys.stderr, "Aborting to avoid VM corruption"
            self._cleanup()
            self.clear_qemuconf = True
            qemu_user = None
            self.reinstate_apparmor = True

        if os.path.exists(self.qemu_tmpdir):
            testlib.recursive_rm(self.qemu_tmpdir)

        LibvirtTestCommon._tearDown(self)

    def _cleanup(self, vm_name=None):
        '''After test cleanup'''
        global qemu_user
        global qemu_savetmpdir
        if vm_name == None:
            vm_name = self.vm_name

        if qemu_user:
            testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s destroy %s' % (qemu_user.login, self.qemu_uri, vm_name)])
            if self.qemu_uri == 'qemu:///system' or self.qemu_uri == 'qemu:///session':
                disk = self._get_first_disk(self.qemu_uri, vm_name)

            testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s undefine %s' % (qemu_user.login, self.qemu_uri, vm_name)])

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        if os.path.exists(aa_files):
            os.unlink(aa_files)

        if qemu_savetmpdir and os.path.exists(qemu_savetmpdir):
            testlib.recursive_rm(qemu_savetmpdir)

    def _get_first_disk(self, uri, vm_name):
        '''Find the first disk in the VM'''
        global qemu_user
        rc, xml = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s dumpxml %s' % (qemu_user.login, uri, self.vm_name)])
        if rc != 0:
            return ""

        in_disk = False
        disk = ''
        for line in xml.splitlines():
            if re.search('^ *<disk ', line):
                in_disk = True
                continue
            elif in_disk:
                if re.search('^ *<source file=', line):
                    disk = line.split("'")[1]
                    break
        self.assertFalse(disk == '', "Could not find first disk")
        return disk

    def _get_first_disk_device(self, uri, vm_name):
        '''Find the first disk device in the VM'''
        global qemu_user
        rc, xml = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s dumpxml %s' % (qemu_user.login, uri, self.vm_name)])
        if rc != 0:
            return ""

        in_disk = False
        device = ''
        for line in xml.splitlines():
            if re.search('^ *<disk ', line):
                in_disk = True
                continue
            elif in_disk:
                if re.search('^ *<target dev=', line):
                    device = line.split("'")[1]
                    break
        self.assertFalse(device == '', "Could not find first disk device")
        return device

    def _get_first_net_device(self, uri, vm_name):
        '''Find the first disk device in the VM'''
        global qemu_user
        rc, xml = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s dumpxml %s' % (qemu_user.login, uri, self.vm_name)])
        if rc != 0:
            return ""

        in_interface = False
        device = ''
        for line in xml.splitlines():
            if re.search('^ *<interface ', line):
                in_interface = True
                continue
            elif in_interface:
                if re.search('^ *<target dev=', line):
                    device = line.split("'")[1]
                    break
        if self.qemu_uri != "qemu:///session":
            self.assertFalse(device == '', "Could not find first net device")
        return device

    def _run_virsh_cmd(self, connect_uri, args, search, invert=False, user=None, expected=0):
        '''Run virsh command and search for string'''
        debug = False

        if not user:
            global qemu_user
            user = qemu_user

        if debug:
            print "%s" % (" ".join(['su', '-c', 'sudo -H -u %s virsh -c %s %s' % (user.login, connect_uri, args)]))

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s %s' % (user.login, connect_uri, args)])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        if search != None:
            # 9.10 and lower are noisy and have 'Connecting to qemu:///' as the
            # first line. Get rid of that when searching.
            if self.lsb_release['Release'] < 10.04:
                report = "\n".join(report.splitlines()[1:])

            if invert:
                result = "Found '%s'\n" % (search)
                self.assertTrue(re.search(r'%s' % search, report) == None, result + str(report))
            else:
                result = "Could not find '%s'\n" % search
                self.assertTrue(re.search(r'%s' % search, report) != None, result + str(report))

        if debug:
            print report,

        return report

    def _get_aa_status(self):
        '''Get aa-status output'''
        rc, report = testlib.cmd(['aa-status'])
        return rc, report

    def _uuid_profile_is_loaded(self, uuid):
        '''Check if profile for uuid is loaded'''
        rc, report = self._get_aa_status()
        if rc != 0:
            return False

        for line in report.splitlines():
            if re.search('%s \(' % uuid, line):
                return True
        return False

    def _uuid_is_confined(self, vm_uuid=None):
        '''Check if profile for uuid is loaded'''
        if self.skip_apparmor == True:
            return True

        if vm_uuid == None:
            vm_uuid = self.vm_uuid

        return self._uuid_profile_is_loaded(vm_uuid)

    def _vm_is_confined(self, vm_name=None):
        '''Check if VM is confined'''
        global qemu_user
        if vm_name == None:
            vm_name = self.vm_name
            vm_uuid = self.vm_uuid
        else:
            rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, vm_name)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            vm_uuid = report.splitlines()[0].strip()
            if self.lsb_release['Release'] < 10.04:
                vm_uuid = report.splitlines()[1].strip()

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s dominfo %s' % (qemu_user.login, self.qemu_uri, vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for line in report.splitlines():
            if re.search(r' libvirt-%s \(' % (vm_uuid), line):
                return True
        return False

    def _adjust_perms(self, user, path):
        '''Adjust permissions for path'''
        #if not self.skip_apparmor:
        #    return
        if user == 'default':
            if self.lsb_release['Release'] < 10.10:
                user = "root:root"
            else:
                user = "libvirt-qemu:kvm"

        self.assertTrue(os.path.exists(path), "Could not find %s" % path)

        if os.path.isdir(path):
            testlib.cmd(['chown', '-R', user, path])
        else:
            testlib.cmd(['chown', user, path])
        os.chmod(self.qemu_tmpdir,0775)

    def _virsh_cmd_and_check(self, args, check_aa_files=False, tail=False, invert=False, fn=""):
        '''Helper'''
        self._run_virsh_cmd(self.qemu_uri, args, None)
        time.sleep(3)
        if self.skip_apparmor:
            return

        self.assertTrue(self._uuid_is_confined(), "VM is unconfined")

        if check_aa_files or tail:
            aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
            self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

            if fn == "":
                return

            contents = open(aa_files).read()
            if invert:
                self.assertFalse(fn in contents, "Found '%s' in '%s'"% (fn, aa_files))
            else:
                self.assertTrue(fn in contents, "Could not find '%s' in '%s'"% (fn, aa_files))

            if tail:
                # yuck
                rc, report = testlib.cmd(['tail', '-1', self.logfile])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                if invert:
                    self.assertTrue(fn in report, "Could not find '%s' denial in '%s'"% (fn, report))
                else:
                    self.assertFalse(fn in report, "Found '%s' denial in '%s'"% (fn, report))

    def _define_and_start_guest(self):
        '''Start guest VM'''
        global qemu_user
        self._adjust_perms("%s:%s" % (self.kvm_user, self.kvm_group), self.qemu_tmpdir)

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s define %s' % (qemu_user.login, self.qemu_uri, self.qemu_xml)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s list --all' % (qemu_user.login, self.qemu_uri)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Could not find '%s'\n" % self.vm_name
        abort_tests = True
        self.assertTrue(self.vm_name in report, result + str(report))
        abort_tests = False

        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "start %s" % self.vm_name, "started")
        abort_tests = False

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, self.vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.vm_uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            self.vm_uuid = report.splitlines()[1].strip()

    def test_aa_initialize(self):
        '''Test initialization'''
        global abort_tests
        global qemu_user
        global qemu_savetmpdir

        print "(%s:%s, %s, apparmor=%s) ... " % (self.kvm_user, self.kvm_group, self.qemu_uri, str(not self.skip_apparmor)),
        sys.stdout.flush()

        if qemu_user == None:
            if self.lsb_release['Release'] < 16.10:
                grp="libvirtd"
            else:
                grp="libvirt"
            qemu_user = testlib.TestUser(group=grp)

        testlib.config_replace('/etc/sudoers', '%s ALL=(root) NOPASSWD: ALL' % qemu_user.login, True)
        os.chmod('/etc/sudoers',0440)

        testlib.cmd(['chown', '-R', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.qemu_tmpdir])
        os.chmod(self.qemu_tmpdir,0770)

        qemu_savetmpdir = tempfile.mkdtemp(dir='/tmp')
        testlib.cmd(['chown', '-R', "%s:%s" % (qemu_user.uid, qemu_user.gid), qemu_savetmpdir])
        os.chmod(qemu_savetmpdir,0755)

        if self.skip_apparmor:
            rc, report = testlib.cmd(['apparmor_parser', '-R', '/etc/apparmor.d/usr.sbin.libvirtd'])
        else:
            rc, report = testlib.cmd(['apparmor_parser', '-r', '/etc/apparmor.d/usr.sbin.libvirtd'])
            expected = 0
            result = "apparmor_parser exited with error"
            self.assertEquals(expected, rc, result + report)

        if self.kvm_user != "default":
            # This also restarts the daemon
            self._update_config(self.qemuconf, ['user = "%s"' % self.kvm_user, 'group = "%s"' % self.kvm_group])
        else:
            # Need this for skip_apparmor changes
            self._restart_daemon()

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s define %s' % (qemu_user.login, self.qemu_uri, self.qemu_xml)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s list --all' % (qemu_user.login, self.qemu_uri)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Could not find '%s'\n" % self.vm_name
        abort_tests = True
        self.assertTrue(self.vm_name in report, result + str(report))
        abort_tests = False

    def test_zzzz_teardown_once(self):
        '''Test de-initialization'''
        global qemu_user
        global qemu_savetmpdir
        if qemu_user:
            testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s destroy %s' % (qemu_user.login, self.qemu_uri, self.vm_name)])
            testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s undefine %s' % (qemu_user.login, self.qemu_uri, self.vm_name)])

        self.clear_qemuconf = True
        self.reinstate_apparmor = True
        qemu_user = None

        if qemu_savetmpdir and os.path.exists(qemu_savetmpdir):
            testlib.recursive_rm(qemu_savetmpdir)

class LibvirtTestVirsh(LibvirtTestVirshCommon):
    '''Tests for qemu:///* functionality with virsh'''
    def _setUp(self, uri, user, group, skip_apparmor=True):
        '''Setup'''
        LibvirtTestVirshCommon._setUp(self, uri, user, group, skip_apparmor)

    def _tearDown(self):
        '''Tear down'''
        LibvirtTestVirshCommon._tearDown(self)

    def test_aaaa_domuuid(self):
        '''Test domuuid'''
        report = self._run_virsh_cmd(self.qemu_uri, "domuuid %s" % self.vm_name, self.vm_uuid)

    def test_abaa_domname(self):
        '''Test domname'''
        self._run_virsh_cmd(self.qemu_uri, "domname %s" % self.vm_uuid, self.vm_name)

    def test_acaa_nodeinfo(self):
        '''Test nodeinfo'''
        self._run_virsh_cmd(self.qemu_uri, "nodeinfo", 'CPU model')

    def test_adaa_hostname(self):
        '''Test hostname'''
        self._run_virsh_cmd(self.qemu_uri, "hostname", '^[a-zA-Z0-9]')

    def test_aeaa_uri(self):
        '''Test uri'''
        self._run_virsh_cmd(self.qemu_uri, "uri", self.qemu_uri)

    def test_afaa_version(self):
        '''Test version'''
        self._run_virsh_cmd(self.qemu_uri, "version", 'libvir')

    def test_agaa_list(self):
        '''Test list'''
        self._run_virsh_cmd(self.qemu_uri, "list", 'Id[ \t]*Name')

    def test_agab_list_all(self):
        '''Test list --all'''
        self._run_virsh_cmd(self.qemu_uri, "list --all", self.vm_name)

    def test_ahaa_capabilities(self):
        '''Test capabilities'''
        invert = self.skip_apparmor
        if self.qemu_uri == "qemu:///session":
            invert = True
        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s %s' % (qemu_user.login, self.qemu_uri, "capabilities")])
        if self.lsb_release['Release'] < 10.04:
            report = "\n".join(report.splitlines()[1:])
        if invert:
            result = "Found a non-dac secmodel\n"
            self.assertTrue(checksecmodel(report) == False, result + str(report))
        else:
            result = "Could not find a non-dac secmodel\n"
            self.assertTrue(checksecmodel(report), result + str(report))

    def test_ahab_maxvcpus(self):
        '''Test maxvcpus'''
        if self.lsb_release['Release'] < 11.04:
            return self._skipped("not present before 11.04")
        report = self._run_virsh_cmd(self.qemu_uri, "maxvcpus", search=None)
        result = "Does not start with a number:\n"
        self.assertTrue(re.search(r'^[0-9]', report), result + report)

        report = self._run_virsh_cmd(self.qemu_uri, "--readonly maxvcpus", search=None)
        result = "Does not start with a number:\n"
        self.assertTrue(re.search(r'^[0-9]', report), result + report)

    def test_aiaa_define(self):
        '''Test define'''
        self._run_virsh_cmd(self.qemu_uri, "define %s" % self.qemu_xml, "defined from")

    def test_aiab_readonly(self):
        '''Test define (readonly)'''
        self._run_virsh_cmd(self.qemu_uri, "-r define %s" % self.qemu_xml, "forbidden", expected=1)

    def test_ajaa_autostart(self):
        '''Test autostart'''
        self._run_virsh_cmd(self.qemu_uri, "autostart %s" % self.vm_name, "%s marked as autostarted" % self.vm_name)

    def test_ajab_autostart(self):
        '''Test autostart --disable'''
        self._run_virsh_cmd(self.qemu_uri, "autostart --disable %s" % self.vm_name, "%s unmarked as autostarted" % self.vm_name)
        # libvirt starts on autostart, doesn't stop on un-autostart
        if self.lsb_release['Release'] > 14.10:
            testlib.cmd(['virsh', '-c', self.qemu_uri, 'destroy', self.vm_name])

    def test_akaa_domstate_shutoff(self):
        '''Test domstate (shut off)'''
        self._run_virsh_cmd(self.qemu_uri, "domstate %s" % self.vm_name, "shut off")

    def test_alaa_setmem(self):
        '''Test setmem'''
        return self._skipped("TODO")

    def test_alba_setmaxmem(self):
        '''Test setmem'''
        return self._skipped("TODO")

    def test_alca_start(self):
        '''Test vcpus (setup)'''
        # Only maverick needs the domain started for this test
        if self.lsb_release['Release'] != 10.10:
            return

        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "start %s" % self.vm_name, "started")
        abort_tests = False

    def test_alcb_setvcpus(self):
        '''Test vcpus'''
        # get our previous CPUs
        report = self._run_virsh_cmd(self.qemu_uri, "dominfo %s" % self.vm_name, "\nCPU\(s\):")

        prev_cpus = None
        cpus = 3
        for line in report.splitlines():
            if line.startswith("CPU(s):"):
                prev_cpus = line.split()[1]
                if prev_cpus == cpus:
                    cpus += 1
                break

        # change the vcpus
        if self.lsb_release['Release'] < 11.04:
            self._run_virsh_cmd(self.qemu_uri, "setvcpus %s %d" % (self.vm_name, cpus), search=None)
        else:
            self._run_virsh_cmd(self.qemu_uri, "setvcpus %s %d --config --maximum" % (self.vm_name, cpus), search=None)
            self._run_virsh_cmd(self.qemu_uri, "setvcpus %s %d --config" % (self.vm_name, cpus), search=None)

        # get our new CPUs
        report = self._run_virsh_cmd(self.qemu_uri, "dominfo %s" % self.vm_name, "\nCPU\(s\):")

        cur_cpus = None
        for line in report.splitlines():
            if line.startswith("CPU(s):"):
                cur_cpus = line.split()[1]
                break

        result = 'Got vcpus %s, expected %d\n' % (cur_cpus, cpus)
        self.assertEquals(int(cur_cpus), cpus, result + report)

    def test_alcz_cleanup(self):
        '''Test vcpus (cleanup)'''
        # Only maverick needs the domain started for this test
        if self.lsb_release['Release'] != 10.10:
            return

        self._run_virsh_cmd(self.qemu_uri, "destroy %s" % self.vm_name, "destroyed")

    def test_amaa_start(self):
        '''Test start'''
        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "start %s" % self.vm_name, "started")
        abort_tests = False

    def test_amba_dumpxml(self):
        '''Test dumpxml'''
        self._run_virsh_cmd(self.qemu_uri, "dumpxml %s" % self.vm_name, "apparmor", self.skip_apparmor)

    def test_amca_domid(self):
        '''Test domid'''
        self._run_virsh_cmd(self.qemu_uri, "domid %s" % self.vm_name, "^[0-9]")

    def test_amda_domblkstat(self):
        '''Test domblkstat'''
        disk = self._get_first_disk_device(self.qemu_uri, self.vm_name)
        self._run_virsh_cmd(self.qemu_uri, "domblkstat %s %s" % (self.vm_name, disk), disk)

    def test_amea_domifstat(self):
        '''Test domifstat'''
        interface = self._get_first_net_device(self.qemu_uri, self.vm_name)
        if interface == "":
            return self._skipped("(no net device found)")
        self._run_virsh_cmd(self.qemu_uri, "domifstat %s %s" % (self.vm_name, interface), interface)

    def test_amfa_vcpuinfo(self):
        '''Test vcpuinfo'''
        if self.lsb_release['Release'] > 14.10:
            return self._skipped("vcpuinfo on tcg invalid as of 15.04")

        self._run_virsh_cmd(self.qemu_uri, "vcpuinfo %s" % self.vm_name, 'VCPU:')

    def test_amga_vcpupin(self):
        '''Test vcpupin'''
        global qemu_user
        if self.lsb_release['Release'] > 14.10:
            return self._skipped("support for vcpu pinning in TCG was dropped")
        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s vcpupin %s 0 0' % (qemu_user.login, self.qemu_uri, self.vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

    def test_amha_suspend(self):
        '''Test suspend'''
        self._run_virsh_cmd(self.qemu_uri, "suspend %s" % self.vm_name, "suspended")

    def test_amia_domstate_paused(self):
        '''Test domstate (paused)'''
        self._run_virsh_cmd(self.qemu_uri, "domstate %s" % self.vm_name, "paused")

    def test_amja_resume(self):
        '''Test resume'''
        self._run_virsh_cmd(self.qemu_uri, "resume %s" % self.vm_name, "resumed")

    def test_amka_domstate_running(self):
        '''Test domstate (running)'''
        self._run_virsh_cmd(self.qemu_uri, "domstate %s" % self.vm_name, "running")

    def test_anaa_save(self):
        '''Test save'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "save %s %s" % (self.vm_name, self.qemu_saved_state), "saved to")
        abort_tests = False
        self.assertTrue(os.path.exists(self.qemu_saved_state), "Could not find %s" % self.qemu_saved_state)

    def test_anba_domstate_shutoff_save(self):
        '''Test domstate (shut off after save)'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        self._run_virsh_cmd(self.qemu_uri, "domstate %s" % self.vm_name, "shut off")

    def test_anca_restore(self):
        '''Test restore'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        self.assertTrue(os.path.exists(self.qemu_saved_state), "Could not find %s" % self.qemu_saved_state)
        self._run_virsh_cmd(self.qemu_uri, "restore %s" % self.qemu_saved_state, "restored from")

    def test_anda_domstate_running_restore(self):
        '''Test domstate (running after restore)'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        self._run_virsh_cmd(self.qemu_uri, "domstate %s" % self.vm_name, "running")

    def test_aoaa_destroy(self):
        '''Test destroy'''
        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "destroy %s" % self.vm_name, "destroyed")
        abort_tests = False

    def test_azaa_cleanup(self):
        '''Cleanup'''
        self._cleanup()

    def test_baaa_create(self):
        '''Test create'''
        global abort_tests
        create_name = "test-libvirt-create"
        create_uuid = ""

        subprocess.call(['sed', '-i', "s#<interface type='network'>.*</interface>##g", self.qemu_xml])
        subprocess.call(['sed', '-i', "s,<name>.*</name>,<name>%s</name>,g" % create_name, self.qemu_xml])
        subprocess.call(['sed', '-i', "s,<uuid>.*</uuid>,,g", self.qemu_xml])

        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "create %s" % self.qemu_xml, "created")
        abort_tests = False

        time.sleep(3)

    def test_bbaa_destroy_created(self):
        '''Test destroy on created VM'''
        global abort_tests
        create_name = "test-libvirt-create"
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "destroy %s" % create_name, "destroyed")
        abort_tests = False

    def test_bzaa_cleanup(self):
        '''Cleanup create tests'''
        self._cleanup("test-libvirt-create")

# These test are only known to work with qemu:///system
class LibvirtTestVirshGuest(LibvirtTestVirshCommon):
    '''Tests for qemu:///* functionality for guests'''
    def _setUp(self, uri, user, group, skip_apparmor=True):
        '''Setup'''
        LibvirtTestVirshCommon._setUp(self, uri, user, group, skip_apparmor)

    def _tearDown(self):
        '''Tear down'''
        LibvirtTestVirshCommon._tearDown(self)

    def test_guest_aa_attach_detach_physical(self):
        '''Test attach/detach physical'''
        device_disk = os.path.join(self.qemu_tmpdir, "device_disk.img")
        rc, report = testlib.cmd(['dd', 'if=/dev/zero', 'of=%s' % device_disk, 'bs=1M', 'count=64'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        driver = 'phy'
        if self.lsb_release['Release'] > 11.04:
            # libvirt 0.9 requires this
            driver = 'qemu'

        device_xml = os.path.join(self.qemu_tmpdir, "device.xml")
        xml = '''<disk type='block'>
  <driver name='%s'/>
  <source dev='%s'/>
  <target dev='sdb'/>
</disk>''' % (driver, device_disk)
        open(device_xml, 'w').write(xml)

        print ""
        print "  start VM (and sleeping 30 seconds for LP: #435527)"
        self._define_and_start_guest()
        time.sleep(30)

        new_mac = "52:00:00:00:00:00"
        if self.lsb_release['Release'] == 10.10:
            print "  attach-interface: (skipped on 10.10)"
        else:
            print "  attach-interface"
            self._run_virsh_cmd(self.qemu_uri, "attach-interface %s network default --mac %s" % (self.vm_name, new_mac), None)
            print "  detach-interface"
            self._run_virsh_cmd(self.qemu_uri, "detach-interface %s network --mac %s" % (self.vm_name, new_mac), None)

        print "  attach-device (physical)"
        self._virsh_cmd_and_check("attach-device %s %s" % (self.vm_name, device_xml), check_aa_files=True, tail=True, fn=device_disk)
        if self.lsb_release['Release'] >= 10.10:
            # cannot hot unplug physical block device with qemu in 0.7.7 and higher
            print "  detach-device (physical): (skipped on 10.10 and higher)"
        else:
            print "  detach-device (physical)"
            self._virsh_cmd_and_check("detach-device %s %s" % (self.vm_name, device_xml), check_aa_files=True, invert=True, fn=device_disk)

        print "  attach-disk (physical)"
        driver = "file"
        if self.lsb_release['Release'] > 11.04:
            # libvirt 0.9 requires this
            driver = 'qemu'
        self._virsh_cmd_and_check("attach-disk %s %s sdc --driver=%s" % (self.vm_name, device_disk, driver), check_aa_files=True, tail=True, fn=device_disk)
        if self.lsb_release['Release'] >= 10.10:
            # cannot hot unplug scsi device with qemu in 0.7.7 and higher
            print "  detach-disk (physical): (skipped on 10.10 and higher)"
        else:
            print "  detach-disk (physical)"
            self._virsh_cmd_and_check("detach-disk %s sdc" % (self.vm_name), check_aa_files=True, invert=True, fn=device_disk)

    def test_guest_az_attach_detach_physical(self):
        '''Cleanup attach/detach physical tests'''
        self._cleanup()

    def test_guest_ba_attach_detach_usb(self):
        '''Test attach/detach USB'''
        return self._skipped("TODO")
        self._define_and_start_guest()

    def test_guest_bz_attach_detach_usb(self):
        '''Cleanup attach/detach USB tests'''
        self._cleanup()

    def test_guest_cb_attach_detach_virtio(self):
        '''Test attach/detach virtio'''
        device_disk = os.path.join(self.qemu_tmpdir, "device_disk.img")
        rc, report = testlib.cmd(['dd', 'if=/dev/zero', 'of=%s' % device_disk, 'bs=1M', 'count=64'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        device_xml = os.path.join(self.qemu_tmpdir, "device.xml")
        xml = '''<disk type='file' device='disk'>
  <source file='%s'/>
  <target dev='vdb' bus='virtio'/>
</disk>''' % (device_disk)
        open(device_xml, 'w').write(xml)

        self._define_and_start_guest()

        print ""
        max_tries = 4
        for i in range(1, max_tries+1):
            print "  attach-device (virtio #%d)" % i
            self._virsh_cmd_and_check("attach-device %s %s" % (self.vm_name, device_xml), check_aa_files=True, tail=True, fn=device_disk)
            print "  detach-device (virtio #%d)" % i

            # For some reason, detaching the device doesn't remove the AA
            # rule in 13.10 and above
            check_aa = True
            if self.lsb_release['Release'] >= 13.10:
                check_aa = False

            self._virsh_cmd_and_check("detach-device %s %s" % (self.vm_name, device_xml), check_aa_files=check_aa, invert=True, fn=device_disk)

            # 0.8.5 and higher needs a restart of the vm otherwise get:
            # error: operation failed: adding
            # virtio-blk-pci,bus=pci.0,addr=0x5,drive=drive-virtio-disk1,id=virtio-disk1 device failed: Duplicate ID 'virtio-disk1' for device
            if self.lsb_release['Release'] >= 11.04 and i < max_tries:
                print "  (restarting and sleeping for 30 seconds)"
                self._run_virsh_cmd(self.qemu_uri, "destroy %s" % self.vm_name, "destroyed")
                abort_tests = True
                self._run_virsh_cmd(self.qemu_uri, "start %s" % self.vm_name, "started")
                abort_tests = False
                time.sleep(30)

    def test_guest_cz_attach_detach_virtio(self):
        '''Cleanup attach/detach virtio tests'''
        self._cleanup()

    def test_guest_da_attach_detach_aoe(self):
        '''Test attach/detach AoE'''
        if not os.path.isdir("/dev/etherd"):
            return self._skipped("Could not find '/dev/etherd'")

        tmp = glob.glob('/dev/etherd/e[0-9]*')
        tmp.sort()
        device_aoe = tmp[0]

        driver = 'virtio'
        if self.lsb_release['Release'] > 11.04:
            # libvirt 0.9 requires this
            driver = 'qemu'

        device_xml = os.path.join(self.qemu_tmpdir, "device.xml")
        xml = '''<disk type='block'>
  <driver name='%s'/>
  <source dev='%s'/>
  <target dev='vdb', bus='virtio'/>
</disk>''' % (driver, device_aoe)
        open(device_xml, 'w').write(xml)

        self._define_and_start_guest()

        print "  attach-device (AoE)"
        self._virsh_cmd_and_check("attach-device %s %s" % (self.vm_name, device_xml), check_aa_files=True, tail=True, fn=device_aoe)
        print "  detach-device (AoE)"
        # if fail here, might have hit https://launchpad.net/bugs/455832
        self._virsh_cmd_and_check("detach-device %s %s" % (self.vm_name, device_xml), check_aa_files=True, invert=True, fn=device_aoe)

    def test_guest_dz_attach_detach_aoe(self):
        '''Cleanup attach/detach AoE tests'''
        self._cleanup()

    def test_guest_ea_kernel(self):
        '''Test kernel and initrd'''
        kernel = "/vmlinuz"
        initrd = "/initrd.img"

        subprocess.call(['sed', '-i', "s#</os>#<kernel>%s</kernel><initrd>%s</initrd></os>#g" % (kernel, initrd), self.qemu_xml])

        self._define_and_start_guest()

        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(kernel in contents, "Could not find '%s' in '%s'"% (kernel, aa_files))
        self.assertTrue(initrd in contents, "Could not find '%s' in '%s'"% (initrd, aa_files))

    def test_guest_ez_kernel(self):
        '''Cleanup kernel and initrd'''
        self._cleanup()

    def test_guest_fa_serial(self):
        '''Test alternate serial'''
        serial = os.path.join(self.qemu_tmpdir, "serial.log")

        subprocess.call(['sed', '-i', "s#</devices>#<serial type='file'><source path='%s'/><target port='0'/></serial></devices>#g" % (serial), self.qemu_xml])

        self._define_and_start_guest()

        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(serial in contents, "Could not find '%s' in '%s'"% (serial, aa_files))
        self.assertTrue(os.path.exists(serial), "Could not find '%s'"% (serial))

    def test_guest_fz_serial(self):
        '''Cleanup alternate serial'''
        self._cleanup()

    def test_guest_ga_console(self):
        '''Test alternate console'''
        console = os.path.join(self.qemu_tmpdir, "console.log")

        subprocess.call(['sed', '-i', "s#</devices>#<console type='file'><source path='%s'/><target port='0'/></console></devices>#g" % (console), self.qemu_xml])

        self._define_and_start_guest()

        self.assertTrue(os.path.exists(console), "Could not find '%s'"% (console))
        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(console in contents, "Could not find '%s' in '%s'"% (console, aa_files))

    def test_guest_gb_console(self):
        '''Cleanup alternate console'''
        self._cleanup()

    def test_guest_gc_console_pipe(self):
        '''Test alternate console (pipe)'''
        # AppArmor blocks these on Natty and earlier (LP: #832507)
        if self.lsb_release['Release'] < 11.10:
            return self._skipped("LP: #832507")

        console = os.path.join(self.qemu_tmpdir, "console.pipe")
        pipe_in = "%s.in" % console
        pipe_out = "%s.out" % console

        subprocess.call(['sed', '-i', "s#</devices>#<console type='pipe'><source path='%s'/><target port='0'/></console></devices>#g" % (console), self.qemu_xml])

        # these must exist first
        for f in [pipe_in, pipe_out]:
            rc, report = testlib.cmd(['mkfifo', f])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(f), "Could not find '%s'"% (f))

        self._define_and_start_guest()

        self.assertTrue(os.path.exists(pipe_in), "Could not find '%s'"% (pipe_in))
        self.assertTrue(os.path.exists(pipe_out), "Could not find '%s'"% (pipe_out))
        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(pipe_in in contents, "Could not find '%s' in '%s'"% (pipe_in, aa_files))
        self.assertTrue(pipe_out in contents, "Could not find '%s' in '%s'"% (pipe_out, aa_files))

    def test_guest_gd_console(self):
        '''Cleanup alternate console (pipe)'''
        self._cleanup()

    def test_guest_ha_relative_path(self):
        '''Test relative path'''
        subprocess.call(['sed', '-i', "s#file='/#file='/./#", self.qemu_xml])

        self._define_and_start_guest()

        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

    def test_guest_hz_relative_path(self):
        '''Cleanup relative path'''
        self._cleanup()

    def test_guest_ia_space_path(self):
        '''Test space in path'''
        device_disk = os.path.join(self.qemu_tmpdir, "device with space.img")
        rc, report = testlib.cmd(['dd', 'if=/dev/zero', 'of=%s' % device_disk, 'bs=1M', 'count=64'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        subprocess.call(['sed', '-i', "s#file=.*\.img'/>#file='%s'/>#" % device_disk, self.qemu_xml])

        self._define_and_start_guest()

        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(device_disk in contents, "Could not find '%s' in '%s'"% (device_disk, aa_files))

    def test_guest_iz_space_path(self):
        '''Cleanup space in path'''
        self._cleanup()

    def test_guest_ja_symlink(self):
        '''Test symlink in path'''
        global qemu_user
        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s define %s' % (qemu_user.login, self.qemu_uri, self.qemu_xml)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s list --all' % (qemu_user.login, self.qemu_uri)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        result = "Could not find '%s'\n" % self.vm_name
        abort_tests = True
        self.assertTrue(self.vm_name in report, result + str(report))
        abort_tests = False

        disk = self._get_first_disk(self.qemu_uri, self.vm_name)
        symdisk = os.path.join(self.qemu_tmpdir, 'ln-s')

        rc, report = testlib.cmd(['ln', '-s', disk, symdisk])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        subprocess.call(['sed', '-i', "s#file=.*\.img'/>#file='%s'/>#" % symdisk, self.qemu_xml])

        self._define_and_start_guest()

        if self.skip_apparmor:
            return

        aa_files = "/etc/apparmor.d/libvirt/libvirt-%s.files" % (self.vm_uuid)
        self.assertTrue(os.path.exists(aa_files), "Could not find %s" % aa_files)

        contents = open(aa_files).read()
        self.assertTrue(disk in contents, "Could not find '%s' in '%s'"% (disk, aa_files))
        self.assertTrue(symdisk not in contents, "Found '%s' in '%s'"% (symdisk, aa_files))

    def test_guest_jz_symlink(self):
        '''Cleanup symlink in path'''
        self._cleanup()


class LibvirtTestVirshSystemRoot(LibvirtTestVirsh, LibvirtTestVirshGuest):
    '''Tests for qemu:///system functionality'''
    def setUp(self):
        '''Generic test setup'''
        LibvirtTestVirsh._setUp(self, "qemu:///system", "root", "root", skip_apparmor=True)

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)


class LibvirtTestVirshSystemNonRoot(LibvirtTestVirsh, LibvirtTestVirshGuest):
    '''Tests for qemu:///system functionality'''
    def setUp(self):
        '''Generic test setup'''
        LibvirtTestVirsh._setUp(self, "qemu:///system", "libvirt-qemu", "kvm", skip_apparmor=True)

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)


class LibvirtTestVirshSession(LibvirtTestVirsh):
    '''Tests for qemu:///session functionality'''
    def setUp(self):
        '''Generic test setup'''
        LibvirtTestVirsh._setUp(self, "qemu:///session", "default", "default", skip_apparmor=True)

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)
        testlib.cmd(['chown', "root:root", self.vmimg])

    # Overidden tests
    def test_alca_start(self):
        '''Test vcpus (setup)'''
        global qemu_user
        testlib.cmd(['chown', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.vmimg])
        LibvirtTestVirsh.test_alca_start(self)

    def test_amaa_start(self):
        '''Test start'''
        global qemu_user
        testlib.cmd(['chown', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.vmimg])
        LibvirtTestVirsh.test_amaa_start(self)

    def test_baaa_create(self):
        '''Test create'''
        global qemu_user
        testlib.cmd(['chown', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.vmimg])
        LibvirtTestVirsh.test_baaa_create(self)

    def test_anca_restore(self):
        '''Test restore'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        # needed cause of our tearDown()
        testlib.cmd(['chown', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.vmimg])

        self.assertTrue(os.path.exists(self.qemu_saved_state), "Could not find %s" % self.qemu_saved_state)
        self._run_virsh_cmd(self.qemu_uri, "restore %s" % self.qemu_saved_state, "restored from")

class LibvirtTestVirshAppArmor(LibvirtTestVirsh):
    '''Common methods for apparmor tests'''
    def test_amaa_start(self):
        '''Test start'''
        LibvirtTestVirsh.test_amaa_start(self)
        time.sleep(3)
        self.assertTrue(self._vm_is_confined(), "VM is not confined after start")
        self.assertTrue(self._uuid_profile_is_loaded(self.vm_uuid), "Profile is not loaded for %s" % self.vm_uuid)

    def test_aoaa_destroy(self):
        '''Test destroy'''
        LibvirtTestVirsh.test_aoaa_destroy(self)
        time.sleep(3)
        self.assertFalse(self._vm_is_confined(), "VM is confined after destroy")
        self.assertFalse(self._uuid_profile_is_loaded(self.vm_uuid), "Profile is loaded for %s" % self.vm_uuid)

    def test_baaa_create(self):
        '''Test create'''
        global qemu_user
        LibvirtTestVirsh.test_baaa_create(self)
        vm_name = "test-libvirt-create"
        time.sleep(3)
        self.assertTrue(self._vm_is_confined(vm_name), "VM is not confined after start")

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        vm_uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            vm_uuid = report.splitlines()[1].strip()
        self.assertTrue(self._uuid_profile_is_loaded(vm_uuid), "Profile is not loaded for %s" % vm_uuid)

    def test_bbaa_destroy_created(self):
        '''Test destroy on created VM'''
        global qemu_user
        vm_name = "test-libvirt-create"
        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        vm_uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            vm_uuid = report.splitlines()[1].strip()

        LibvirtTestVirsh.test_bbaa_destroy_created(self)
        time.sleep(3)
        # destroy after create undefines, so only check if loaded
        self.assertFalse(self._uuid_profile_is_loaded(vm_uuid), "Profile is loaded for %s" % vm_uuid)

    def test_anaa_save(self):
        '''Test save'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("LP: #457716")
        LibvirtTestVirsh.test_anaa_save(self)

    def test_anba_domstate_shutoff_save(self):
        '''Test domstate (shut off after save)'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("LP: #457716")
        LibvirtTestVirsh.test_anba_domstate_shutoff_save(self)

    def test_anca_restore(self):
        '''Test restore'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("LP: #457716")
        LibvirtTestVirsh.test_anca_restore(self)

    def test_anda_domstate_running_restore(self):
        '''Test domstate (running after restore)'''
        if self.lsb_release['Release'] == 11.04:
            return self._skipped("LP: #795366")
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("LP: #457716")
        LibvirtTestVirsh.test_anda_domstate_running_restore(self)


class LibvirtTestVirshSystemRootAppArmor(LibvirtTestVirshAppArmor, LibvirtTestVirshGuest):
    '''Tests for qemu:///system functionality with apparmor'''
    def setUp(self):
        '''Generic test setup'''
        LibvirtTestVirsh._setUp(self, "qemu:///system", "root", "root", skip_apparmor=False)

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)


class LibvirtTestVirshSystemNonRootAppArmor(LibvirtTestVirshAppArmor, LibvirtTestVirshGuest):
    '''Tests for qemu:///system functionality with apparmor'''
    def setUp(self):
        '''Generic test setup'''
        LibvirtTestVirsh._setUp(self, "qemu:///system", "libvirt-qemu", "kvm", skip_apparmor=False)

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)


class LibvirtTestVirshSessionAppArmor(LibvirtTestVirshAppArmor):
    '''Tests for qemu:///session functionality with apparmor'''
    def setUp(self):
        '''Generic test setup'''
        global qemu_user
        LibvirtTestVirsh._setUp(self, "qemu:///session", "default", "default", skip_apparmor=False)
        if qemu_user != None:
            testlib.cmd(['chown', "%s:%s" % (qemu_user.uid, qemu_user.gid), self.vmimg])

    def tearDown(self):
        '''Tear down method'''
        LibvirtTestVirsh._tearDown(self)
        testlib.cmd(['chown', "root:root", self.vmimg])

    # Overidden tests
    def test_amba_dumpxml(self):
        '''Test dumpxml'''
        self._run_virsh_cmd(self.qemu_uri, "dumpxml %s" % self.vm_name, "apparmor", invert=True)

    def test_amaa_start(self):
        '''Test start'''
        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "start %s" % self.vm_name, "started")
        abort_tests = False

        time.sleep(3)
        self.assertFalse(self._vm_is_confined(), "VM is confined after start")
        self.assertFalse(self._uuid_profile_is_loaded(self.vm_uuid), "Profile is loaded for %s" % self.vm_uuid)

    def test_aoaa_destroy(self):
        '''Test destroy'''
        global abort_tests
        abort_tests = True
        self._run_virsh_cmd(self.qemu_uri, "destroy %s" % self.vm_name, "destroyed")
        abort_tests = False

        time.sleep(3)
        self.assertFalse(self._vm_is_confined(), "VM is confined after destroy")
        self.assertFalse(self._uuid_profile_is_loaded(self.vm_uuid), "Profile is loaded for %s" % self.vm_uuid)

    def test_baaa_create(self):
        '''Test create'''
        global qemu_user
        LibvirtTestVirsh.test_baaa_create(self)
        vm_name = "test-libvirt-create"
        time.sleep(3)
        self.assertFalse(self._vm_is_confined(vm_name), "VM is confined after start")

        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        vm_uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            vm_uuid = report.splitlines()[1].strip()
        self.assertFalse(self._uuid_profile_is_loaded(vm_uuid), "Profile is loaded for %s" % vm_uuid)

    def test_bbaa_destroy_created(self):
        '''Test destroy on created VM'''
        global qemu_user
        vm_name = "test-libvirt-create"
        rc, report = testlib.cmd(['su', '-c', 'sudo -H -u %s virsh -c %s domuuid %s' % (qemu_user.login, self.qemu_uri, vm_name)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        vm_uuid = report.splitlines()[0].strip()
        if self.lsb_release['Release'] < 10.04:
            vm_uuid = report.splitlines()[1].strip()

        LibvirtTestVirsh.test_bbaa_destroy_created(self)
        time.sleep(3)
        # destroy after create undefines, so only check if loaded
        self.assertFalse(self._uuid_profile_is_loaded(vm_uuid), "Profile is loaded for %s" % vm_uuid)


class LibvirtTestCVEs(LibvirtTestCommon):
    '''Tests for CVE fixes in libvirt'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_CVE_2010_2242(self):
        '''Test CVE-2010-2242'''
        # IMPORTANT: this test may require a reboot

        # See if we have any libvirt rules
        rc, report = testlib.cmd(['iptables', '-L', '-v', '-n'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "virbr0"
        if self.lsb_release['Release'] < 9.04:
            search = "vnet0"
        result = "Could not find '%s' in:\n" % (search)
        self.assertTrue(search in report, result + report)

        rc, report = testlib.cmd(['iptables', '-L', '-v', '-n', '-t', 'nat'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        search = "masq ports: 1024-65535 for tcp"
        result = "Could not find %s in:\n" % (search)
        self.assertTrue(re.search(r'MASQUERADE\s+tcp\s+.*masq ports:\s+1024\-65535', report), result + report)

        search = "masq ports: 1024-65535 for udp"
        result = "Could not find %s in:\n" % (search)
        self.assertTrue(re.search(r'MASQUERADE\s+udp\s+.*masq ports:\s+1024\-65535', report), result + report)

        search = "MASQUERADE all"
        result = "Could not find %s in:\n" % (search)
        self.assertTrue(re.search(r'MASQUERADE\s+all\s+', report), result + report)

    def test_CVE_2010_2237_2238(self):
        '''Test CVE-2010-2237 and CVE-2010-2238'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("%s does not probe backing stores" % (self.lsb_release['Release']))

        self.xmltmp = os.path.join(self.tmpdir, "vm.xml")
        shutil.copy(self.vmxml, self.xmltmp)

        print ""
        for probe in ['', '0', '1']:
            if probe == "1":
                print " Disk probing enabled:"
            elif probe == "0":
                print " Disk probing disabled:"
            else:
                print " Disk probing not specified:"

            if probe != '':
                self._update_config(self.qemuconf, ["allow_disk_format_probing = %s" % probe])

            for t in ['raw', 'qcow2']:
                # Define the disk as one type, but use another type. Disk
                # shouldn't show up in guest, but will show up in vah and xml
                disk = ""
                if t == "raw":
                    disk = os.path.join(os.getcwd(), self.vmqcow2)
                else:
                    disk = os.path.join(os.getcwd(), self.vmimg)
                subprocess.call(['sed', '-i', "s#<source file=.*#<source file='" + disk + "'/><driver name='qemu' type='%s'/>#g" % (t), self.xmltmp])
                self._define_vm(self.connect_uri, self.vm_name, self.xmltmp)
                uuid = self._get_domuuid(self.connect_uri, self.vm_name)

                # vah should use the specified disk
                print "  virt-aa-helper has specified disk (type=%s)" % (t)
                args = ['-d', '-u', 'libvirt-%s' % uuid, '-r']
                if probe != '':
                    args += ['-p', probe]
                rc, report = testlib.cmd_pipe(['cat', self.xmltmp], ['/usr/lib/libvirt/virt-aa-helper'] + args)
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))
                self.assertTrue(disk in report, "Could not find '%s' in:\n%s" % (disk, report))

                # vah should not pick up the backing store on raw specified images or if probe=0
                if t == "raw" or probe == "0":
                    print "  virt-aa-helper does not have backing store (type=%s)" % (t)
                    rc, report = testlib.cmd_pipe(['cat', self.xmltmp], ['/usr/lib/libvirt/virt-aa-helper'] + args)
                    expected = 0
                    result = 'Got exit code %d, expected %d\n' % (rc, expected)
                    self.assertEquals(expected, rc, result + str(report))
                    self.assertFalse(self.vmpristine in report, "Found '%s' in:\n%s" % (self.vmpristine, report))

                # domxml-to-native should use format=<type>
                print "  domxml-to-native uses format (type=%s)" % (t)
                rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-to-native', 'qemu-argv', self.xmltmp])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + str(report))
                self.assertTrue(disk in report, "Could not find '%s' in:\n%s" % (disk, report))
                result = "Did not find 'format=%s' in report" % (t)
                self.assertTrue('format=%s' % (t) in report, result + str(report))

                if t == "raw":
                    print "  qemu 'info block' has correct format (type=%s)" % (t)
                    self._start_vm(self.connect_uri, self.vm_name)
                    if self.lsb_release['Release'] >= 16.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        search = "^drive-ide0-0-0 \(#block[0-9]+\): %s \(%s\)" % (disk, t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertRegexpMatches(output, search, result + output)
                    elif self.lsb_release['Release'] >= 14.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        search = "drive-ide0-0-0: %s (%s)" % (disk, t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertTrue(search in output, result + output)
                    elif self.lsb_release['Release'] >= 12.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        for search in ["drive-ide0-0-0:", "removable=0", "io-status=ok", "file=%s" % (disk), "ro=0", "drv=%s" % (t), "encrypted=0"]:
                            result = "Could not find '%s' in:\n" % (search)
                            self.assertTrue(search in output, result + output)
                    else:
                        output = self._run_qemu_command_and_kill_vm('info block')
                        search = "ide0-hd0: type=hd removable=0 file=%s ro=0 drv=%s" % (disk, t)
                        if self.lsb_release['Release'] >= 10.10:
                            search = "drive-ide0-0-0: type=hd removable=0 file=%s ro=0 drv=%s" % (disk, t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertTrue(search in output, result + output)

                # vah should pick up the backing store on qcow2 if probe=1 and format is qcow2
                if t != "raw" and probe == "1":
                    disk = os.path.join(os.getcwd(), self.vmqcow2)
                    subprocess.call(['sed', '-i', "s#<source file=.*#<source file='" + disk + "'/><driver name='qemu' type='%s'/>#g" % (t), self.xmltmp])
                    self._define_vm(self.connect_uri, self.vm_name, self.xmltmp)

                    print "  virt-aa-helper has backing store (type=%s)" % (t)

                    rc, report = testlib.cmd_pipe(['cat', self.xmltmp], ['/usr/lib/libvirt/virt-aa-helper', '-d', '-p', probe, '-u', 'libvirt-%s' % uuid, '-r' ])
                    expected = 0
                    result = 'Got exit code %d, expected %d\n' % (rc, expected)
                    self.assertEquals(expected, rc, result + str(report))
                    self.assertTrue(self.vmpristine in report, "Could not find '%s' in:\n%s" % (self.vmpristine, report))

                    print "  qemu 'info block' has correct format (type=%s)" % (t)
                    self._start_vm(self.connect_uri, self.vm_name)
                    if self.lsb_release['Release'] >= 16.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        search = "^drive-ide0-0-0 \(#block[0-9]+\): %s \(%s\)" % (disk, t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertRegexpMatches(output, search, result + output)
                    elif self.lsb_release['Release'] >= 14.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        search = "drive-ide0-0-0: %s (%s)" % (disk, t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertTrue(search in output, result + output)
                    elif self.lsb_release['Release'] >= 12.04:
                        rc, output = testlib.cmd(['virsh', 'qemu-monitor-command', '--hmp', self.vm_name, 'info block'])
                        # now kill the vm - because we're not running _run_qemu_command_and_kill_vm() which
                        # otherwise would do so for us.
                        self._destroy_vm(self.connect_uri, self.vm_name)
                        # and make sure the output has what we want
                        for search in ["drive-ide0-0-0:", "removable=0", "io-status=ok", "file=%s" % (disk), "ro=0", "drv=%s" % (t), "encrypted=0"]:
                            result = "Could not find '%s' in:\n" % (search)
                            self.assertTrue(search in output, result + output)
                    else:
                        output = self._run_qemu_command_and_kill_vm('info block')
                        search = "ide0-hd0: type=hd removable=0 file=%s backing_file=%s ro=0 drv=%s" % (disk, os.path.join(os.getcwd(), self.vmpristine), t)
                        if self.lsb_release['Release'] >= 10.10:
                            search = "drive-ide0-0-0: type=hd removable=0 file=%s backing_file=%s ro=0 drv=%s" % (disk, os.path.join(os.getcwd(), self.vmpristine), t)
                        result = "Could not find '%s' in:\n" % (search)
                        self.assertTrue(search in output, result + output)

    def test_CVE_2010_2239(self):
        '''Test CVE-2010-2239'''
        if self.lsb_release['Release'] < 9.04:
            return self._skipped("%s does not have backing stores" % (self.lsb_release['Release']))
        if self.lsb_release['Release'] == 9.04:
            return self._skipped("%s affected, but ignored" % (self.lsb_release['Release']))

        pool_name = self.pool_name
        pool_uuid = "4a458219-9b8b-2af0-77b8-adebf563f5fa"
        connect_uri = 'qemu:///system'

        print "\n  setting up %s for %s (%s)" % (os.path.basename(self.pool_dir), self.vm_virtinst_name, connect_uri)
        self._setup_storage_pool(pool_name, self.pool_dir, pool_uuid, connect_uri)

        vol_pristine_img = os.path.join(self.pool_dir, "pristine.img")
        vol_bs_xml = os.path.join(self.tmpdir, "bs.xml")
        vol_bs_name = os.path.basename(self.vol_bs_img)

        shutil.copy(os.path.join(os.getcwd(), self.vmpristine), vol_pristine_img)

        # create the volume with a backingstore
        contents = '''<volume>
  <name>%s</name>
  <key>%s</key>
  <allocation>147456</allocation>
  <capacity unit="M">10</capacity>
  <source>
  </source>
  <target>
    <path>%s</path>
    <format type='qcow2'/>
  </target>
  <backingStore>
    <path>%s</path>
    <format type='qcow2'/>
  </backingStore>
</volume>
''' % (vol_bs_name, self.vol_bs_img, self.vol_bs_img, vol_pristine_img)
        testlib.create_fill(vol_bs_xml, contents)

        print "  vol-create (with backing store)"
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-create', self.pool_name, vol_bs_xml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        self.assertTrue(os.path.exists(self.vol_bs_img), "Could not find '%s'" % self.vol_bs_img)

        # verify the volume with a backingstore was added to the pool
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'vol-list', self.pool_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = vol_bs_name
        result = "Could not find '%s':\n" % (search)
        self.assertTrue(search in report, result + report)

        xmltmp = os.path.join(self.tmpdir, "vm.xml")
        shutil.copy(os.path.join(os.getcwd(), self.vmxml), xmltmp)
        subprocess.call(['sed', '-i', "s#<source file='.*'/>#<source file='" + self.vol_bs_img + "'/><driver name='qemu' type='qcow2'/>#g", xmltmp])

        # AppArmor blocks these on Karmic (LP: #470636)
        if self.lsb_release['Release'] == 9.10:
            testlib.config_replace("/etc/apparmor.d/abstractions/libvirt-qemu", "  %s/** rw,\n" % self.pool_dir, True)

        # define image, then see if it has type defined
        print "  define %s" % self.vm_name
        self._define_vm(self.connect_uri, self.vm_name, xmltmp)
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'dumpxml', self.vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        if self.lsb_release['Release'] > 10.04:
            subprocess.call(['chgrp', '-R', 'kvm', self.tmpdir])
            subprocess.call(['chmod', '-R', 'g+rw', self.tmpdir])
            subprocess.call(['chmod', '0770', self.tmpdir])

        print "  start %s" % self.vm_name
        self._start_vm(self.connect_uri, self.vm_name)
        print "  stop %s" % self.vm_name
        self._destroy_vm(self.connect_uri, self.vm_name)

        # 0.8.8 and later changed their behavior and this check is actually
        # not required per upstream. Leaving it for earlier releases to catch
        # any changes in behavior.
        if self.lsb_release['Release'] < 11.04:
            # now replace the pristine image with a raw one
            os.unlink(vol_pristine_img)
            print "  replacing backing store"
            shutil.copy(os.path.join(os.getcwd(), self.vmimg), vol_pristine_img)
            print "  start %s" % self.vm_name
            rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'start', self.vm_name])
            not_expected = 0
            result = 'Got exit code %d but should not have\n' % (rc)
            self.assertTrue(rc != not_expected, result + report)

    def test_CVE_2011_1146(self):
        '''Test CVE-2011-1146'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("%s not-affected" % (self.lsb_release['Release']))
        rc, report = testlib.cmd(['virsh', '-c', self.connect_uri, 'domxml-to-native', 'qemu-argv', self.vmxml])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['virsh', '-r', '-c', self.connect_uri, 'domxml-to-native', 'qemu-argv', self.vmxml])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))


class LibvirtTestRemote(LibvirtTestCommon):
    '''Tests for libvirt  functionality'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

        # setup a user such that we can do:
        # sudo -H -u <username> virsh -c qemu+ssh://127.0.0.1/system ...
        self.remote_user = testlib.TestUser()
        self.ssh_dir = os.path.join(self.remote_user.home, ".ssh")
        os.mkdir(self.ssh_dir)
        os.chmod(self.ssh_dir,0700)

        self._remote_start_vm = False

        # private key
        ssh_id_rsa = os.path.join(self.ssh_dir, "id_rsa")
        contents = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz05JxnpXaiZIrVHvRGt+wZGQOu+x2GQI6yP8G9JaLonPh0pU
LcnjFL5YZeGnO2YpZEbEZxDWhMSCUlK95eZKsNVSJyoSuqewp/RczHbmhqPUy5YU
d5GldltaAM71CWtD8/f5QWiMGpDtUAMK60qa8ljk7jm6NRqxCgo1djdKWQKZdn3L
OLZd36vJD79fUdo2TP4hWwFh8Lw8FEBE6kwYARvRZxEza3L5mat9FR4IcbL/DjLa
6QbhCe9Qvigg6Es8IqvucJvnBonuw2Dxh/M3n1szrL4TzmXhLCYy08slhH1IKhZq
ZNHLtyFdntB/IOIY5fvpyEaJ7buFH1h/WInmdwIDAQABAoIBAGGUx3Nu6TDlPnaf
R9JcCzmQjGTBqWRjijMtKCHsfVjEs/RKD5/SFVsRUkj61B5Is5kpGpAtQ90RJwsb
OZo7MdNVRqt6yYAlKSmWBAyWt2KPQb5nMdEqtMkmrRIOWReK71yq0CBy1ug2ag6s
r/objx4eq/xbHgSbQNSqA4pW8l882dWCWWIMtZE/Alo6Hr+SMQUVxi/k1ynBSESy
Xr/g/P1u3EKKFXVGX8zQJSC9WLkSui9p1e+MayBq4eSiqrct42iitSWprpqA6bsY
88IFDBC+MkY6R37ausW1dL5THOqRY/E4hAgwUgp7kJl1s7vxUEoHJwBJvI6o2s9D
6Ls/GeECgYEA8rT+QM/Aok9Uzl1ctAa7j1QmzGHnKza03uRG5ux3M5lCbzxVh940
/HqyCQr0jthosDxQwUzK1kkY2n8ItxGei0xZM6hsvpzQGJsBoFW72Rc+Mnbmf1Ih
Op2TOOji6j8/IUG/e37eTkGgAbt6xuCcgdsizAFJ208jev4zcCtm3lECgYEA2qju
5AFk3oJV3uDaX/7bbfnJ89ePR7Ev6yQ3176uq6P5EdNyXp8tM0Z+Bad49D0XIQTz
sJ9570/BEvnNAa1gVN54p879ifwsXszs9xmHqAqa1aPGnsZBbxPyDFmxcWM24Nag
dse1Yd5Ah82sXNRf4LBIdxT6d7rjaSvJJ1C43kcCgYEAwUCaXlLN6K9QMI0oXnQp
7gMsbXrbDY6e0Adl6UOJ2n0C5/1bgTbOa+bqUcb2WbM5EHLGPlP+Akfr0TZrYxFV
c0cUk8xc4h2MmLr7vYXmcAJQ1O/VsrVbngeQDTVqUOiRRNLMO/IV4qvgUuDL7wUz
uTYaa+PuwgAumSVFIeB9JTECgYAg3txqsjrzqCw4gRzS6YEbGz3cxj7nzB8j/iHW
8PdZHiFHKL48szkcSDCRsQdhz/02HYR0vMSb0SV5MMw8wE+G8pq4v0kmAR66cZv9
2XynKlD0ZNZq7+rOQ/VTHfiqzvtk+V7N/F+sArk4sRaELfjr0hRSsniknxeoq8hl
fKEN6QKBgE7r/n31ol5X/Hq0QWetP/llNB/iEQChBlJfmyqPPzDmwCIb+BdELX8N
FD7nZNMSfO1MnIcL2FnaSXkiJ2721UvOfXWX4rhlQjMLV93/WLAQuq2mmiHRkQeu
88qNDso9Bwtpshm4mzozD2xpVTAgQWaB5DyWhtwVnJWsAJn+wjn/
-----END RSA PRIVATE KEY-----
'''
        testlib.create_fill(ssh_id_rsa, contents)
        os.chmod(ssh_id_rsa,0600)

        # public key
        ssh_id_rsa_pub = os.path.join(self.ssh_dir, "id_rsa.pub")
        contents = '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPTknGeldqJkitUe9Ea37BkZA677HYZAjrI/wb0louic+HSlQtyeMUvlhl4ac7ZilkRsRnENaExIJSUr3l5kqw1VInKhK6p7Cn9FzMduaGo9TLlhR3kaV2W1oAzvUJa0Pz9/lBaIwakO1QAwrrSpryWOTuObo1GrEKCjV2N0pZApl2fcs4tl3fq8kPv19R2jZM/iFbAWHwvDwUQETqTBgBG9FnETNrcvmZq30VHghxsv8OMtrpBuEJ71C+KCDoSzwiq+5wm+cGie7DYPGH8zefWzOsvhPOZeEsJjLTyyWEfUgqFmpk0cu3IV2e0H8g4hjl++nIRontu4UfWH9YieZ3 foo@bar
'''
        testlib.create_fill(ssh_id_rsa_pub, contents)
        os.chmod(ssh_id_rsa_pub,0644)

        # authorized_keys
        ssh_authorized_keys = os.path.join(self.ssh_dir, "authorized_keys")
        testlib.create_fill(ssh_authorized_keys, 'from="127.0.0.1" %s' % contents)
        os.chmod(ssh_authorized_keys,0600)

        testlib.cmd(['chown', '-R', "%s:%s" % (self.remote_user.uid, self.remote_user.gid), self.ssh_dir])

        # known_hosts via a command with no StrictHostKeyChecking
        rc, report = testlib.cmd(['sudo', '-H', '-u', self.remote_user.login, 'ssh', '-t', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '127.0.0.1', 'uname'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if self.lsb_release['Release'] < 16.10:
            grp="libvirtd"
        else:
            grp="libvirt"
        testlib.cmd(['adduser', self.remote_user.login, grp])
        testlib.cmd(['adduser', self.remote_user.login, "kvm"])

        self.virsh_cmd_args = ['sudo', '-H', '-u', self.remote_user.login, \
                               'virsh', '-c', 'qemu+ssh://127.0.0.1/system']

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        self.remote_user = None

    def test_capabilities(self):
        '''Test remote capabilities'''
        # get our 'remote' capabilities
        rc, remote = testlib.cmd(self.virsh_cmd_args + ['capabilities'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + remote)

        # get our 'local' capabilities
        rc, local = testlib.cmd(['virsh', 'capabilities'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + local)

        result = "remote and local are different:\n= Remote =\n%s\n\n= Local =\n%s" % (remote, local)
        self.assertEquals(expected, rc, result)

    def test_maxvcpus(self):
        '''Test remote maxvcpus'''
        if self.lsb_release['Release'] < 11.04:
            return self._skipped("not present before 11.04")

        rc, report = testlib.cmd(self.virsh_cmd_args + ['maxvcpus'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Does not start with a number:\n"
        self.assertTrue(re.search(r'^[0-9]', report), result + report)

        rc, report = testlib.cmd(self.virsh_cmd_args + ['--readonly', 'maxvcpus'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Does not start with a number:\n"
        self.assertTrue(re.search(r'^[0-9]', report), result + report)

    def test_setvcpus(self):
        '''Test remote setvcpus'''
        self.undefine_qemu = True
        self._define_vm(self.connect_uri, self.vm_name, self.vmxml)
        if self.lsb_release['Release'] == 10.10:
            self._start_vm(self.connect_uri, self.vm_name)

        # get our previous CPUs
        rc, report = testlib.cmd(self.virsh_cmd_args + ['dominfo', self.vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        prev_cpus = None
        cpus = 3
        for line in report.splitlines():
            if line.startswith("CPU(s):"):
                prev_cpus = line.split()[1]
                if prev_cpus == cpus:
                    cpus += 1
                break

        # change the vcpus
        if self.lsb_release['Release'] < 11.04:
            rc, report = testlib.cmd(self.virsh_cmd_args + ['setvcpus', self.vm_name, str(cpus)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
        else:
            rc, report = testlib.cmd(self.virsh_cmd_args + ['setvcpus', self.vm_name, str(cpus), '--config', '--maximum'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(self.virsh_cmd_args + ['setvcpus', self.vm_name, str(cpus), '--config'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # get our new CPUs
        rc, report = testlib.cmd(self.virsh_cmd_args + ['dominfo', self.vm_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        cur_cpus = None
        for line in report.splitlines():
            if line.startswith("CPU(s):"):
                cur_cpus = line.split()[1]
                break

        result = 'Got vcpus %s, expected %d\n' % (cur_cpus, cpus)
        self.assertEquals(int(cur_cpus), cpus, result + report)


def reset():
    '''Try to reset test environment back to a usable state'''

    rc, report = testlib.cmd(['id'])
    vm = 'qatest-i386'
    for c in ['qemu:///session', 'qemu:///system']:
        print "Destroying %s (%s)" % (vm, c)
        testlib.cmd(['virsh', '-c', c, 'destroy', vm])
        print "Undefining %s (%s)" % (vm, c)
        testlib.cmd(['virsh', '-c', c, 'undefine', vm])

    qatest_dir = "./libvirt/qatest/"
    if os.path.isdir(qatest_dir):
        print "Removing '%s'" % qatest_dir
        testlib.recursive_rm(qatest_dir)

    ubuntu_version = testlib.manager.lsb_release["Release"]
    if ubuntu_version >= 9.10:
        print "Stopping apparmor"
        testlib.cmd(['sudo', '/etc/init.d/apparmor', 'stop'])
        print "Removing /etc/apparmor.d/libvirt/libvirt-*"
        for f in glob.glob('/etc/apparmor.d/libvirt/libvirt-*'):
            os.unlink(f)
        print "Starting apparmor"
        testlib.cmd(['sudo', '/etc/init.d/apparmor', 'start'])

    print "Restarting libvirt"
    do_stop_libvirtd()
    testlib.cmd(['sudo', 'killall', 'dnsmasq'])
    do_start_libvirtd()

    print "Done"
    sys.exit(0)

def setuppackages():
    '''Installs packages needed to run this script'''
    if os.getuid() != 0:
        print >>sys.stderr, "Need to be root to run this command"
        sys.exit(1)

    fh = open(sys.argv[0])
    for line in fh.readlines():
        if line.startswith("# QRT-Packages: "):
            pkgs = line.split(':')[1].split()
            args = ['apt-get', 'install', '-y', '--force-yes'] + pkgs
            print "Running: %s" % " ".join(args)
            rc, report = testlib.cmd(args)
            if rc != 0:
                print >>sys.stderr, "apt-get failed:\n%s" % report
                sys.exit(1)
            break

def setupnetwork():
    '''Sets up the default network compatible with nested virtualization'''
    rc, report = testlib.cmd(['id'])

    # libvirt will fail with error if defining things just after it
    # it starts. This capabilities call is a hack to know when libvirtd
    # is ready, since it will wait rather than return error
    rc, report = testlib.cmd(['virsh', 'capabilities'])
    if rc != 0:
        print >>sys.stderr, "virsh capabilities failed:\n%s" % report
        sys.exit(1)

    rc, report = testlib.cmd_pipe(['virsh', 'net-dumpxml', 'default'], ['sed', '-e', 's#192.168.122.#192.168.123.#g', '-e', 's#^Connecting.*##g'])
    print report
    if rc != 0:
        print >>sys.stderr, "virsh net-dumpxml failed:\n%s" % report
        sys.exit(1)
    tmp = tempfile.mktemp(dir='/tmp')
    testlib.create_fill(tmp, report)

    rc, report = testlib.cmd(['virsh', 'net-destroy', 'default'])
    if rc != 0:
        #print >>sys.stderr, "WARN: virsh net-destroy failed:\n%s" % report
        print >>sys.stderr, "WARN: virsh net-destroy failed. Continuing (non-fatal)"

    rc, report = testlib.cmd(['virsh', 'net-undefine', 'default'])
    if rc != 0:
        print >>sys.stderr, "WARN: virsh net-undefine failed. Continuing (non-fatal)"

    rc, report = testlib.cmd(['virsh', 'net-define', tmp])
    if rc != 0:
        print >>sys.stderr, "virsh net-define failed:\n%s" % report
        subprocess.call(['mv', '-f', tmp, '/tmp/net.xml'])
        print >>sys.stderr, "xml saved in /tmp/net.xml"
        sys.exit(1)

    rc, report = testlib.cmd(['virsh', 'net-autostart', 'default'])
    if rc != 0:
        print >>sys.stderr, "virsh net-autostart default failed:\n%s" % report
        subprocess.call(['mv', '-f', tmp, '/tmp/net.xml'])
        print >>sys.stderr, "xml saved in /tmp/net.xml"
        sys.exit(1)

    # clean up
    os.unlink(tmp)

    print "Restarting libvirt"
    do_stop_libvirtd()
    testlib.cmd(['sudo', 'killall', 'dnsmasq'])
    do_start_libvirtd()
    print "Done"
    sys.exit(0)


if __name__ == '__main__':
    testlib.require_sudo()

    if len(sys.argv) > 1 and sys.argv[1] == 'setup-all':
        setuppackages()
        setupnetwork()  # which exits when done

    if len(sys.argv) > 1 and sys.argv[1] == 'setup-network':
        setupnetwork()  # which exits when done

    if len(sys.argv) > 1 and sys.argv[1] == 'reset':
        reset()  # which exists when done

    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-m", "--migrate-host", dest="remotemachine", help="Specify host to migrate to (eg, 'localhost', '<ipaddr>', '<hostname>')", metavar="HOST")
    parser.add_option("-c", "--copy", dest="copyimage", help="Copy image when migrating", action="store_true")
    (options, args) = parser.parse_args()

    if options.remotemachine:
        print "setting remotemachine to " + remotemachine
        remotemachine = options.remotemachine
        if options.copyimage:
            copy_image = True

    ubuntu_version = testlib.manager.lsb_release["Release"]

    suite = unittest.TestSuite()

    # virsh/apparmor tests
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSystemRoot))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSession))

    if ubuntu_version >= 9.10:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSystemRootAppArmor))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSessionAppArmor))
    else:
        print >>sys.stderr, "Skipping AppArmor tests on 9.04 and lower"

    if ubuntu_version >= 10.10:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSystemNonRootAppArmor))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirshSystemNonRoot))
    else:
        print >>sys.stderr, "Skipping non-root tests on 10.04 and lower"

    # miscellaneous other tests
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestRemote))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestVirtinst))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestCVEs))

    if options.remotemachine:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibvirtTestMigrate))
    else:
        print >>sys.stderr, "Skipping migrate test (use '-m' to enable)"
    rc = unittest.TextTestRunner(verbosity=2).run(suite)


    if abort_tests:
        print >>sys.stderr, "FAIL: %d tests aborted" % (aborted_tests)
        sys.exit(1)

    if not rc.wasSuccessful():
        sys.exit(1)

