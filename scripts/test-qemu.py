#!/usr/bin/python
#
#    test-qemu.py quality assurance test script for qemu-kvm
#    Copyright (C) 2011-2016 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: qemu-kvm netcat-openbsd openssh-client lsb-release
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends: libvirt/ qemu/

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    Some of the tests might be host specific and therefore should be run in
    a virtualized environment. If using in a chroot, make sure that /proc
    is mounted. Eg:
    $ sudo mount --bind /proc /var/lib/schroot/mount/lucid-amd64-df6e1e8b-6862-444d-960a-e2d0626e5b35/proc

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-qemu.py --compact -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-qemu.py -v'

    Inspiration for some of this came from:
    http://en.wikibooks.org/wiki/QEMU/Monitor

    Networking information for slirp came from :
    http://wiki.qemu.org/Documentation/Networking

    NOTES:
    - This has been tested on Ubuntu 10.04 LTS and later. It probably will
      fail without modification for earlier releases
    - Tests using QemuGuestCommon() (ie, ones requiring ssh access) may fail
      under load, especially with nested virtualization. This can easily happen
      if running multiple VMs with nested virtualization concurrently with this
      script running in each

    TODO:
     - should verify we have important devices with 'info qdm'
     - verify kvm support only on machines that have it ('info kvm')
     - qemu-img should convert to/from all formats
     - finish test_qemu_usb() (pass a USB device into it)
     - mouse_move, mouse_booton, mouse_set index
     - sendkey
     - savevm, loadvm, delvm
     - system_reset, system_powerdown
     - memsave, pmemsave
     - migration
     - host_net*
     - netdev*
     - acl-*
     - balloon
     - qemu-io
     - qemu-nbd
     - plug/unplug USB drive 15 times and make sure the guest is ok
     - look into http://wiki.qemu.org/Download, which has images and other
       things to test qemu.
     - handle low disk space better. We have the --compact option, but should
       also check for room, suggest --compact and/or recommend removing
       stuff (eg libgtk2.0-0)
'''

import unittest, subprocess, sys, os
import re
import tempfile
import testlib
import time
import apt
import apt_pkg

guest_vm_tarball = "libvirt/qatest.tar.bz2"
guest_virtio_vm_tarball = "qemu/qatest-virtio.tar.bz2"
cleanup_other_vm = False

use_private = True
try:
    from private.qrt.mytest import QemuPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

def get_qemu_version():
    cache = apt.Cache()
    try:
        versions = cache['qemu-system-common']
    except:
        versions = cache['qemu-common']
    v = versions.versions[0].version
    return v

class QemuCommon(testlib.TestlibCase):
    '''Test Qemu.'''

    def _setUp(self, unpack_vm=True):
        '''Set up prior to each test_* function'''
        global guest_vm_tarball
        global guest_virtio_vm_tarball

        self.qemu_version = get_qemu_version()

        self.tmpdir = tempfile.mkdtemp(dir='/tmp')

        self.qemuimg_exe = "qemu-img"

        self.vmtarball = guest_vm_tarball
        self.vmimg_orig = os.path.join(os.path.dirname(guest_vm_tarball), "qatest/qatest.img")
        self.vmimg = os.path.join(os.path.dirname(guest_vm_tarball), "qatest/qatest.qcow2")
        self.vmmem = "192"
        self.vmname = "qatest-vm"
        self.vmuuid = "ded3a46b-bb60-43f4-8113-d041aeb93cdf"

        self.vmtarball_virtio = guest_virtio_vm_tarball
        self.vmimg_virtio_orig = os.path.join(os.path.dirname(guest_virtio_vm_tarball), "qatest-virtio/qatest-virtio.img")
        self.vmimg_virtio = os.path.join(os.path.dirname(guest_virtio_vm_tarball), "qatest-virtio/qatest-virtio.qcow2")

        self.monitor_ip = "127.0.0.1"
        self.monitor_port = "4444"
        self.ssh_port = "4422"
        self.ssh_args = ['-t',
                         '-p', self.ssh_port,
                         '-o', 'BatchMode=yes',
                         '-o', 'ConnectTimeout=60',
                        ]
        self.ssh_user = "qatest"
        self.qemu_pidfile = os.path.join(self.tmpdir, "pid")

        self.qemunet_gateway = "10.0.2.2"
        self.qemunet_dns = "10.0.2.3"
        self.qemunet_ip = "10.0.2.15"

        # Why certain options are used:
	# -serial none				so the terminal doesn't get
        #                                       touched
        # -chardev null,id=chardevmon		not strictly needed
        # -daemonize				so we don't have to fork here
        # -display none				don't launch an SDL window
        # -monitor				allows connection with:
        #                                       nc -q 1 monitor_ip monitor_port
        # -pidfile				for tearDown to destroy the VM
	# -net user				for networking via slirp (nic
        #                                       added in _start_vm())
        # -name					for identification
        # -uuid					for identification
        # -usb					for info tests
        # -usb					for RTC tests

        if self.lsb_release['Release'] < 12.04:
            self.qemu_args = ['-m', self.vmmem,
                              '-serial', 'none',
                              '-chardev', 'null,id=chardevmon',
                              '-pidfile', self.qemu_pidfile,
                              '-daemonize',
                              '-nographic',
                              '-monitor', "tcp:%s:%s,server,nowait" % (self.monitor_ip, self.monitor_port),
                              '-net', 'user,hostfwd=tcp:%s:%s-:22' % (self.monitor_ip, self.ssh_port),
                              '-usb',
                              '-rtc', 'base=utc',
                              '-name', self.vmname,
                              '-uuid', self.vmuuid]
        else:
            self.qemu_args = ['-m', self.vmmem,
                              '-serial', 'none',
                              '-chardev', 'null,id=chardevmon',
                              '-pidfile', self.qemu_pidfile,
                              '-daemonize',
                              '-display', 'none',
                              '-monitor', "tcp:%s:%s,server,nowait" % (self.monitor_ip, self.monitor_port),
                              '-net', 'user,hostfwd=tcp:%s:%s-:22' % (self.monitor_ip, self.ssh_port),
                              '-usb',
                              '-rtc', 'base=utc',
                              '-name', self.vmname,
                              '-uuid', self.vmuuid]

        if unpack_vm and not os.path.exists(self.vmimg_orig):
            if os.path.exists(self.vmtarball):
                print >>sys.stdout, "  untarring '%s'  " % (self.vmtarball)
                sys.stdout.flush()
                testlib.cmd(['tar', '-C', 'libvirt', '-jxf', self.vmtarball])
            else:
                raise ValueError, "Couldn't find '%s'" % (self.vmtarball)

        if unpack_vm and not os.path.exists(self.vmimg):
            print >>sys.stdout, "  creating qcow2 '%s' from '%s'" % (self.vmimg, self.vmimg_orig)
            rc, report = testlib.cmd([self.qemuimg_exe, 'convert', '-f', 'raw', self.vmimg_orig, '-O', 'qcow2', self.vmimg])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(self.vmimg), "Could not find '%s'" % (self.vmimg))

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self._stop_vm()

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _check_vm_is_running(self, emulator="qemu-system-i386"):
        '''Verify VM running'''
        if emulator == "qemu-system-i386" and self.lsb_release['Release'] < 12.04:
            emulator = "qemu"
        #print "%s %s" % (emulator, self.qemu_pidfile)
        #subprocess.call(['bash'])
        self.assertTrue(testlib.check_pidfile(emulator, self.qemu_pidfile), "PID in '%s' is not running" % (self.qemu_pidfile))

    def _start_vm(self, disk, emulator="qemu-system-i386", nic=None, my_args=None):
        '''Start VM'''
        if emulator == "qemu-system-i386" and self.lsb_release['Release'] < 12.04:
            emulator = "qemu"
        if my_args == None:
            args = [] + self.qemu_args
        else:
            args = [] + my_args

        if disk != None:
            args += ['-hda', disk]

        if nic != None:
            args += ['-net', 'nic,model=%s' % nic]

        #print "DEBUG: %s" % " ".join(args)

	# FIXME: why doesn't this work in a chroot? It isn't horrible that it
        # doesn't work, as the next command will fail
	#self.assertFalse(testlib.check_port(int(self.monitor_port), "tcp"), "Something already listening on tcp port '%s'" % self.monitor_port)

        rc, report = testlib.cmd([emulator] + args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(os.path.exists(self.qemu_pidfile), "Could not find '%s'" % self.qemu_pidfile)
        self. _check_vm_is_running(emulator)
        self.assertTrue(testlib.check_port(int(self.monitor_port), "tcp"), "Not listening on tcp port '%s'" % self.monitor_port)

        report = self._monitor_cmd("info status")
        search = "VM status: running"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def _stop_vm(self):
        '''Stop VM'''
        self._monitor_cmd("quit", with_assert=False)
        if os.path.exists(self.qemu_pidfile):
            try:
                fd = open(self.qemu_pidfile, 'r')
                pid = fd.readline().rstrip('\n')
                fd.close()
            except:
                print >>sys.stderr, "Could not open '%s'" % self.qemu_pidfile

            # kill the process
            testlib.cmd(['kill', pid])
            testlib.cmd(['kill', '-9', pid])
            os.unlink(self.qemu_pidfile)

            # make sure port is deallocated
            time.sleep(1)

    def _monitor_cmd(self, cmd, with_assert=True):
        '''Run a qemu monitor command'''
        rc, report = testlib.cmd_pipe(['echo', cmd], ['nc', '-q', '1', self.monitor_ip, self.monitor_port])
        if with_assert:
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        return report


class QemuImage(QemuCommon):
    '''Tests for qemu-img'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_qemuimg_create(self):
        '''Test qemu-img create'''
        formats = ['qcow', 'qcow2', 'vdi', 'vmdk', 'vpc']
        if self.lsb_release['Release'] < 15.04:
            formats.insert(0, 'cow')
        size = '5.0M'
        print ""
        for f in formats:
            print "  %s" % f
            fn = os.path.join(self.tmpdir, "disk.%s" % f)
            rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', f, fn, size])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd([self.qemuimg_exe, 'info', fn])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            search = "file format: %s" % f
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            search = "virtual size: %s" % size
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

    def test_qemuimg_convert(self):
        '''Test qemu-img convert'''
        formats = ['qcow', 'qcow2', 'vdi', 'vmdk', 'vpc']
        if self.lsb_release['Release'] < 15.04:
            formats.insert(0, 'cow')
        size = '5.0M'

        # create source file as raw. TODO: convert to/from all formats
        orig = os.path.join(self.tmpdir, "disk.raw")
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', 'raw', orig, size])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([self.qemuimg_exe, 'info', orig])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "file format: raw"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "virtual size: %s" % size
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print ""
        for f in formats:
            print "  %s" % f
            fn = os.path.join(self.tmpdir, "disk.%s" % f)
            rc, report = testlib.cmd([self.qemuimg_exe, 'convert', '-f', 'raw', orig, '-O', f, fn])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd([self.qemuimg_exe, 'info', fn])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            search = "file format: %s" % f
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            search = "virtual size: %s" % size
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

    def test_qemuimg_snapshot(self):
        '''Test qemu-img snapshot'''
        size = '5.0M'

        # create source file as qcow2
        orig = os.path.join(self.tmpdir, "disk.qcow2")
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', 'qcow2', orig, size])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # create the snapshot
        snap = os.path.join(self.tmpdir, "disk_snap.qcow2")
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-F', 'qcow2', '-b', orig, '-f', 'qcow2', snap])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for fn in [orig, snap]:
            rc, report = testlib.cmd([self.qemuimg_exe, 'info', fn])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            search = "file format: qcow2"
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            search = "virtual size: %s" % size
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            if fn == snap:
                search = "backing file: %s" % orig
                result = "Could not find '%s' in report" % search
                self.assertTrue(search in report, result + report)


class QemuMonitor(QemuCommon):
    '''Tests for qemu monitor'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self._start_vm(disk=self.vmimg)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_qemu_help(self):
        '''Test qemu help'''

        report = self._monitor_cmd("help")
        search = "info [subcommand]"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)
        #print "DEBUG: qemu help:\n%s" % report

    def test_qemu_media(self):
        '''Test qemu media'''
        iso = os.path.join(self.tmpdir, "iso")
        testlib.cmd(['touch', iso])
        report = self._monitor_cmd("change ide1-cd0 %s" % iso)

        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % iso
        else:
            search = "%s" % iso
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        report = self._monitor_cmd("eject -f ide1-cd0")
        time.sleep(2)
        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % iso
        else:
            search = "%s" % iso
        result = "Found '%s' in report" % search
        self.assertTrue(search not in report, result + report)

    def test_qemu_info(self):
        '''Test qemu info'''
        commands = [ ("blockstats", "ide0-hd0: rd_bytes="),
                     ("chardev", "filename=tcp:%s:%s,server" % (self.monitor_ip, self.monitor_port)),
                     ("cpus", "* CPU #0: "),
                     ("history", ": 'info block'"),
                     ("jit", "Translation buffer state"),
                     #("kvm", "kvm support: enabled"), # TODO
                     #("mem", "ur-"), # FIXME
                     ("mice", "QEMU PS/2 Mouse"),
                     ("name", self.vmname),
                     ("numa", "0 nodes"),
                     ("pci", "Host bridge: PCI device"),
                     ("pci", "ISA bridge: PCI device"),
                     ("pci", "IDE controller: PCI device"),
                     ("pci", "Bridge: PCI device"),
                     ("pci", "VGA controller: PCI device"),
                     #("pcmcia", "No PCMCIA sockets"),
                     ("qdm", "virtio-blk-pci"), # TODO: many more of there
                     ("qdm", "virtio-net-pci"),
                     ("qtree", "bus: main-system-bus"),
                     ("registers", "EAX="),
                     ("registers", "EIP="),
                     ("status", "VM status: running"),
                     #("tlb", " ----A--U-"), # FIXME
                     ("usb", "info usb"), # for now, just check for the command since
                                          # we didn't connect any devices
                     # Searching for "Hub: USB device" is host-specific
                     # for example, my Thinkpad T61 doesn't have one.
                     # Only search for "Class" for now
                     ("usernet", "VLAN 0 (user.0)"),
                     ("uuid", self.vmuuid),
                     ("version", "(qemu"),
                     #("vnc", "Server: disabled"),
                   ]

        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            commands += [("block", "file=%s" % self.vmimg)]
        else:
            commands += [("block", "%s" % self.vmimg)]

        if self.lsb_release['Release'] < 13.04:
            commands += [("help", "info version")]

        if self.lsb_release['Release'] < 12.04:
            commands += [("network", "user.0: net=10")]
        elif self.lsb_release['Release'] < 13.10:
            commands += [("network", "user.0: type=user,net=10")]
            commands += [("roms", "addr=")]
        else:
            commands += [("network", "user.0: index=0,type=user,net=10")]
            commands += [("roms", "name=")]

        if self.lsb_release['Release'] == 13.10:
            commands += [("chardev", "chardevmon: filename=(null)")]
        else:
            commands += [("chardev", "chardevmon: filename=null")]

        if self.lsb_release['Release'] < 12.10:
            commands += [("pic", "pic0: irr=")]

        commands.sort()

        print ""
        for c, search in commands:
            print "  %s (%s)" % (c, search)
            report = self._monitor_cmd("info %s" % c)
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

    def test_qemu_usb(self):
        '''Test qemu usb'''
        return self._skipped("TODO")

        # (qemu) help usb_add
        # usb_add device -- add USB device (e.g. 'host:bus.addr' or 'host:vendor_id:product_id')
        device = ""
        report = self._monitor_cmd("usb_add %s" % device)

        report = self._monitor_cmd("info usb")
        search = "Device 0.1"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        report = self._monitor_cmd("usb_del 0.1")
        time.sleep(2)
        report = self._monitor_cmd("info usb")
        search = "Device 0.1"
        result = "Found '%s' in report" % search
        self.assertTrue(search not in report, result + report)

    def test_qemu_screendump(self):
        '''Test qemu screendump'''
        ppm = os.path.join(self.tmpdir, "ppm")

        # give VM a chance to run
        time.sleep(5)
        report = self._monitor_cmd("screendump %s" % ppm)
        self.assertTrue(os.path.exists(ppm), "Could not find '%s'" % (ppm))

    def test_qemu_suspend(self):
        '''Test qemu stop/cont'''
        report = self._monitor_cmd("stop")
        report = self._monitor_cmd("info status")
        search = "VM status: paused"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        time.sleep(3)

        report = self._monitor_cmd("cont")
        report = self._monitor_cmd("info status")
        search = "VM status: running"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def test_qemu_snapshot(self):
        '''Test qemu snapshot'''
        self._stop_vm()

        snap = os.path.join(self.tmpdir, "disk_snap.qcow2")
        orig = os.path.join(os.getcwd(), self.vmimg)
        cksum = testlib.get_md5(orig)

        print ""

        # create the snapshot
        print "  create snapshot"
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-F', 'qcow2', '-b', orig, '-f', 'qcow2', snap])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(os.path.exists(snap), "Could not find '%s'" % snap)

        print "  start with -drive file=<snapshot>"
        self._start_vm(disk=snap)

        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = " file=%s" % snap
        else:
            search = " %s" % snap
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = " backing_file=%s" % orig
        else:
            search = " Backing file:     %s" % orig
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print "  stop and verify backing store"
        self._stop_vm()
        new_cksum = testlib.get_md5(orig)
        self.assertTrue(cksum == new_cksum, "Backing store changed! '%s' != '%s'" % (cksum, new_cksum))

        # now start with -snapshot, which puts the snapshot in /tmp/ somewhere
        print "  start with -snapshot"
        args = ['-snapshot'] + self.qemu_args
        self._start_vm(disk=orig, my_args=args)

        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = " file=/tmp/"
        else:
            if self.lsb_release['Release'] >= 14.04:
                search = " /var/tmp/"
            else:
                search = " /tmp/"
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = " backing_file=%s" % orig
        else:
            search = " Backing file:     %s" % orig
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print "  stop and verify backing store"
        self._stop_vm()
        new_cksum = testlib.get_md5(orig)
        self.assertTrue(cksum == new_cksum, "Backing store changed! '%s' != '%s'" % (cksum, new_cksum))

    def test_qemu_drive_ops(self):
        '''Test qemu drive operations (add/hotplug/hotunplug)'''
        dummy = os.path.join(self.tmpdir, "dummy.raw")
        scsi = os.path.join(self.tmpdir, "scsi.raw")
        virtio = os.path.join(self.tmpdir, "virtio.raw")

        print ""

        for d in [dummy, scsi, virtio]:
            # create source file as raw
            rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', 'raw', d, '5.0M'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(d), "Could not find '%s'" % (d))

        # add the drive
        print "  add dummy drive"
        drive_id = "drive-dummy"
        report = self._monitor_cmd("drive_add dummy file=%s,if=none,id=%s" % (dummy, drive_id))
        report = self._monitor_cmd("info block")

        if apt_pkg.version_compare(self.qemu_version, '1:2.5') < 0:
            search = "%s: " % drive_id
        else:
            search = "%s " % drive_id

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % dummy
        else:
            search = "%s" % dummy
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # delete the drive
        print "  delete dummy drive (drive_del)",
        if self.lsb_release['Release'] < 11.04:
            # drive_del doesn't exist in Maverick and earlier
            print "(skipped: drive_del does not exist)"
        else:
            report = self._monitor_cmd("drive_del %s" % drive_id)
            report = self._monitor_cmd("info block")
            search = "%s: " % drive_id
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
                search = "file=%s" % dummy
            else:
                search = "%s" % dummy
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            print ""

        # hotplug a scsi drive
        print "  hotplug scsi drive"
        device_id = "device-scsi0-0-1"

        if self.lsb_release['Release'] < 14.04:
            report = self._monitor_cmd("pci_add auto storage file=%s,if=scsi,id=%s" % (scsi, device_id))
        else:
            self._monitor_cmd("device_add driver=lsi")
            report = self._monitor_cmd("drive_add 0 file=%s,if=none,id=%s" % (scsi, device_id))
            self._monitor_cmd("device_add scsi-hd,drive=%s"%(device_id))

        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            self.assertTrue("OK domain" in report, "Could not find 'OK' in report:\n" + report)
        else:
            self.assertTrue("OK" in report, "Could not find 'OK' in report:\n" + report)
        domain = report.split(',')[0][-1]
        bus = report.split(',')[1][-1]
        slot = report.split(',')[2][-1]

        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % scsi
        else:
            search = "%s" % scsi
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        if apt_pkg.version_compare(self.qemu_version, '1:2.5') < 0:
            search = "%s: " % device_id
        else:
            search = "%s " % device_id

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # hotunplug a scsi drive
        print "  hotunplug scsi drive (drive_del)",
        if self.lsb_release['Release'] < 11.04:
            # drive_del doesn't exist in Maverick and earlier
            print "(skipped: drive_del does not exist)"
        else:
            report = self._monitor_cmd("drive_del %s" % (device_id))
            report = self._monitor_cmd("info block")
            if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
                search = "file=%s" % scsi
            else:
                search = "%s" % scsi
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            search = "%s: " % device_id
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            print ""

        # hotplug a virtio drive
        print "  hotplug virtio drive"
        device_id = "device-virtio0-0-1"

        if self.lsb_release['Release'] < 14.04:
            report = self._monitor_cmd("pci_add auto storage file=%s,if=virtio,id=%s" % (virtio, device_id))
        else:
            report = self._monitor_cmd("drive_add 0 if=none,file=%s,id=%s" % (virtio, device_id))

        self.assertTrue("OK" in report, "Could not find 'OK' in report:\n" + report)

        report = self._monitor_cmd("info block")
        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % virtio
        else:
            search = "%s" % virtio
        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        if apt_pkg.version_compare(self.qemu_version, '1:2.5') < 0:
            search = "%s: " % device_id
        else:
            search = "%s " % device_id

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # hotunplug a virtio drive
        print "  hotunplug virtio drive (drive_del)",
        if self.lsb_release['Release'] < 11.04:
            # drive_del doesn't exist in Maverick and earlier
            print "(skipped: drive_del does not exist)"
        else:
            report = self._monitor_cmd("drive_del %s" % (device_id))
            report = self._monitor_cmd("info block")
            if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
                search = "file=%s" % virtio
            else:
                search = "%s" % virtio
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            search = "%s: " % device_id
            result = "Found '%s' in report" % search
            self.assertTrue(search not in report, result + report)
            print ""


class QemuCapabilities(QemuCommon):
    '''Tests for qemu capabilities'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_machine(self):
        '''Test -M'''
        machine_types = ['pc', 'isapc', 'pc-0.10', 'pc-0.11', 'pc-0.12']
        if self.lsb_release['Release'] >= 11.04:
            machine_types += ['pc-0.13', 'pc-0.14']

        emulator='qemu-system-i386'
        if self.lsb_release['Release'] < 12.04:
            emulator = "qemu"
        rc, report = testlib.cmd([emulator, '-M', '?'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print ""
        for m in machine_types:
            print "  %s" % m

            regex = "^%s\s" % m
            result = "Could not find '%s' in report" % regex
            self.assertTrue(re.search(regex, report, re.MULTILINE), result + report)

            # Can we start with the machine type?
            args = ['-M', m] + self.qemu_args
            self._start_vm(disk=self.vmimg, my_args=args)
            self._stop_vm()

    def test_devices(self):
        '''Test -device'''
        # To Update:
        # $ qemu-system-i386 -M pc -device ? 2>&1 | sort > /tmp/old
        # $ qemu-system-i386 -M pc -device ? 2>&1 | sort > /tmp/new
        # $ diff -Naur /tmp/old /tmp/new
        #

        # These are common to all releases
        devices = [
                   'AC97',
                   'cirrus-vga',
                   'e1000',
                   'ES1370',
                   'i6300esb',
                   'i82550',
                   'i82551',
                   'i82557a',
                   'i82557b',
                   'i82557c',
                   'i82558a',
                   'i82558b',
                   'i82559a',
                   'i82559b',
                   'i82559c',
                   'i82559er',
                   'i82562',
                   'ib700',
                   'ide-drive',
                   'isa-ide',
                   'isa-parallel',
                   'isa-serial',
                   'lsi53c895a',
                   'ne2k_isa',
                   'ne2k_pci',
                   'pcnet',
                   'piix3-usb-uhci',
                   'piix4-usb-uhci',
                   'rtl8139',
                   'sb16',
                   'scsi-disk',
                   'scsi-generic',
                   'usb-braille',
                   'usb-host',
                   'usb-hub',
                   'usb-kbd',
                   'usb-mouse',
                   'usb-net',
                   'usb-serial',
                   'usb-storage',
                   'usb-tablet',
                   'usb-wacom-tablet',
                   'VGA',
                   'virtio-balloon-pci',
                   'virtio-blk-pci',
                   'virtio-net-pci',
                   'vmware-svga',
                  ]

        # devices only in Lucid
        if self.lsb_release['Release'] == 10.04:
            devices += ['ads7846',
                        'ds1338',
                        'escc',
                        'esp',
                        'i440FX',
                        'i440FX-pcihost',
                        'i8042',
                        'isabus-bridge',
                        'isa-fdc',
                        'lan9118',
                        'lm8323',
                        'm48t59',
                        'm48t59_isa',
                        'max1110',
                        'max1111',
                        'max7310',
                        'mc146818rtc',
                        'pci-bridge',
                        'PIIX3',
                        'piix3-ide',
                        'piix4-ide',
                        'smc91c111',
                        'ssi-sd',
                        'tmp105',
                        'twl92230',
                        'virtio-console-pci',
                        'wm8750',
                       ]

        # devices only in Quantal and earlier
        if self.lsb_release['Release'] < 13.04:
            devices += [
                        'pci-assign',
                        'testdev',
                       ]

        # devices only in Saucy and earlier
        if self.lsb_release['Release'] < 14.04:
            devices += [
                        'smbus-eeprom',
                        'SUNW,fdtwo',
                        'sysbus-fdc',
                       ]

        # devices in Precise and higher
        elif self.lsb_release['Release'] >= 12.04:
            devices += ['hda-duplex',
                        'hda-output',
                        'i82801',
                        'ich9-ahci',
                        'intel-hda',
                        'ioh3420',
                        'ide-hd',      # needs a disk
                        'ide-cd',      # needs a disk
                        'isa-applesmc',
                        'isa-debugcon',
                        'ivshmem',
                        'pci-ohci',
                        'scsi-hd',     # needs a disk
                        'scsi-cd',     # needs a disk
                        'usb-bt-dongle',
                        'virtconsole',
                        'virtio-9p-pci',
                        'virtio-serial-pci',
                        'virtserialport',
                        'vt82c686b-usb-uhci',
                        'x3130-upstream',
                        'xio3130-downstream',
                       ]

        # devices in Precise to saucy
        elif self.lsb_release['Release'] in [12.04, 12.10, 13.10]:
            devices += ['sysbus-ohci',]

        emulator='qemu-system-i386'
        if self.lsb_release['Release'] < 12.04:
            emulator = "qemu"
        rc, report = testlib.cmd([emulator, '-M', 'pc', '-device', '?'])
        print ""
        devices.sort()
        for d in devices:
            print "  %s" % d,
            regex = '^name "%s",\s' % d
            result = "Could not find '%s' in report" % regex
            self.assertTrue(re.search(regex, report, re.MULTILINE), result + report)

            # Can we start with the device? (excepting problematic ones)
            no_start_devices = [
                     'debugcon',          # needs char device
                     'hda-duplex',        # investigate
                     'hda-output',        # investigate
                     'ide-drive',         # needs arg
                     'i440FX',            # needs arg
                     'isa-debugcon',      # needs char device
                     'isa-fdc',           # hang
                     'isa-ide',           # hang
                     'isa-parallel',      # needs char device
                     'isa-serial',        # hang
                     'ivshmem',           # needs 'chardev' or 'shm'
                     'ne2k_isa',          # hang
                     'pci-assign',        # needs arg
                     'PIIX3',             # needs arg
                     'piix3-ide',         # needs arg
                     'piix4-ide',         # needs arg
                     'scsi-disk',         # needs a disk
                     'scsi-generic',      # needs a scsi bus
                     'SUNW,fdtwo',        # investigate
                     'usb-braille',       # needs char device
                     'usb-serial',        # needs char device
                     'usb-storage',       # needs arg
                     'virtconsole',       # needs virtio-serial-bus
                     'virtio-blk-pci',    # needs arg
                     'virtserialport',    # needs virtio-serial-bus
                    ]

            if self.lsb_release['Release'] < 11.04:
                no_start_devices += [
                     'ads7846',           # needs SSI bus
                     'ds1338',            # needs I2C bus
                     'i440FX-pcihost',    # not via command line
                     'i8042',             # not via command line
                     'isabus-bridge',     # not via command line
                     'lm8323',            # needs I2C bus
                     'm48t59',            # hang
                     'm48t59_isa',        # hang
                     'max1110',           # needs SSI bus
                     'max1111',           # needs SSI bus
                     'max7310',           # needs I2C bus
                     'mc146818rtc',       # not via command line
                     'smbus-eeprom',      # needs I2C bus
                     'ssi-sd',            # needs SSI bus
                     'tmp105',            # needs I2C bus
                     'twl92230',          # needs I2C bus
                     'virtio-console-pci',# needs arg
                     'wm8750',            # needs I2C bus
                    ]

            if self.lsb_release['Release'] >= 10.10:
                no_start_devices += [
                     'usb-bt-dongle',     # needs arg
                    ]

            if self.lsb_release['Release'] >= 11.10:
                no_start_devices += [
                     'virtio-9p-pci',     # "Virtio-9p device couldn't find fsdev with the id = NULL"
                    ]

            if self.lsb_release['Release'] >= 12.04:
                no_start_devices += [
                     'ide-hd',     # needs a disk
                     'ide-cd',     # needs a disk
                     'scsi-hd',     # needs a disk
                     'scsi-cd',     # needs a disk
                    ]

            if d in no_start_devices:
                print "(skipping start)"
                continue
            print ""
            sys.stdout.flush()
            args = ['-device', d] + self.qemu_args
            self._start_vm(disk=self.vmimg, my_args=args)
            self._stop_vm()

class QemuCVEs(QemuCommon):
    '''Reproducers for CVEs'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_CVE_2011_1751(self):
        '''Test CVE-2011-1751 (may take a while)'''
	# This test does not work well on 10.04 LTS (and presumably earlier.
        # On 10.04 LTS need to test manually with:
        # 1. start VM with (at least) '-M pc-0.10 -clock dynticks -rtc base=utc -monitor tcp:127.0.0.1:4444,server,nowait'
        # 2. echo 'info pci' | nc -q 1 127.0.0.1 4444
        # 3. verify '1, function 2:' is in the output
        # 4. echo 'o 0xae08 2' | nc -q 1 127.0.0.1 4444
        # 5. verify 'o 0xae08 2' is in the output
        # 6. echo 'info pci' | nc -q 1 127.0.0.1 4444 # do this several times
        # 7. verify the machine did not crash (ie, qemu is still running)
        # 8. echo 'info pci' | nc -q 1 127.0.0.1 4444
        # 9. verify '1, function 2:' is not in the output

        if self.lsb_release['Release'] < 10.10:
            return self._skipped("not reliable on 10.04 and earlier")

        # FIXME: is this a regression?
        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("TODO: causes failure on 12.10 and later")

        print ""
        args = ['-M', 'pc-0.10', '-clock', 'dynticks'] + self.qemu_args

        # This doesn't always fail reliably, but usually can every few VM
        # starts
        i = 1
        while i < 10:
            print "  attempt %d..." % i
            i += 1
            sys.stdout.flush()
            self._start_vm(disk=self.vmimg, my_args=args)

            # This device is removed when sending '2' to 0xae08
            device_search = "1, function 2:"
            report = self._monitor_cmd("info pci")
            result = "Could not find '%s' in report" % device_search
            self.assertTrue(device_search in report, result + report)

            report = self._monitor_cmd("o 0xae08 2")
            search = "o 0xae08 2"
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            # Run 'info pci' a few times after the ioport command to make the
            # failure reliable.
            count = 0
            while count < 5:
                self._monitor_cmd("info pci")
                count += 1
                self._check_vm_is_running()

            # make sure device was removed
            device_search = "1, function 2:"
            report = self._monitor_cmd("info pci")
            result = "Found '%s' in report" % device_search
            self.assertTrue(device_search not in report, result + report)

            self._stop_vm()

class QemuGuestCommon(QemuCommon):
    '''Common functions for guest tests'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        global cleanup_other_vm
        unpack_vm = True
        if cleanup_other_vm:
            unpack_vm = False
        QemuCommon._setUp(self, unpack_vm=unpack_vm)

        global guest_virtio_vm_tarball

        if cleanup_other_vm:
            global guest_vm_tarball
            other_vm_dir = os.path.join(os.path.dirname(guest_vm_tarball), "qatest")
            if os.path.exists(other_vm_dir):
                print >>sys.stdout, "  removing '%s'" % (other_vm_dir)
                testlib.recursive_rm(other_vm_dir)

        if not os.path.exists(self.vmimg_virtio_orig):
            if os.path.exists(self.vmtarball_virtio):
                print >>sys.stdout, "  untarring '%s'  " % (self.vmtarball_virtio)
                sys.stdout.flush()
                testlib.cmd(['tar', '-C', 'qemu', '-jxf', self.vmtarball_virtio])
            else:
                raise ValueError, "Couldn't find '%s'" % (self.vmtarball_virtio)

        if not os.path.exists(self.vmimg_virtio):
            print >>sys.stdout, "  creating qcow2 '%s' from '%s'" % (self.vmimg_virtio, self.vmimg_virtio_orig)
            rc, report = testlib.cmd([self.qemuimg_exe, 'convert', '-f', 'raw', self.vmimg_virtio_orig, '-O', 'qcow2', self.vmimg_virtio])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(self.vmimg_virtio), "Could not find '%s'" % (self.vmimg_virtio))

        self.ssh_args += ['-i', os.path.join(os.path.dirname(guest_virtio_vm_tarball), 'qatest-virtio/ssh/qatest-virtio.id_rsa'),
                          '-oUserKnownHostsFile=%s' % os.path.join(os.path.dirname(guest_virtio_vm_tarball), 'qatest-virtio/ssh/known_hosts'),
                         ]

        self.qemu_args += ['-drive', 'file=%s,if=none,id=drive-virtio-disk0,boot=on,format=qcow2' % (self.vmimg_virtio), '-device', 'virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0']

    def _tearDown(self):
        '''Clean up after each test_* function'''
        QemuCommon._tearDown(self)

    def _start_vm(self, disk, emulator="qemu-system-i386", nic=None, my_args=None):
        '''Start VM, waiting until it is able to receive ssh commands'''
        if emulator == "qemu-system-i386" and self.lsb_release['Release'] < 12.04:
            emulator = "qemu"
        timeout_interval = 3
        print " (starting vm and waiting for response (this may take a while)"
        QemuCommon._start_vm(self, disk=disk, emulator=emulator, nic=nic, my_args=my_args)

        args = self.ssh_args + ["%s@%s" % (self.ssh_user, self.monitor_ip), 'uptime']
	idx = args.index('ConnectTimeout=60') # if we don't have this in args, just
                                        # explode
        args[idx] = 'ConnectTimeout=%d' % timeout_interval
        rc, report = testlib.cmd(['ssh'] + args)
        count = 0
	while rc == 255 and count < 60: # 255 is what is returned with
                                        # 'ssh_exchange_identification' error.
                                        # Yes, wait up to 180 seconds.
            rc, report = testlib.cmd(['ssh'] + args)
            count += 1

            time.sleep(timeout_interval)

    def _ssh_cmd(self, cmd, search=None, user=None, host=None, with_assert=True):
        '''Run a command in the guest'''
        if user == None:
            user = self.ssh_user
        if host == None:
            host = self.monitor_ip

        args = self.ssh_args + ["%s@%s" % (user, host)] + cmd
        #print "DEBUG: %s" % " ".join(args)

        rc, report = testlib.cmd(['ssh'] + args)
        count = 0
        while rc == 255 and count < 5: # try again if ssh_exchange_identification error
            count += 1
            time.sleep(5)
            rc, report = testlib.cmd(['ssh'] + args)

        if with_assert:
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        if search != None:
            result = "Could not find '%s' in report" % search
            self.assertTrue(search in report, result + report)

        return report

    def _do_slirp_tests(self):
        '''Common disk networking checks'''
        print "  ifconfig"
        self._ssh_cmd(['ifconfig'], search="eth0")

        print "  /proc/net/dev"
        self._ssh_cmd(['cat', '/proc/net/dev'], search="eth0")

        for h in [ self.qemunet_gateway, self.qemunet_ip ]:
            print "  ping %s" % h
            self._ssh_cmd(['ping', '-c', '1', h], search="1 packets transmitted, 1 received, 0% packet loss")

        print "  dns for www.ubuntu.com"
        self._ssh_cmd(['host', 'www.ubuntu.com'], search="www.ubuntu.com has address ")

    def _do_disk_access_tests(self, topdir="/"):
        '''Common disk access checks'''
        etc_dir = "/etc"
        tmp_dir = "/tmp"
        if topdir != "/":
            etc_dir = os.path.join(topdir, "etc")
            self._ssh_cmd(['mkdir', etc_dir], user="root")
            self._ssh_cmd(['cp', "/etc/hosts", etc_dir], user="root")

            tmp_dir = os.path.join(topdir, "tmp")
            self._ssh_cmd(['mkdir', tmp_dir], user="root")
            self._ssh_cmd(['chmod', '1777', tmp_dir], user="root")

        print "  recursive find"
        self._ssh_cmd(['find', etc_dir, '-name', 'hosts'], search="%s" % os.path.join(etc_dir, "hosts"), user="root")

        print "  read"
        self._ssh_cmd(['cat', os.path.join(etc_dir, "hosts")], search="127.0.0.1")

        print "  stat"
        self._ssh_cmd(['stat', os.path.join(etc_dir, "hosts")], search="File: `%s'" % os.path.join(etc_dir, "hosts"))

        print "  write"
        fn = os.path.join(tmp_dir, 'foo')
        self._ssh_cmd(['touch', fn])
        self._ssh_cmd(['stat', fn], search="File: `%s'" % fn)
        fn = os.path.join(tmp_dir, 'bar')
        self._ssh_cmd(['cp', '/etc/hosts', fn])
        self._ssh_cmd(['stat', fn], search="File: `%s'" % fn)
        self._ssh_cmd(['cat', fn], search="127.0.0.1")

    def _hotunplug_disk(self, addr="0:0x8", device_id="device-disk0-0-2"):
        '''Hotunplug a disk'''
        if self.lsb_release['Release'] < 14.04:
            print "  hotunplug drive (pci_del)"
            self._monitor_cmd("pci_del pci_addr=%s" % (addr))
        else:
            print "  hotunplug drive (device_del)"
            self._monitor_cmd("device_del %s" % (device_id))
        time.sleep(3)
        report = self._monitor_cmd("info block")
        search = "%s: " % device_id
        result = "Found '%s' in report" % search
        self.assertTrue(search not in report, result + report)


    def _hotplug_disk(self, disk_type="virtio", addr="0:0x8", device_id="device-disk0-0-2"):
        '''Hotplug a disk'''
        guest_device = "/dev/vdb" # we assume we are using the qatest-virtio
                                  # image, which already has /dev/vda
        if disk_type == "scsi" or disk_type == "usb":
            guest_device = "/dev/sda"

        if disk_type != "usb":
            print "  acpiphp loaded"
            self._ssh_cmd(['modprobe', 'acpiphp'], user="root") # this module is needed for hotplugging
            self._ssh_cmd(['lsmod'], search="acpiphp")

        disk = os.path.join(self.tmpdir, "disk.raw")

        # create a disk source file as raw
        size = '20M'
        rc, report = testlib.cmd([self.qemuimg_exe, 'create', '-f', 'raw', disk, '20M'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(os.path.exists(disk), "Could not find '%s'" % (disk))

        # hotplug a drive
        if self.lsb_release['Release'] < 14.04:
            if disk_type == "usb":
                print "  plug in USB drive (sleeping 10 seconds to let usb-storage pick it up)"
                self._monitor_cmd("drive_add 0 file=%s,if=none,id=%s" % (disk, device_id))
                self._monitor_cmd("device_add usb-storage,id=%s,drive=%s" % (device_id, device_id))
                time.sleep(10) # needed to let the device to settle before scanning
            else:
                print "  hotplug disk drive"
                report = self._monitor_cmd("pci_add pci_addr=%s storage file=%s,if=%s,id=%s" % (addr, disk, disk_type, device_id))
                self.assertTrue("OK" in report, "Could not find 'OK' in report:\n" + report)
        else:
            disk_type_to_device = {'scsi': 'scsi-disk', 'virtio': 'virtio-blk-pci', 'usb': 'usb-storage' }
            device = disk_type_to_device[disk_type]
            print "  hotplug %s drive" %(disk_type)
            report = self._monitor_cmd("drive_add 0 file=%s,if=none,id=%s" % (disk, device_id))
            # check if drive_add is OK
            self.assertTrue("OK" in report, "Could not find 'OK' in report:\n" + report)

            # add a scsi controller, if needed
            if disk_type == "scsi": 
                self._monitor_cmd("device_add driver=lsi")

            # attach the drive to a guest device
            self._monitor_cmd("device_add %s,id=%s,drive=%s" % (device, device_id, device_id))

        report = self._monitor_cmd("info block")

        if apt_pkg.version_compare(self.qemu_version, '1.6') < 0:
            search = "file=%s" % disk
        else:
            search = "%s" % disk

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        if apt_pkg.version_compare(self.qemu_version, '1:2.5') < 0:
            search = "%s: " % device_id
        else:
            search = "%s " % device_id

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print "  partition hotplugged drive"
        time.sleep(5)
        search = "unknown partition table"
        self._ssh_cmd(['dmesg'], search, user="root")
        self._ssh_cmd(['parted', '-s', guest_device, 'mklabel', 'msdos'], user="root")
        self._ssh_cmd(['parted', '-s', guest_device, 'mkpart', 'primary', 'ext2', '0', size], user="root")

        print "  create filesystem on hotplugged drive"
        guest_device += "1"
        self._ssh_cmd(['mke2fs', guest_device], search="This filesystem will be automatically checked", user="root")

        print "  mount %s" % guest_device
        self._ssh_cmd(['mount', guest_device, '/mnt'], user="root")

        print "  %s used" % guest_device
        self._ssh_cmd(['df'], search=guest_device)

        self._do_disk_access_tests(topdir="/mnt")

        print "  umount %s" % guest_device
        self._ssh_cmd(['sync'], user="root")
        self._ssh_cmd(['umount', guest_device], user="root")

        print "  %s id not used" % guest_device
        report = self._ssh_cmd(['df'])
        search = guest_device
        result = "Found '%s' in report" % search

class QemuGuest(QemuGuestCommon):
    '''Guest tests'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        QemuGuestCommon._setUp(self)
        self._start_vm(disk=None, nic="e1000") # disk is specified via -drive in _setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        QemuGuestCommon._tearDown(self)

    def test_nic(self):
        '''Test network interfaces'''
        print ""

        for i in ['e1000', 'ne2k_pci', 'rtl8139', 'pcnet', 'i82551', 'i82557b', 'i82559er']:
            print ' %s:' % i
            self._stop_vm()
            self._start_vm(disk=None, nic=i) # disk is specified via -drive in _setUp()
            # wait for ssh to come up properly
            time.sleep(2)
            self._do_slirp_tests()

    def test_scsi(self):
        '''Test scsi'''
        if self.lsb_release['Release'] in [ 12.10, 13.04 ]:
            return self._skipped("FIXME: test doesn't work on 12.10, 13.04")

        print ""
        self._hotplug_disk(disk_type="scsi")
        self._hotunplug_disk()

    def test_usb_disk(self):
        '''Test USB disk'''

        if self.lsb_release['Release'] < 12.04:
            return self._skipped("FIXME: test doesn't work on 10.04")

        print ""
        self._hotplug_disk(disk_type="usb")
        if self.lsb_release['Release'] < 14.04:
            print "  TODO: unplug disk"
        else:
            self._hotunplug_disk()


class QemuGuestVirtio(QemuGuestCommon):
    '''Virtio tests'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        QemuGuestCommon._setUp(self)
        args = ['-net', 'nic,model=virtio'] + self.qemu_args
        self._start_vm(disk=None, my_args=args) # disk is specified via -drive in _setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        QemuGuestCommon._tearDown(self)

    def test_virtio_disk(self):
        '''Test virtio disk'''
        print ""
        print "  virtio_blk loaded"
        self._ssh_cmd(['lsmod'], search="virtio_blk")

        print "  /dev/vda1 used"
        self._ssh_cmd(['df'], search="/dev/vda1")

        self._do_disk_access_tests()

    def test_virtio_disk_hotplugged(self):
        '''Test virtio hotplugged disk'''
        print ""
        print "  virtio_blk loaded"
        self._ssh_cmd(['lsmod'], search="virtio_blk")

        self._hotplug_disk(disk_type="virtio")
        self._hotunplug_disk()

    def test_virtio_net(self):
        '''Test virtio net'''
        print ""
        print "  virtio_net loaded"
        self._ssh_cmd(['lsmod'], search="virtio_net")

        self._do_slirp_tests()

    def test_virtio_nic_hotplugged(self):
        '''Test virtio hotplug nic'''

        # FIXME: can't figure out syntax on Quantal+
        # Attempting to add device fails with the following error:
        # Property 'virtio-net-pci.netdev' can't take value 'hub0port0', it's in use
        if self.lsb_release['Release'] in [ 12.10, 13.04 ]:
            return self._skipped("FIXME: test doesn't work on 12.10, 13.04")

        addr = "0:0x8"
        device_id = "testlibnet"
        print ""
        print "  acpiphp loaded"
        self._ssh_cmd(['modprobe', 'acpiphp'], user="root") # this module is needed for hotplugging
        self._ssh_cmd(['lsmod'], search="acpiphp")

        # verify the device isn't already there
        report = self._monitor_cmd("info pci")
        search = '  Bus  0, device   8, function 0'
        result = "Found '%s' in report" % search
        self.assertTrue(search not in report, result + report)

        print "  hotplug nic"
        if self.lsb_release['Release'] < 13.10:
            report = self._monitor_cmd("pci_add pci_addr=%s nic model=virtio,id=%s" % (addr, device_id))
            self.assertTrue("OK" in report, "Could not find 'OK' in report:\n" + report)
            report = self._monitor_cmd("info pci")
            search = '  Bus  0, device   8, function 0'
        else:
            self._monitor_cmd("device_add virtio-net-pci,id=%s" % (device_id))
            report = self._monitor_cmd("info network")
            self.assertTrue("%s"%(device_id) in report, "Could not find '%s' in report:\n"%(device_id) + report)
            report = self._monitor_cmd("info pci")
            search = device_id

        result = "Could not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print "  hotunplug nic"
        if self.lsb_release['Release'] < 13.10:
            self._monitor_cmd("pci_del pci_addr=%s" % (addr))
        else:
            self._monitor_cmd("device_del %s" % (device_id))
        report = self._monitor_cmd("info pci")
        search = '  Bus  0, device   8, function 0'
        result = "Found '%s' in report" % search
        self.assertTrue(search not in report, result + report)


class QemuMisc(QemuCommon):
    '''Example class for developing qemu tests'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self.runas_user = None

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self.runas_user = None

    def test_aa_runas(self):
        '''Test runas'''
        if os.getuid() != 0:
            return self._skipped("need to run as root")
        self.runas_user = testlib.TestUser()

        args = ['-runas', self.runas_user.login] + self.qemu_args
        self._start_vm(disk=self.vmimg, my_args=args)

        try:
            fd = open(self.qemu_pidfile, 'r')
        except:
            raise
        pid = fd.readline().rstrip('\n')
        fd.close()

        try:
            fd = open("/proc/%s/status" % pid, 'r')
        except:
            raise
        uid = None
        for line in fd.readlines():
            if not line.startswith("Uid:"):
                continue
            uid = line.split()[1]
            break
        fd.close()

        self.assertFalse(uid == None, "Could not find uid for process")
        self.assertTrue(uid != 0, "uid is '0'")
        self.assertTrue(self.runas_user.uid == int(uid), "runas id (%d) != '%s'" % (self.runas_user.uid, uid))


class QemuStub(QemuCommon):
    '''Example class for developing qemu tests'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_aa_stub(self):
        '''Qemu test stub'''
        self._start_vm(disk=self.vmimg)
        print '''Use:
$ echo 'qemu-system-i386 monitor command' | nc %s %s
Eg:
$ echo 'info block' | nc %s %s''' % (self.monitor_ip, self.monitor_port, self.monitor_ip, self.monitor_port)
        subprocess.call(['bash'])


if __name__ == '__main__':
    if not os.path.exists(guest_vm_tarball):
        print >>sys.stderr, "Could not find '%s'" % guest_vm_tarball
        print >>sys.stderr, "Please see %s/README.qatest for more information." % os.path.dirname(guest_vm_tarball)
        sys.exit(1)

    if not os.path.exists("/proc/net/dev"):
        print >>sys.stderr, "Could not find '/proc/net/dev'. Please make sure /proc is mounted."
        sys.exit(1)

    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-c", "--compact", dest="compact", help="Remove other VM to save space", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")

    (options, args) = parser.parse_args()

    if hasattr(options, 'help'):
        parser.print_help()
        sys.exit(0)

    verbosity = 1
    if options.verbose:
        verbosity = 2

    # more configurable
    suite = unittest.TestSuite()

    if options.compact:
        cleanup_other_vm = True

        # do some pre-cleanup
        other_vm_dir = os.path.join(os.path.dirname(guest_virtio_vm_tarball), "qatest-virtio")
        if os.path.exists(other_vm_dir):
            print >>sys.stdout, "  removing '%s'" % (other_vm_dir)
            testlib.recursive_rm(other_vm_dir)

        other_vm_dir = os.path.join(os.path.dirname(guest_vm_tarball), "qatest")
        if os.path.exists(other_vm_dir):
            print >>sys.stdout, "  removing '%s'" % (other_vm_dir)
            testlib.recursive_rm(other_vm_dir)

    # these tests use libvirt/qatest
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuMonitor))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuImage))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuMisc))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuCVEs))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuCapabilities))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuPrivateTest))

    # IMPORTANT: these tests use qemu/qatest-virtio and most be listed after
    # the tests that use libvirt/qatest
    if not os.path.exists(guest_virtio_vm_tarball):
        print >>sys.stderr, "WARN: could not find '%s'. Some tests will be skipped" % guest_vm_tarball
        print >>sys.stderr, "Please see %s/README.qatest-virtio for more information." % os.path.dirname(guest_virtio_vm_tarball)
    else:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuGuest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuGuestVirtio))

    # example class
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(QemuStub))

    rc = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
