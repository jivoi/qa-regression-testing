#!/usr/bin/python
#
#    test-util-linux.py quality assurance test script for util-linux tools
#    Copyright (C) 2008-2010 Canonical Ltd.
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

'''
  How to run in a VM:
    $ sudo ./test-util-linux.py -v

  TODO:
    - test the other utils that aren't included here
    - perform more than run tests on a few tools
'''
# QRT-Depends: util-linux
# QRT-Alternates: loop-aes-utils
# QRT-Privilege: root

import unittest
import testlib
import os
import tempfile
import sys


class BsdUtilsTest(testlib.TestlibCase):
    '''Test bsdutils package functionality'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpname = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpname):
            os.unlink(self.tmpname)

    def test_logger(self):
        '''Test logger'''
        if self.lsb_release['Release'] >= 11.04:
            logfile = "/var/log/syslog"
        else:
            logfile = "/var/log/messages"

        unique_string = testlib.random_string(10)

        rc, report = testlib.cmd(['logger', '-t', 'test-util-linux', 'Random String: ' + unique_string])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['grep', unique_string, logfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_wall(self):
        '''Test wall'''
        handle, self.tmpname = testlib.mkstemp_fill("Testing wall...this message can be ignored...")
        rc, report = testlib.cmd(['wall'], stdin=handle)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        os.unlink(self.tmpname)

    def test_renice(self):
        '''Test renice'''
        our_pid = os.getpid()

        # Get our old priority
        rc, report = testlib.cmd(['cut', '-d', ' ', '-f', '19', '/proc/%s/stat' % our_pid])
        old_priority = int(report)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Use renice to up it by 1
        rc, report = testlib.cmd(['renice', '%s' % (old_priority + 1), '-p', '%s' % our_pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure it got changed
        rc, report = testlib.cmd(['cut', '-d', ' ', '-f', '19', '/proc/%s/stat' % our_pid])
        priority = int(report)
        result = 'Got priority %d, expected %d\n' % (priority, old_priority + 1)
        self.assertEquals(priority, old_priority + 1, result)

        # Use renice to lower it back
        rc, report = testlib.cmd(['renice', '%s' % old_priority, '-p', '%s' % our_pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure it got changed back
        rc, report = testlib.cmd(['cut', '-d', ' ', '-f', '19', '/proc/%s/stat' % our_pid])
        priority = int(report)
        result = 'Got priority %d, expected %d\n' % (priority, old_priority)
        self.assertEquals(priority, old_priority, result)

    def test_script(self):
        '''Test script'''
        handle, self.tmpname = tempfile.mkstemp(prefix='testlib', dir='/tmp')
        rc, report = testlib.cmd(['script', '-c', 'ls /', self.tmpname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure the file contains what we're expecting
        rc, report = testlib.cmd(['cat', self.tmpname])
        for i in ['etc', 'Script done']:
            result = "Couldn't find '%s:' in report" % i
            self.assertTrue(i in report, result + report)

        os.unlink(self.tmpname)


class MountTest(testlib.TestlibCase):
    '''Test mount package functionality'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_mount(self):
        '''Test mount'''
        test_iso = 'util-linux/test.iso'
        test_file = 'testfile.txt'

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        # mount the iso file
        rc, report = testlib.cmd(['mount', '-o', 'loop', test_iso, self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can see the file inside
        result = "Couldn't find testfile %s in mounted directory" % test_file
        self.assertTrue(os.path.exists('%s/%s' % (self.tmpdir, test_file)), result)

        # unmount it
        rc, report = testlib.cmd(['umount', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure we can't see the file anymore
        result = "Found testfile %s in mounted directory" % test_file
        self.assertFalse(os.path.exists('%s/%s' % (self.tmpdir, test_file)), result)

        testlib.recursive_rm(self.tmpdir)

    def test_fake_unmount(self):
        '''Test umount with --fake option'''

        # We didn't backport the --fake option to dapper
        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Skipped: Dapper doesn't have --fake option")

        # Make sure we actually have the --fake option first before
        # mounting stuff
        rc, report = testlib.cmd(['umount', '--fake', self.tmpdir])
        result = "umount doesn't have --fake option!\n"
        self.assertFalse("unrecognized option '--fake'" in report, result + report)

        test_iso = 'util-linux/test.iso'
        test_file = 'testfile.txt'

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        # mount the iso file
        rc, report = testlib.cmd(['mount', '-o', 'loop', test_iso, self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can see the file inside
        result = "Couldn't find testfile %s in mounted directory" % test_file
        self.assertTrue(os.path.exists('%s/%s' % (self.tmpdir, test_file)), result)

        # fake unmount it
        rc, report = testlib.cmd(['umount', '--fake', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can see the file inside
        result = "Couldn't find testfile %s in mounted directory" % test_file
        self.assertTrue(os.path.exists('%s/%s' % (self.tmpdir, test_file)), result)

        # unmount it for real
        rc, report = testlib.cmd(['umount', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure we can't see the file anymore
        result = "Found testfile %s in mounted directory" % test_file
        self.assertFalse(os.path.exists('%s/%s' % (self.tmpdir, test_file)), result)

        testlib.recursive_rm(self.tmpdir)

    def test_swapon(self):
        '''Test swapon'''
        # for now, just see if it runs
        rc, report = testlib.cmd(['swapon', '-s'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find 'Filename' in report"
        self.assertTrue('Filename' in report, result + report)

    def test_losetup(self):
        '''Test losetup'''
        # for now, just see if it runs
        rc, report = testlib.cmd(['losetup', '-f'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '/dev/loop' in report"
        self.assertTrue('/dev/loop' in report, result + report)


class UtilLinuxTest(testlib.TestlibCase):
    '''Test util-linux package functionality'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpname = ""
        self.tmpdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpname):
            os.unlink(self.tmpname)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_dmesg(self):
        '''Test dmesg'''
        rc, report = testlib.cmd(['dmesg'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # How can we test dmesg?
        result = "dmesg output is less than 300 bytes:"
        self.assertFalse(len(report) < 300, result + report)

    def test_mkswap(self):
        '''Test mkswap'''
        handle, self.tmpname = tempfile.mkstemp(prefix='testlib', dir='/tmp')

        rc, report = testlib.cmd(['dd', 'if=/dev/zero', 'of=%s' % self.tmpname, 'bs=1024', 'count=65536'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['mkswap', self.tmpname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['grep', 'SWAPSPACE2', self.tmpname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.unlink(self.tmpname)

    def test_fdisk(self):
        '''Test fdisk'''
        output_string = 'Device'
        rc, report = testlib.cmd(['fdisk', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_sfdisk(self):
        '''Test sfdisk'''
        output_string = 'Device'
        rc, report = testlib.cmd(['sfdisk', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_cfdisk(self):
        '''Test cfdisk'''
        output_string = 'Filesystem Type'

        # Figure out what the boot device is
        rc, out = self.shell_cmd(["mount"])
        self.assertEquals(rc, 0, "Could not call mount!")

        device = None
        for l in out.splitlines():
            fs = l.split(' ')[2]
            if fs == '/':
                d = l.split(' ')[0].strip()
                if '/dev/mapper' in d:
                    rc, out = self.shell_cmd(["pvs", "-o", "pv_name", "--noheadings"])
                    self.assertEquals(rc, 0, "Could not call pvs!")
                    d = out.strip()
                device = d.strip("0123456789")

        self.assertTrue(device is not None, "Could not determine device!")

        rc, report = testlib.cmd(['cfdisk', '-Ps', device])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_hwclock(self):
        '''Test hwclock'''
        # Test reading clock
        output_string = 'Time read from Hardware Clock'
        rc, report = testlib.cmd(['hwclock', '--show', '--debug', '--test'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

        # Test setting clock
        output_string = 'Setting Hardware Clock'
        rc, report = testlib.cmd(['hwclock', '--systohc', '--debug', '--test'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_isosize(self):
        '''Test isosize'''
        test_iso = 'util-linux/test.iso'
        test_iso_size = 358400

        rc, report = testlib.cmd(['isosize', test_iso])
        size = int(report)
        result = 'Got size %d, expected %d\n' % (size, test_iso_size)
        self.assertEquals(size, test_iso_size, result)

    def test_getopt(self):
        '''Test getopt'''
        getopt_parse = '/usr/share/doc/util-linux/examples/getopt-parse.bash'
        getopt_parse_results = """Option a
Option c, no argument
Option c, argument `more'
Option b, argument ` very long '
Remaining arguments:
--> `par1'
--> `another arg'
--> `wow!*\?'"""

        rc, report = testlib.cmd(['/bin/bash', getopt_parse, '-a', 'par1', 'another arg', '--c-long', 'wow!*\?', '-cmore', '-b', " very long "])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % getopt_parse_results
        self.assertTrue(getopt_parse_results in report, result + report)

    def test_mcookie(self):
        '''Test mcookie'''
        # just see if it runs
        rc, report = testlib.cmd(['mcookie'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_namei(self):
        '''Test namei'''
        namei_path = '/usr/share/doc/util-linux'
        namei_results = """f: /usr/share/doc/util-linux
 d /
 d usr
 d share
 d doc
 d util-linux"""

        rc, report = testlib.cmd(['namei', namei_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % namei_results
        self.assertTrue(namei_results in report, result + report)

    def test_whereis(self):
        '''Test whereis'''
        output_string = 'whereis: /usr/bin/whereis /usr/share/man/man1/whereis.1.gz'
        rc, report = testlib.cmd(['whereis', 'whereis'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_rename_ul(self):
        '''Test rename.ul'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        for x in range(10):
            testlib.cmd(['touch', self.tmpdir + '/foo%s' % x])

        rc, report = testlib.cmd(['/bin/bash', '-c', 'rename.ul foo foo0 ' + self.tmpdir + '/foo?'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for x in range(10):
            result = "File '%s' is missing" % x
            self.assertTrue(os.path.exists('%s/foo0%s' % (self.tmpdir, x)), result)

        testlib.recursive_rm(self.tmpdir)

    def test_chrt(self):
        '''Test chrt'''
        # for now, just see if it runs
        our_pid = os.getpid()

        output_string = 'SCHED_OTHER'
        rc, report = testlib.cmd(['chrt', '-p', '%s' % our_pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_ionice(self):
        '''Test ionice'''
        # for now, just see if it runs
        our_pid = os.getpid()

        output_string = 'none: prio'
        rc, report = testlib.cmd(['ionice', '-p%s' % our_pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_taskset(self):
        '''Test taskset'''
        # for now, just see if it runs
        our_pid = os.getpid()

        output_string = 'current affinity mask:'
        rc, report = testlib.cmd(['taskset', '-p', '%s' % our_pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_ipcs(self):
        '''Test ipcs'''
        # for now, just see if it runs
        output_string = 'Shared'
        rc, report = testlib.cmd(['ipcs'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_rev(self):
        '''Test rev'''
        input_string = 'UbuntuRocks'
        output_string = 'skcoRutnubU'

        rc, report = testlib.cmd_pipe(['echo', input_string], 'rev')
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

    def test_rdev(self):
        '''Test rdev'''
        # for now, just see if it runs
        output_string = '/'
        rc, report = testlib.cmd(['rdev'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % output_string
        self.assertTrue(output_string in report, result + report)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BsdUtilsTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MountTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UtilLinuxTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
