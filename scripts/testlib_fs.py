#!/usr/bin/python
#
#    testlib_fs.py quality assurance test script
#    Copyright (C) 2009 Canonical Ltd.
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
#    along with this program.  If not, see <httpd://www.gnu.org/licenses/>.
#

# QRT-Packages: lvm2

'''
    TODO:
      - device files
      - suid/sgid files and directories
      - MAXPATH check
      - deep directories
      - lots more
'''

import os
import stat
import sys
import tempfile
import testlib
import time

class FSCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self, type):
        '''Set up prior to each test_* function'''
        self.tmpdir = ""
        self.loop = ""
        self.mnt = ""
        self.img = ""
        self.img_size = 0
        self.debugfs = ""
        self.lvm_size = 0
        self.lv_path = ""
        self.type = type
        print "(%s) ... " % type,
        sys.stdout.flush()

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None
        self.user2 = None
        if self.debugfs != '':
            self._umount_fs(self.debugfs, loop=None)
        if self.lv_path != "" and self.loop != "":
            if self.mnt != '':
                self._umount_fs(self.mnt, loop=None, use_assert=False)

            time.sleep(3)
            self._destroy_lv(self.lv_path)

            rc, report = testlib.cmd(['losetup', '-d', self.loop])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
        elif self.mnt != '':
            self._umount_fs(self.mnt, self.loop, use_assert=False)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _mkfs(self, dev):
        '''Create fs on device (usually overridden)'''
        self._do_mkfs(self.type, dev, args)

    def _do_mkfs(self, type, dev, args=[]):
        '''Create fs on device'''
        cmd = ['mkfs', '-t', type]
        if len(args) > 0:
            cmd += args
        cmd += [dev]

        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _mount_fs(self, dev, mnt, args=[], type=None):
        '''Mount device on mountpoint'''
        if not type:
            type = self.type

        cmd = ['mount', '-t', type]
        if len(args) > 0:
            cmd += args
        cmd += [dev, mnt]

        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _get_size(self, mnt):
        '''Find filesystem size according to df'''
        rc, report = rc, report = testlib.cmd(['df', '-P'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '%s' in report" % mnt
        self.assertTrue(mnt in report, result + report)

        for line in report.splitlines():
            if mnt in line:
                return line.split()[1]

        return ""

    def _attach_to_loop_device(self, path):
        '''Attach file to loop device'''
        rc, report = testlib.cmd(['losetup', '-f'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find '/dev/loop' in report"
        self.assertTrue(report.startswith('/dev/loop'), result + report)

        dev = report.strip()

        rc, report = testlib.cmd(['losetup', dev, path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return dev

    def _create_dd(self, path, size):
        '''Create file with dd'''
        rc, report = testlib.cmd(['dd', 'if=/dev/zero', 'of=%s' % path, "bs=1M", "count=%s" % (str(size))])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "records in"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "records out"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def _destroy_lv(self, lv_path):
        '''Destroy LV, VG and PV'''
        if os.path.exists(lv_path):
            self._umount_fs(self.mnt, loop=None, use_assert=False)
            lv = os.path.basename(lv_path)
            vg = os.path.basename(os.path.dirname(lv_path))

            rc, report = testlib.cmd(['lvremove', '-f', lv_path])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(['vgremove', vg])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(['pvremove', self.loop])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def _create_lv(self, dd_path, size, vgname, lvname):
        '''Create PV, VG and LV'''
        rc, report = testlib.cmd(['modprobe', 'dm-mod'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertFalse(os.path.isdir("/dev/%s" % vgname), "volume group '%s' already exists" % vgname)
        self.lv_path = os.path.join("/dev", vgname, lvname)
        self.assertFalse(os.path.exists(self.lv_path), "logical volume '%s' already exists" % lvname)

        self.loop = self._attach_to_loop_device(dd_path)

        rc, report = testlib.cmd(['pvcreate', self.loop])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['vgcreate', vgname, self.loop])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['lvcreate', '-n', lvname, '-L', "%sM" % (str(size)), vgname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _umount_fs(self, mnt, loop=None, use_assert=True):
        '''Unmount device'''
        rc, report = testlib.cmd(['umount', mnt])
        if use_assert:
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # if loop device, disassociate it
        if loop:
            rc, report = testlib.cmd(['losetup', '-d', loop])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def _create_fs(self, size=64, use_lvm=False, mount_args=[]):
        '''Create an fs of specified size'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.img = os.path.join(self.tmpdir, "dd")
        self.mnt = os.path.join(self.tmpdir, "mnt")
        os.mkdir(self.mnt)

        self.img_size = size

        dev = ""
        if use_lvm:
            lvname = "testliblvm"
            vgname = "testlib"

            # with lvm, make the dd bigger than the LV, so we can grow if
            # needed
            self.lvm_size = self.img_size + 128
            self._create_dd(self.img, self.lvm_size)
            self._create_lv(self.img, size, vgname, lvname)

            dev = self.lv_path

        else:
            self._create_dd(self.img, self.img_size)
            self.loop = self._attach_to_loop_device(self.img)

            dev = self.loop

        self._mkfs(dev)
        self._mount_fs(dev, self.mnt, mount_args)

    def test_create(self):
        '''Test create (mkfs/mount/umount)'''
        self._create_fs()
        self._umount_fs(self.mnt)

    def test_df(self):
        '''Test df'''
        self._create_fs()

        rc, report = testlib.cmd(['df', '-P'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = self.loop
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "-blocks"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        rc, report = testlib.cmd(['df', '-P', '-i'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = self.loop
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "Inodes"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def test_fsck(self, journal=True):
        '''Test fsck'''
        self._create_fs()

        # Unmount without disassociating the loop device
        self._umount_fs(self.mnt)

        rc, report = testlib.cmd(['fsck', '-y', '-V', self.loop])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "complete"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        if journal:
            search = "journal"
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)

    def test_files(self, skip_atime=False, create=True):
        '''Test file operations'''
        if create:
            self._create_fs()

        fn = os.path.join(self.mnt, "file")
        contents = "foo\n"

        print ""
        print "  create"
        f = open(fn, 'w')
        f.write(contents)
        f.close()

        print "  read"
        f = open(fn)
        read_contents = f.read()
        f.close()
        result = "Couldn't find '%s' in report" % contents
        self.assertTrue(contents in read_contents, result)

        print "  append"
        append = "bar\n"
        f = open(fn, 'a')
        f.write(append)
        f.close()

        f = open(fn)
        read_contents = f.read()
        f.close()

        result = "Couldn't find '%s' in report" % contents
        self.assertTrue(contents in read_contents, result)

        result = "Couldn't find '%s' in report" % append
        self.assertTrue(append in read_contents, result)

        result = "Couldn't find '%s' in report" % contents + append
        self.assertTrue(contents + append in read_contents, result)

        if skip_atime:
            print "  atime (skipped)"
        else:
            print "  atime"
            old_atime = os.stat(fn)[stat.ST_ATIME]
            time.sleep(2)

            open(fn).read()
            f = open(fn)
            f.read()
            f.close()
            atime = os.stat(fn)[stat.ST_ATIME]
            self.assertTrue(old_atime != atime, "atimes match (should be %d != %d)" % (old_atime, atime))

        print "  ctime"
        old_ctime = os.stat(fn)[stat.ST_CTIME]
        time.sleep(2)

        rc, report = testlib.cmd(['chmod', 'g+w', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        ctime = os.stat(fn)[stat.ST_CTIME]
        self.assertTrue(old_ctime != ctime, "ctimes match (should be %d != %d)" % (old_ctime, ctime))

        print "  mtime"
        old_ctime = os.stat(fn)[stat.ST_CTIME]
        old_mtime = os.stat(fn)[stat.ST_MTIME]
        time.sleep(2)

        append = "bar\n"
        f = open(fn, 'a')
        f.write(append)
        f.close()

        ctime = os.stat(fn)[stat.ST_CTIME]
        mtime = os.stat(fn)[stat.ST_MTIME]
        self.assertTrue(old_ctime != ctime, "ctimes match (should be %d != %d)" % (old_ctime, ctime))
        self.assertTrue(old_mtime != mtime, "mtimes match (should be %d != %d)" % (old_mtime, mtime))

    def test_permissions(self):
        '''Test permissions/ownership'''
        def file_access(path, username, mode, needs_access):
            '''Determine if user has read, write or execute access to the
               file.
            '''
            if mode == "read":
                rc, report = testlib.cmd(['su', '-c', 'cat %s' % path, username])
            elif mode == "write":
                rc, report = testlib.cmd(['su', '-c', 'echo "# has write" > %s' % path, username])
                f = open(path)
                report = f.read()
                f.close()
            elif mode == "execute":
                rc, report = testlib.cmd(['su', '-c', path, username])
            else:
                print "Unsupported mode '%s'" % mode

            # debugging
            #ls_rc, ls_report = testlib.cmd(['ls', '-l', path])
            #print "      DEBUG: rc=%d,mode=%s,user=%s,access=%s,report=%s" % (rc, mode, username, needs_access, ls_report.strip())
            #print "      DEBUG: %s" % (open(path).read())

            expected = 0
            result = 'Got exit code %d\n' % (rc)
            if needs_access:
                self.assertTrue(expected == rc, result + report)
            else:
                self.assertFalse(expected == rc, result + report)
            search = "# has %s" % mode
            result = "Couldn't find '%s' in report" % search
            if needs_access:
                self.assertTrue(search in report, result + report)
            else:
                self.assertFalse(search in report, result + report)

        def dir_access(path, username, mode, needs_access):
	    '''Determine if user has read, write or execute access to the
               directory.'''
            if mode == "read":
                rc, report = testlib.cmd(['su', '-c', 'ls %s' % path, username])
            elif mode == "write":
                rc, report = testlib.cmd(['su', '-c', 'touch %s' % os.path.join(path, "testme"), username])
                testlib.cmd(['su', '-c', 'rm -f %s' % os.path.join(path, "testme"), username])
            elif mode == "execute":
                rc, report = testlib.cmd(['su', '-c', 'cat %s' % path, username])
            else:
                print "Unsupported mode '%s'" % mode

            # debugging
            #ls_path = path
            #if not os.path.isdir(path):
            #    ls_path = os.path.dirname(path)
            #ls_rc, ls_report = testlib.cmd(['ls', '-ld', ls_path])
            #print "      DEBUG: rc=%d,mode=%s,user=%s,access=%s,report=%s" % (rc, mode, username, needs_access, ls_report.strip())

            expected = 0
            result = 'Got exit code %d\n' % (rc)
            if needs_access:
                self.assertTrue(expected == rc, result + report)
            else:
                self.assertFalse(expected == rc, result + report)

            if mode == "execute":
                search = "# has"
                result = "Couldn't find '%s' in report" % search
                if needs_access:
                    self.assertTrue(search in report, result + report)
                else:
                    self.assertFalse(search in report, result + report)


        self._create_fs()

        self.user = testlib.TestUser()
        self.user2 = testlib.TestUser()

        dir = os.path.join(self.mnt, "foo")
        os.mkdir(dir)
        fn = os.path.join(dir, "bar")

        rc, report = testlib.cmd(['chmod', '-R', 'a+rX', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print ""
        print "  file:"

	# The idea here is to have self.user access the file. The file's
        # ownership is adjusted to self.user2 accordingly.
        for j in ['o', 'g', 'u']:
            for i in ['rx', 'w', 'r', '']:	# need 'rx' instead of just 'x' for a script
                # reset the file contents, ownership, and permissions each time
                f = open(fn, 'w')
                f.write("#!/bin/sh\n# has read\necho -n '#' ; echo ' has execute'\n")
                f.close()

                rc, report = testlib.cmd(['chown', "%s:%s" % (self.user2.login, self.user2.login), fn])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                rc, report = testlib.cmd(['chmod', "0000", fn])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                # set new permissions
                p = "%s=%s" % (j, i)
                print "    %s" % p
                rc, report = testlib.cmd(['chmod', p, fn])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                if j == 'u' or j == 'g':
                    file_access(fn, self.user.login, 'read', False)
                    file_access(fn, self.user.login, 'write', False)
                    file_access(fn, self.user.login, 'execute', False)

                    if j == 'u':
                        # set owner
                        rc, report = testlib.cmd(['chown', "%s" % (self.user.login), fn])
                        expected = 0
                        result = 'Got exit code %d, expected %d\n' % (rc, expected)
                        self.assertEquals(expected, rc, result + report)
                    elif j == 'g':
                        rc, report = testlib.cmd(['chgrp', self.user.login, fn])
                        expected = 0
                        result = 'Got exit code %d, expected %d\n' % (rc, expected)
                        self.assertEquals(expected, rc, result + report)

                file_access(fn, self.user.login, 'read', 'r' in i)
                file_access(fn, self.user.login, 'execute', 'x' in i)
                # 'write' must be last since it overwrites the file
                file_access(fn, self.user.login, 'write', 'w' in i)


        rc, report = testlib.cmd(['chmod', "0777", fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        f = open(fn, 'w')
        f.write("#!/bin/sh\n# has read\necho -n '#' ; echo ' has execute'\n")
        f.close()

        print "  directory:"
        for j in ['o', 'g', 'u']:
            for i in ['r', 'wx', 'x', '']:
                # reset each time
                rc, report = testlib.cmd(['chmod', "0000", dir])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                rc, report = testlib.cmd(['chown', "%s:%s" % (self.user2.login, self.user2.login), dir])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                # set new permissions
                p = "%s=%s" % (j, i)
                print "    %s" % p
                rc, report = testlib.cmd(['chmod', p, dir])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                if j == 'u' or j == 'g':
                    dir_access(dir, self.user.login, 'read', False)
                    dir_access(dir, self.user.login, 'write', False)
                    dir_access(fn, self.user.login, 'execute', False)
                    if j == 'u':
                        # set owner
                        rc, report = testlib.cmd(['chown', "%s" % (self.user.login), dir])
                        expected = 0
                        result = 'Got exit code %d, expected %d\n' % (rc, expected)
                        self.assertEquals(expected, rc, result + report)
                    elif j == 'g':
                        rc, report = testlib.cmd(['chgrp', self.user.login, dir])
                        expected = 0
                        result = 'Got exit code %d, expected %d\n' % (rc, expected)
                        self.assertEquals(expected, rc, result + report)

                dir_access(dir, self.user.login, 'read', 'r' in i)
                dir_access(dir, self.user.login, 'write', 'w' in i)
                dir_access(fn, self.user.login, 'execute', 'x' in i)

