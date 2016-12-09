#!/usr/bin/python
#
#    test-fuse.py quality assurance test script for fuse
#    Copyright (C) 2010-2015 Canonical Ltd.
#    Author: Marc Deslaurers <marc.deslauriers@ubuntu.com>
#    Author: Steve Beattie <sbeattie@ubuntu.com>
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
# QRT-Packages: openssh-server openssh-client sshfs fuse-utils libfuse-dev build-essential
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: loop-aes-utils
# files and directories required for the test to run:
# QRT-Depends: fuse util-linux
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    This test should be run in a virtual machine (VM). While efforts are
    made to make these tests non-destructive, there is no guarantee this
    script will not alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-fuse.py -v'

'''

import unittest, sys, os
import testlib
import shutil
import re
import tempfile
import time

use_private = True
try:
    from private.qrt.fuse import PrivateFuseTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class FuseTest(testlib.TestlibCase):
    '''Test fuse.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        self.sshd_config = '/etc/ssh/sshd_config'
        self.sshd_rsa_private_keyfile = '/etc/ssh/ssh_host_rsa_key'
        self.sshd_rsa_private_key = \
'''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs7PQMZkt6/s3ibdNW6C4ZUr6k1uSE0XZ5RK2cfdh0Ug1+DkJ
Rp8WTdsIKOVY69No1k3zKGm7EFvx5JhmSXxFcPqMj1/+NYw+JeT8q18JzPrhvEmI
KhP3+ydW+B+6w8PP2uEIpOS9OX7ISQgsgJ2J2M48aP2aAkdAjtO61JepJ6d+UHtD
cFyRS7P/17/o1QfWalAgbdLpZuq0eguRedVO6OTugTLu96g3w7Tk7watLO0GRStG
PlXRNRyZW4ER6xnUrG5lbEYICTYISA5yLSYBb3TTPyfQv6flD9SD64Xa8kgktGkD
AbMx7wa6BiRMeshNM+uFRJ/ZimcAKdUJMyYf4QIDAQABAoIBAQCt+W+eFQZ4aAYk
temWw8rBhg2BjC2nqwCA3dT0EOQKkTZu0glA7dPSHDOSJDgqV8ovb9fxUCticyGE
hmbAzicMcgSS6gRaIyQn28EiyCfc4yaX+zhwRFTYOgXgwhc2X+Rjq2mK+kiX2T5e
NiOfgOVrmH6zxpHLkt/VZvaByzJgyA2deH3KT9W/O+Mm52dDaer3ZKNKy/orpxbo
Ip4SbNIEdTylX9DoBZQzn6AKBkc/S8Qok3xGT/uM/mbj2IruwHwrkFURYQyzbcmQ
jDX1T3AJz92+LbiW8kKw8uODfoVdxv91ooTmST4z6izU6shpNGsHOHtV/rsOfvGs
H/fNYqSBAoGBAO9ULRjWeWcyMO/M+dLc4z4+LQ4QWPMVChuxjNVKIX4HycrXbIo4
uEZYhIDYDW7tIJp7Jp4YPzpbAGQldR//3EW3Pr9t4e7Y7TT2EDutNpFn+2a+cr2J
Qn+k0aO458V0vNXofpThIPyZppCF6y2ass/LG/RrIx+4XeIhprFzFlmtAoGBAMA4
Wc5GCaPbh+URejTptbE/WCBolUgt6gMDuEMvwVrdRJSP/7HTy5SdCzEExn8S86AY
S3TBGq5c5Pa+S8vuGXWaVidsVr4tf50yNTBkmyMazzi8cM+q0BHWFqT5L5+wbfpW
ahS+vidFhoF+1jK14Gg4WMVfZubDX4aiRYC44s2FAoGAfgU3/eUpZhKCvDKVtdfD
/Mlmlgo7nDwO54g1XTY8ro1RT3Lh32KAfeIsW1/oqulICrAgJI0l9gdnDFTA+MmU
Zk1YSBqHJmqpdQLAh3vsyOIU+gP8jRsSnf3eubQqrsmKiaRzytdEtF3/3Af4Tzov
P8V2gdxMUW6WWPVZPgUY1r0CgYBoerilnAAFZn/5DITmWdn+W7Xk97Ocpgg6Vz1C
l6R7ZSWvso2C9OIFB09b94KE86IkdNAeyA9ekvOJAmpkkCiaeac2inajrEtfADlU
8no4nIviBNs0pV2vNDTeuusd22IL3giO+haVdf7kSDLZIW62d1oY/gAKkktL/MvW
aagtmQKBgFQJ8FhBmSU/pkl5cRLEySwFWv/SvK7/VPBB1KDnbqAFC3YV1J2EIghL
7Rq/s93NCBweb97e5SgH/IBPpWnlXzRGL5ApmwXuoPzp7PZokgw7Tv4X8SSjaOmP
ITfOx9KgntLukRe860E+CbkBxEhPD+2+GhtXL0d21o4JoS/YQb80
-----END RSA PRIVATE KEY-----
'''
        self.sshd_rsa_public_key = \
'''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzs9AxmS3r+zeJt01boLhlSvqTW5ITRdnlErZx92HRSDX4OQlGnxZN2wgo5Vjr02jWTfMoabsQW/HkmGZJfEVw+oyPX/41jD4l5PyrXwnM+uG8SYgqE/f7J1b4H7rDw8/a4Qik5L05fshJCCyAnYnYzjxo/ZoCR0CO07rUl6knp35Qe0NwXJFLs//Xv+jVB9ZqUCBt0ulm6rR6C5F51U7o5O6BMu73qDfDtOTvBq0s7QZFK0Y+VdE1HJlbgRHrGdSsbmVsRggJNghIDnItJgFvdNM/J9C/p+UP1IPrhdrySCS0aQMBszHvBroGJEx6yE0z64VEn9mKZwAp1QkzJh/h root@localhost
'''
        testlib.config_replace(self.sshd_rsa_private_keyfile, self.sshd_rsa_private_key)
        testlib.config_replace(self.sshd_rsa_private_keyfile + ".pub", self.sshd_rsa_public_key)

        self.daemon = testlib.TestDaemon("/etc/init.d/ssh")
        self.daemon.restart()

        self.current_dir = os.getcwd()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0777)

        # create first user
        self.userX = testlib.TestUser()
        os.mkdir(self.userX.home + "/.ssh", 0700)
        os.chown(self.userX.home + "/.ssh", self.userX.uid, self.userX.gid)
        testlib.create_fill(self.userX.home + "/.ssh/known_hosts",
                            "localhost,127.0.0.1 " + self.sshd_rsa_public_key)
        os.chown(self.userX.home + "/.ssh/known_hosts", self.userX.uid, self.userX.gid)
        self.generate_ssh_keys(self.userX)

        # create second user
        self.userY = testlib.TestUser()
        os.mkdir(self.userY.home + "/.ssh", 0700)
        os.chown(self.userY.home + "/.ssh", self.userY.uid, self.userY.gid)
        testlib.create_fill(self.userY.home + "/.ssh/known_hosts",
                            "localhost,127.0.0.1 " + self.sshd_rsa_public_key)
        os.chown(self.userY.home + "/.ssh/known_hosts", self.userY.uid, self.userY.gid)
        self.generate_ssh_keys(self.userY)
        # Make sure second user can ssh into the first users account
        shutil.copy2(self.userY.home + "/.ssh/id_rsa.pub", self.userX.home + "/.ssh/authorized_keys")
        os.chown(self.userX.home + "/.ssh/authorized_keys", self.userX.uid, self.userX.gid)

        # Hardy and older need to have users in the fuse group
        if self.lsb_release['Release'] <= 8.04:
            rc, out = self.shell_cmd(["gpasswd", "-a", self.userX.login, "fuse"])
            self.assertEquals(rc, 0, "Could not add userX to fuse group!")
            rc, out = self.shell_cmd(["gpasswd", "-a", self.userY.login, "fuse"])
            self.assertEquals(rc, 0, "Could not add userY to fuse group!")

    def _cmd_as_user(self, user, cmd):
        # Can't use sudo here as hardy's sudo doesn't support running
        # commands with the -i option
        _cmd = ['su', '-l', user.login, '-c', ' '.join(cmd)]
        return _cmd

    def user_run_cmd(self, user, cmd):
        command = self._cmd_as_user(user, cmd)
        rc, out = self.shell_cmd(command)
        return [rc, out]

    def fuse_ssh_mount(self, user, share, mountpoint):
        cmd = ["sshfs", share, mountpoint]
        command = self._cmd_as_user(user, cmd)
        rc, out = self.shell_cmd(command)
        return [rc, out]

    def fuse_unmount(self, mountpoint, user=None, extra_args=None):
        cmd = ["fusermount"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.extend(["-u", mountpoint])
        if user == None:
            command = cmd
        else:
            command = self._cmd_as_user(user, cmd)
        rc, out = self.shell_cmd(command)
        return [rc, out]

    def get_sshfs_mounts(self):
        rc, out = self.shell_cmd(["mount", "-t", "fuse.sshfs"])
        self.assertEquals(rc, 0, "Could not call mount!")

        mounts = []
        for l in out.splitlines():
            share = l.split(' ')[0].strip()
            mountpoint = l.split(' ')[2].strip()
            options = l.split(' ')[5].strip()
            mounts.append([share, mountpoint, options])
        return mounts

    def search_mtab(self, mountpoint):
        mounts = self.get_sshfs_mounts()
        found = False
        for [m_share, m_mountpoint, m_options] in mounts:
            if m_mountpoint == mountpoint:
                found = True
        return found

    def generate_ssh_keys(self, user, keytype='rsa'):
        command = self._cmd_as_user(user, ["ssh-keygen", "-q", "-N", '""', '-t', keytype, '-f', user.home + "/.ssh/id_" + keytype])
        expected = 0
        rc, cmp_out = self.shell_cmd(command)
        self.assertEquals(expected, rc, cmp_out)

    def modify_sshd_config(self, items):
        '''take a list of key:value pairs and insert/replace into the sshd config'''

        contents = ""
        found = {}
        for line in file(self.sshd_config):
            for item in items.keys():
                if re.search("^\s*%s\s+" % (item), line):
                    found[item] = True
                    line = "%s %s\n" %(item, items[item])
                contents += line
        for item in items.keys():
            if not item in found.keys():
                contents += "%s %s\n" %(item, items[item])

        testlib.config_replace(self.sshd_config, contents)
        self.daemon.restart()

    def _simple_ssh_login(self, user, extra_args=None):
        expected = 0
        rc, cmp_out = self.shell_cmd(['cat', '/etc/lsb-release'])
        self.assertEquals(expected, rc, cmp_out)

        command = ['ssh']
        if extra_args:
            command.extend(extra_args)
        command.extend(['-x', 'localhost', 'cat', '/etc/lsb-release'])
        rc, out = self.user_run_cmd(user, command)
        self.assertEquals(expected, rc, out)
        self.assertEquals(cmp_out, out, out)


    def tearDown(self):
        '''Clean up after each test_* function'''

        os.chdir(self.current_dir)

        # Clean up exploit
        self.fuse_unmount(os.path.join(self.userY.home, "tmp-moved/mountpoint"))
        if os.path.exists("/mountpoint"):
            testlib.cmd(['umount', "/mountpoint"])
            testlib.recursive_rm("/mountpoint")

        # Unmount all leftover sshfs mounts
        # this may be destructive...
        # TODO: keep a list somewhere, and only unmount what this script
        #       actually mounted itself.
        mounts = self.get_sshfs_mounts()
        for [m_share, m_mountpoint, m_options] in mounts:
            self.fuse_unmount(m_mountpoint)

        # Clean exploit crud from mtab
        testlib.cmd(['sed', '-i', "/fuse.FuseMinimal/d", "/etc/mtab"])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        # Wait for accountsservice to settle down so we can actually
        # delete the users successfully
        time.sleep(2)

        self.userX = None
        self.userY = None
        testlib.config_restore(self.sshd_rsa_private_keyfile)
        testlib.config_restore(self.sshd_rsa_private_keyfile + ".pub")
        testlib.config_restore(self.sshd_config)
        self.daemon.restart()

    def test_00_sshd_listening(self):
        '''Test to ensure ssh is running'''
        # No idea why hardy doesn't work
        if self.lsb_release['Release'] == 8.04:
            return self._skipped("TODO: fix this check for hardy")

        self.assertTrue(testlib.check_port(22, 'tcp'))

    def test_ssh(self):
        '''Test if ssh is working between users'''

        self._simple_ssh_login(self.userY, extra_args=['-l', self.userX.login])

    def test_sshfs(self):
        '''Test if we can mount with fuse'''

        testfile = self.userX.home + "/testfile"
        mountpoint = self.userY.home + "/mountpoint"
        mounted_testfile = mountpoint + "/testfile"
        teststring = "Ubuntu rocks!"

        testlib.create_fill(testfile, teststring)
        os.chown(testfile, self.userX.uid, self.userX.gid)
        os.mkdir(mountpoint, 0700)
        os.chown(mountpoint, self.userY.uid, self.userY.gid)

        share = self.userX.login + "@localhost:" + self.userX.home

        # Perform mount
        expected = 0
        [rc, out] = self.fuse_ssh_mount(self.userY, share, mountpoint)
        self.assertEquals(expected, rc, out)

        # Make sure it's in the mtab
        result = self.search_mtab(mountpoint)
        self.assertEquals(result, True, "Could not find mountpoint in mtab!")

        # Check file is readable (needs to be done as the user)
        expected = 0
        [rc, out] = self.user_run_cmd(self.userY, ['cat', mounted_testfile])
        self.assertEquals(expected, rc, "Could not read mounted testfile!")
        self.assertEquals(out, teststring, "Could not find teststring in %s!" % out)

        # Check if file can be written (needs to be done as the user)
        tempfile = self.userY.home + "/tempfile"
        testlib.create_fill(tempfile, teststring)
        os.chown(testfile, self.userY.uid, self.userY.gid)
        [rc, out] = self.user_run_cmd(self.userY, ['mv', tempfile, mountpoint])
        self.assertEquals(expected, rc, "Could not write to mountpoint!")
        expected = 0
        [rc, out] = self.user_run_cmd(self.userY, ['cat', mountpoint + "/tempfile"])
        self.assertEquals(expected, rc, "Could not read mounted tempfile!")
        self.assertEquals(out, teststring, "Could not find teststring in %s!" % out)

        # Check unmount
        expected = 0
        [rc, out] = self.fuse_unmount(mountpoint, user=self.userY)
        self.assertEquals(expected, rc, out)

    def test_sshfs_mount_ownership(self):
        '''Test mountpoint ownership'''

        mountpoint = self.userY.home + "/mountpoint"

        # Create this as root
        os.mkdir(mountpoint, 0700)

        share = self.userX.login + "@localhost:" + self.userX.home

        # Perform mount, this should fail
        expected = 1
        [rc, out] = self.fuse_ssh_mount(self.userY, share, mountpoint)
        self.assertEquals(expected, rc, "Fuse didn't enforce mountpoint ownership!")
        self.assertTrue("Permission denied" in out, "Couldn't find error message!")

        # Make sure it's not in the mtab
        result = self.search_mtab(mountpoint)
        self.assertEquals(result, False, "Found mountpoint in mtab!")

    def test_sshfs_unmount(self):
        '''Make sure another user can't unmount'''

        mountpoint = self.userY.home + "/mountpoint"

        os.mkdir(mountpoint, 0700)
        os.chown(mountpoint, self.userY.uid, self.userY.gid)

        share = self.userX.login + "@localhost:" + self.userX.home

        # Perform mount
        expected = 0
        [rc, out] = self.fuse_ssh_mount(self.userY, share, mountpoint)
        self.assertEquals(expected, rc, out)

        # Make sure it's in the mtab
        result = self.search_mtab(mountpoint)
        self.assertEquals(result, True, "Could not find mountpoint in mtab!")

        # Try and unmount as wrong user
        expected = 1
        [rc, out] = self.fuse_unmount(mountpoint, user=self.userX)
        self.assertEquals(expected, rc, out)

        # Make sure it's still in the mtab
        result = self.search_mtab(mountpoint)
        self.assertEquals(result, True, "Could not find mountpoint in mtab!")

        # Unmount with the correct user
        expected = 0
        [rc, out] = self.fuse_unmount(mountpoint, user=self.userY)
        self.assertEquals(expected, rc, out)

    def test_zz_cve_2010_3879(self):
        '''Test CVE-2010-3879'''

        # Doesn't compile on natty+
        if self.lsb_release['Release'] >= 11.04:
            return self._skipped("PoC doesn't compile on natty and newer")

        test_iso = 'util-linux/test.iso'
        test_file = 'testfile.txt'
        mountpoint = "/mountpoint"

        if os.path.exists(mountpoint):
            testlib.recursive_rm(mountpoint)
        os.mkdir(mountpoint, 0777)

        # mount the iso file
        rc, report = testlib.cmd(['mount', '-o', 'loop', test_iso, mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can see the file inside
        result = "Couldn't find testfile %s in mounted directory" % test_file
        self.assertTrue(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        # Compile required binaries and move to user's dir
        sourceA = os.path.join(self.tmpdir, "DirModifyInotify.c")
        binaryA = os.path.join(self.userY.home, "DirModifyInotify")
        sourceB = os.path.join(self.tmpdir, "FuseMinimal.c")
        binaryB = os.path.join(self.userY.home, "FuseMinimal")
        script = os.path.join(self.userY.home, "Test.sh")

        shutil.copy('./fuse/DirModifyInotify.c', sourceA)
        shutil.copy('./fuse/FuseMinimal.c', sourceB)

        testlib.create_fill(script, '''
#!/bin/bash
mkdir -p tmp%s
(cd tmp%s; sleep 1; ../../FuseMinimal .) &
(./DirModifyInotify --Watch tmp%s --Watch /etc/mtab --WatchCount 8 --MovePath tmp --LinkTarget /) &
sleep 3
fusermount -u -z %s/
killall DirModifyInotify
killall FuseMinimal
''' % (mountpoint, mountpoint, mountpoint, mountpoint))

        os.chmod(script, 0755)

        rc, report = testlib.cmd(['gcc', '-o', binaryA, sourceA])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['gcc', '-D_FILE_OFFSET_BITS=64', '-lfuse',
                                  '-Wall', '-o', binaryB, sourceB])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected = 0
        [rc, out] = self.user_run_cmd(self.userY, [script])
        self.assertEquals(expected, rc, "CVE-2010-3879 script failed! RC:'%s', Output:'%s'" % (rc,out))

        # Clean up exploit
        self.fuse_unmount(os.path.join(self.userY.home, "tmp-moved/mountpoint"))

        result = 'Mount went missing! Vulnerable to CVE-2010-3879!\n'
        self.assertTrue(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        # unmount it
        rc, report = testlib.cmd(['umount', mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure we can't see the file anymore
        result = "Found testfile %s in mounted directory" % test_file
        self.assertFalse(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        os.chdir(self.current_dir)
        testlib.recursive_rm(mountpoint)

    def test_zz_cve_2010_3879_2(self):
        '''Test CVE-2010-3879 - Part 2'''

        # Doesn't compile on natty+
        if self.lsb_release['Release'] >= 11.04:
            return self._skipped("PoC doesn't compile on natty and newer")

        #
        # Running the original exploit twice in a row has uncovered a
        # second issue, where having crap leftover in the mtab causes
        # fuse to misbehave
        #

        test_iso = 'util-linux/test.iso'
        test_file = 'testfile.txt'
        mountpoint = "/mountpoint"

        if os.path.exists(mountpoint):
            testlib.recursive_rm(mountpoint)
        os.mkdir(mountpoint, 0777)

        # mount the iso file
        rc, report = testlib.cmd(['mount', '-o', 'loop', test_iso, mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can see the file inside
        result = "Couldn't find testfile %s in mounted directory" % test_file
        self.assertTrue(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        # Compile required binaries and move to user's dir
        sourceA = os.path.join(self.tmpdir, "DirModifyInotify.c")
        binaryA = os.path.join(self.userY.home, "DirModifyInotify")
        sourceB = os.path.join(self.tmpdir, "FuseMinimal.c")
        binaryB = os.path.join(self.userY.home, "FuseMinimal")
        script = os.path.join(self.userY.home, "Test.sh")

        shutil.copy('./fuse/DirModifyInotify.c', sourceA)
        shutil.copy('./fuse/FuseMinimal.c', sourceB)

        testlib.create_fill(script, '''
#!/bin/bash
mkdir -p tmp%s
(cd tmp%s; sleep 1; ../../FuseMinimal .) &
(./DirModifyInotify --Watch tmp%s --Watch /etc/mtab --WatchCount 8 --MovePath tmp --LinkTarget /) &
sleep 3
fusermount -u -z %s/
killall DirModifyInotify
killall FuseMinimal
return 0
''' % (mountpoint, mountpoint, mountpoint, mountpoint))

        os.chmod(script, 0755)

        rc, report = testlib.cmd(['gcc', '-o', binaryA, sourceA])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['gcc', '-D_FILE_OFFSET_BITS=64', '-lfuse',
                                  '-Wall', '-o', binaryB, sourceB])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected = 0
        [rc, out] = self.user_run_cmd(self.userY, [script])
        self.assertEquals(expected, rc, "CVE-2010-3879 script failed! RC:'%s', Output:'%s'" % (rc,out))

        # Clean up exploit
        self.fuse_unmount(os.path.join(self.userY.home, "tmp-moved/mountpoint"))
        testlib.recursive_rm(os.path.join(self.userY.home, "tmp-moved"))
        # This should be a symlink to /, so don't do a recursive_rm!
        os.unlink(os.path.join(self.userY.home, "tmp"))

        # Run it a second time
        expected = 0
        [rc, out] = self.user_run_cmd(self.userY, [script])
        self.assertEquals(expected, rc, "CVE-2010-3879 script failed! RC:'%s', Output:'%s'" % (rc,out))

        result = 'Mount went missing! Vulnerable to CVE-2010-3879, part 2!\n'
        self.assertTrue(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        # unmount it
        rc, report = testlib.cmd(['umount', mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure we can't see the file anymore
        result = "Found testfile %s in mounted directory" % test_file
        self.assertFalse(os.path.exists('%s/%s' % (mountpoint, test_file)), result)

        os.chdir(self.current_dir)
        testlib.recursive_rm(mountpoint)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(FuseTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PrivateFuseTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
