#!/usr/bin/python
#
#    test-redhat-cluster.py quality assurance test script for redhat-cluster
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
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: redhat-cluster-suite lvm2
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_fs.py

'''
    IMPORTANT:
      It is critical that your /etc/hosts file, uname -n and cluster.conf
      are in agreement, otherwise cman will not start. If the hostname is
      "node1", then do the following for Hardy and later:
      do something like this:
      1. Confirm that "uname -n" returns "node1" (*not* "node1.testlib.domain").
         If it doesn"t, set it with "sudo hostname node1"
      2. Adjust /etc/hosts to have (adjust IP accordingly):
         192.168.122.100 node1.testlib.domain
      3. Adjust /etc/cluster/cluster.conf to have:
         <clusternode name="node1.testlib.domain" ...
      4. Make sure all other references to node1 in cluster.conf use
         "node1.testlib.domain"

      Dapper
      1. Confirm that "uname -n" returns "node1" (*not* "node1.testlib.domain").
         If it does not, set it with "sudo hostname node1"
      2. Adjust /etc/hosts to have (adjust IP accordingly):
         192.168.122.100 node1.testlib.domain
      3. Make *sure* there are no other occurences of the IP address (eg
         192.168.122.100), the FQDN (eg "node1.testlib.domain") or the short
         hostname (eg "node1") in /etc/hosts
      4. Adjust /etc/cluster/cluster.conf to have:
         <clusternode name="node1" ...
      5. Make sure all other references to node1 in cluster.conf use
         "node1"

    If the cluster was working and no longer is, can try rebooting. Can also purge
    all the redhat-cluster-suite packages and reboot.

    NOTES:
      - Need at least 300MB of space in /tmp to run this script
      - If get a lot of failures, then the loop devices may not get
        disassociated. Need to perform:
        for i in `seq 0 7` ; do sudo losetup -d /dev/loop$i ; done
      - Intrepid lvm with gfs2 do not play nice together (kernel OOPS). Tests
        have been adjusted for this
      - Dapper does not ship mount.gfs and doesn't have gfs2-tools
      - Dapper must use the server kernel (cman.ko needs to be loaded)

    TODO:
      - Test on Jaunty and higher
'''


import unittest, sys
import testlib
import testlib_fs
import os
import stat
import tempfile
import time

try:
    from private.qrt.RedhatCluster import PrivateRedhatClusterTest
except ImportError:
    class PrivateRedhatClusterTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class RedhatClusterTest(testlib.TestlibCase, PrivateRedhatClusterTest):
    '''Test redhat cluster'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.cluster_conf = "/etc/cluster/cluster.conf"
        self.hosts_file = "/etc/hosts"
        self.ip = None
        self.cluster_name = "testlib_cluster"
        self.tmpdir = ""
        self.domain_name = "testlib.domain"

        # these are listed in boot start order
        self.scripts = ['openais', 'cman', 'clvm', 'gfs2-tools', 'gfs-tools', 'rgmanager']
        if self.lsb_release['Release'] >= 8.10:
            self.scripts = ['corosync', 'openais', 'cman', 'clvm', 'gfs2-tools', 'gfs-tools', 'rgmanager']
        if self.lsb_release['Release'] < 8.04:
            self.scripts = ['ccs', 'cman', 'gulm', 'fence', 'clvm', 'gfs-tools', 'rgmanager']

        # daemons to check to make sure they are running
        self.daemons = ['clurgmgrd', 'clvmd', 'dlm_controld', 'fenced', 'aisexec', 'ccsd']
        if self.lsb_release['Release'] >= 8.10:
            self.daemons.remove('aisexec')
            self.daemons.append('corosync')
        if self.lsb_release['Release'] < 8.04:
            self.daemons.remove('aisexec')
            self.daemons.remove('dlm_controld')

        if not os.path.exists(os.path.dirname(self.cluster_conf)):
            os.mkdir(os.path.dirname(self.cluster_conf))

        rc, report = testlib.cmd(['hostname'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.hostname = report.strip()
        self.fqdn = "%s.%s" % (self.hostname, self.domain_name)

        self.ip = self._get_ip()

        stanza = "%s %s" % (self.ip, self.fqdn)
        hosts_contents = open(self.hosts_file).read()
        if self.lsb_release['Release'] < 8.04:
            for line in hosts_contents.splitlines():
                if stanza in line or line.startswith('#'):
                    continue
                result = "Found one of %s, %s or %s in %s. Please remove these entries" % (self.ip, self.fqdn, self.hostname, self.hosts_file)
                self.assertFalse(self.ip in line or self.fqdn in line or self.hostname in line, result)

        # update /etc/hosts, permanently (for good reboots)
        if stanza not in hosts_contents:
            testlib.config_replace(self.hosts_file, "%s\n" % stanza, True)

        cluster_version = "5"
        name = self.fqdn
        if self.lsb_release['Release'] < 8.04:
            cluster_version = "2"
            name = self.hostname

        self.cluster_contents = '''<?xml version="1.0" ?>
<cluster config_version="%s" name="%s">
	<fence_daemon post_fail_delay="0" post_join_delay="3"/>
	<clusternodes>
		<clusternode name="%s" nodeid="1" votes="1">
			<fence>
				<method name="1">
					<device name="testlib-fence" nodename="%s"/>
				</method>
			</fence>
		</clusternode>
	</clusternodes>
	<cman/>
	<fencedevices>
		<fencedevice agent="fence_manual" name="testlib-fence"/>
	</fencedevices>
	<rm>
		<failoverdomains/>
		<resources/>
	</rm>
</cluster>
''' % (cluster_version, self.cluster_name, name, name)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._stop_cluster()
        testlib.config_restore(self.cluster_conf)
        # don't restore this in case want to reboot
        #testlib.config_restore(self.hosts_file)
        if os.path.exists("/tmp/rgmanager-dump"):
            os.unlink("/tmp/rgmanager-dump")
        if os.path.exists("/var/log/cluster/rgmanager-dump"):
            os.unlink("/var/log/cluster/rgmanager-dump")
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _get_ip(self):
        rc, output = testlib.cmd(['ip','-4','-o','addr','show'])
        self.assertEqual(rc, 0, output)
        for line in output.splitlines():
            if not line.split(' ')[1].startswith('eth'):
                continue
            ip = line.split('inet ')[1].split('/')[0]
            break
        self.assertNotEqual(ip, None, 'Cannot find ip:\n%s' % (output))
        return ip

    def _has_joined(self):
        '''Determine if node has joined the cluster'''
        rc, report = testlib.cmd(['clustat'])
        search_terms = [self.hostname, 'Online']
        for search in search_terms:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

    def _start_cluster(self):
        '''Start cluster'''
        initscripts = list(self.scripts)
        for i in initscripts:
            rc, report = testlib.cmd(['/etc/init.d/%s' % i, 'start'])
            if i in ['cman', 'rgmanager']:
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
        time.sleep(3)

        testlib.cmd(['cman_tool', 'join'])
        self._has_joined()

    def _stop_cluster(self):
        '''Stop cluster'''
        testlib.cmd(['cman_tool', 'leave'])

        initscripts = list(self.scripts)
        initscripts.reverse()
        for i in initscripts:
            rc, report = testlib.cmd(['/etc/init.d/%s' % i, 'stop'])
        testlib.cmd(['killall', '-9', 'ccsd'])
        time.sleep(3)

    def _restart_cluster(self):
        '''Restart cluster'''
        self._stop_cluster()
        self._start_cluster()

    def test_daemons(self):
        '''Test daemons'''
        testlib.config_replace(self.cluster_conf, self.cluster_contents)
        self._restart_cluster()

        for d in self.daemons:
            rc, report = testlib.cmd(['pidof', d])
            expected = 0
            result = 'Got exit code %d, expected %d for %s\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)

    def test_clustat(self):
        '''Test clustat'''
        testlib.config_replace(self.cluster_conf, self.cluster_contents)
        self._restart_cluster()

        search_terms = [self.hostname, self.cluster_name, 'Online']
        if self.lsb_release['Release'] < 8.04:
            search_terms.remove(self.cluster_name)

        rc, report = testlib.cmd(['clustat'])
        for search in search_terms:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

        search_terms.remove('Online')
        search_terms.append('<?xml')
        rc, report = testlib.cmd(['clustat', '-x'])
        for search in search_terms:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

    def test_rg_test(self):
        '''Test rg_test'''
        if self.lsb_release['Release'] < 8.04:
            return self._skipped("rg_test does not exist on Dapper")

        testlib.config_replace(self.cluster_conf, self.cluster_contents)

        print ""
        print "  config"
        rc, report = testlib.cmd(['rg_test', 'test', self.cluster_contents])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "Running in test mode"
        result = "Couldn't find '%s' in report\n" % search
        self.assertTrue(search in report, result + report)

        print "  malformed config"
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        fn = os.path.join(self.tmpdir, "xml")
        malformed = '''<?xml version="1.0" ?>
<cluster config_version="5" name="testlib_cluster">
'''
        testlib.create_fill(fn, malformed)
        rc, report = testlib.cmd(['rg_test', 'test', fn])
        search = "Error parsing"
        result = "Couldn't find '%s' in report\n" % search
        self.assertTrue(search in report, result + report)

        print "  rules"
        rc, report = testlib.cmd(['rg_test', 'rules'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ['Resource Rules for', 'Agent:', 'Actions:']:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

    def test_clurgmgrd(self):
        '''Test clurgmgrd (rgmanager)'''
        testlib.config_replace(self.cluster_conf, self.cluster_contents)
        self._restart_cluster()

        print ""
        print "  daemon accepts signals"
        pid = open("/var/run/clurgmgrd.pid").read()
        rc, report = testlib.cmd(['kill', '-USR1', pid])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(3)

        if self.lsb_release['Release'] >= 8.04:
            print "  CVE-2008-6552"
            fn = "/tmp/rgmanager-dump"
            result = "Found '%s'" % fn
            self.assertFalse(os.path.exists(fn), result)

            print "  rgmanager-dump"
            fn = "/var/log/cluster/rgmanager-dump"
            result = "Could not find '%s'" % fn
            self.assertTrue(os.path.exists(fn), result)

            contents = open(fn).read()
            for search in ['Cluster configuration', 'View-Formation States', 'CMAN']:
                result = "Couldn't find '%s' in report\n" % search
                self.assertTrue(search in contents, result + contents)

    def test_cman_tool(self):
        '''Test cman_tool'''
        testlib.config_replace(self.cluster_conf, self.cluster_contents)
        self._restart_cluster()

        search_terms = [self.hostname, self.ip]
        cmd = ['cman_tool', 'nodes', '-a']
        if self.lsb_release['Release'] < 8.04:
            cmd.remove('-a')
            search_terms.remove(self.ip)
        rc, report = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for search in search_terms:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

        rc, report = testlib.cmd(['cman_tool', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for search in [self.hostname, self.cluster_name, 'Quorum']:
            result = "Couldn't find '%s' in report\n" % search
            self.assertTrue(search in report, result + report)

    def test_junk(self):
        '''Test junk in cluster.conf'''
        # This was for CVE-2008-6560, but couldn't reproduce

        cluster_version = "5"
        name = self.fqdn
        if self.lsb_release['Release'] < 8.04:
            cluster_version = "2"
            name = self.hostname

        malformed = '''<?xml version="1.0" ?>
<cluster config_version="%s" name="%s">
	<fence_daemon post_fail_delay="0" post_join_delay="3"/>
	<clusternodes>
		<clusternode name="%s" nodeid="1" votes="1">
			<fence>
				<method name="1">
					<device name="testlib-fence" nodename="%s"/>
				</method>
			</fence>
		</clusternode>
	</clusternodes>
	<cman/>
	<junk>
''' % (cluster_version, self.cluster_name, name, name)
	# add lots of junk
	for i in range(1,64):
            malformed += '		<extrajunk foo%d="bar"/>\n' % i

	malformed += '''	</junk>
	<fencedevices>
		<fencedevice agent="fence_manual" name="testlib-fence"/>
	</fencedevices>
	<rm>
		<failoverdomains/>
		<resources/>
	</rm>
</cluster>
'''
        testlib.config_replace(self.cluster_conf, malformed)
        self._restart_cluster()


class RedhatClusterFSCommon(testlib_fs.FSCommon):
    '''Test cluster fs'''

    def _setUpGFS(self, type):
        '''Set up prior to each test_* function'''
        testlib_fs.FSCommon._setUp(self, type)

    def _tearDownGFS(self):
        '''Clean up after each test_* function'''
        testlib_fs.FSCommon._tearDown(self)

    #
    # FSCommon overrides
    #
    def _mkfs(self, dev):
        '''Create a filesystem on device'''
        args = ['-O', '-r', '32', '-j', '1', '-p', 'lock_nolock']
        self._do_mkfs(self.type, dev, args)

    def _create_fs(self, size=192, use_lvm=False, args=[], ignore_local_fs=True):
        '''Create an fs of specified size'''
        mount_args = args
        if ignore_local_fs:
            mount_args.append('-o')
            mount_args.append('ignore_local_fs')
        testlib_fs.FSCommon._create_fs(self, size, use_lvm, mount_args)

    #
    # Tests
    #
    def test_files(self):
        '''Test file operations'''
        print ""
        print " without ignore_local_fs:",
        self._create_fs(ignore_local_fs=False)
        testlib_fs.FSCommon.test_files(self, skip_atime=True, create=False)

        # now try with local fs optimizations
        self._umount_fs(self.mnt, loop=None)
        self._mount_fs(self.loop, self.mnt, ['-o', 'ignore_local_fs'])
        print " with ignore_local_fs:",
        testlib_fs.FSCommon.test_files(self, skip_atime=True, create=False)

    def test_quota(self):
        '''Test quota operations'''
        use_lvm = True
        if self.type == "gfs2" and self.lsb_release['Release'] == 8.10:
            use_lvm = False

        self._create_fs(use_lvm=use_lvm)

        dev = self.loop
        if use_lvm:
            dev = self.lv_path

        print ""
        print "  edit -p quota"
        rc, report = testlib.cmd(['gfs2_edit', '-p', 'quota', dev])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "quota file contents"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        print "  edit -x -p quota"
        rc, report = testlib.cmd(['gfs2_edit', '-x', '-p', 'quota', dev])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "quota file contents"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "[................]"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # Need a non-loop device for these
        if use_lvm:
            print "  quota init"
            rc, report = testlib.cmd(['%s_quota' % self.type, 'init', '-f', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            print "  quota list"
            rc, report = testlib.cmd(['%s_quota' % self.type, 'list', '-f', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
        else:
            print "  Skipping gfs2_quota (gfs2/lvm quota checks on Intrepid causes kernel OOPS)"

    def test_meta(self):
        '''Test meta'''
        self._create_fs()

        # NOTE: gfs2_edit works on both gfs2 and gfs filesystems

        # superblock
        rc, report = testlib.cmd(['gfs2_edit', '-p', 'sb', self.loop])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "The superblock"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        for i in ['mh_magic', 'mh_type', 'sb_lockproto']:
            result = "Could not find '%s'\n" % (i)
            self.assertTrue(i in report, result + report)

        rc, report = testlib.cmd(['gfs2_edit', '-x', '-p', 'sb', self.loop])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "The superblock"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        search = "[................]"
        result = "Couldn't find '%s' in report" % search
        self.assertTrue(search in report, result + report)

        # savemeta
        if self.type == "gfs2":
            savemeta = os.path.join(self.tmpdir, "savemata")
            rc, report = testlib.cmd(['gfs2_edit', 'savemeta', self.loop, savemeta])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            search = "Metadata saved"
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            size = os.stat(savemeta)[stat.ST_SIZE]
            result = "Saved meta has size of '0'"
            self.assertTrue(size > 0, result)

            # restoremeta
            rc, report = testlib.cmd(['gfs2_edit', 'restoremeta', savemeta, self.loop])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            search = "restore successful"
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)

    def test_grow(self):
        '''Test grow'''
        if self.type == "gfs2" and self.lsb_release['Release'] == 8.10:
            return self._skipped("gfs2 grow on Intrepid lvm causes kernel OOPS")

        self._create_fs(use_lvm=True)

        prev_size = self._get_size(self.mnt)
        self.assertFalse(prev_size == "", 'previous size is empty')

        grow_by = self.lvm_size - self.img_size - 8	# must be at least '64'
        self.assertTrue(grow_by > 64, "Not enough room to grow volume")

        rc, report = testlib.cmd(['lvextend', '-L', '+%sM' % grow_by, self.lv_path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(3)

        rc, report = testlib.cmd(['%s_grow' % self.type, self.lv_path])
        if self.type == "gfs2":
            search = "grew by %sMB" % grow_by
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)
        else:
            search = "Preparing"
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)

            search = "Done"
            result = "Couldn't find '%s' in report" % search
            self.assertTrue(search in report, result + report)

        size = self._get_size(self.mnt)
        self.assertFalse(prev_size == "", 'size is empty')
        # failures here could be https://bugzilla.redhat.com/show_bug.cgi?id=482756
        self.assertTrue(int(prev_size) < int(size), "size '%s' not larger than '%s'" % (size, prev_size))

    def test_gfs_tool(self):
        '''Test gfs_tool/gfs2_tool'''
        self._create_fs(use_lvm=True)

        print ""
        if self.type == "gfs" or self.lsb_release['Release'] < 8.10:
            print "  counters"
            rc, report = testlib.cmd(['%s_tool' % self.type, 'counters', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for i in ['locks', 'locks held']:
                result = "Could not find '%s'\n" % (i)
                self.assertTrue(i in report, result + report)

        # gfs2_tool df blows up on Intrepid
        if self.type == "gfs" or self.lsb_release['Release'] != 8.10:
            print "  df"
            rc, report = testlib.cmd(['%s_tool' % self.type, 'df', self.mnt])
            for i in ['Block size', 'Journals', 'Resource Groups']:
                result = "Could not find '%s'\n" % (i)
                self.assertTrue(i in report, result + report)

        if self.type == "gfs":
            print "  getsb"
            rc, report = testlib.cmd(['%s_tool' % self.type, 'getsb', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for i in ['mh_magic', 'mh_type']:
                result = "Could not find '%s'\n" % (i)
                self.assertTrue(i in report, result + report)

            print "  jindex"
            rc, report = testlib.cmd(['%s_tool' % self.type, 'jindex', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for i in ['ji_addr', 'ji_reserved']:
                result = "Could not find '%s'\n" % (i)
                self.assertTrue(i in report, result + report)

            print "  rindex"
            rc, report = testlib.cmd(['%s_tool' % self.type, 'rindex', self.mnt])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for i in ['ri_addr', 'ri_reserved']:
                result = "Could not find '%s'\n" % (i)
                self.assertTrue(i in report, result + report)

        rc, report = testlib.cmd(['%s_tool' % self.type, 'gettune', self.mnt])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for i in ['quota', 'statfs']:
            result = "Could not find '%s'\n" % (i)
            self.assertTrue(i in report, result + report)

        print "  list"
        rc, report = testlib.cmd(['%s_tool' % self.type, 'list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'dm-'
        result = "Could not find '%s'\n" % (i)
        self.assertTrue(search in report, result + report)

        print "  lockdump"
        rc, report = testlib.cmd(['%s_tool' % self.type, 'lockdump', self.mnt])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ['s:SH', 's:UN', 's:EX']
        if self.type == "gfs" or self.lsb_release['Release'] < 8.10:
            search_terms = ['gl_flags', 'gh_flags', 'Glock', 'Holder']
        for i in search_terms:
            result = "Could not find '%s'\n" % (i)
            self.assertTrue(i in report, result + report)


class RedhatClusterGFS(RedhatClusterFSCommon):
    '''Test GFS'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUpGFS("gfs")
        self.metamnt = ""
        self.tmprace = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.metamnt != "":
            self._umount_fs(self.metamnt, loop=None, use_assert=False)

        self._tearDownGFS()

        if os.path.exists(self.tmprace):
            os.unlink(self.tmprace)


class RedhatClusterGFS2(RedhatClusterFSCommon):
    '''Test GFS2'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUpGFS("gfs2")
        self.metamnt = ""
        self.tmprace = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.metamnt != "":
            self._umount_fs(self.metamnt, loop=None, use_assert=False)

        self._tearDownGFS()

        if os.path.exists(self.tmprace):
            os.unlink(self.tmprace)

    #
    # GFS2 specific tests
    #
    def test_debugfs(self):
        '''Test debugfs'''
        self._create_fs(use_lvm=True)

        self.debugfs = os.path.join(self.tmpdir, "debugfs")
        os.mkdir(self.debugfs)

        rc, report = testlib.cmd(['mount', '-t', 'debugfs', 'none', self.debugfs])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = os.path.join(self.debugfs, self.type)
        self.assertTrue(os.path.isdir(search), "Could not find '%s'" % search)

        rc, output = testlib.cmd(['gfs2_tool', 'list'])
        self.assertEqual(rc, 0, output)
        dev = ""
        for line in output.splitlines():
            if not line.split(' ')[1].startswith('dm-'):
                continue
            dev = line.split(' ')[1]
            break

        glocks = os.path.join(self.debugfs, self.type, os.path.basename(dev) + "/glocks")
        self.assertTrue(os.path.exists(glocks), "Could not find '%s'" % glocks)

        report = open(glocks).read()
        for i in ['inode']:
            result = "Could not find '%s' in %s\n" % (i, glocks)
            self.assertTrue(i in report, result + report)

    def test_debugfs_CVE_2008_6552(self):
        '''Test CVE-2008-6552 (debugfs)'''
        self.tmprace = "/tmp/debugfs"
        if os.path.isdir(self.tmprace):
            return self._skipped("'%s' exists and is a directory") % self.tmprace

        rc, report = testlib.cmd(['touch', self.tmprace])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._create_fs()

        rc, report = testlib.cmd(['%s_tool' % self.type, 'lockdump', self.mnt])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_meta_mount(self):
        '''Test meta mount'''
        self._create_fs()

        self.metamnt = os.path.join(self.tmpdir, "meta")
        os.mkdir(self.metamnt)

        if os.path.isdir(self.tmprace):
            return self._skipped("'%s' exists and is a directory") % self.tmprace

        rc, report = testlib.cmd(['mount', '-t', '%smeta' % self.type, self.loop, self.metamnt])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for i in ['statfs', 'quota']:
            result = "Could not find '%s' in %s\n" % (i, self.metamnt)
            self.assertTrue(os.path.exists(os.path.join(self.metamnt, i)), result + report)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RedhatClusterTest))

    # Dapper doesn't have mount.gfs (where is it?)
    if testlib.ubuntu_release() != "dapper":
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RedhatClusterGFS))

    # Dapper doesn't have gfs2
    if testlib.ubuntu_release() != "dapper":
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RedhatClusterGFS2))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
