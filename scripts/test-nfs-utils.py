#!/usr/bin/python
#
#    test-nfs-utils.py quality assurance test script
#    kind of based on test-samba.py
#
#    Copyright (C) 2008-2015 Canonical Ltd.
#    Author: Kees Cook <kees@canonical.com>
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
# QRT-Packages: nfs-common nfs-kernel-server
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends:

'''
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get -y install nfs-kernel-server bind9-host
    $ sudo ./test-nfs-utils.py -v
    $ sudo ./test-nfs-utils.py <client hostname> -v
    $ sudo ./test-nfs-utils.py tmpserve -v

#  If specify <client hostname>, the scripts will also do client showmount test
#  to <client hostname>.

#  If use 'tmpserve', then this script will start nfs serving /tmp, then drop
#  to a shell. This allows for quick testing of clients and the server. Clients
#  can mount, do what they want, then unmount. After unmounting, just type
#  'exit' in the shell.

  TODO:
    NFSv4
    Kerberos
    A lot more nfs testing as this script is pretty basic
'''

import unittest, subprocess, tempfile, os, os.path, time, socket, sys
import testlib

test_client = ""

class NfsutilsCommon(testlib.TestlibCase):
    '''Common routines for testing nfs shares.'''
    def _setUp(self):
        '''Common test setup'''
        self.nfs_exports = "/etc/exports"
        self.tmpname = ""
        self.tmpdir = ""

        # be nice if this worked, but it doesn't always
        # self.ip = socket.gethostbyname(socket.gethostname())

        rc, report = testlib.cmd(['host', socket.gethostname()])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.ip = report.split(' ').pop().strip()

        self._restart()

    def _tearDown(self):
        '''Common test tear down'''
        testlib.config_restore(self.nfs_exports)
        self._stop()
        if os.path.exists(self.tmpname):
            os.unlink(self.tmpname)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _start(self):
        '''Startup with each test'''
        rc, report = testlib.cmd(['start', 'statd'])
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)

        rc, report = testlib.cmd(['start', 'idmapd'])
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)

        rc, report = testlib.cmd(["/etc/init.d/nfs-kernel-server", 'start'])
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)

    def _stop(self):
        '''Stop with each test'''
        rc, report = testlib.cmd(['stop', 'statd'])
        if rc != 0 and 'Unknown instance' in report:
            rc = 0
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)

        rc, report = testlib.cmd(['stop', 'idmapd'])
        if rc != 0 and 'Unknown instance' in report:
            rc = 0
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)

        rc, report = testlib.cmd(["/etc/init.d/nfs-kernel-server", 'stop'])
        result = 'Got exit code %d, expected 0\n' % rc
        self.assertEquals(0, rc, result + report)
        time.sleep(2)

    def _restart(self):
        '''Shutdown and startup with each test'''
        self._stop()
        self._start()

    def _test_number_files(self, dir, mnt):
        '''Make sure that we can see all the files. dir should be empty
           and calling function needs to clean out dir.'''
        n = 3000
        if not os.path.isdir(dir):
            return False
        if not os.path.isdir(mnt):
            return False

        for i in range(n):
            rc, report = testlib.cmd(['touch', os.path.join(dir, str(i) + ".txt") ])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        files = os.listdir(dir)
        nfiles = len(files)
        report = 'number of files is %d, should be %d' % (nfiles, n)
        self.assertEquals(n, nfiles, report)

        files = os.listdir(mnt)
        nfiles = len(files)
        report = 'number of files is %d, should be %d' % (nfiles, n)
        self.assertEquals(n, nfiles, report)


    def _test_number_dirs(self, dir, mnt):
        '''Make sure that we can see all the dirs. dir should be empty
           and calling function needs to clean out dir.'''
        n = 3000
        if not os.path.isdir(dir):
            return False
        if not os.path.isdir(mnt):
            return False

        for i in range(n):
            os.mkdir(os.path.join(dir, str(i) + ".dir"))

        files = os.listdir(dir)
        nfiles = len(files)
        report = 'number of dirs is %d, should be %d' % (nfiles, n)
        self.assertEquals(n, nfiles, report)

        files = os.listdir(mnt)
        nfiles = len(files)
        report = 'number of dirs is %d, should be %d' % (nfiles, n)
        self.assertEquals(n, nfiles, report)

    def _word_find(self,report,name):
        '''Check for a specific string'''
        warning = 'Could not find "%s"\n' % name
        self.assertTrue(name in report, warning + report)


class NfsutilsGeneric(NfsutilsCommon):
    '''Test for showmount functions'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        testlib.config_replace(self.nfs_exports,'''#
/tmp localhost(rw,sync,no_subtree_check)
''')
        self._restart()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_showmount(self):
        '''(NfsutilsGeneric) Test connection with showmount'''
        for h in [self.ip, socket.gethostname(), 'localhost', '127.0.0.1']:
            rc, report = testlib.cmd(['showmount','-e', h])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._word_find(report,'/tmp')

    def test_client_showmount(self):
        '''(NfsutilsGeneric) Test client connection with showmount'''
        if test_client == "":
            return self._skipped("no host specified")

        try:
            client_ip = socket.gethostbyname(test_client)
            client = test_client
        except:
            return self._skipped("'%s' is invalid" % (test_client))

        for h in [client, client_ip]:
            rc, report = testlib.cmd(['showmount', '-e', h])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._word_find(report,'/tmp')

class NfsutilsStub(NfsutilsCommon):
    '''Stub tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_stub(self):
        '''(NfsutilsStub) stub'''
        pass


class Nfsutilsv3share(NfsutilsCommon):
    '''nfs v3 tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        testlib.config_replace(self.nfs_exports,'''#
/tmp localhost(rw,sync,no_subtree_check)
''')
        self._restart()

        self.mountpoint = tempfile.mkdtemp(prefix='testlib', dir='/mnt')
        os.chmod(self.mountpoint, 0755)

        self.testdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.testdir, 01777)

    def tearDown(self):
        '''Tear down method'''
        subprocess.call(['umount',self.mountpoint])
        if os.path.exists(self.mountpoint):
            testlib.recursive_rm(self.mountpoint)
        if os.path.exists(self.testdir):
            testlib.recursive_rm(self.testdir)
        self._tearDown()

    def test_mount(self):
        '''(Nfsutilsv3share) mount (read/write)'''
        rc, report = testlib.cmd(['mount', '-t', 'nfs', 'localhost:/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        dir = os.path.join(self.mountpoint, os.path.basename(self.testdir))

        # Verify read access
        self.assertTrue(os.path.exists(dir))

        # Now try a file write
        string = 'This is a test for writing'
        handle, self.tmpname = tempfile.mkstemp(prefix='test-write', \
                                                dir='/tmp')
        handle = file(self.tmpname,'w')
        handle.write(string)
        handle.close()

        rc, report = testlib.cmd(['cp', self.tmpname, dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_number_files(self):
        '''(Nfsutilsv3share) Test number files'''
        rc, report = testlib.cmd(['mount', '-t', 'nfs', 'localhost:/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        NfsutilsCommon._test_number_files(self, self.tmpdir, dir)

        testlib.recursive_rm(self.tmpdir)
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        NfsutilsCommon._test_number_dirs(self, self.tmpdir, dir)

class NfsutilsTmpServe(NfsutilsCommon):
    '''Used to startup nfs serving /tmp'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        print >>sys.stdout, "\nMount the remote share with:\n$ sudo mount -t nfs %s:/tmp /mnt" % (self.ip)
        sys.stdout.flush()

        testlib.config_replace(self.nfs_exports,'''#
/tmp *(rw,sync,no_subtree_check)
''')
        self._restart()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_serve_tmp(self):
        '''(NfsutilsTmpServe) start nfs serving /tmp'''
        subprocess.call(['bash'])


if __name__ == '__main__':
    suite = unittest.TestSuite()

    tmpserve = False
    if (len(sys.argv) == 1 or sys.argv[1] != '-v'):
        if sys.argv[1] == "tmpserve":
            tmpserve = True
        else:
            test_client = sys.argv[1]

    if tmpserve:
        # useful for testing apps that use nfs
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(NfsutilsTmpServe))
    else:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(NfsutilsGeneric))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nfsutilsv3share))
        #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(NfsutilsStub))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
