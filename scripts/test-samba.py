#!/usr/bin/python
#
#    test-samba.py quality assurance test script
#    Copyright (C) 2008-2016 Canonical Ltd.
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

# QRT-Packages: samba smbclient bind9-host sudo
# QRT-Alternates: smbfs cifs-utils

'''
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get -y install samba smbclient smbfs bind9-host sudo
    $ sudo ./test-samba.py -v
    $ sudo ./test-samba.py <client hostname> -v
    $ sudo ./test-samba.py tmpserve -v

  If specify <client hostname>, the scripts will also do client browsing tests
  to <client hostname>.

  If use 'tmpserve', then this script will start samba serving /tmp, then drop
  to a shell. This allows for quick testing of clients and the server. Clients
  can mount, do what they want, then unmount. After unmounting, just type
  'exit' in the shell.

  This script also has a test for swat, but it is disabled by default. To run it,
  you need to install the "elinks" and "swat" packages, restart the inetd daemon,
  and uncomment the test at the bottom of this script.

  TODO:
    smbtree
    winbindd
'''

import unittest, subprocess, tempfile, os, os.path, grp, time, socket, sys, stat, re
import testlib

test_client = ""

class SambaCommon(testlib.TestlibCase):
    '''Common routines for testing samba shares.'''
    def _setUp(self):
        '''Common test setup'''
        self.smb_conf = "/etc/samba/smb.conf"
        self.rundir = "/var/run/samba"
        self.tmpname = ""
        self.tmpdir = ""
        self.daemons = [ "smbd", "nmbd" ]

        # be nice if this worked, but it doesn't always
        # self.ip = socket.gethostbyname(socket.gethostname())

        rc, report = testlib.cmd(['host', '-t', 'A', socket.gethostname()])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.ip = report.split(' ').pop().strip()

        self._restart()

    def _tearDown(self):
        '''Common test tear down'''
        testlib.config_restore(self.smb_conf)
        self._stop()
        if os.path.exists(self.tmpname):
            os.unlink(self.tmpname)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _start(self):
        '''Startup with each test'''

        if self.lsb_release['Release'] >= 15.04:
            self.assertTrue(subprocess.call(['/bin/systemctl', 'start', 'nmbd'], \
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT) \
                              == 0)
            self.assertTrue(subprocess.call(['/bin/systemctl', 'start', 'smbd'], \
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT) \
                              == 0)
        else:
            self.assertTrue(subprocess.call(['/sbin/start', 'nmbd'], \
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT) \
                              == 0)
            self.assertTrue(subprocess.call(['/sbin/start', 'smbd'], \
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT) \
                              == 0)
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            for count in ['1', '2', '3', '4', '5']:
                if testlib.check_pidfile(d, pidfile):
                    break
	        time.sleep(1)
        # give samba a few seconds to settle down and accept connections
	time.sleep(3)

    def _stop(self):
        '''Stop with each test'''
        if self.lsb_release['Release'] >= 15.04:
            subprocess.call(['/bin/systemctl', 'stop', 'nmbd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.call(['/bin/systemctl', 'stop', 'smbd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            subprocess.call(['/sbin/stop', 'nmbd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.call(['/sbin/stop', 'smbd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            for count in ['1', '2', '3', '4', '5']:
                if not os.path.exists(pidfile):
                    break
	        time.sleep(1)

    def _restart(self):
        '''Shutdown and startup with each test'''
        self._stop()
        self._start()

    def _testparm(self):
        '''Check the configuration'''
        rc, report = testlib.cmd(['testparm', '-s'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _adduser(self):
        '''Add a test user'''
        user = testlib.TestUser()#group='users',uidmin=2000,lower=True)

        # smbpasswd seems to collide on its auth files randomly.
        for i in ['account_policy','group_mapping','passdb','secrets']:
            tdb = os.path.join('/var/lib/samba',i+'.tdb')
            if os.path.exists(tdb):
                os.unlink(tdb)

        self._restart()

        # Set SMB password
        prompt, name = testlib.mkstemp_fill(user.password + \
                               '\n' + user.password + '\n')
        os.unlink(name)
        self.assertShellExitEquals(0,['smbpasswd','-L', '-s','-a', \
                                   user.login], stdin = prompt)

        # Enable SMB user
        self.assertShellExitEquals(0,['smbpasswd','-L', '-e', \
                                   user.login])

        return user

    def _testDaemons(self, daemons):
        '''Daemons running'''
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            warning = "Could not find pidfile '" + pidfile + "'"
            self.assertTrue(os.path.exists(pidfile), warning)
            self.assertTrue(testlib.check_pidfile(d, pidfile))

    def _browse(self):
        '''Issue a browse request and check for a specific string'''
        rc, report = testlib.cmd(['smbclient','-N','-L','localhost'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        return report

    def _smbcmd(self,mount,cmd,exitcode=0,user=None,password=None):
        smbclient = ['smbclient']
        if password==None:
            smbclient += ['-N']
        if user!=None:
            smbclient += ['-U',user]
        smbclient += ['-c',cmd,'//localhost'+mount]
        if password!=None:
            smbclient += [password]

        rc, report = testlib.cmd(smbclient)
        result = 'Got exit code %d, expected %d\nCommand: %s\n' % (rc, \
                  exitcode, ' '.join(smbclient))
        self.assertEquals(exitcode, rc, result + report)

        return report

    def _smbget(self,mount,path,exitcode=0,user=None,password=None):
        '''Get contents of a remote file'''
        dir = os.path.dirname(path) 
        base = os.path.basename(path)

        tmpdir = tempfile.mkdtemp(dir='/tmp')
        cmd = 'lcd '+tmpdir+';get '+base

        report = self._smbcmd(mount,cmd,exitcode,user,password)

        contents = ''
        if exitcode == 0:
            localpath = os.path.join(tmpdir,base)
            contents = file(localpath).read()
            os.unlink(localpath)

        testlib.recursive_rm(tmpdir)
        return contents, report

    def _smbput(self,local_path,mount,target_dir,exitcode=0,user=None,\
                password=None):
        '''Put local file to remote path'''
        local_dir = os.path.dirname(local_path) 
        local_base = os.path.basename(local_path)

        cmd = 'lcd '+local_dir+';cd '+target_dir+';put '+local_base
        return self._smbcmd(mount,cmd,exitcode,user,password)

    def _smbdir(self,mount,target_dir,exitcode=0,user=None,password=None):
        '''Get directory of remote path'''

        cmd = 'cd '+target_dir+';dir'
        return self._smbcmd(mount,cmd,exitcode,user,password)

    def _set_security(self, sec=""):
        '''Set security parameter in smb.conf'''
        self.assertTrue(os.path.exists(self.smb_conf))
        self.assertTrue(os.path.exists(self.smb_conf + '.autotest'))

        if sec == "":
            # comment out the security if none defined
            subprocess.call(['sed', '-i', 's/^ *security =/;security =/', \
                            self.smb_conf])
        else:
            # strip out old comments
            subprocess.call(['sed', '-i', 's/^; *security *=.*//', self.smb_conf])

            # strip out other security lines
            subprocess.call(['sed', '-i', 's/^ *security *=.*//', self.smb_conf])

            # add a security line to the global section
            subprocess.call(['sed', '-i', 's/^\[global\]/[global]\\nsecurity = ' + sec + '\\n/', self.smb_conf])

        self._testparm()
        self._restart()

    def _word_find(self,report,name):
        '''Check for a specific string'''
        warning = 'Could not find "%s"\n' % name
        self.assertTrue(name in report, warning + report)

    def _test_dir_list(self, dir):
        '''Make sure ls doesn't crash samba:
           http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=451839'''
        rc, report = testlib.cmd(['ls', dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        SambaCommon._testDaemons(self, self.daemons)

    def _test_number_files(self, dir, mnt):
        '''Make sure that samba can see all the files. dir should be empty
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
        '''Make sure that samba can see all the dirs. dir should be empty
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



class SambaGeneric(SambaCommon):
    '''Test for generic anonymous functions'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_browse_ipc(self):
        '''(SambaGeneric) Browse IPC share and Workgroup'''
        for h in [self.ip, socket.gethostname(), 'localhost', '127.0.0.1']:
            for version in ['default','1']:
                args = ['-N']
                if version != 'default':
                    args += ['-m', version]
                for p in ['default', '139', '445']:
                    cmd = ['smbclient'] + args
                    if p != 'default':
                        cmd += ['-p',p]

                    cmd += ['-L', h]
                    rc, report = testlib.cmd(cmd)
                    expected = 0
                    result = 'Got exit code %d, expected %d\n' % (rc, expected)
                    self.assertEquals(expected, rc, result + report)

                    self._word_find(report,'IPC$')
                    self._word_find(report,'Samba, Ubuntu')

                    self._word_find(report,'WORKGROUP')

    def test_browse_only_printdriver_disk(self):
        '''(SambaGeneric) Browse only a print driver share'''
        disks = [f for f in self._browse().splitlines() if ' Disk ' in f]
        for f in disks:
            self.assertTrue('print$' in f,'Unexpected "Disk" share:\n' + f)

    def test_nmb_advertise(self):
        '''(SambaGeneric) Server advertise'''
        for h in [self.ip, 'localhost', '127.0.0.1']:
            rc, report = testlib.cmd(['nmblookup', '-B', h, '__SAMBA__'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self._word_find(report, self.ip + ' __SAMBA__<00>')

            rc, report = testlib.cmd(['nmblookup', '-B', h, '*'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self._word_find(report, self.ip + ' *<00>')

    def test_client_browsing(self):
        '''(SambaGeneric) Client browsing'''
        if test_client == "":
            return self._skipped("no host specified")

        try:
            client_ip = socket.gethostbyname(test_client)
            client = test_client
        except:
            return self._skipped("'%s' is invalid" % (test_client))

        for h in [client, client_ip]:
            rc, report = testlib.cmd(['nmblookup', '-B', h, '*'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self._word_find(report, client_ip + ' *<00>')

        rc, report = testlib.cmd(['nmblookup', '*'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, client_ip + ' *<00>')
        self._word_find(report, self.ip + ' *<00>')

    def test_daemons(self):
        '''(SambaGeneric) Daemons running'''
        SambaCommon._testDaemons(self, self.daemons)


class SambaTmp(SambaCommon):
    '''Test a world-writable share'''
    def setUp(self):
        '''Tmp test setup'''
        self._setUp()
        testlib.config_replace(self.smb_conf,'''#
[tmp]
   comment = Temp Directory
   path = /tmp
   browseable = yes
   writable = yes
   public = yes
   guest ok = yes
''',append=True)
        self._testparm()
        self._restart()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_tmp_browse(self):
        '''(SambaTmp) Browse tmp share'''
        report = self._browse()
        disks = [f for f in report.splitlines() if ' Disk ' in f]
        found = False
        for f in disks:
            if 'Temp Directory' in f:
                found = True
        self.assertTrue(found, 'Did not find tmp share:\n' + report)

    def test_tmp_file_read(self):
        '''(SambaTmp) Read remote file contents'''
        string = 'This is a test for reading'
        handle, self.tmpname = tempfile.mkstemp(prefix='test-read', \
                                                dir='/tmp')
        handle = file(self.tmpname,'w')
        handle.write(string)
        handle.close()

        # verify that we cannot read a private file on an anon share
        contents, report = self._smbget('/tmp',self.tmpname, exitcode=1)
        self.assertTrue('NT_STATUS_ACCESS_DENIED opening remote file' in \
                        report, 'Should not be able to read file:\n' + \
                        report)

        os.chmod(self.tmpname,0744)
        contents, report = self._smbget('/tmp',self.tmpname)
        self.assertTrue('getting file ' in report, \
                        'Should be able to read file:\n' + report)

        self.assertTrue(string == contents, \
                        'Contents mis-match "%s" != "%s"' % \
                        (string,contents))

    def test_tmp_file_write(self):
        '''(SambaTmp) Write remote file contents'''
        string = 'This is a test for writing'
        handle, self.tmpname = tempfile.mkstemp(prefix='test-write', \
                                                dir='/tmp')
        handle = file(self.tmpname,'w')
        handle.write(string)
        handle.close()

        self.tmpdir = tempfile.mkdtemp(prefix='target-dir',dir='/tmp')
        # Make sure we can't write to private directories
        report = self._smbput(self.tmpname,'/tmp', \
                              os.path.basename(self.tmpdir),exitcode=1)
        self.assertTrue('Failed to open ' in report or \
                        'NT_STATUS_ACCESS_DENIED opening remote file ' in \
                        report, 'Should not be able to write file:\n' + \
                        report)

        os.chmod(self.tmpdir,0777)
        report = self._smbput(self.tmpname,'/tmp', \
                              os.path.basename(self.tmpdir))
        self.assertTrue('putting file ' in report, \
                        'Should be able to write file:\n' + report)

        newpath = os.path.join(self.tmpdir,os.path.basename(self.tmpname))
        contents = file(newpath).read()
        self.assertTrue(string == contents, \
                        'Contents miss-match "%s" != "%s"' % \
                        (string,contents))


class SambaUser(SambaCommon):
    '''Test access to a user-writable share'''
    def setUp(self):
        '''User test setup'''
        self._setUp()

        self.user = self._adduser()

        subprocess.call(['groupadd','evilsamba'])
        subprocess.call(['usermod','-G','users,evilsamba',self.user.login])

        if not os.path.exists('/var/tmp/samba-forcedgroup'):
            os.mkdir('/var/tmp/samba-forcedgroup', 0755)
        if not os.path.exists('/var/tmp/samba-forcedgroup/readable'):
            os.mkdir('/var/tmp/samba-forcedgroup/readable')
        if not os.path.exists('/var/tmp/samba-forcedgroup/writable'):
            os.mkdir('/var/tmp/samba-forcedgroup/writable')
        if not os.path.exists('/var/tmp/samba-forcedgroup/unreadable'):
            os.mkdir('/var/tmp/samba-forcedgroup/unreadable')
        os.chown('/var/tmp/samba-forcedgroup/readable', 0, \
                 grp.getgrnam('users')[2])
        os.chmod('/var/tmp/samba-forcedgroup/readable', 0770)
        os.chown('/var/tmp/samba-forcedgroup/writable', 0, \
                 grp.getgrnam('evilsamba')[2])
        os.chmod('/var/tmp/samba-forcedgroup/writable', 0770)
        os.chown('/var/tmp/samba-forcedgroup/unreadable', 0, 0)
        os.chmod('/var/tmp/samba-forcedgroup/unreadable', 0770)

        #subprocess.call(['ls','-la','/var/tmp/samba-forcedgroup'])
        #subprocess.call(['id',self.user.login])

        testlib.config_replace(self.smb_conf,'''#
[forcedgroup]
   comment = Test Directory
   path = /var/tmp/samba-forcedgroup
   create mode = 0664
   directory mode = 2775
   force group = evilsamba
   valid users = @users
   writable = yes
''',append=True)

        self._testparm()
        self._restart()

    def tearDown(self):
        '''User test cleanup'''
        testlib.recursive_rm('/var/tmp/samba-forcedgroup/writable')
        testlib.recursive_rm('/var/tmp/samba-forcedgroup/readable')
        testlib.recursive_rm('/var/tmp/samba-forcedgroup/unreadable')
        testlib.recursive_rm('/var/tmp/samba-forcedgroup')

        testlib.config_restore(self.smb_conf)
        subprocess.call(['groupdel','evilsamba'])
        self.user = None
        self._tearDown()

    def test_user_dir_readable(self):
        '''(SambaUser) Read user share directory contents'''

        unreadable_exitcode = 1

        # This directory should be unreadable
        report = self._smbdir('/forcedgroup','unreadable', \
                              exitcode=unreadable_exitcode,
                              user=self.user.login, \
                              password=self.user.password)
        self.assertTrue('NT_STATUS_ACCESS_DENIED listing ' in report, \
                        'Should not be able to read directory:\n' + report)

        # This directory should be readable
        report = self._smbdir('/forcedgroup','readable', \
                              user=self.user.login, \
                              password=self.user.password)
        self.assertTrue(' D        0 ' in report, \
                        'Should be able to read directory:\n' + report)

    def test_user_file_write(self):
        '''(SambaUser) Write user share remote file contents'''
        string = 'This is a test for writing with group perms'
        handle, self.tmpname = tempfile.mkstemp(prefix='test-write', \
                                                dir='/tmp')
        handle = file(self.tmpname,'w')
        handle.write(string)
        handle.close()

        # This should not be writable
        report = self._smbput(self.tmpname,'/forcedgroup','.', \
                              user=self.user.login, \
                              password=self.user.password,exitcode=1)
        self.assertTrue('Failed to open ' in report or \
                        'NT_STATUS_ACCESS_DENIED opening remote file ' in \
                        report, 'Should not be able to write file:\n' + \
                        report)

        # This should be writable
        report = self._smbput(self.tmpname,'/forcedgroup','writable', \
                              user=self.user.login, \
                              password=self.user.password)
        self.assertTrue('putting file ' in report, \
                        'Should be able to write file:\n' + report)

        newpath = os.path.join('/var/tmp/samba-forcedgroup/writable', \
                               os.path.basename(self.tmpname))
        contents = file(newpath).read()
        self.assertTrue(string == contents, \
                        'Contents mis-match "%s" != "%s"' % \
                        (string,contents))


class SambaSmbfs(SambaCommon):
    '''smbfs tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        testlib.config_replace(self.smb_conf,'''#
[tmp]
   comment = Temp Directory
   path = /tmp
   browseable = yes
   writable = yes
   public = yes
   guest ok = yes
''',append=True)
        self._testparm()
        self._restart()

        self.user = None
        self.mountpoint = tempfile.mkdtemp(prefix='testlib', dir='/mnt')
        os.chmod(self.mountpoint, 0755)

        self.testdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.testdir, 01777)

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        subprocess.call(['umount',self.mountpoint])
        if os.path.exists(self.mountpoint):
            testlib.recursive_rm(self.mountpoint)
        if os.path.exists(self.testdir):
            testlib.recursive_rm(self.testdir)
        self.user = None

    def test_guest(self):
        '''(SambaSmbfs) Guest mount (read-only)'''
        rc, report = testlib.cmd(['mount', '-t', 'smbfs', '-oguest', '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify read access
        self.assertTrue(os.path.exists(os.path.join(self.mountpoint, \
                          os.path.basename(self.testdir))))

        SambaCommon._test_dir_list(self, self.mountpoint)

    def test_user(self):
        '''(SambaSmbfs) User mount (read/write)'''
        self.user = self._adduser()
        rc, report = testlib.cmd(['mount', '-t', 'smbfs', '-o', \
                                  'dmask=0777,fmask=0777' + \
                                  ',username=' + self.user.login + \
                                  ',password=' + self.user.password, \
                                  '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Read/write access
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

        os.chmod(self.tmpname,0644)

        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'cp', self.tmpname, dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        SambaCommon._test_dir_list(self, self.mountpoint)

    def test_number_files(self):
        '''(SambaSmbfs) Test number files'''
        rc, report = testlib.cmd(['mount', '-t', 'smbfs', '-oguest', '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        SambaCommon._test_number_files(self, self.tmpdir, dir)

        testlib.recursive_rm(self.tmpdir)
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        SambaCommon._test_number_dirs(self, self.tmpdir, dir)

class SambaUnixext(SambaCommon):
    '''unix extensions tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

        self.user = None
        self.mountpoint = tempfile.mkdtemp(prefix='testlib', dir='/mnt')
        os.chmod(self.mountpoint, 0755)

        self.testdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.testdir, 01777)

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        subprocess.call(['umount',self.mountpoint])
        if os.path.exists(self.mountpoint):
            testlib.recursive_rm(self.mountpoint)
        if os.path.exists(self.testdir):
            testlib.recursive_rm(self.testdir)
        self.user = None

    def _unixext_setup(self, unixext=None, widelinks=None):
        '''Set up cmd.conf file for Unixext tests'''
        testlib.config_replace(self.smb_conf,'''#
[tmp]
   comment = Temp Directory
   path = /tmp
   browseable = yes
   writable = yes
   public = yes
   guest ok = yes
''',append=True)

        if unixext is not None:
            subprocess.call(['sed', '-i', 's/^\[global\]/[global]\\nunix extensions = ' + unixext + '\\n/', self.smb_conf])

        if widelinks is not None:
            subprocess.call(['sed', '-i', 's/^\[global\]/[global]\\nwide links = ' + unixext + '\\n/', self.smb_conf])

        self._testparm()
        self._restart()

    def test_default(self):
        '''(SambaUnixext) Default options'''

        self._unixext_setup()

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-oguest', '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        mount_temp_dir = os.path.join(self.mountpoint, os.path.basename(self.testdir))

        # verify read access
        self.assertTrue(os.path.exists(mount_temp_dir))

        # Create a file in our temp dir
        handle, name = testlib.mkstemp_fill('This is a temp file.', dir=mount_temp_dir)

        # See if we can create a symlink to the test file
        current_dir = os.getcwd()
        os.chdir(mount_temp_dir)
        rc, report = testlib.cmd(['ln', '-s', os.path.basename(name), 'test-symlink1'])
        os.chdir(current_dir)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Is it actually a symlink? This makes sure unix extensions work.
        sb = os.lstat(os.path.join(mount_temp_dir, 'test-symlink1'))
        self.assertTrue(stat.S_ISLNK(sb.st_mode), "test-symlink1 isn't a symlink!!!")

        # See if we can create a symlink to a path outside the samba share
        #
        # Since CVE-2010-0926 got fixed, wide links should get disabled
        # automatically when unix extensions are enabled, so this should
        # fail.
        #
        current_dir = os.getcwd()
        os.chdir(mount_temp_dir)
        rc, report = testlib.cmd(['ln', '-s', '/etc/hosts', 'test-symlink2'])
        os.chdir(current_dir)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Since we don't get an error back on Dapper and Precise+, let's try
        # and read the actual file. We shouldn't be able to because wide links
        # should be automatically disabled.
        time.sleep(2)
        rc, report = testlib.cmd(['cp', os.path.join(mount_temp_dir, 'test-symlink2'), os.path.join(mount_temp_dir, 'test-read')])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


    def test_unixextdis(self):
        '''(SambaUnixext) Test with unix extensions disabled'''

        if self.lsb_release['Release'] >= 10.04:
            return self._skipped('TODO: fix this test for lucid+')

        self._unixext_setup(unixext="no")

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-oguest', '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        mount_temp_dir = os.path.join(self.mountpoint, os.path.basename(self.testdir))

        # verify read access
        self.assertTrue(os.path.exists(mount_temp_dir))

        # Create a file in our temp dir
        handle, name = testlib.mkstemp_fill('This is a temp file.', dir=mount_temp_dir)

        # See if we can create a symlink to the test file
        # With unix extensions disabled, we shouldn't be able to create
        # symlinks
        current_dir = os.getcwd()
        os.chdir(mount_temp_dir)
        rc, report = testlib.cmd(['ln', '-s', os.path.basename(name), 'test-symlink1'])
        os.chdir(current_dir)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Create a symlink to a path outside the samba share
        #
        # With unix extensions disabled, and wide links enabled the symlink
        # should get mapped to the actual file server-side
        #
        rc, report = testlib.cmd(['ln', '-s', '/etc/hosts', os.path.join(self.testdir, 'test-symlink2')])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure it's seen as a regular file
        sb = os.lstat(os.path.join(mount_temp_dir, 'test-symlink2'))
        self.assertTrue(stat.S_ISREG(sb.st_mode), "test-symlink2 isn't a regular file!!!")

        # See if we can read the file
        rc, report = testlib.cmd(['cp', os.path.join(mount_temp_dir, 'test-symlink2'), os.path.join(mount_temp_dir, 'test-read')])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


    def test_unixextandwldis(self):
        '''(SambaUnixext) Test with unix extensions and wide links disabled'''

        self._unixext_setup(unixext="no", widelinks="no")

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-oguest', '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        mount_temp_dir = os.path.join(self.mountpoint, os.path.basename(self.testdir))

        # verify read access
        self.assertTrue(os.path.exists(mount_temp_dir))

        # Create a file in our temp dir
        handle, name = testlib.mkstemp_fill('This is a temp file.', dir=mount_temp_dir)

        # See if we can create a symlink to the test file
        # With unix extensions disabled, we shouldn't be able to create
        # symlinks
        current_dir = os.getcwd()
        os.chdir(mount_temp_dir)
        rc, report = testlib.cmd(['ln', '-s', os.path.basename(name), 'test-symlink1'])
        os.chdir(current_dir)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Create a symlink to a path outside the samba share
        #
        # With unix extensions and wide links disabled, the symlink should
        # result in a file that is unreadable when mounted
        #
        rc, report = testlib.cmd(['ln', '-s', '/etc/hosts', os.path.join(self.testdir, 'test-symlink2')])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # See if we can read the file, we shouldn't be able to if wide links are disabled
        rc, report = testlib.cmd(['cp', os.path.join(mount_temp_dir, 'test-symlink2'), os.path.join(mount_temp_dir, 'test-read')])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


class SambaCifs(SambaCommon):
    '''cifs tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        testlib.config_replace(self.smb_conf,'''#
[tmp]
   comment = Temp Directory
   path = /tmp
   browseable = yes
   writable = yes
   public = yes
   guest ok = yes
''',append=True)
        self._testparm()
        self._restart()

        self.user = None
        self.creds = ""
        self.mountpoint = tempfile.mkdtemp(prefix='testlib', dir='/mnt')
        os.chmod(self.mountpoint, 0755)
        self.user_mountpoint = ""

        self.testdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.testdir, 01777)

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        subprocess.call(['umount',self.mountpoint])
        if (self.user_mountpoint != ""):
            subprocess.call(['umount',self.user_mountpoint])
        if os.path.exists(self.mountpoint):
            testlib.recursive_rm(self.mountpoint)
        if os.path.exists(self.testdir):
            testlib.recursive_rm(self.testdir)
        if os.path.exists(self.creds):
            os.unlink(self.creds)
        self.user = None

    def test_guest(self):
        '''(SambaCifs) Guest mount (read-only)'''

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'guest,sec=none', '//localhost/tmp', \
                                  self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # verify read access
        self.assertTrue(os.path.exists(os.path.join(self.mountpoint, \
                          os.path.basename(self.testdir))))

        SambaCommon._test_dir_list(self, self.mountpoint)

    def test_user(self):
        '''(SambaCifs) User mount (read/write)'''
        self.user = self._adduser()

        # try with password=
        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'user=' + self.user.login + \
                                  ',pass=' + self.user.password, \
                                  '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(2)

        rc, report = testlib.cmd(['umount',self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # try with user=name%password
        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'user=' + self.user.login + \
                                  '%' + self.user.password, \
                                  '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(2)

        rc, report = testlib.cmd(['umount',self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # try with credentials=
        handle, self.creds = testlib.mkstemp_fill('username=' + \
                                                  self.user.login + '\n' + \
                                                  'password=' + \
                                                  self.user.password + '\n')
        handle.close()

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'credentials=' + self.creds,
                                  '//localhost/tmp', self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Read/write access
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

        os.chmod(self.tmpname,0644)

        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'cp', self.tmpname, dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        SambaCommon._test_dir_list(self, self.mountpoint)

    def test_cve_2009_2948(self):
        '''(SambaCifs) Credential file disclosure (CVE-2009-2948)'''
        self.user = self._adduser()

        # Set up the credentials file
        handle, self.creds = testlib.mkstemp_fill('username=' + \
                                                  self.user.login + '\n' + \
                                                  'password=' + \
                                                  self.user.password + '\n')
        handle.close()

        # Only root can read the credentials file
        os.chmod(self.creds,0600)

        # Create a mountpoint owned by the user
        self.user_mountpoint = tempfile.mkdtemp(prefix='testlib', dir=self.user.home)
        os.chmod(self.user_mountpoint, 0755)
        os.chown(self.user_mountpoint, self.user.uid, self.user.gid)

        # See if the user can read the credentials file
        rc, report = testlib.cmd(['sudo', '-u', self.user.login,
                                  '/sbin/mount.cifs', '//localhost/tmp',
                                  self.user_mountpoint, '--verbose',
                                  '-o', 'credentials=' + self.creds])
        result = 'Got exit code %d, expected 1 or 255\n' % rc
        self.assertTrue(rc == 255 or rc == 1, result + report)

        result = 'Found user password in report\n'
        self.assertFalse(self.user.password in report, result + report)

    def test_number_files(self):
        '''(SambaCifs) Test number of files'''

        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'guest,sec=none', '//localhost/tmp', \
                                  self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        SambaCommon._test_number_files(self, self.tmpdir, dir)

        testlib.recursive_rm(self.tmpdir)
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.tmpdir,0777)
        dir = os.path.join(self.mountpoint, os.path.basename(self.tmpdir))
        SambaCommon._test_number_dirs(self, self.tmpdir, dir)

class SambaHomes(SambaCommon):
    '''home directory tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        testlib.config_replace(self.smb_conf,'''#
[homes]
   comment = Home Directories
   browseable = yes
''',append=True)

        self._testparm()
        self._restart()

        self.user = None
        self.creds = ""
        self.mountpoint = tempfile.mkdtemp(prefix='testlib', dir='/mnt')
        os.chmod(self.mountpoint, 0755)

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        subprocess.call(['umount',self.mountpoint])
        if os.path.exists(self.mountpoint):
            testlib.recursive_rm(self.mountpoint)
        if os.path.exists(self.creds):
            os.unlink(self.creds)
        self.user = None
        self.nohome_user = None

    def test_homedir_user(self):
        '''(SambaHomes) Regular User mount'''

        self.user = self._adduser()

        # Create a special file in the user's homedir
        rc, report = testlib.cmd(['touch', os.path.join(self.user.home,self.user.login + "-homedir")])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Try to mount the user's home directory
        home_dir = "//localhost/" + self.user.login
        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'user=' + self.user.login + \
                                  ',pass=' + self.user.password, \
                                  home_dir, self.mountpoint])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Verify special file
        test_file = os.path.join(self.mountpoint, self.user.login + "-homedir")
        self.assertTrue(os.path.exists(test_file))

    def test_no_homedir_user(self):
        '''(SambaHomes) User with no homedir mount (CVE-2009-2813)'''

        self.user = self._adduser()

        # Create a special file in the user's homedir
        rc, report = testlib.cmd(['touch', os.path.join(self.user.home,self.user.login + "-homedir")])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Set the user's home directory to an empty string ("")
        rc, report = testlib.cmd(['usermod', '-d', '""', self.user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Try to mount the user's home directory
        home_dir = "//localhost/" + self.user.login
        rc, report = testlib.cmd(['mount', '-t', 'cifs', '-o', \
                                  'user=' + self.user.login + \
                                  ',pass=' + self.user.password, \
                                  home_dir, self.mountpoint])
        result = 'Got exit code %d, expected 32 or 255\n' % rc
        self.assertTrue(rc == 255 or rc == 32, result + report)

        # Verify special file isn't there and we're not in the root filesystem
        test_file = os.path.join(self.mountpoint, self.user.login + "-homedir")
        root_dir = os.path.join(self.mountpoint, "root")
        self.assertFalse(os.path.exists(test_file))
        self.assertFalse(os.path.exists(root_dir))


class SambaTmpServe(SambaCommon):
    '''Used to startup samba serving /tmp'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        self.user = self._adduser()
        print >>sys.stdout, "\nMount the remote share with:\n$ sudo mount -t cifs -o uid=<your uid>,username=%s,password=%s //%s/tmp /mnt" % (self.user.login, self.user.password, self.ip)
        sys.stdout.flush()

        testlib.config_replace(self.smb_conf,'''#
[tmp]
   comment = Temp Directory
   path = /tmp
   browseable = yes
   writable = yes
   public = yes
   guest ok = yes
''',append=True)
        self._testparm()
        self._restart()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        self.user = None

    def test_serve_tmp(self):
        '''(SambaTmpServe) start samba serving /tmp'''
        subprocess.call(['bash'])

class SambaSwat(SambaCommon):
    '''Swat tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()
        self.user = self._adduser()

    def _regex_find(self,report,content):
        '''Check for a specific regex'''
        warning = 'Could not find "%s"\n' % content
        self.assertTrue(re.search(content, report), warning + report)

    def _fetch_swat_url(self, url="", regex="", username=None, password=None, source=False):
        '''Test the given nagios url'''

        command = ['elinks', '-verbose', '2', '-no-home', '1']

        if source == True:
            command.extend(['-source', '1'])
        else:
            command.extend(['-dump'])

        if username != None:
            command.extend(["http://" + username + ":" + password +"@localhost:901/" + url])
        else:
            command.extend(["http://localhost:901/" + url])

        rc, report = testlib.cmd(command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if regex != "":
            self._regex_find(report, regex)

        return report

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()
        self.user = None

    def test_a_login(self):
        '''(SambaSwat) test login'''

        self._fetch_swat_url(regex="Welcome to SWAT", username=self.user.login,
                             password=self.user.password)
    def test_cve_2011_2694(self):
        '''(SambaSwat) test CVE-2011-2694'''

        url = 'passwd?username=""><script>alert("XSS")</script>'
        report=self._fetch_swat_url(url, username=self.user.login,
                             password=self.user.password, source=True)

        warning = 'The server returned the XSS!!!\n'
        self.assertFalse(re.search("<script>alert\(\"XSS\"\)</script>", report), warning + report)

        warning = 'Could not find the username!!!\n'
        self.assertTrue(re.search("name=username value=%s" % self.user.login, report), warning + report)

    def test_cve_2011_2522(self):
        '''(SambaSwat) test CVE-2011-2522'''

        # We can't really get this to work on Ubuntu without setting a
        # root password and stuff, so let's just check if the nonce is
        # present.
        url = 'status'
        report=self._fetch_swat_url(url, username=self.user.login,
                             password=self.user.password, source=True)

        warning = 'Could not find xsrf nonce!!!\n'
        self.assertTrue(re.search("name=\"xsrf\"", report), warning + report)

        warning = 'Could not find status header!!!\n'
        self.assertTrue(re.search("Server Status", report), warning + report)


class SambaStub(SambaCommon):
    '''Stub tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_stub(self):
        '''(SambaStub) stub'''
        pass


if __name__ == '__main__':
    testlib.require_sudo()

    suite = unittest.TestSuite()
    ubuntu_version = testlib.manager.lsb_release["Release"]

    tmpserve = False
    if (len(sys.argv) == 1 or sys.argv[1] != '-v'):
        if sys.argv[1] == "tmpserve":
            tmpserve = True
        else:
            test_client = sys.argv[1]

    if tmpserve:
        # useful for testing apps that use samba
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaTmpServe))
    else:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaGeneric))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaTmp))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaUser))
        # Quantal+ no longer provide the smbfs compatibility wrapper
        if ubuntu_version < 12.10:
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaSmbfs))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaCifs))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaHomes))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaUnixext))
        #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaSwat))
        #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SambaStub))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
