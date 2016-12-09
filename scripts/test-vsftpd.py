#!/usr/bin/python
#
#    test-vsftpd.py quality assurance test script for vsftpd
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: vsftpd lftp
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) and not
    on a production machine. While efforts are made to make these tests
    non-destructive, there is no guarantee this script will not alter the
    machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-vsftpd.py -v'

    TODO:
    - a lot more tests!

'''


import unittest, sys, os, tempfile, socket, time
import testlib

try:
    from private.qrt.vsftpd import PrivateVsftpdTest
except ImportError:
    class PrivateVsftpdTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class VsftpdTest(testlib.TestlibCase, PrivateVsftpdTest):
    '''Test vsftpd.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.user = testlib.TestUser()
        self.user_testfile = os.path.join(self.user.home, "testfile")
        self.user_teststring = "Ubuntu rocks!"
        testlib.create_fill(self.user_testfile, self.user_teststring)

        self.vsftpd_conf = "/etc/vsftpd.conf"
        testlib.config_set(self.vsftpd_conf,'write_enable','YES', spaces=False)
        testlib.config_set(self.vsftpd_conf,'local_enable','YES', spaces=False)

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="vsftpd-")

        self.daemon = testlib.TestDaemon("/etc/init.d/vsftpd")
        self.daemon.restart()

        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.daemon.stop()

        testlib.config_restore(self.vsftpd_conf)

        if self.current_dir != os.getcwd():
            os.chdir(self.current_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        self.user = None

    def _download_file(self, user=None, password=None, remote_file=None, url="localhost", expected=0):
        '''Download a file with lftp'''
        rc, report = testlib.cmd(['lftp', '-c', 'open -u %s,%s %s; mget %s' % (user,password,url,remote_file)])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _upload_file(self, user=None, password=None, upload_file=None, url="localhost", expected=0):
        '''Download a file with lftp'''
        rc, report = testlib.cmd(['lftp', '-c', 'open -u %s,%s %s; put %s' % (user,password,url,upload_file)])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _check_contents(self, filename=None, expected_contents=None):
        '''Check if file exists and contains the expected contents'''
        error = "Didn't find the testfile."
        self.assertTrue(os.path.exists(filename), error)

        contents = file(filename).read()
        self.assertTrue(expected_contents == contents, \
                        'Contents miss-match "%s" != "%s"' % \
                        (expected_contents,contents))

    def test_aa_download_single(self):
        '''Test download'''

        # Download file in temp directory
        os.chdir(self.tempdir)
        self._download_file(user=self.user.login, password=self.user.password,
                            remote_file='testfile')
        os.chdir(self.current_dir)

        self._check_contents(os.path.join(self.tempdir,'testfile'),self.user_teststring)


    def test_aa_download_glob(self):
        '''Test download with globbing'''

        # Download file in temp directory
        os.chdir(self.tempdir)

        self._download_file(user=self.user.login, password=self.user.password,
                            remote_file='test*')
        os.chdir(self.current_dir)

        self._check_contents(os.path.join(self.tempdir,'testfile'),self.user_teststring)

    def test_aa_upload(self):
        '''Test upload'''

        # Create new tempfile
        new_file = os.path.join(self.tempdir,'newfile')
        string = 'This is a test for uploading'
        handle = file(new_file,'w')
        handle.write(string)
        handle.close()

        self._upload_file(user=self.user.login, password=self.user.password,
                          upload_file=new_file)

        os.unlink(new_file)

        # Work in temp directory
        os.chdir(self.tempdir)
        self._download_file(user=self.user.login, password=self.user.password,
                            remote_file='newfile')
        os.chdir(self.current_dir)

        self._check_contents(new_file,string)

    def x_test_cve_2011_0762(self):
        '''Test CVE-2011-0762'''

        # Disabled, as I couldn't reproduce even with original reproducer.

        os.chdir(self.tempdir)

        # Based upon http://cxib.net/stuff/vspoc232.c

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', 21))
        s.send("USER %s\nPASS %s\n\n" % (self.user.login,self.user.password))
        data = s.recv(4096)
        s.send("STAT {{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{{*},{.}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}]}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}\n")
        s.close()

        # See if it still works
        self._download_file(user=self.user.login, password=self.user.password,
                            remote_file='testfile')

        error = "Didn't find the testfile."
        self.assertTrue(os.path.exists(os.path.join(self.tempdir,'testfile')), error)

        os.chdir(self.current_dir)

    def test_network_isolation(self):
        '''Test network isolation'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("isolate_network not supported in %s" % self.lsb_release['Codename'].capitalize())
        for isolate in ['YES', 'NO']:
            testlib.config_set(self.vsftpd_conf,'isolate_network',isolate, spaces=False)
            self.daemon.restart()

            # Download file in temp directory
            os.chdir(self.tempdir)
            self._download_file(user=self.user.login, password=self.user.password,
                                remote_file='testfile')
            os.chdir(self.current_dir)

            self._check_contents(os.path.join(self.tempdir,'testfile'),self.user_teststring)

            # cleanup
            os.unlink(os.path.join(self.tempdir,'testfile'))

    def test_CVE_2011_2189(self):
        '''Test CVE-2011-2189 for 60 seconds'''
        # This is actually a kernel issue, but we are patching vsftpd so it
        # won't trigger this. It is known to work on 2.6.32-28.55-generic.
        # 2.6.36 and higher kernels are known to be ok.
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("isolate_network not supported in %s" % self.lsb_release['Codename'].capitalize())

        # prepare our files to upload
        upload_topdir = os.path.join(self.tempdir, 'upload')
        max_dirs = 6
        max_files = 6
        snippet = ""
        for i in range(1,max_dirs+1):
            d = os.path.join(self.tempdir, 'tmp%d' % i)
            testlib.cmd(['mkdir', d])
            ud = os.path.join(upload_topdir, 'tmp%d' % i)
            testlib.cmd(['mkdir', '-p', ud])
            for j in range(1, max_files+1):
                f = os.path.join(d, 'test%d' % (j))
                testlib.cmd(['dd', 'if=/dev/urandom', 'of=%s' % (f), 'bs=1', 'count=2048'])
                if i == 1:
                    f_bn = os.path.basename(f)
                    snippet += "put %s -o %s.$i\n" % (f_bn, f_bn)

        testlib.cmd(['chown', '-R', self.user.login, self.tempdir])

        script = os.path.join(self.tempdir,'feedftp')
        contents = '''#!/bin/bash
cd %s
while [ 1 ] ; do
   if [ ! -d "tmp$1" ]; then
       echo "tmp$1 does not exist. Stopping"
       break
   fi
   lftp -u %s,%s localhost <<EOF
cd %s/upload/tmp$1
lcd %s/tmp$1
%s
EOF

let i=$i+1

done
''' % (self.tempdir, self.user.login, self.user.password, self.tempdir, self.tempdir, snippet)
        testlib.create_fill(script, contents, mode=0755)

        testlib.config_set(self.vsftpd_conf,'isolate_network','YES', spaces=False)
        self.daemon.restart()

        exploit = os.path.join(self.tempdir,'exploit')
        contents = '''#!/bin/sh
cd %s
for i in 1 2 3 4 5 6 7 8 ; do
    %s $i >/dev/null &
done
''' % (self.tempdir, script)
        testlib.create_fill(exploit, contents, mode=0755)

        rc, report = testlib.cmd(['wc', '-l', '/proc/vmallocinfo'])
        vmalloc_baseline = int(report.split()[0])

        self.listener = os.fork()
        if self.listener == 0:
            #args = ['/bin/sh', '-c', 'exec %s' % exploit]
            args = ['/bin/sh', '-c', 'exec %s >/dev/null 2>&1' % exploit]
            os.execv(args[0], args)
            sys.exit(0)
        time.sleep(60)

        rc, report = testlib.cmd(['wc', '-l', '/proc/vmallocinfo'])
        vmalloc_now = int(report.split()[0])

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)
        time.sleep(3) # let exploit be killed
        testlib.cmd(['killall', '-9', os.path.basename(script)])
        time.sleep(3) # let feedftp be killed

        vmalloc_diff = vmalloc_now - vmalloc_baseline
        #print "%d - %d = %d" % (vmalloc_now, vmalloc_baseline, vmalloc_diff)
        # allow for some climb since we are on a live OS
        self.assertTrue(vmalloc_diff < 5, "%d entries added to /proc/vmallocinfo!" % vmalloc_diff)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
