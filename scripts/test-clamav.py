#!/usr/bin/python
#
#    test-clamav.py quality assurance test script
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
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

'''
    How to run against a clean schroot named 'edgy':
        schroot -c edgy -u root -- sh -c 'apt-get -y install sudo lsb-release clamav clamav-daemon zip bzip2 mpack clamav-testfiles clamav-milter rar && /etc/init.d/clamav-daemon stop && sleep 5 && /etc/init.d/clamav-daemon start && while ! [ -e /var/run/clamav/clamd.ctl ]; do sleep 5; echo Waiting for clamd to finish loading signatures ...; done && ./test-clamav.py -v'

    NOTE:
      rar only exists on dapper i386, but it still fails
      may have to wait a long time on feisty for /var/run/clamav/clamd.ctl, but
        it should eventually come up
      feisty clamscan hangs in all 0.90.2-0ubuntu1* packages

    TODO:
      * see https://wiki.ubuntu.com/MOTU/Clamav/TestingProcedures
      * amavisd-new integration
      * clamsmtpd integration
'''

# QRT-Depends: private/qrt/clamav.py clamav/
# QRT-Packages: clamav clamav-daemon zip bzip2 mpack clamav-testfiles clamav-milter sudo rar

import unittest, subprocess, shutil, os, os.path, sys, time, socket
import tempfile, testlib
import glob
import stat
import pwd

try:
    from private.qrt.clamav import PrivateClamavTest
except:
    class PrivateClamavTest(object):
        '''Empty Class'''
    print >>sys.stdout, "Skipping private tests"

class ClamavTest(testlib.TestlibCase, PrivateClamavTest):
    '''Test clamav functionality.'''

    def setUp(self):
        # List of file and directories to remove on cleanup
        self.list_unlink = []
        self.list_rmdir  = []
        self.tmpdir = ""

        # Work directory
        self.dir = tempfile.mkdtemp()
        os.chmod(self.dir,0755) # readable so clamd can see the files
        self._rmdir(self.dir)

        self.eicar_file = self.dir + '/eicar.txt'
        self._unlink(self.eicar_file)

        rc, output = testlib.cmd(['clamd', '--version'])
        result = 'Got exit code %d\n' % (rc)
        self.assertTrue(rc == 0, result + output)
        self.version = output.split()[1].split('/')[0].split('.')

        # Instead of this file, the "clamav-testfiles" package could be used.
        fd = file(self.eicar_file,'w')
        # split up EICAR sig so we don't accidentally set off a scanner
        # This is from www.eicar.com, basically CC SA-BY:
        # http://www.eicar.org/anti_virus_test_file.htm
        self.eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'
        self.eicar+= 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        fd.write(self.eicar)
        fd.close()

        self.path_clamscan = '/usr/bin/clamscan'
        self.path_clamdctl = '/var/run/clamav/clamd.ctl'
        self._clamd_reinit()

        self.test_dirs = ['/', '/tmp', '/etc', '/tmp/testlib-clamav', '/var/crash']
        self.topdir = os.getcwd()

    def _clamd_reinit(self):
        '''Reopen the clamd unix socket.'''
        self.clamd = None
        # Delay for clamd initialization
        count = 90
        while count > 0:
            if os.path.exists(self.path_clamdctl):
                break
            time.sleep(1)
            count -= 1

        sock = socket.socket(socket.AF_UNIX)
        sock.connect(self.path_clamdctl)
        self.clamd = sock.makefile('r+')

    def _unlink(self,path):
        self.list_unlink += [path]

    def _rmdir(self,path):
        self.list_rmdir += [path]

    def tearDown(self):
        self.clamd = None
        self.user = None

        for path in self.list_unlink:
            if os.path.exists(path):
                os.unlink(path)
        for path in self.list_rmdir:
            if os.path.exists(path):
                os.rmdir(path)
        if self.tmpdir != "" and os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        for d in self.test_dirs:
            if os.path.exists(d):
                subprocess.call(['chown', 'root', d])

        os.chdir(self.topdir)

    def _clamscan(self,to_scan):
        '''Scan a specific file with clamscan.'''
        return testlib.cmd([self.path_clamscan, to_scan])

    def _clamd(self,to_scan,report_clamd_error=False):
        '''Scan a specific file with clamd.'''
        # FIXME: for some reason, we must re-open the clamd connection
        # on every file?  Clearly this script is making the requests
        # incorrectly...
        self._clamd_reinit()

        self.clamd.write('SCAN %s\n' % to_scan)
        self.clamd.flush()
        # have this match the _clamscan symantic: 0 == success
        rc = self.clamd.readline()
        if rc.find(' OK\n') > 0:
                #print 'OK: "%s"\n' % rc
                return 0, rc
        if rc.find(' FOUND\n') > 0:
                #print 'FOUND: "%s"\n' % rc
                return 1, rc
        else:
                #print >>sys.stderr, 'clamd FAILURE: "%s"\n' % rc
                if report_clamd_error:
                    return 2, rc
                return 0, rc

    def _flag_container(self,container_cmd,suffix,flag=1,takedest=1):
        '''Containment worker for generalized testing'''
        # takedest means the program consumes the source file and does
        # not require the dest file in the command line (gzip, bzip2)

        if flag:
            source_file = os.path.join(self.dir,'eicar')
            shutil.copy(self.eicar_file, source_file)
        else:
            source_file = os.path.join(self.dir,'clean')
            shutil.copy(self.path_clamscan, source_file)
        test_file = source_file + '.%s' % (suffix)
        self._unlink(test_file)

        cmd = container_cmd
        if takedest:
            cmd += [test_file]
            self._unlink(source_file)
        cmd += [source_file]

        rc, out = testlib.cmd(cmd)
        self.assertEquals(rc, 0, out)

        self._scan_file(test_file, flag)

    def test_clamd_alive(self):
        '''Test clamd is listening'''
        self.clamd.writelines('PING\n')
        self.clamd.flush()
        self.assertEquals(self.clamd.readline(),'PONG\n')
        self.assertTrue(os.path.exists(self.path_clamscan))

    def _scan_file(self, pathname, expected, clamd_expected=None):
        rc, out = self._clamscan(pathname)
        self.assertEquals(rc, expected, "clamscan got exit code %d (wanted %d):\n%s" % (rc, expected, out) )

        # In Intrepid and newer, clamd is profiled to only scan out of /tmp.
        # Also, this handles relative file paths (private, etc)
        to_scan = pathname

        suffix = ""
        if '.' in pathname:
            suffix = "." + pathname.split('.').pop()
        clean = tempfile.NamedTemporaryFile(prefix="clamav-", suffix=suffix)

        if not pathname.startswith('/tmp/'):
            clean.write(open(pathname).read())
            clean.flush()
            os.chmod(clean.name,0444)
            to_scan = clean.name

        if clamd_expected == None:
            clamd_expected = expected
        rc, out = self._clamd(to_scan)
        self.assertEquals(rc, clamd_expected, "clamd got exit code %d (wanted %d):\n%s" % (rc, clamd_expected, out) )

    def test_clean(self):
        '''Passes clean files'''
        self._scan_file(self.path_clamscan, 0)

    def test_eicar(self):
        '''Flags EICAR'''

        fd = file(self.eicar_file)
        self.assertEquals(fd.read(),self.eicar)
        fd.close()

        self._scan_file(self.eicar_file, 1)

    def test_eicar_rar(self):
        '''Flags EICAR RAR'''
        if self.lsb_release['Release'] <= 6.06 and self.dpkg_arch != 'i386':
            self._skipped("RAR support in Dapper only exists on i386")
            return

        expected = 1
        if self.version[0] > 0 or self.version[1] > 92:
            self._skipped("RAR support only exists in 0.92 and earlier")
            expected = 0
        elif self.lsb_release['Release'] >= 7.10:
            self._skipped("RAR support only exists prior to Gutsy")
            expected = 0

        self._flag_container(['/usr/bin/rar', 'a'], 'rar', expected)

    def test_clean_rar(self):
        '''Passes clean RAR'''
        if self.lsb_release['Release'] <= 6.06 and self.dpkg_arch != 'i386':
            self._skipped("RAR support in Dapper only exists on i386")
        else:
            self._flag_container(['/usr/bin/rar', 'a'], 'rar', 0)

    def test_eicar_gzip(self):
        '''Flags EICAR gzip'''
        self._flag_container(['/bin/gzip'], 'gz', 1, takedest=0)

    def test_clean_gzip(self):
        '''Passes clean gzip'''
        self._flag_container(['/bin/gzip'], 'gz', 0, takedest=0)

    def test_eicar_bzip2(self):
        '''Flags EICAR bzip2'''
        self._flag_container(['/bin/bzip2'], 'bz2', 1, takedest=0)

    def test_clean_bzip2(self):
        '''Passes clean bzip2'''
        self._flag_container(['/bin/bzip2'], 'bz2', 0, takedest=0)

    def test_eicar_zip(self):
        '''Flags EICAR ZIP'''
        self._flag_container(['/usr/bin/zip'], 'zip', 1)

    def test_clean_zip(self):
        '''Passes clean ZIP'''
        self._flag_container(['/usr/bin/zip'], 'zip', 0)

    def test_clean_mbox(self):
        '''Passes clean mbox'''
        self._flag_container(['/usr/bin/mpack','-s','clean test','-o'], 'mbox', 0)

    def test_recursive_jpeg(self):
        '''Handle high recursion JPEG (LP# 304017)'''

        tmp = tempfile.NamedTemporaryFile(suffix=".jpg")
        # From https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1266
        crasher  = "\xff\xd8" # jpg marker
        crasher += "\xff\xed" # exif data
        crasher += "\x00\x02" # length
        crasher += "Photoshop 3.0\x00"
        crasher += "8BIM"
        crasher += "\x04\x0c" # thumbnail id
        crasher += "\x00"
        crasher += "\x01"
        crasher += "\x01\x01\x01\x01"
        crasher += "0123456789012345678912345678" # skip over 28 bytes
        for i in range(0,200000):
            tmp.write(crasher)
        tmp.flush()

        self._scan_file(tmp.name, 0)

    def test_stock_clamav_files(self):
        '''Correctly flag ClamAV-shipped test files'''
        print ''
        success = True
        result = ""
        for target in glob.glob('clamav/test/clam*'):
            print "  " + target + " ...",
            sys.stdout.flush()
            ok = True

            expected = 1
            clamd_expected = None

            # ClamAV gets better each release, so upstream files aren't
            # correctly detected with some releases.  This is a map of
            # those expectations.
            if os.path.basename(target) in ['clam.pdf']:
                # This is not detected until 0.96.1
                if int(self.version[0]) == 0 and (int(self.version[1]) < 96 or (int(self.version[1]) == 96 and len(self.version) == 2)):
                    expected = 0

            # For some reason, this file isn't detected by clamdscan, only
            # clamscan
            if os.path.basename(target) == 'clam_cache_emax.tgz':
                clamd_expected = 0

            try:
                self._scan_file(target, expected, clamd_expected)
            except Exception, e:
                ok = False
                success = False
                result += target + ":\n" + str(e)
            if ok:
                print "ok"
            else:
                print "FAIL"
        self.assertTrue(success, result)

    def _eicar_mbox(self):
        '''Create an mbox file containing the eicar test sig'''
        eicar_mbox = self.dir + '/eicar.mbox'
        self._unlink(eicar_mbox)
        self.assertEquals(subprocess.call(['/usr/bin/mpack', '-s', 'eicar test', '-o', eicar_mbox, self.eicar_file], stdout=subprocess.PIPE), 0)
        os.chmod(eicar_mbox,0644)
        return eicar_mbox

    def test_eicar_mbox(self):
        '''Flags EICAR mbox'''

        eicar_mbox = self._eicar_mbox()
        rc, out = self._clamscan(eicar_mbox)
        self.assertEquals(rc, 1, out)
        rc, out = self._clamd(eicar_mbox)
        self.assertEquals(rc, 1, out)

    def test_eicar_mbox_corrupted(self):
        '''Flags EICAR mbox with corruption (CVE-2006-2406)'''

        eicar_mbox = self._eicar_mbox()
        # Corrupt the mbox in an attempt to bypass the MIME decoder
        str = file(eicar_mbox).read()
        str = str.replace('VA','VA\n        ')
        str = str.replace('FQ','FQ\n        ')
        str = str.replace('EQ','EQ\n        ')
        str = str.replace('LU','LU\n        ')
        eicar2_mbox = self.dir + '/eicar2.mbox'
        self._unlink(eicar2_mbox)
        file(eicar2_mbox,'w').writelines(str)

        rc, out = self._clamscan(eicar2_mbox)
        self.assertEquals(rc, 1, out)
        rc, out = self._clamd(eicar2_mbox)
        self.assertEquals(rc, 1, out)

    def test_clamav_testfiles(self):
        '''Test files from clamav-testfiles'''
        err = False
        dir = "/usr/share/clamav-testfiles"
        if not os.path.isdir(dir):
            self._skipped("Could not find '%s'" % (dir))
            return

        print >>sys.stdout, ""
        sys.stdout.flush()
        for f in os.listdir(dir):
            if not f.startswith("clam"):
                continue

            path = os.path.join(dir, f)
            print >>sys.stdout, "  %s..." % (f),
            sys.stdout.flush()

            expected = 1
            clamd_expected = None
            if (self.version[0] > 0 or self.version[1] > 92) and f.endswith(".rar"):
                self._skipped("RAR support only exists in 0.92 and earlier")
                expected = 0
            elif self.lsb_release['Release'] >= 7.10 and f.endswith(".rar"):
                print >>sys.stdout, "(RAR support only exists prior to Gutsy)",
                expected = 0

            # For some reason, this file isn't detected by clamdscan, only
            # clamscan
            if f == 'clam_cache_emax.tgz':
                clamd_expected = 0

            try:
                self._scan_file(path, expected, clamd_expected)
                print >>sys.stdout, "ok"
            except:
                err = True
                print >>sys.stdout, "FAIL"
                sys.stdout.flush()

        self.assertFalse(err, "Found errors")

    def test_freshclam(self):
        '''Test freshclam'''
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/var/lib/clamav')
        testlib.cmd(['chown', self.user.login, self.tmpdir])

        logfile = os.path.join(self.tmpdir, "freshclam.log")
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'freshclam', '--log=%s' % (logfile), '--datadir=%s' % (self.tmpdir)])
        expected = 0
        result = 'Got exit code %d\n' % (rc)
        self.assertTrue(rc == expected, result + report)

    def test_bug365823(self):
        '''Test LP: #365823 (clamav-milter chowns directories to clamav)'''
        if self.lsb_release['Release'] != 9.04:
            self._skipped("bug 365823 affected 9.04")
            return

        if self.version[1] != 95 or (len(self.version) >= 3 and self.version[2] > 1):
            self._skipped("bug 365823 only affected 0.95.1")
            return

        clamav_dirs = ['/var/lib/clamav', '/var/log/clamav', '/var/run/clamav']

        if not os.path.exists('/tmp/testlib-clamav'):
            os.mkdir('/tmp/testlib-clamav')

        clamav_uid = pwd.getpwnam("clamav")[2]
        clamav_gid = pwd.getpwnam("clamav")[3]
        for d in self.test_dirs:
            subprocess.call(['chown', str(clamav_uid), d])

        # check if postinst fixes things
        rc, report = testlib.cmd(['/etc/init.d/clamav-milter', 'stop'])
        rc, report = testlib.cmd(['/var/lib/dpkg/info/clamav-milter.postinst', 'configure', "0.95.1+dfsg-1ubuntu1"])
        expected = 0
        result = 'Got exit code %d\n' % (rc)
        self.assertTrue(rc == expected, result + report)

        for d in self.test_dirs:
            uid = os.stat(d)[stat.ST_UID]
            expected_uid = 0
            if d == "/tmp/testlib-clamav":
                expected_uid = clamav_uid

            self.assertTrue(uid == expected_uid, "'%s' had uid of '%d', expected '%d'" % (d, uid, expected_uid))

        for d in clamav_dirs:
            uid = os.stat(d)[stat.ST_UID]
            expected_uid = clamav_uid

            self.assertTrue(uid == expected_uid, "'%s' had uid of '%d', expected '%d'" % (d, uid, expected_uid))

        # check if initscript chowns to clamav
        d = '/'
        os.chdir(d)
        rc, report = testlib.cmd(['/etc/init.d/clamav-milter', 'restart'])
        expected = 0
        result = 'Got exit code %d\n' % (rc)
        self.assertTrue(rc == expected, result + report)

        uid = os.stat(d)[stat.ST_UID]
        expected_uid = 0
        self.assertTrue(uid == expected_uid, "'%s' had uid of '%d', expected '%d'" % (d, uid, expected_uid))

        os.chdir(self.topdir)

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/bin/freshclam', 9.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.check_apparmor('/usr/sbin/clamd', 9.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    unittest.main()
