#!/usr/bin/python
#
#    test-tcpdump.py quality assurance test script for tcpdump
#    Copyright (C) 2008-2011 Canonical Ltd.
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
# QRT-Packages: tcpdump python-pexpect
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install && ./test-tcpdump.py [<interface>]'
'''

import unittest, sys
import testlib
import glob
import os
import pexpect
import re
import shutil
import tempfile
import time

interface="eth0"

class TcpdumpTest(testlib.TestlibCase):
    '''Test login package functionality'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.interface = interface
        self.common_args = ['tcpdump', '-i', self.interface, '-c', '1']
        self.tempdir = tempfile.mkdtemp()
        self.apparmor_protected_files = ['/foo', '/root/.foo']
        for p in self.apparmor_protected_files:
            if os.path.exists(p):
                self._skipped("Skipping '%s'" % p)
                self.apparmor_protected_files.remove(p)

        self.version_with_apparmor = 9.04

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        self.user = None
        for p in self.apparmor_protected_files:
            if os.path.exists(p):
                os.unlink(p)

    def _regex_find(self, regex, content):
        '''See if anything in "content" matches the "regex"'''
        pat = re.compile(r'' + regex)
        for line in content.splitlines():
            #print "Checking: %s" % line
            if pat.search(line):
                return
        warning = 'No match for "%s"\n' % (regex)
        self.assertTrue(False, warning + content)

    def test_basic(self):
        '''Test basic'''
        failed = False
        failures = ""
        print ""
        for arg in ['-A', '-v', '-vvv', '-e', '-n', '-N', '-O', '-p', '-q', '-S', '-s 0', '-u', '-x', '-xx', '-X', '-XX']:
            print "  %s:" % arg,
            ok = True
            args = self.common_args + arg.split()
            if arg != '-n' and arg != '-v':
                # add '-n' for all tests except '-n' and '-v'. This should
                # speed up the test generally
                args.append('-n')
            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            if rc != expected:
                ok = False
                failed = True
                failures += result + report + "\n"
            else:
                reg = '^\d\d:\d\d:\d\d\.\d{6} '
                try:
                    self._regex_find(reg, report)
                except Exception, e:
                    ok = False
                    failed = True
                    failures += arg + ":\n" + str(e) + "\n"

            if ok:
                print "ok"
            else:
                print "FAIL"

        self.assertFalse(failed, failures)

    def test_droppriv(self):
        '''Test dropped privs'''
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)

        rc, report = testlib.cmd(self.common_args + ['-Z', self.user.login])
        expected = 0
        result = 'Got exit code %d\n' % (rc)
        self.assertTrue(rc == expected, result + report)
        reg = '^\d\d:\d\d:\d\d\.\d{6} '
        self._regex_find(reg, report)

    def test_file_read(self):
        '''Test read from file'''
        return self._skipped("TODO")

    def test_file_write(self):
        '''Test write to file'''
        out = os.path.join(self.tempdir, "foo")
        rc, report = testlib.cmd(self.common_args + ['-w', out])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)
        self.assertTrue(os.path.getsize(out) > 0, "%s is empty" % out)

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/tcpdump', self.version_with_apparmor, is_running=False)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_file_write_apparmor(self):
        '''Test write to apparmor protected file'''
        if self.lsb_release['Release'] < self.version_with_apparmor:
            return self._skipped("Skipped apparmor check")

        # This is vulnerable to symlink attacks when apparmor isn't working
        for out in self.apparmor_protected_files:
            rc, report = testlib.cmd(self.common_args + ['-w', out])
            expected = 0
            result = 'Got exit code %d\n' % (rc)
            self.assertFalse(rc == 0, result + report)

    def test_read_write_apparmor(self):
        '''Test read from apparmor protected file'''
        if self.lsb_release['Release'] < self.version_with_apparmor:
            return self._skipped("Skipped apparmor check")

        # This is vulnerable to symlink attacks when apparmor isn't working
        for in_file in self.apparmor_protected_files:
            shutil.copy('/etc/passwd', in_file)
            rc, report = testlib.cmd(self.common_args + ['-r', in_file])
            opened_str = 'bad dump file format'
            self.assertFalse(opened_str in report, in_file + ":\n" + report)

    def test_lp585150(self):
        '''Test LP: #585150'''
        rc, report = testlib.cmd(['tcpdump', '-c', '1'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)

    def test_lp722856(self):
        '''Test LP: #722856'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("not affected in this release of Ubuntu")

        def cleanup():
            '''Cleanup stray tcpdump processes. For some reason, tcpdump runs
               away if it can't exec the compressor'''
            testlib.cmd(['killall', '-9', 'tcpdump'])
            time.sleep(3)
            testlib.cmd(['killall', '-9', 'tcpdump'])

        commands = [ ("gzip", ".gz"),
                     ("bzip2", ".bz2"),
                   ]

        for exe, ext in commands:
            try:
                child = pexpect.spawn('/usr/sbin/tcpdump -i %s -w %s/out:%%F-%%H-%%M-%%S -G 1 -z %s' % (self.interface, self.tempdir, exe))
                time.sleep(6)
                child.expect("tcpdump: listening on", timeout=5)
                report = child.after
                child.close()
            except:
                cleanup()
                raise
            cleanup()

            num = 2
            self.assertTrue(len(glob.glob("%s/*%s" % (self.tempdir, ext))) >= num, "Could not find '%d' compressed '%s' files" % (num, ext))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] != '-v':
        interface = sys.argv[1]

    print "You will need to generate traffic on '%s' for this to work" % (interface)

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TcpdumpTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
