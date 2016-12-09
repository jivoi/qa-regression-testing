#!/usr/bin/python
#
#    test-apport.py quality assurance test script for apport
#    Copyright (C) 2009-2015 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install apport build-essential sudo && rm -f /var/crash/* ; ./test-apport.py -v'

    NOTE:
    - will clean out /var/crash
'''

# QRT-Packages: apport build-essential sudo python-mock python3-mock valgrind apport-valgrind apport-retrace apport-kde libnih-dev libglib2.0-dev python3-pyqt4 python3-pykde4
# QRT-Privilege: root

import unittest, subprocess
import testlib
import os
import shutil
from stat import S_IMODE
import tempfile
import time

class ApportTest(testlib.TestlibCase):
    '''Test apport'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.daemon = testlib.TestDaemon("/etc/init.d/apport")
        self.defaults = "/etc/default/apport"
        self.core_pattern = "/proc/sys/kernel/core_pattern"
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        self.crashdir = "/var/crash"
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        testlib.cmd(['adduser', self.user.login, 'adm'])
        testlib.cmd(['adduser', self.user.login, 'admin']) # needed by some tests
        self.test_dir = os.path.join(self.crashdir, "testlib-dir")
        self.test_empty = os.path.join(self.crashdir, "testlib.empty")
        self.test_old = os.path.join(self.crashdir, "testlib.old")

        # we need a program that is in a package here, for apport to generate
        # a report
        self.test_exec = "/usr/bin/free"
        self.test_exec_bak = "/usr/bin/free.testlib"
        self.test_exec_report = os.path.join(self.crashdir, "_usr_bin_free")

        # name this, but don't create it
        self.test_file = os.path.join(self.crashdir, "testlib-file")

        testlib.create_fill(self.test_empty, '')
        os.chown(self.test_empty, self.user.uid, self.user.gid)
        testlib.create_fill(self.test_old, 'stuff')
        subprocess.call(['touch', '-t', '200601010000', self.test_old])
        os.chown(self.test_old, self.user.uid, self.user.gid)

        os.mkdir(self.test_dir)
        os.chown(self.test_dir, self.user.uid, self.user.gid)

        # The location of the test-runner changed in karmic(?)
        if os.path.exists("/usr/share/apport/testsuite/run-tests"):
            self.testsuite = "/usr/share/apport/testsuite/run-tests"
	else:
            self.testsuite = "/usr/share/apport/testsuite/run"

        # Vivid no longer ships the test suite
        if self.lsb_release['Release'] >= 15.04:
            self.testsuite = None

        self.apt_sources = "/etc/apt/sources.list"

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore(self.defaults)
        if os.path.exists(self.apt_sources + ".autotest"):
            testlib.config_restore(self.apt_sources)
            testlib.cmd(['apt-get', 'update'])

        self.user = None
        if os.path.exists(self.test_empty):
            os.unlink(self.test_empty)

        if os.path.exists(self.test_old):
            os.unlink(self.test_old)

        if os.path.exists(self.test_file):
            os.unlink(self.test_file)

        if os.path.exists(self.test_dir):
            testlib.recursive_rm(self.test_dir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        if os.path.exists(self.test_exec_bak):
            if os.path.exists(self.test_exec):
                os.unlink(self.test_exec)
            os.rename(self.test_exec_bak, self.test_exec)

        if os.path.exists(self.test_exec_report):
            os.unlink(self.test_exec_report)

        for f in os.listdir(self.crashdir):
            if f.startswith(os.path.basename(self.test_exec_report)):
                os.unlink(os.path.join(self.crashdir, f))

        # clean out /var/crash too
        for f in os.listdir("/var/crash"):
            os.unlink(os.path.join("/var/crash", f))

        if self.testsuite:
            testlib.config_restore(self.testsuite)
            os.chmod(self.testsuite, 0755)

    def enable(self):
        '''enable apport'''
        self.daemon.stop()
        testlib.config_replace(self.defaults, "", append=True)
        subprocess.call(['sed', '-i', 's/^enabled=.*/enabled=1/g', self.defaults])
        self.daemon.start()

        rc, report = testlib.cmd(['cat', self.core_pattern])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(report.startswith('|'), "%s does not start with '|'" % (self.core_pattern))

    def disable(self):
        '''disable apport'''
        self.daemon.stop()
        rc, report = testlib.cmd(['cat', self.core_pattern])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(report.startswith('c'), "%s does not start with 'c'\n%s" % (self.core_pattern, report))

        # test if enabled=0 disables apport
        testlib.config_replace(self.defaults, "", append=True)
        subprocess.call(['sed', '-i', 's/^enabled=.*/enabled=0/g', self.defaults])

        self.daemon.start()
        rc, report = testlib.cmd(['cat', self.core_pattern])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue(report.startswith('c'), "%s does not start with 'c'\n%s" % (self.core_pattern, report))

    def test_started(self):
        '''Test if apport is successfully started'''
        self.enable()

    def test_stopped(self):
        '''Test if apport is successfully stopped'''
        self.enable()
        self.disable()

    def test_var_crash(self):
        '''Make sure /var/crash is world-writable'''
        self.enable()
        self.assertEquals(S_IMODE(os.stat(self.crashdir)[0]) & 01777, 1023, "'%s' is not chmod 1777" % (self.crashdir))

    def test_CVE_2009_1295(self):
        '''Test CVE-2009-1295'''
        self.enable()
        not_vuln = os.path.join(self.test_dir, "not_vuln")
        testlib.create_fill(not_vuln, 'if you are reading this after executing cron.daily/apport, you are safe')
        not_vuln_empty = os.path.join(self.test_dir, "not_vuln.empty")
        testlib.create_fill(not_vuln_empty, '')

        rc, report = testlib.cmd(['/etc/cron.daily/apport'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for f in [self.test_dir, not_vuln, not_vuln_empty]:
            self.assertTrue(os.path.exists(f), "File '%s' removed!" % (f))

    def test_cron_daily(self):
        '''Test /etc/cron.daily/apport'''
        self.enable()

        rc, report = testlib.cmd(['/etc/cron.daily/apport'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['touch', self.test_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for f in [self.test_file]:
            self.assertTrue(os.path.exists(f), "File '%s' removed!" % (f))

        for f in [self.test_empty, self.test_old]:
            self.assertFalse(os.path.exists(f), "File '%s' not removed!" % (f))

    def test_crash(self):
        '''Test apport crash report'''
        self.enable()

        contents = '''int main() {
    main();
}
'''
        crash_source = os.path.join(self.tmpdir, "crasher.c")
        crash_bin = os.path.join(self.tmpdir, "crasher")
        testlib.create_fill(crash_source, contents)
        rc, report = testlib.cmd(['gcc', '-o', crash_bin, crash_source])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # move our crasher into place
        self.assertFalse(os.path.exists(self.test_exec_bak), "'%s' already exists!" % (self.test_exec_bak))
        os.rename(self.test_exec, self.test_exec_bak)
        shutil.copy(crash_bin, self.test_exec)

        print ""
        for user in ['root', self.user.login]:
            print "  user: %s" % (user)
            cmd_args = ['/usr/share/apport/apport-checkreports']
            if user == "root":
                fn = self.test_exec_report + ".0.crash"
                cmd_args.append('-s')
            else:
                fn = self.test_exec_report + ".%s.crash" % (self.user.uid)
            self.assertFalse(os.path.exists(fn), "'%s' already exists!" % fn)

            subprocess.call(['sudo', '-u', user, self.test_exec])
            time.sleep(3)
            self.assertTrue(os.path.exists(fn), "'%s' does not exist" % fn)
            rc, report = testlib.cmd(cmd_args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertTrue(os.path.basename(self.test_exec) in report, "'%s' not in report!" % (os.path.basename(self.test_exec)))

    def test_apport_suite(self):
        '''Run testsuite'''

        # Vivid no longer ships the test suite
        if self.lsb_release['Release'] >= 15.04:
             return self._skipped("Skipped: 15.04+ doesn't ship test suite")

	# make sure we have something sane here, otherwise an out of date
        # debmirror might cause problems
        contents = '''
deb http://archive.ubuntu.com/ubuntu %s main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu %s-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu %s-updates main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu %s main restricted universe multiverse
deb-src http://security.ubuntu.com/ubuntu %s-security main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu %s-updates main restricted universe multiverse
''' % (self.lsb_release['Codename'], self.lsb_release['Codename'],
       self.lsb_release['Codename'], self.lsb_release['Codename'],
       self.lsb_release['Codename'], self.lsb_release['Codename'])
        testlib.config_replace(self.apt_sources, contents)
        testlib.cmd(['apt-get', 'update'])

        self.enable()
        self.assertTrue(os.path.exists(self.testsuite), "'%s' does not exist" % (self.testsuite))

        # apport contains a comprehensive test suite that is installed by
        # default. However, some tests are known to fail. This is an attempt
        # to report new failues
        expected = 0
        expected_failure_strings = []
        if self.lsb_release['Release'] == 12.04:
            expected_failure_strings.append('ERROR: test_install_packages_unversioned (__main__.T)')
            expected_failure_strings.append('ERROR: test_install_packages_versioned (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_damaged (__main__.T)')
            expected_failure_strings.append('ERROR: test_run_report_bug_unpackaged_pid (__main__.T)')
            expected_failure_strings.append('ERROR: test_install_packages_system (__main__.T)')
            expected_failure_strings.append('ERROR: test_crashes (__main__.T)')
            expected_failure_strings.append('ERROR: test_crashes_error (__main__.T)')
            expected_failure_strings.append('ERROR: test_crashes_transient_error (__main__.T)')
            expected_failure_strings.append('ERROR: test_dupcheck (__main__.T)')
            expected_failure_strings.append('ERROR: test_publish_db (__main__.T)')
            expected_failure_strings.append('ERROR: test_stderr_redirection (__main__.T)')
            expected_failure_strings.append('ERROR: test_dbus_service_timeout_running (__main__.T)')
            expected_failure_strings.append('ERROR: test_interactive (__main__.T)')
            expected_failure_strings.append('ERROR: hook /usr/share/apport/general-hooks/cloud_archive.py crashed:')
            expected_failure_strings.append('ERROR: test_add_gdb_info (__main__.T)')
            expected_failure_strings.append('FAIL: test_run_crash_argv_file (__main__.T)')
            expected_failure_strings.append('FAIL: test_run_crash_unreportable (__main__.T)')
            expected_failure_strings.append('FAIL: test_address_to_offset_live (__main__.T)')
            expected_failure_strings.append("AssertionError: Invalid problem report: This problem report is damaged and cannot be processed.")
            expected_failure_strings.append('AssertionError: u"This problem report is damaged and cannot be processed.\\n\\nIOError(\'Invalid core dump: \',)" != None')
            expected_failure_strings.append('AssertionError: False is not true')
            expected = '!1' # indeterminate :\
        elif self.lsb_release['Release'] == 14.04:
            expected_failure_strings.append("ERROR: Package download error, try again later: Failed to fetch http://archive.ubuntu.com/ubuntu/pool/main/a/aspell/aspell-doc_0.60.7~20110707-1_all.deb Could not resolve 'nonexistent'")
            expected_failure_strings.append('FAIL: test_dbus_service_unknown_wrongbus_notrunning (__main__.T)')
            expected_failure_strings.append('FAIL: test_install_packages_unversioned (__main__.T)')
            expected_failure_strings.append('FAIL: test_install_packages_versioned (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort_glib (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort_libnih (__main__.T)')
            expected_failure_strings.append('AssertionError: False is not true : provided by /usr/share/dbus-1/services/gvfs-metadata.service (/usr/lib/gvfs/gvfsd-metadata is running)')
            expected_failure_strings.append('AssertionError: False is not true')
            expected_failure_strings.append('AssertionError: False is not true')
            expected_failure_strings.append('ERROR: test_run_report_bug_unpackaged_pid (__main__.T)')
            expected = '!1' # indeterminate :\
        elif self.lsb_release['Release'] == 14.10:
            expected_failure_strings.append("ERROR: Package download error, try again later: Failed to fetch http://archive.ubuntu.com/ubuntu/pool/main/a/aspell/aspell-doc_0.60.7~20110707-1_all.deb Could not resolve 'nonexistent'")
            expected_failure_strings.append('FAIL: test_dbus_service_unknown_wrongbus_notrunning (__main__.T)')
            expected_failure_strings.append('FAIL: test_install_packages_unversioned (__main__.T)')
            expected_failure_strings.append('FAIL: test_install_packages_versioned (__main__.T)')
            expected_failure_strings.append('FAIL: test_find_package_desktopfile (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort_glib (__main__.T)')
            expected_failure_strings.append('ERROR: test_add_gdb_info_abort_libnih (__main__.T)')
            expected_failure_strings.append('AssertionError: False is not true : provided by /usr/share/dbus-1/services/gvfs-metadata.service (/usr/lib/gvfs/gvfsd-metadata is running)')
            expected_failure_strings.append("AssertionError: 'no debug symbol package found for coreutils\\n' != ''")
            expected_failure_strings.append("AssertionError: 'no debug symbol package found for coreutils\\n' != ''")
            expected_failure_strings.append("AssertionError: '/usr/share/applications/shotwell.desktop' != None : multi-desktop package shotwell-common")
            expected_failure_strings.append('ERROR: test_run_report_bug_unpackaged_pid (__main__.T)')
            expected = '!1' # indeterminate :\

        testlib.config_replace(self.testsuite, "", append=True)
        os.chmod(self.testsuite, 0755)
        subprocess.call(['sed', '-i', 's/^python .*chroot.py .*/# removed chroot.py/g', self.testsuite])

        rc, report = testlib.cmd(['sudo', '-H', '-u', self.user.login, 'sh', self.testsuite])
        if expected == '!1':
            self.assertNotEquals(rc, 0, 'Got exit code 0:\n%s' % report)
        else:
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # now make sure we only have the expected failures
        new_errors = []
        for line in report.splitlines():
            if line.startswith('ERROR:') or line.startswith('FAIL:') or line.startswith('AssertionError:'):
                if line not in expected_failure_strings:
                    new_errors.append(line)
                else:
                    self._skipped("Skipping '%s'" % line)
        self.assertEquals(len(new_errors), 0, "Full report: %s\nFound new failure(s):\n %s" % (report, "\n ".join(new_errors)))

    def test_apportbug(self):
        '''Test apport-bug'''
        ap_report = os.path.join(self.tmpdir, "testlib.report")
        rc, report = testlib.cmd(['apport-bug', '--save=%s' % ap_report, '/bin/ls'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        contents = open(ap_report).read()
        terms = ['Package: coreutils', 'DistroRelease: Ubuntu', 'ProblemType: Bug']
        for search in terms:
            self.assertTrue(search in contents, "Could not find '%s' in:\n%s" % (search, contents))


if __name__ == '__main__':
    # simple
    testlib.require_sudo()
    unittest.main()

