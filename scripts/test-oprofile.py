#!/usr/bin/python
#
#    test-oprofile.py quality assurance test script for PKG
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: oprofile
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    This test should be run in a virtual machine (VM) where the kernel matches
    the userspace for the release this is running on (ie, chroots may have
    unpredictable results). This should not be run on a production machine.
    While efforts are made to make these tests non-destructive, there is no
    guarantee this script will not alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-oprofile.py -v'

    NOTES
    - http://oprofile.sourceforge.net/doc/index.html
    - make sure that oprofiled is not running and /root/.oprofile/daemonrc is
      removed before running
'''


import unittest, sys, os
import testlib
import shutil
import tempfile
import time

try:
    from private.qrt.oprofile import PrivateOprofileTest
except ImportError:
    class PrivateOprofileTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class OprofileTest(testlib.TestlibCase, PrivateOprofileTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')
        self.oprofile_daemonrc = "/root/.oprofile/daemonrc"
        self.pid = None
        self.session_dir = "/var/lib/oprofile"
        self.cdump = os.path.join(self.session_dir, "complete_dump")
        self.bad_write = None

        self._setup_oprofile()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.pid != None:
            testlib.cmd(['kill', self.pid])
            testlib.cmd(['kill', '-9', self.pid])
            self.pid = None
        # make sure it is really dead
        testlib.cmd(['killall', '-9', 'oprofiled'])

        if os.path.exists(self.oprofile_daemonrc):
            testlib.config_restore(self.oprofile_daemonrc)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        # put any existing daemonrc back in place
        if os.path.exists(self.oprofile_daemonrc + ".bak"):
            if os.path.exists(self.oprofile_daemonrc):
                os.unlink(self.oprofile_daemonrc)
            shutil.move(self.oprofile_daemonrc + ".bak", self.oprofile_daemonrc)

        if self.bad_write != None and os.path.exists(self.bad_write):
            os.unlink(self.bad_write)

    def _setup_oprofile(self):
        '''Setup oprofile'''
        if os.path.exists(self.oprofile_daemonrc) and \
           not os.path.exists(self.oprofile_daemonrc + ".bak"):
            shutil.move(self.oprofile_daemonrc, self.oprofile_daemonrc + ".bak")

        # setup for working in QEMU
        rc, report = testlib.cmd(['oprofile', '--deinit'])
        expected = 127
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        if os.path.exists(self.cdump):
            os.unlink(self.cdump)

        rc, report = testlib.cmd(['modprobe', 'oprofile', 'timer=1'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['oprofile', '--init'])
        expected = 127
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['opcontrol', '--no-vmlinux'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['opcontrol', '--reset'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

    def _gen_stats(self):
        '''Generate some profiling stats'''
        # Do this a few time to make sure we have stats
        count = 0
        while count < 3:
            # Now generate some profiling data
            rc, report = testlib.cmd(['apt-get', 'update'])
            #print "DEBUG: %s" % report

            rc, report = testlib.cmd(['apt-cache', 'policy', 'dpkg'])
            #print "DEBUG: %s" % report

            rc, report = testlib.cmd(['dpkg', '--get-selections'])
            #print "DEBUG: %s" % report

            time.sleep(1)
            count += 1

        time.sleep(5)
        rc, report = testlib.cmd(['opcontrol', '--dump'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

    def _start_profiler(self):
        '''Start profiler'''
        rc, report = testlib.cmd(['opcontrol', '--start'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Daemon started"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))
        search = "Profiler running"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        rc, report = testlib.cmd(['pgrep', 'oprofile'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        pid = report.splitlines()[-1]
        self.assertTrue(testlib.check_pid('/usr/bin/oprofiled', pid), "Could not find running oprofiled")
        self.pid = pid

    def _stop_profiler(self):
        '''Stop profiler'''
        if self.pid == None:
            return

        rc, report = testlib.cmd(['opcontrol', '--shutdown'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Stopping profiling"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))
        search = "Killing daemon"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        self.assertFalse(testlib.check_pid('/usr/bin/oprofiled', self.pid), "Found running oprofiled")

    def test_daemon(self):
        '''Test daemon'''
        self._start_profiler()

        stats= "/dev/oprofile/stats"
        self.assertTrue(os.path.exists(stats), "Could not find '%s'" % stats)
        cpu_type= "/dev/oprofile/cpu_type"
        self.assertTrue(os.path.exists(cpu_type), "Could not find '%s'" % cpu_type)

        self._stop_profiler()

    def test_opcontrol_dump(self):
        '''Test opcontrol --dump'''
        self._start_profiler()

        self.assertFalse(os.path.exists(self.cdump), "Found '%s'" % self.cdump)

        rc, report = testlib.cmd(['opcontrol', '--dump'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        self.assertTrue(os.path.exists(self.cdump), "Could not find '%s'" % self.cdump)

    def test_opcontrol_reset(self):
        '''Test opcontrol --reset'''
        self._start_profiler()
        self._gen_stats()

        rc, report = testlib.cmd(['opreport'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = 'dpkg'
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        rc, report = testlib.cmd(['opcontrol', '--reset'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Signalling daemon... done"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        # verify dpkg not in report
        rc, report = testlib.cmd(['opreport'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = 'dpkg'
        self.assertTrue(search not in report, "Found '%s' in report:\n%s" % (search, report))

    def test_ophelp(self):
        '''Test ophelp'''
        self._start_profiler()
        rc, report = testlib.cmd(['ophelp'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        search = "Using timer interrupt"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

    def test_opnnotate(self):
        '''Test opannotate'''
        self._start_profiler()
        self._gen_stats()

        rc, report = testlib.cmd(['opannotate', '--assembly'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        terms = ['Command line: opannotate --assembly', 'Profiling through timer interrupt', 'file format elf', ':Disassembly of section .plt']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))
        #print "DEBUG: %s" % report

    def test_opgprof(self):
        '''Test opgrpof'''
        self._start_profiler()
        self._gen_stats()

        os.chdir(self.tmpdir)

        rc, report = testlib.cmd(['opgprof', '/usr/bin/dpkg'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        gmon = os.path.join(self.tmpdir, "gmon.out")
        self.assertTrue(os.path.exists(gmon), "Could not find '%s'" % gmon)

    def test_oparchive(self):
        '''Test oparchive'''
        self._start_profiler()
        self._gen_stats()

        ar_dir = os.path.join(self.tmpdir, "archives")
        rc, report = testlib.cmd(['oparchive', '--output-directory', ar_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        exe = ar_dir + "/usr/bin/dpkg"
        self.assertTrue(os.path.exists(exe), "Could not find '%s'" % exe)

    def test_opreport(self):
        '''Test opreport'''
        self._start_profiler()
        self._gen_stats()

        rc, report = testlib.cmd(['opreport'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        #print "DEBUG: %s" % report

        terms = ['Profiling through timer interrupt', 'TIMER:0', 'dpkg']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        rc, report = testlib.cmd(['opreport', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        #print "DEBUG: %s" % report
        terms = ['Profiling through timer interrupt', 'app name', 'symbol name', 'dpkg']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        rc, report = testlib.cmd(['opreport', '-l', '--verbose=all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))
        #print "DEBUG: %s" % report
        terms = ['Matched sample files:', 'name: TIMER:0', 'bfd_info::get_symbols() for /usr/bin/dpkg']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

    def test_CVE_2011_1760a(self):
        '''Test CVE-2011-1760 (opcontrol -e)'''
        # http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=624212
        self._start_profiler()

        rc, report = testlib.cmd(['opcontrol', '-e', 'abcd;/usr/bin/id'])
        search = "uid=0(root)"
        self.assertTrue(search not in report, "Found '%s' in report:\n%s" % (search, report))

    def test_CVE_2011_1760b(self):
        '''Test CVE-2011-1760 (opcontrol --vmlinux)'''
        self._start_profiler()

        # create a bad vmlinux file
        malfn = self.tmpdir + "/bad;id"
        rc, report = testlib.cmd(['touch', malfn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + str(report))

        rc, report = testlib.cmd(['opcontrol', '--vmlinux=%s' % malfn])

        # see if in the daemonrc
        contents = file(self.oprofile_daemonrc).read()
        self.assertFalse(malfn in contents, "Found '%s' in daemonrc" % (malfn))

        # command is run
        rc, report = testlib.cmd(['opcontrol', '--stop'])
        search = "uid=0(root)"
        self.assertTrue(search not in report, "Found '%s' in report:\n%s" % (search, report))

    def test_CVE_2011_1760c(self):
        '''Test CVE-2011-1760 (opcontrol --save)'''
        # Create a 'samples' directory
        bad_session = os.path.join(self.tmpdir, "samples")
        os.mkdir(bad_session)

        # Create a file named 'current' in that directory
        bad_current = os.path.join(bad_session, "current")
        testlib.config_replace(bad_current, "my_commands")

        self.bad_write = "/gotcha"

        # setup the oprofile session directory to the root of the 'samples'
        # directory
        rc, report = testlib.cmd(['opcontrol', '--session-dir=%s' % self.tmpdir])

        # Execute --save with a path relative to the 'current' file
        rc, report = testlib.cmd(['opcontrol', '--save=../../..%s' % self.bad_write])

        # See if it worked
        self.assertFalse(os.path.exists(self.bad_write), "Found '%s'" % (self.bad_write))


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
