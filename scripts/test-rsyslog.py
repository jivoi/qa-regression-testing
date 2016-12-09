#!/usr/bin/python
#
#    test-rsyslog.py quality assurance test script for rsyslog
#    Copyright (C) 2011-2014 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: rsyslog apparmor-utils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
## QRT-Depends: private/qrt/rsyslog.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    TODO:
    - on 12.04 and later, also test with apparmor enabled
'''


import unittest, sys, os
import tempfile
import testlib
import socket
import time

try:
    from private.qrt.Rsyslog import PrivateRsyslogTest
except ImportError:
    class PrivateRsyslogTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class RsyslogTest(testlib.TestlibCase, PrivateRsyslogTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.config_file = "/etc/rsyslog.conf"
        self.pidfile = "/var/run/rsyslogd.pid"
        self.initscript = "/etc/init.d/rsyslog"
        self.exe = "/usr/sbin/rsyslogd"
        self.tempdir = ""

        self.aa_profile = "usr.sbin.rsyslogd"
        self.aa_abs_profile = "/etc/apparmor.d/%s" % self.aa_profile
        self.version_with_apparmor = 12.04
        # This hack is only used until we have tests run both confined and
        # unconfined
        self.aa_unload_at_teardown = False

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.config_file + ".autotest"):
            testlib.config_restore(self.config_file)
            self._restart_daemon()

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        if self.aa_unload_at_teardown and os.path.exists(self.aa_abs_profile):
            testlib.cmd(['aa-disable', self.aa_abs_profile])

    def _logger(self, msg, tag="test-rsyslog", pid=False, priority=None):
        '''Log to syslog via logger and verify it went through'''
        args = ['-t', tag]
        if pid:
            args.append('-i')
        if priority != None:
            args.append('-p')
            args.append(priority)

        rc, report = testlib.cmd(['logger'] + args + [msg])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._search_log(msg)

    def _logger_raw(self, msg, host=None, port=514, proto="udp", v6=False,
                    search_msg=None):
        '''Write directly to /dev/log, not via logger. Can also be used to
           write over the network.'''
        s = None

        if search_msg == None:
            search_msg = msg

        if host == None: # write to /dev/log
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect("/dev/log")
        else:            # connect to host
            t = socket.SOCK_DGRAM
            p = 17
            if proto == "tcp":
                t = socket.SOCK_STREAM
                p = 6

            f = socket.AF_INET
            if v6: # untested
                f = socket.AF_INET6

            s = socket.socket(f, t, p)
            (a, b, c, d, addr) = socket.getaddrinfo(host, port, f, t, p)[0]
            s.connect(addr)

        send_msg = msg
        if proto == "tcp": # TCP requires the line feed, but we don't want
                           # to search for it
            send_msg += '\n'

        s.send(send_msg)
        self._search_log(search_msg)

    def _logger_imfile(self, msg, log=None, tag="testlib-tag1", search=None):
        '''Write directly to logfile and setup for imfile monitoring'''
        # http://rsyslog.com/doc/imfile.html

        if log == None:
            # /var/log for AppArmor
            self.tempdir = tempfile.mkdtemp(dir='/var/log',prefix="testlib-")
            os.chmod(self.tempdir, 0775)
            log = os.path.join(self.tempdir, "log")

        contents = '''
# http://rsyslog.com/doc/imfile.html
$ModLoad imfile
# File to monitor
$InputFileName %s
# Tag for rsyslog to add to syslog messages
$InputFileTag %s:
# Used internally by rsyslog, in its $WorkDirectory
$InputFileStateFile testlib-stat-file1
# The severity and facility to use with syslog messages
$InputFileSeverity error
$InputFileFacility daemon
# Normally 10. Let's lower this so we don't have to wait so long with our tests
$InputFilePollInterval 2
# Activates the monitor. Must be added for each file to monitor
$InputRunFileMonitor
''' % (log, tag)
        testlib.config_replace(self.config_file, contents, append=True)
        self._restart_daemon()
        time.sleep(2)

        f = open(log, 'a')
        f.write("%s\n" % msg)
        f.close()

        if search == None:
            search = msg
        self._search_log("%s: %s" % (tag, search), tries=15)

    def _unique_string(self, length=10):
        '''Generate a unique string. Useful for searching in logs'''
        return testlib.random_string(length)

    def _search_log(self, msg, tries=5):
        '''Search logs for msg'''
        logfile = "/var/log/syslog"

        # Because this test is inherently racy, try a few times
        count = 1
        rc = 1
        while count <= tries:
            #print "DEBUG: msg='%s', logfile='%s', count = %d" % (msg, logfile, count)
            rc, report = testlib.cmd(['grep', msg, logfile])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            if rc == expected:
                break
            time.sleep(1)
            count += 1

        self.assertEquals(expected, rc, result + report)

    def _start_daemon(self):
        '''Start daemon'''
        if self.lsb_release['Release'] < 14.04:
            rc, report = testlib.cmd([self.initscript, 'start'])
        else:
            rc, report = testlib.cmd(['start', 'rsyslog'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

    def _stop_daemon(self):
        '''Stop daemon'''
        expected = 0
        if self.lsb_release['Release'] < 14.04:
            rc, report = testlib.cmd([self.initscript, 'stop'])
        else:
            rc, report = testlib.cmd(['stop', 'rsyslog'])
            if rc != expected and 'Unknown instance' in report:
                rc = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _restart_daemon(self):
        '''Restart daemon'''
        self._stop_daemon()
        self._start_daemon()

    def test_daemon(self):
        '''Test daemon'''
        self._stop_daemon()
        time.sleep(2)
        self.assertFalse(testlib.check_pidfile(self.exe, self.pidfile))
        self._start_daemon()
        time.sleep(2)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))
        self._restart_daemon()
        time.sleep(2)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

    def test_logger(self):
        '''Test logger'''
        unique_string = self._unique_string()
        self._logger(unique_string)

        unique_string = self._unique_string()
        self._logger(unique_string, tag=unique_string, pid=True)
        self._search_log(unique_string + "\[[0-9]\+\]: " + unique_string)

        unique_string = self._unique_string()
        self._logger(unique_string, tag=unique_string, pid=True, priority="daemon.warn")
        self._search_log(unique_string + "\[[0-9]\+\]: " + unique_string)

    def test_network_udp(self):
        '''Test network (udp)'''
        testlib.config_replace(self.config_file, "$ModLoad imudp\n$UDPServerRun 514\n", append=True)
        self._restart_daemon()

        unique_string = self._unique_string()
        self._logger_raw(unique_string, host="127.0.0.1")

    def test_network_tcp(self):
        '''Test network (tcp)'''
        port = 1514
        testlib.config_replace(self.config_file, "$ModLoad imtcp\n$InputTCPServerRun %d\n" % port, append=True)
        self._restart_daemon()

        unique_string = self._unique_string()
        self._logger_raw(unique_string, host="127.0.0.1", port=port, proto="tcp")

    def test_message_pri(self):
        '''Test message with PRI'''

        testlib.config_replace(self.config_file, "$ModLoad imudp\n$UDPServerRun 514\n", append=True)
        self._restart_daemon()

        unique_string = self._unique_string()
        self._logger_raw('<100> ' + unique_string, host = "127.0.0.1",
                         search_msg = unique_string)

    def test_cve_2014_3634(self):
        '''Test CVE-2014-3634'''

        if self.lsb_release['Release'] < 12.04:
            return self._skipped("Doesn't work on 10.04")

        # This isn't a good test for the security issue, it's just a
        # sanity check to make sure the event is logged properly when the
        # update is applied
        testlib.config_replace(self.config_file, "$ModLoad imudp\n$UDPServerRun 514\n", append=True)
        self._restart_daemon()

        unique_string = self._unique_string()
        self._logger_raw('<201> ' + unique_string, host = "127.0.0.1",
                         search_msg = unique_string)

    def test_cve_2014_3683(self):
        '''Test CVE-2014-3683'''

        # This isn't a good test for the security issue, it's just a
        # sanity check to make sure the event is logged properly when the
        # update is applied
        testlib.config_replace(self.config_file, "$ModLoad imudp\n$UDPServerRun 514\n", append=True)
        self._restart_daemon()

        unique_string = self._unique_string()
        self._logger_raw('<3500000000> ' + unique_string,
                         host = "127.0.0.1",
                         search_msg = unique_string)

    def test_imfile(self):
        '''Test imfile'''
        unique_string = self._unique_string()
        self._logger_imfile(unique_string)

    def test_CVE_2011_4623(self):
        '''Test CVE-2011-4623'''
        unique_string = self._unique_string()
        crafted = "%s%s" % (unique_string, 'A' * (65536 - len(unique_string)))
        self._logger_imfile(crafted, search=unique_string)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

    # Run this last so if we enable the profile then we don't unload it
    def test_zz_apparmor(self):
        '''Test apparmor'''
        if self.lsb_release['Release'] < 12.04:
            return self._skipped("No profile in 11.10 and under")

        self.aa_unload_at_teardown = True

        # Currently while we have a profile, it is shipped disabled by default.
        # Verify that.
        rc, report = testlib.check_apparmor(self.aa_abs_profile, 12.04, is_running=False)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)

        # Verify it is syntactically correct
        rc, report = testlib.cmd(['apparmor_parser', '-p', self.aa_abs_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)

        # Verify it loads ok
        rc, report = testlib.cmd(['aa-enforce', self.aa_abs_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)

        self._stop_daemon()
        self._start_daemon()

        rc, report = testlib.check_apparmor(self.aa_abs_profile, 12.04, is_running=True)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RsyslogTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
