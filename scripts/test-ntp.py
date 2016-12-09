#!/usr/bin/python
#
#    test-ntp.py quality assurance test script
#    Copyright (C) 2009-2016 Jamie Strandboge <jamie@canonical.com>
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

# QRT-Packages: ntp ntpdate openssl
# QRT-Depends: private/qrt/ntp.py
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'feisty':
        schroot -c feisty -u root -- sh -c 'apt-get -y install ntpdate ntp && ./test-ntp.py -v'

    Need 'ntp-server' on Dapper

    TODO:
      Go through http://support.ntp.org/bin/view/Support/ConfiguringAutokey
'''

import unittest, subprocess, os, sys, time
import testlib
import re
import tempfile

try:
    from private.qrt.ntp import PrivateNtpTest
except ImportError:
    class PrivateNtpTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class NtpTest(testlib.TestlibCase, PrivateNtpTest):
    '''Test NTP functionality.'''

    def setUp(self):
        '''Setup mechanisms'''
        self.initscript = "/etc/init.d/ntp"

        self._stop()
        self._start()

        self.tmpdir = ""
        self.topdir = os.getcwd()

        self.config = "/etc/ntp.conf"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._stop()

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        os.chdir(self.topdir)

        testlib.config_restore(self.config)

    def _start(self):
        '''Start the daemon'''
        subprocess.call([self.initscript, 'start'], \
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1)

    def _stop(self):
        '''Stop the daemon'''
        subprocess.call([self.initscript, 'stop'], \
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1)
        subprocess.call(['killall', '-9', 'ntpd'], \
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def _check_daemons(self):
        '''Check for pidfile and if running'''
        pidfile = "/var/run/ntpd.pid"
        warning = "Could not find pidfile '%s'" % (pidfile)
        self.assertTrue(os.path.exists(pidfile), warning)
        self.assertTrue(testlib.check_pidfile("ntpd", pidfile))

    def _find_peer(self):
        '''Find the first non-127.x.x.x peer via ntpdc'''
        rc, report = testlib.cmd(['ntpdc', '-n', '-l', '127.0.0.1'])
        pat = re.compile(r'^client *[0-9.]+$')
        peer = ''
        for line in report.splitlines():
            if pat.search(line):
                peer = re.sub('^client *', '', line)
                break
        self.assertTrue(peer != '', 'Could not find peer')
        return peer

    def _setup_keys(self):
        '''Setup public keys'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        rnd = os.path.join(self.tmpdir, '.rnd')
        os.environ.setdefault('RANDFILE', '')
        os.environ['RANDFILE'] = rnd

        os.chdir(self.tmpdir)

        # create the RANDFILE by calling openssl and throwing away the results
        rc, report = testlib.cmd(['openssl', 'genrsa'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(os.path.exists(rnd), "Could not find '%s'" % (rnd))

        rc, report = testlib.cmd(['ntp-keygen', '-p', 'test'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        found_cert = False
        found_host = False
        for f in os.listdir(self.tmpdir):
            if f.startswith("ntpkey_cert_"):
                found_cert = True
            if f.startswith("ntpkey_host_"):
                found_host = True
        self.assertTrue(found_cert, "Could not find ntpkey_cert_*")
        self.assertTrue(found_host, "Could not find ntpkey_host_*")

        testlib.config_replace(self.config, '''crypto pw test
crypto randfile /dev/urandom
keysdir %s
''' % (self.tmpdir), append=True)

        self._stop()
        self._start()
        self._check_daemons()

    def test_daemons(self):
        '''Test daemon'''
        self._check_daemons()

    def test_ntp(self):
        '''Test ntp'''
        host = "127.0.0.1"
        rc, report = testlib.cmd(['ntpdate', '-q', host])

        str = "server %s, stratum" % (host)
        result = "'%s' not found in report\n" % (str)
        self.assertTrue(str in report, result + report)


    def test_ntpdate(self):
        '''Test ntpdate'''
        host = "0.debian.pool.ntp.org"
        rc, report = testlib.cmd(['ntpdate', '-q', host])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        str1 = "step time server"
        str2 = "adjust time server"
        result = "Neither '%s' or '%s' found in report\n" % (str1, str2)
        self.assertTrue(str1 in report or str2 in report, result + report)

    def test_ntpq(self):
        '''Test ntpq'''
        host = "127.0.0.1"
        rc, report = testlib.cmd(['ntpq', '-n', '-c', 'peer', host])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        found_peer = False
        pat = re.compile(r'^[ *+^][1-9]')
        for line in report.splitlines():
            if pat.search(line):
                found_peer = True
                break

        self.assertTrue(found_peer, "Could not find peer in report:\n%s" % (report))

    def test_keys(self):
        '''Test ntp-keygen and public key configuration'''
        self._setup_keys()

        host = "127.0.0.1"
        rc, report = testlib.cmd(['ntpq', '-c', 'rv 0 cert', host])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        found_cert = False
        pat = re.compile(r'^cert=')
        for line in report.splitlines():
            if pat.search(line):
                found_cert = True
                break

        self.assertTrue(found_cert, "Could not find cert in report:\n%s" % (report))

    def test_ntpdc(self):
        '''Test ntpdc'''

        # ntpd 4.2.7p230 and higher disabled processing ntpdc queries
        if self.lsb_release['Release'] >= 16.04:
            return self._skipped("ntpdc no longer supported")

        peer = self._find_peer()

        # search for string or regex using the command. Use:
        # '<ntp command>', '<string>', '<regex>'
        commands = ( ('listpeers', '', '^client '),
                     ('peers', '', '^=[0-9]'),
                     ('dmpeers', '', '^( |\*)[0-9]'),
                     ('showpeer %s' % peer, 'offset', None),
                     ('pstats %s' % peer, 'remote host:', None),
                     ('kerninfo', 'pll offset:', None),
                     ('loopinfo', 'offset:', None),
                     ('sysinfo', 'precision:', None),
                     ('sysstats', 'time since restart:', None),
                     ('memstats', 'total peer memory:', None),
                     ('iostats', 'receive buffers:', None),
                     ('timerstats', 'alarms handled:', None),
                     ('reslist', '0.0.0.0', None),
                     ('monlist', peer, None)
                     # these (and more) require a key. See:
                     # http://www.eecis.udel.edu/~mills/ntp/html/ntpdc.html
                     #('ifstats', '', None), 		# needs Key id
                     #('ifreload', '', None),		# needs Key id
                     #('', '', None)
                   )

        for cmd, out, regex in commands:
            if cmd == 'monlist':
                time.sleep(10) # sometimes monlist is slow to update
            rc, report = testlib.cmd(['ntpdc', '-n', '-c', cmd, '127.0.0.1'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            if regex != None:
                pat = re.compile(r'%s' % regex)
                found = False
                for line in report.splitlines():
                    if pat.search(line):
                        found = True
                result = "No match for '%s' in report\n" % (regex)
                self.assertTrue(found, result + report)
            else:
                result = "Could not find '%s' in report\n" % (out)
                self.assertTrue(out in report, result + report)

    def test_servers_in_ntpconf(self):
        '''Test servers in ntp.conf'''

        # Find servers for ntp.conf
        servers = []
        conf_file = open(self.config).read()
        pat = re.compile(r'^server\s*')
        for line in conf_file.splitlines():
            if pat.search(line):
                servers.append(line.split()[1])

        print ""
        for s in servers:
            print "  %s" % s
            rc, report = testlib.cmd(['ntpdate', '-q', s])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            str1 = "step time server"
            str2 = "adjust time server"
            result = "Neither '%s' or '%s' found in report\n" % (str1, str2)
            self.assertTrue(str1 in report or str2 in report, result + report)

            rr_hosts = []
            pat = re.compile(r'^server ')
            for line in report.splitlines():
                if pat.search(line):
                    rr_hosts.append(line.split()[1].split(',')[0])

            rc, report = testlib.cmd(['ntpdc', '-n', '-l', '127.0.0.1'])
            pat = re.compile(r'^client *[0-9.]+$')
            found_peer = False
            for line in report.splitlines():
                if pat.search(line):
                    peer = re.sub('^client *', '', line)
                    if peer in rr_hosts:
                        found_peer = True
                        break

            self.assertTrue(found_peer, "Could not find '%s' in pool (%s)" % (s, str(rr_hosts)))

    def test_apparmor(self):
        '''test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/ntpd', 9.10, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    unittest.main()

