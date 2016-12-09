#!/usr/bin/python
#
#    test-dhcp.py quality assurance test script
#    Copyright (C) 2009-2016 Canonical Ltd.
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
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get remove --purge dhcp3-client dhcp3-server
    $ sudo apt-get -y install dhcp3-client dhcp3-server
    $ sudo ./test-dhcp.py -y

  TODO:
    - IPv6
    - lots more
'''

# QRT-Depends: 
# QRT-Packages: isc-dhcp-server isc-dhcp-client

import unittest, subprocess
import os
import socket
import sys
import testlib
import tempfile
import time

try:
    from private.qrt.dhcp3 import PrivateDhcp3Test
except ImportError:
    class PrivateDhcp3Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class BasicTest(testlib.TestlibCase, PrivateDhcp3Test):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.server_initscript = "/etc/init.d/isc-dhcp-server"

        self.server_pidfile = "/var/run/dhcp-server/dhcpd.pid"
        self.server_config = "/etc/dhcp/dhcpd.conf-testlib"
        self.server_leases = "/var/lib/dhcp/dhcpd.leases-testlib"
        self.server_binary = "/usr/sbin/dhcpd"
        self.client_config = "/etc/dhcp/dhclient.conf-testlib"
        self.client_pidfile = "/var/run/dhclient-testlib.pid"
        self.client_lease = "/var/lib/dhcp/dhclient.lease-testlib"
        self.client_binary = "/sbin/dhclient"

        if self.lsb_release['Release'] >= 15.04:
            self.server_pidfile = "/var/run/dhcpd.pid"

        self.interface = "eth0"
        self.server_args = []
        # 12.10 and higher use the upstream priv-dropping
        if self.lsb_release['Release'] >= 12.10:
            self.server_args += ['-user', 'dhcpd', '-group', 'dhcpd']
        self.server_args += ['-cf', self.server_config, '-pf', self.server_pidfile, '-lf', self.server_leases, self.interface]

        self.client_args = []
        self.client_args += ['-cf', self.client_config, '-pf', self.client_pidfile, '-lf', self.client_lease, self.interface]

        subprocess.call(['touch', self.server_leases])
        # 12.10 and higher use the upstream priv-dropping and need files
        # owned by root
        if self.lsb_release['Release'] >= 12.10:
            subprocess.call(['chown', 'root:root', self.server_leases])
        else:
            subprocess.call(['chown', 'dhcpd:dhcpd', self.server_leases])

    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.server_pidfile):
            self.stop_daemon(self.server_pidfile)
        if os.path.exists(self.client_pidfile):
            self.stop_daemon(self.client_pidfile)

        for f in [self.server_pidfile, self.server_config, self.server_leases, "%s~" % self.server_leases, self.client_config, self.client_pidfile, self.client_lease]:
            if os.path.exists(f):
                os.unlink(f)

        testlib.cmd(['killall', 'dhcpd'])

    def stop_daemon(self, pidfile):
        '''Stop daemon'''
        # always stop the main server, so it isn't in the way
        testlib.cmd([self.server_initscript, "stop"])

        if os.path.exists(pidfile):
            testlib.cmd(['start-stop-daemon', '--stop', '--quiet', '--pidfile', pidfile])

    def start_daemon(self):
        '''Start daemon'''
        rc, report = testlib.cmd(['start-stop-daemon', '--start', '--quiet', '--pidfile', self.server_pidfile, '--exec', self.server_binary, '--'] + self.server_args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_daemon(self):
        '''Test dhcpd'''
        contents = '''
ddns-update-style none;
default-lease-time 60;
max-lease-time 720;
allow bootp;
authoritative;
log-facility local7;
subnet 192.168.122.0 netmask 255.255.255.0 {
    range 192.168.122.50 192.168.122.60;
}
'''
        testlib.create_fill(self.server_config, contents)
        self.start_daemon()
        time.sleep(2)

        self.assertTrue(testlib.check_pidfile(os.path.basename(self.server_binary), self.server_pidfile))

        rc, report = testlib.check_apparmor(self.server_binary, 9.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_apparmor(self):
        '''Test apparmor'''
        # client-- don't check if running here, we do that in the other tests
        for exe in [ self.server_binary, self.client_binary, '/usr/lib/NetworkManager/nm-dhcp-client.action', '/usr/lib/connman/scripts/dhclient-script' ]:
            rc, report = testlib.check_apparmor(exe, 9.04, is_running=False)
            if rc < 0:
                return self._skipped(report)

            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def test_apparmor_env_bypass(self):
        '''Test apparmor environment bypass (LP: #1045986)'''

        hack_script = os.path.join(self.tmpdir, 'run-parts')
        hack_output = os.path.join(self.tmpdir, 'output.txt')

        contents = '''
#!/bin/bash
echo "ohnoze!" > %s
''' % (hack_output)
        testlib.create_fill(hack_script, contents)
        subprocess.call(['chmod', '755', hack_script])

        rc, report = testlib.cmd(['bash', '-c',
                                  'PATH=' + self.tmpdir + ':$PATH /sbin/dhclient-script'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertFalse(os.path.exists(hack_output), 'Found output file!')

    def test_dhclient(self):
        '''Test dhclient (requires reachable dhcpd)'''
        self.stop_daemon(self.server_pidfile)
        time.sleep(2)

        contents = '''
send host-name "%s";
request subnet-mask, broadcast-address, time-offset, routers,
	domain-name, domain-name-servers, domain-search, host-name,
	netbios-name-servers, netbios-scope, ntp-servers;
''' % (socket.gethostname())
        testlib.create_fill(self.client_config, contents)

        rc, report = testlib.cmd([os.path.basename(self.client_binary)] + self.client_args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(5)
        if not os.path.exists(self.client_pidfile):
            time.sleep(25)

        self.assertTrue(os.path.exists(self.client_lease), "%s does not exist after 30 seconds" % (self.client_lease))
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.client_binary), self.client_pidfile))

        rc, report = testlib.check_apparmor(self.client_binary, 9.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

