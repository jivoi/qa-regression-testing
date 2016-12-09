#!/usr/bin/python
#
#    test-haproxy.py quality assurance test script for haproxy
#    Copyright (C) 2013-2016 Canonical Ltd.
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
# QRT-Packages: haproxy elinks
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: apache2:!precise apache2-mpm-prefork:precise
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-haproxy.py -v'

    How to run in a clean schroot named 'precise':
    $ schroot -c precise -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-haproxy.py -v'
'''

import unittest, sys
import testlib
import testlib_httpd

use_private = True
try:
    from private.qrt.haproxy import HaproxyPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class HaproxyTest(testlib_httpd.HttpdCommon, testlib.TestlibCase):
    '''Test haproxy.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.haproxy_default = "/etc/default/haproxy"
        self.haproxy_config = "/etc/haproxy/haproxy.cfg"
        self.haproxy_daemon = testlib.TestDaemon("/etc/init.d/haproxy")
        self.my_ip = self._get_my_ip()

        testlib.config_set(self.haproxy_default, "ENABLED", "1", False)
        default_config = '''
global
    daemon
    maxconn 256

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend http-in
    bind *:8000
    default_backend servers

backend servers
    server server1 127.0.0.1:80 maxconn 32
    server server2 %s:80 maxconn 32
''' % self.my_ip

        testlib.config_replace(self.haproxy_config, default_config)
        testlib_httpd.HttpdCommon._setUp(self, clearlogs = True)
        self.haproxy_daemon.restart()

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_httpd.HttpdCommon._tearDown(self)
        self.haproxy_daemon.stop()
        testlib.config_restore(self.haproxy_default)
        testlib.config_restore(self.haproxy_config)

    def _get_my_ip(self):
        '''Attempt to get local ip address'''
        # Yes, this is awful.
        rc, report = testlib.cmd(["/sbin/ifconfig"])
        return report.split("\n")[1].split()[1][5:]

    def _search_apache_log(self, ip):
        '''Look for an ip in the apache log file'''
        for line in open(self.access_log).readlines():
            if line.startswith(ip + " "):
                return True
        return False

    def test_aaa_http(self):
        '''Test http server'''
        self._test_url("http://localhost:80/", "It works")

    def test_aab_haproxy_default(self):
        '''Test haproxy default config'''

        # Do it twice, so we round-robin both configured addresses
        self._test_url("http://localhost:8000/", "It works")
        self._test_url("http://localhost:8000/", "It works")

        for ip in ('127.0.0.1', self.my_ip):
            error = "Could not find %s in log file!" % ip
            self.assertTrue(self._search_apache_log(ip), error)


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(HaproxyTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(HaproxyPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
