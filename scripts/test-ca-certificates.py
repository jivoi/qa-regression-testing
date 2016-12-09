#!/usr/bin/python
#
#    test-ca-certificates.py quality assurance test script for ca-certificates
#    Copyright (C) 2010-2014 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Based on test-w3m.py by Steve Beattie <steve.beattie@canonical.com>
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
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run in a clean virtual machine:
    1. sudo apt-get -y install w3m apache2-mpm-prefork ssl-cert openssl ca-certificates lsb-release python-pexpect
    2. sudo ./test-w3m.py -v

'''

# QRT-Depends: data testlib_httpd.py testlib_ssl.py ssl
# QRT-Packages: w3m apache2-mpm-prefork ssl-cert openssl ca-certificates lsb-release python-pexpect
# QRT-Privilege: root

import unittest, sys, os, shutil, time
import testlib
import testlib_httpd
import testlib_ssl
import tempfile
import pexpect

class TestCommon(testlib_httpd.HttpdCommon):
    '''Common methods'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.exe = '/usr/bin/w3m'
        self.configdir = os.path.join(os.path.expanduser('~'), '.w3m')
        self.configdir_bak = self.configdir + '.testlib.bak'
        self._move_config_dir()
        self.tempdir = tempfile.mkdtemp()
        self.topdir = os.getcwd()
        self.ca_cert_path = "/etc/ssl/certs/ca-certificates.crt"

    def _tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        if os.path.exists(self.configdir_bak):
            if os.path.exists(self.configdir):
                testlib.recursive_rm(self.configdir)
            shutil.move(self.configdir_bak, self.configdir)
        os.chdir(self.topdir)

    def _move_config_dir(self):
        '''Move the .w3m directory out of the way'''
        if os.path.exists(self.configdir):
            if not os.path.exists(self.configdir_bak):
                shutil.move(self.configdir, self.configdir_bak)
            else:
                testlib.recursive_rm(self.configdir)

    def _w3m_cmd(self, url, search, verify=True, extra_args=[]):
        '''Execute w3m with the given url'''
        ssl_verify_server = "0"
        if verify:
            ssl_verify_server = "1"
        cmdline = "%s -dump -o ssl_ca_file=%s -o ssl_verify_server=%s %s" % (self.exe, self.ca_cert_path, ssl_verify_server, url)
        child = pexpect.spawn(cmdline)
        time.sleep(1.0)
        child.expect(".*%s.*" % (search), timeout=2)
        child.sendline('n')
        time.sleep(1.0)
        child.kill(0)


class TestURLs(TestCommon):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''

        if self.lsb_release['Release'] == 10.04:
            return self._skipped("Fails on 10.04...no idea why...")

        self._w3m_cmd("https://launchpad.net/", "Launchpad")

    def test_https_verify_google(self):
        '''Test https verify (www.google.com)'''
        self._w3m_cmd("https://www.google.com/", "Google")

    def test_https_verify_spi(self):
        '''Test https verify (members.spi-inc.org)'''
        self._w3m_cmd("https://members.spi-inc.org/", "SPI")

    def test_https_noverify(self):
        '''Test https no verify (wiki.ubuntu.com)'''
        self._w3m_cmd("https://wiki.ubuntu.com/", "Ubuntu", verify=False)

    def test_diginotar(self):
        '''Test DigiNotar'''
        crt = "/usr/share/ca-certificates/mozilla/DigiNotar_Root_CA.crt"
        self.assertFalse(os.path.exists(crt), "Found '%s'" % crt)

    def test_cacert(self):
        '''Test cacert.org certs'''
        # We don't want to ship these, so make sure they're not present
        # See LP: #1258286
        crt = "/usr/share/ca-certificates/cacert.org/cacert.org.crt"
        self.assertFalse(os.path.exists(crt), "Found '%s'" % crt)


class TestLocalHTTPD(TestCommon):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

        self.ca_certificates_conf = "/etc/ca-certificates.conf"
        self.hosts_file = "/etc/hosts"
        testlib_httpd.HttpdCommon._setUp(self)

        self.local_ca = "/usr/local/share/ca-certificates/testlib.crt"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

        testlib.config_restore(self.ca_certificates_conf)
        testlib.config_restore(self.hosts_file)
        testlib_httpd.HttpdCommon._tearDown(self)

        if os.path.exists(self.local_ca):
            os.unlink(self.local_ca)
            testlib.cmd(['update-ca-certificates'])
        for fn in ['/etc/ssl/certs/testlib.crt', '/etc/ssl/certs/testlib.pem']:
            try:
                os.unlink(fn)
            except:
                pass

    def test_apache_daemon(self):
        '''Test Apache daemon'''
        if self.lsb_release['Release'] >= 13.10:
            pidfile = "/var/run/apache2/apache2.pid"
        else:
            pidfile = "/var/run/apache2.pid"
        self.assertTrue(testlib.check_pidfile("apache2", pidfile))

    def test_apache_status(self):
        '''Test Apache status (apache2ctl)'''
        rc, report = testlib.cmd(['apache2ctl', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_update_ca_certificates_usr_local(self):
        '''Test update-ca-certificates for local CA (/usr/local)'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("CA in /usr/local not supported")

        # Create a CA, update /etc/hosts and create a test page
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)

        testlib.config_replace(self.hosts_file, "127.0.0.1 server", True)
        test_str = testlib_httpd.create_html_page(self.html_page)

        # First, try to access the self-signed server
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str, verify=False)
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), "unable to get local issuer certificate")

        # Next, install the local CA
        shutil.copy(cacert_pem, self.local_ca)
        testlib.recursive_rm(tmpdir)

        rc, report = testlib.cmd(['update-ca-certificates'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now try to access it
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str)

        # Next, remove the installed CA
        os.unlink(self.local_ca)
        rc, report = testlib.cmd(['update-ca-certificates'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Last, try to access the self-signed server again
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str, verify=False)
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), "unable to get local issuer certificate")

    def test_update_ca_certificates_usr(self):
        '''Test update-ca-certificates for local CA (/usr)'''
        self.local_ca = "/usr/share/ca-certificates/testlib.crt"

        # Create a CA, update /etc/hosts and create a test page
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)

        testlib.config_replace(self.hosts_file, "127.0.0.1 server", True)
        test_str = testlib_httpd.create_html_page(self.html_page)

        # First, try to access the self-signed server
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str, verify=False)
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), "unable to get local issuer certificate")

        # Next, install the local CA
        shutil.copy(cacert_pem, self.local_ca)
        testlib.config_replace(self.ca_certificates_conf, os.path.basename(self.local_ca) + '\n', True)
        testlib.recursive_rm(tmpdir)

        rc, report = testlib.cmd(['update-ca-certificates'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now try to access it
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str)

        # Next, remove the installed CA
        testlib.config_restore(self.ca_certificates_conf)
        os.unlink(self.local_ca)
        rc, report = testlib.cmd(['update-ca-certificates'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Last, try to access the self-signed server again
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str, verify=False)
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), "unable to get local issuer certificate")

    def test_update_ca_certificates_java(self):
        '''TODO: test update-ca-certificates with ca-certificates-java installed'''

if __name__ == '__main__':
    suite = unittest.TestSuite()

    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestURLs))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestLocalHTTPD))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
