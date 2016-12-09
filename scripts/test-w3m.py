#!/usr/bin/python
#
#    test-w3m.py quality assurance test script for w3m
#    Copyright (C) 2010-2014 Canonical Ltd.
#    Author: Steve Beattie <steve.beattie@canonical.com>
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

class TestURLs(testlib_httpd.HttpdCommon):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.exes = ['w3m']
        self.configdir = os.path.join(os.path.expanduser('~'), '.w3m')
        self.configdir_bak = self.configdir + '.testlib.bak'
        self._move_config_dir()
        self.tempdir = tempfile.mkdtemp()
        self.topdir = os.getcwd()

    def tearDown(self):
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

    def _w3m_cmd(self, url, search='', expected=0, extra_args=[]):
        '''Execute w3m with the given url'''
        command = ['w3m', '-dump']
        if len(extra_args) > 0:
            command += extra_args
        rc, report = testlib.cmd(command + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != '':
            result = 'Could not find \'%s\'\n' % (search)
            self.assertTrue(search in report, result + report)

    def test_file(self):
        '''Test file'''
        self._w3m_cmd("./data/well_formed_xhtml1.0.html", search='Sample content')

    def test_ftp(self):
        '''Test ftp (ftp.debian.org)'''
        self._w3m_cmd("ftp://ftp.debian.org/", search='Index of ftp://ftp.debian.org/')

    def test_http(self):
        '''Test http (ubuntu.com)'''
        self._w3m_cmd("http://www.ubuntu.com/")

    def test_http_intl(self):
        '''Test http (www.google.de)'''
        self._w3m_cmd("http://www.google.de/")
        self._w3m_cmd("./data/www.google.de.html", search='Datenschutz')

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''
        self._w3m_cmd("https://launchpad.net/")

    def test_https_noverify(self):
        '''Test https no verify (wiki.ubuntu.com)'''
        self._w3m_cmd("https://wiki.ubuntu.com/", extra_args=['-o', 'ssl_verify_server=0'])

    #def test_gopher(self):
    #    '''Test gopher (gopher://gopher.quux.org/)'''
    #    self._w3m_cmd("gopher://gopher.quux.org/")

class TestLocalHTTPD(testlib_httpd.HttpdCommon):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.exes = ['w3m']
        self.configdir = os.path.join(os.path.expanduser('~'), '.w3m')
        self.configdir_bak = self.configdir + '.testlib.bak'
        self._move_config_dir()
        self.tempdir = tempfile.mkdtemp()
        self.topdir = os.getcwd()
        self.hosts_file = "/etc/hosts"

        testlib_httpd.HttpdCommon._setUp(self)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        if os.path.exists(self.configdir_bak):
            if os.path.exists(self.configdir):
                testlib.recursive_rm(self.configdir)
            shutil.move(self.configdir_bak, self.configdir)
        os.chdir(self.topdir)
        testlib.config_restore(self.hosts_file)

        testlib_httpd.HttpdCommon._tearDown(self)

    def _move_config_dir(self):
        '''Move the .w3m directory out of the way'''
        if os.path.exists(self.configdir):
            if not os.path.exists(self.configdir_bak):
                shutil.move(self.configdir, self.configdir_bak)
            else:
                testlib.recursive_rm(self.configdir)

    def _w3m_cmd(self, url, search='', expected=0, extra_args=[]):
        '''Execute w3m with the given url'''
        command = ['w3m', '-dump']
        if len(extra_args) > 0:
            command += extra_args
        rc, report = testlib.cmd(command + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != '':
            result = 'Could not find \'%s\'\n' % (search)
            self.assertTrue(search in report, result + report)

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

    def test_http(self):
        '''Test http'''
        self._w3m_cmd("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._w3m_cmd("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_ssl(self):
        '''Test https (self signed with ca cert)'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        # We need to add server to the hosts file, or w3m errors while
        # validating the cert's CN before the NUL byte check
        testlib.config_replace(self.hosts_file, "127.0.0.1 server", True)

        #cmdline = "w3m -dump -o ssl_ca_file=" + ca + " https://localhost"
        test_str = testlib_httpd.create_html_page(self.html_page)
        self._w3m_cmd("https://server/" + \
                       os.path.basename(self.html_page), test_str, extra_args=['-o', 'ssl_ca_file=' + ca])

    def test_ssl_no_verify(self):
        '''Test https (self signed/no ca cert)'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        # We need to add server to the hosts file, or w3m errors while
        # validating the cert's CN before the NUL byte check
        testlib.config_replace(self.hosts_file, "127.0.0.1 server", True)

        test_str = testlib_httpd.create_html_page(self.html_page)

        cmdline = "w3m -dump https://server/" + os.path.basename(self.html_page)

        child = pexpect.spawn(cmdline)
        time.sleep(1.0)
        child.expect(".*unable to get local issuer certificate.*", timeout=2)
        child.sendline('y')
        time.sleep(1.0)
        child.kill(0)

    def test_ssl_null_byte(self):
        '''Test a null-byte CN cert (CVE-2009-3490)'''
        srvkey_pem = 'ssl/badguy.key'
        srvcert_pem = 'ssl/badguy-nul-cn.crt'
        srv_ca = 'ssl/ca.crt'
        ca = os.path.join(self.tempdir, os.path.basename(srv_ca))
        shutil.copy(srv_ca, ca)

        # We need to add www.bank.com to the hosts file, or w3m errors while
        # validating the cert's CN before the NUL byte check
        testlib.config_replace(self.hosts_file, "127.0.0.1 www.bank.com", True)

        test_str = testlib_httpd.create_html_page(self.html_page)

        self._prepare_ssl(srvkey_pem, srvcert_pem)

        cmdline = "w3m -dump -o ssl_ca_file=" + ca + " https://www.bank.com/" + \
                  os.path.basename(self.html_page)

        # Make sure w3m detected the NUL byte
        child = pexpect.spawn(cmdline)
        time.sleep(1.0)
        child.expect(".*Bad cert ident.*", timeout=2)
        child.sendline('y')
        time.sleep(1.0)
        child.kill(0)

if __name__ == '__main__':
    testlib.require_root()
    suite = unittest.TestSuite()

    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestURLs))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestLocalHTTPD))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
