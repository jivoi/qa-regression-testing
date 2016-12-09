#!/usr/bin/python
#
#    test-wget.py quality assurance test script
#    Copyright (C) 2009-2016 Canonical Ltd.
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
    $ sudo apt-get -y install apache2-mpm-prefork ssl-cert openssl lsb-release wget

'''

# QRT-Depends: testlib_httpd.py testlib_ssl.py ssl
# QRT-Packages: apache2 apache2-mpm-prefork wget ssl-cert openssl lsb-release
# QRT-Privilege: root

import unittest, subprocess
import os
import testlib
import testlib_httpd
import testlib_ssl
import tempfile
import sys

class BasicTest(testlib_httpd.HttpdCommon):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        self.hosts_file = "/etc/hosts"

        if self.lsb_release['Release'] >= 12.10:
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
        else:
            self.default_site = "/etc/apache2/sites-available/default"

        if self.lsb_release['Release'] >= 14.04:
            self.document_root = "/var/www/html"
        else:
            self.document_root = "/var/www"

        self.evil_filename = ".hiddenfile"
        self.evil_file = os.path.join(self.document_root, self.evil_filename)

        testlib.create_fill(self.evil_file, "This is an evil file.")

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="wget-")

        testlib_httpd.HttpdCommon._setUp(self)

    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        if os.path.exists(self.evil_file):
            os.unlink(self.evil_file)

        testlib.config_restore(self.hosts_file)
        testlib.config_restore(self.default_site)

        testlib_httpd.HttpdCommon._tearDown(self)

    def _test_url_wget(self, url="http://localhost/", content="", invert=False, expected=0, extra_opts=[]):
        '''Test the given url with wget'''
        report = self._get_page_wget(url, expected=expected, extra_opts=extra_opts)

        if content != "":
            self._word_find(report, content, invert)

    def _get_page_wget(self, url="http://localhost/", expected=0, extra_opts=[]):
        '''Get contents of given url with wget'''
        rc, report = testlib.cmd(['wget', '-O', '-'] + extra_opts + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def _download_file_wget(self, url="http://localhost/", directory=".", expected=0, extra_opts=[]):
        '''Download a file with wget'''
        rc, report = testlib.cmd(['wget', '-P', directory] + extra_opts + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

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
        self._test_url_wget("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_wget("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_alt_cert_chain(self):
        '''Test alternative certificate chains in openssl'''

        self._test_url_wget("https://www.ibps.alpes.banquepopulaire.fr",
                            "Bienvenue")

        self._test_url_wget("https://fbstatic-a.akamaihd.net/rsrc.php/v2/yb/r/GsNJNwuI-UM.gif")


    def test_ftp(self):
        '''Test ftp (ftp.debian.org)'''
        self._test_url_wget("ftp://ftp.debian.org/",
                            content='Index of / on ftp.debian.org')

    def test_ssl(self):
        '''Test https'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self._prepare_ssl(srvkey_pem, srvcert_pem)

        testlib.recursive_rm(tmpdir)

        # modern wget now returns 5 on ssl validation errors
        if self.lsb_release['Release'] <= 9.10:
            expected = 1
        else:
            expected = 5

        # Cert is self-signed, make sure wget says so
        if self.lsb_release['Release'] <= 8.04:
            error_str = 'ERROR: Certificate verification error for localhost'
        else:
            error_str = "ERROR: cannot verify localhost's certificate"

        self._test_url_wget("https://localhost/", error_str, expected=expected)

        # Let's try an SSL page without validating the self-signed cert
        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_wget("https://localhost/" + \
                       os.path.basename(self.html_page), test_str, extra_opts=['--no-check-certificate'])

    def test_ssl_null_byte(self):
        '''Test a null-byte CN cert (CVE-2009-3490)'''
        srvkey_pem = 'ssl/badguy.key'
        srvcert_pem = 'ssl/badguy-nul-cn.crt'

        # We need to add www.bank.com to the hosts file, of wget dies while
        # validating the cert's CN before the NUL byte check
        testlib.config_replace(self.hosts_file, "127.0.0.1 www.bank.com", True)

        self._prepare_ssl(srvkey_pem, srvcert_pem)

        # modern wget now returns 5 on ssl validation errors
        if self.lsb_release['Release'] <= 9.10:
            expected = 1
        else:
            expected = 5

        # Make sure wget detected the NUL byte
        self._test_url_wget("https://www.bank.com/", "ERROR: certificate common name is invalid (contains a NUL character)", expected=expected)

        # Let's try an SSL page without validating the self-signed cert
        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_wget("https://www.bank.com/" + \
                       os.path.basename(self.html_page), test_str, extra_opts=['--no-check-certificate'])

    def test_cve_2010_2252(self):
        '''Test CVE-2010-2252'''

        bad_file_path = os.path.join(self.tempdir, self.evil_filename)
        good_file_path = os.path.join(self.tempdir, "log")
        specified_file_path = os.path.join(self.tempdir, "specified")

        # Add the redirect to the config file
        testlib.config_replace(self.default_site, "", append=True)

        subprocess.call(['sed', '-i', "s/DocumentRoot \\(.*\\)/DocumentRoot \\1" +
                                      "\\nRedirectMatch log $1\/" +
                                      self.evil_filename + "/", self.default_site])

        self._reload()

        # Attempt to download the file
        self._download_file_wget("http://localhost/log", directory = self.tempdir)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Didn't find the %s file." % good_file_path
        self.assertTrue(os.path.exists(good_file_path), error)

        # Remove files
        if os.path.exists(bad_file_path):
            os.unlink(bad_file_path)
        if os.path.exists(good_file_path):
            os.unlink(good_file_path)

        # Attempt to download the file with the new option
        self._download_file_wget("http://localhost/log", directory = self.tempdir, 
                                 extra_opts=['--trust-server-names'])

        error = "Found the %s file." % good_file_path
        self.assertFalse(os.path.exists(good_file_path), error)

        error = "Didn't find the %s file." % bad_file_path
        self.assertTrue(os.path.exists(bad_file_path), error)

        # Remove files
        if os.path.exists(bad_file_path):
            os.unlink(bad_file_path)
        if os.path.exists(good_file_path):
            os.unlink(good_file_path)

        # Attempt to download the file with a specified filename
        self._download_file_wget("http://localhost/log", directory = self.tempdir, 
                                 extra_opts=['-O', specified_file_path])

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Found the %s file." % good_file_path
        self.assertFalse(os.path.exists(good_file_path), error)

        error = "Didn't find the %s file." % specified_file_path
        self.assertTrue(os.path.exists(specified_file_path), error)


if __name__ == '__main__':
    testlib.require_root()
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

