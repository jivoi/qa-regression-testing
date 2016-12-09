#!/usr/bin/python
#
#    test-libwww-perl.py quality assurance test script
#    Copyright (C) 2010 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: apache2-mpm-prefork libapache2-mod-php5 libwww-perl ssl-cert openssl lsb-release libio-socket-ssl-perl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py testlib_ssl.py ssl
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root


'''
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get -y install apache2-mpm-prefork libapache2-mod-php5 ssl-cert openssl lsb-release libio-socket-ssl-perl libwww-perl

'''

import unittest
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
        self.php5_content_dispo = "/var/www/test-content-dispo.php"
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libwww-perl-")

        testlib_httpd.HttpdCommon._setUp(self)

    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        if os.path.exists(self.php5_content_dispo):
            os.unlink(self.php5_content_dispo)

        testlib.config_restore(self.hosts_file)
        self._disable_mod("php5")

        testlib_httpd.HttpdCommon._tearDown(self)

    def _test_url_lwp(self, url="http://localhost/", content="", invert=False, expected=0, extra_opts=[]):
        '''Test the given url with lwp-download'''
        filename = self._get_page_lwp(url, expected=expected, extra_opts=extra_opts)

        if content != "":
            report = open(filename).read()
            self._word_find(report, content, invert)

    def _get_page_lwp(self, url="http://localhost/", expected=0, extra_opts=[]):
        '''Get contents of given url with lwp'''
        rc, report = testlib.cmd(['lwp-download'] + extra_opts + [url] + [self.tempdir])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if "Saving to" in report:
            return report.split("'")[1]
        else:
            return False

    def test_apache_daemon(self):
        '''Test Apache daemon'''
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
        self._test_url_lwp("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_lwp("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_php(self):
        '''Test php'''
        self._enable_mod("php5")
        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url_lwp("http://localhost/" + \
                       os.path.basename(self.php_page), test_str)

    def test_ssl(self):
        '''Test https'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self._prepare_ssl(srvkey_pem, srvcert_pem)

        testlib.recursive_rm(tmpdir)

        self._test_url_lwp("https://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_lwp("https://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_cve_2010_2253(self):
        '''Test CVE-2010-2253'''
        self._enable_mod("php5")

        test_str = testlib_httpd.create_html_page(self.html_page)

        bad_filename = ".blah.txt"
        bad_file_path = os.path.join(self.tempdir,bad_filename)

        script = '''<?php
$file = "%s";
header("Pragma: public");
      header("Expires: 0");
      header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
      header("Cache-Control: private",false);
      header("Content-Type: application/octet-stream");
      header("Content-Disposition: attachment; filename=\\"%s\\";");
      header("Content-Transfer-Encoding: binary");
      header("Content-Length: " . filesize($file));
  readfile($file);
exit;
?>
''' % (self.html_page, bad_filename)

        testlib.create_fill(self.php5_content_dispo, script)

        # See if it actually downloaded the file
        self._test_url_lwp("http://localhost/" + \
                       os.path.basename(self.php5_content_dispo), expected=1)

        # Make sure it didn't use the bad filename
        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

