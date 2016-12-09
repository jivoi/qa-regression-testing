#!/usr/bin/python
#
#    test-lftp.py quality assurance test script
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
# QRT-Packages: apache2-mpm-prefork libapache2-mod-php5 lftp ssl-cert openssl lsb-release
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
    $ sudo apt-get -y install apache2-mpm-prefork libapache2-mod-php5 ssl-cert openssl lsb-release lftp

'''

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
        self.default_site = "/etc/apache2/sites-available/default"
        self.php5_content_dispo = "/var/www/test-content-dispo.php"
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libwww-perl-")

        self.evil_filename = ".hiddenfile"
        self.evil_file = os.path.join("/var/www", self.evil_filename)
        testlib.create_fill(self.evil_file, "This is an evil file.")

        testlib_httpd.HttpdCommon._setUp(self)

        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Shutdown methods'''

        if self.current_dir != os.getcwd():
            os.chdir(self.current_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        if os.path.exists(self.php5_content_dispo):
            os.unlink(self.php5_content_dispo)

        if os.path.exists(self.evil_file):
            os.unlink(self.evil_file)

        testlib.config_restore(self.hosts_file)
        testlib.config_restore(self.default_site)
        self._disable_mod("php5")

        testlib_httpd.HttpdCommon._tearDown(self)

    def _test_url_lftp(self, url="http://localhost/", content="", invert=False, expected=0, extra_opts=[]):
        '''Test the given url with lftp'''
        report = self._get_page_lftp(url, expected=expected, extra_opts=extra_opts)

        if content != "":
            self._word_find(report, content, invert)

    def _get_page_lftp(self, url="http://localhost/", expected=0, extra_opts=[]):
        '''Get contents of given url with lftp'''
        rc, report = testlib.cmd(['lftp', '-c', 'cat'] + extra_opts + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def _download_file_lftp(self, url="http://localhost/", directory=".", expected=0, extra_opts=[]):
        '''Download a file with lftp'''
        rc, report = testlib.cmd(['lftp', '-c', 'get', '-O', directory] + extra_opts + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def _download_file_lftp_get1(self, url="http://localhost/", directory=".", expected=0,
                                       extra_cmd="", extra_opts=""):
        '''Download a file with lftp'''

        command = extra_cmd + "get1 " + extra_opts + " " + url

        os.chdir(directory)
        rc, report = testlib.cmd(['lftp', '-c', command])
        os.chdir(self.current_dir)

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

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
        self._test_url_lftp("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_lftp("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_php(self):
        '''Test php'''
        self._enable_mod("php5")
        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url_lftp("http://localhost/" + \
                       os.path.basename(self.php_page), test_str)

    def test_ssl(self):
        '''Test https'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self._prepare_ssl(srvkey_pem, srvcert_pem)

        testlib.recursive_rm(tmpdir)

        self._test_url_lftp("https://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url_lftp("https://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_cve_2010_2251_1(self):
        '''Test CVE-2010-2251, part 1'''

        # This test makes sure filenames suggested by the server via a
        # Content-Disposition header and begin with '.' are always ignored,
        # even if we try using the new xfer:auto-rename option.

        self._enable_mod("php5")

        test_str = testlib_httpd.create_html_page(self.html_page)

        bad_filename = ".blah.txt"
        bad_file_path = os.path.join(self.tempdir,bad_filename)

        good_filename = os.path.basename(self.php5_content_dispo)
        good_file_path = os.path.join(self.tempdir,good_filename)

        specified_filename = "specified"
        specified_file_path = os.path.join(self.tempdir, specified_filename)

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

        self._download_file_lftp_get1("http://localhost/" + good_filename,
                       directory = self.tempdir)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Didn't find the %s file." % good_file_path
        self.assertTrue(os.path.exists(good_file_path), error)

        # Clean up before the next test
        if os.path.exists(bad_file_path):
            os.unlink(bad_file_path)
        if os.path.exists(good_file_path):
            os.unlink(good_file_path)

        if self.lsb_release['Release'] > 6.06:
            # Attempt to download the file with the new option
            self._download_file_lftp_get1("http://localhost/" + good_filename,
                           directory = self.tempdir, extra_cmd='set xfer:auto-rename yes;')

            error = "Found the %s file." % bad_file_path
            self.assertFalse(os.path.exists(bad_file_path), error)

            error = "Didn't find the %s file." % good_file_path
            self.assertTrue(os.path.exists(good_file_path), error)

            # Clean up before the next test
            if os.path.exists(bad_file_path):
                os.unlink(bad_file_path)
            if os.path.exists(good_file_path):
                os.unlink(good_file_path)

        # Attempt to download the file with a specified filename
        self._download_file_lftp_get1("http://localhost/" + good_filename,
                       directory = self.tempdir, extra_opts='-o ' + specified_filename)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Found the %s file." % good_file_path
        self.assertFalse(os.path.exists(good_file_path), error)

        error = "Didn't find the %s file." % specified_file_path
        self.assertTrue(os.path.exists(specified_file_path), error)


    def test_cve_2010_2251_2(self):
        '''Test CVE-2010-2251, part 2'''

        # This test makes sure filenames suggested by the server via a
        # Content-Disposition header are ignored, unless the new
        # xfer:auto-rename option is used.

        self._enable_mod("php5")

        test_str = testlib_httpd.create_html_page(self.html_page)

        bad_filename = "blah.txt"
        bad_file_path = os.path.join(self.tempdir,bad_filename)

        good_filename = os.path.basename(self.php5_content_dispo)
        good_file_path = os.path.join(self.tempdir,good_filename)

        specified_filename = "specified"
        specified_file_path = os.path.join(self.tempdir, specified_filename)

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

        self._download_file_lftp_get1("http://localhost/" + good_filename,
                       directory = self.tempdir)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Didn't find the %s file." % good_file_path
        self.assertTrue(os.path.exists(good_file_path), error)

        # Clean up before the next test
        if os.path.exists(bad_file_path):
            os.unlink(bad_file_path)
        if os.path.exists(good_file_path):
            os.unlink(good_file_path)

        if self.lsb_release['Release'] > 6.06:
            # Attempt to download the file with the new option
            self._download_file_lftp_get1("http://localhost/" + good_filename,
                           directory = self.tempdir, extra_cmd='set xfer:auto-rename yes;')

            error = "Found the %s file." % good_file_path
            self.assertFalse(os.path.exists(good_file_path), error)

            error = "Didn't find the %s file." % bad_file_path
            self.assertTrue(os.path.exists(bad_file_path), error)

            # Clean up before the next test
            if os.path.exists(bad_file_path):
                os.unlink(bad_file_path)
            if os.path.exists(good_file_path):
                os.unlink(good_file_path)

        # Attempt to download the file with a specified filename
        self._download_file_lftp_get1("http://localhost/" + good_filename,
                       directory = self.tempdir, extra_opts='-o ' + specified_filename)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Found the %s file." % good_file_path
        self.assertFalse(os.path.exists(good_file_path), error)

        error = "Didn't find the %s file." % specified_file_path
        self.assertTrue(os.path.exists(specified_file_path), error)

    def test_cve_2010_2251_3(self):
        '''Test CVE-2010-2251, part 3'''

        # This test makes sure filenames suggested by the server after a
        # redirect are ignored.

        bad_file_path = os.path.join(self.tempdir, self.evil_filename)
        good_file_path = os.path.join(self.tempdir, "log")

        # Add the redirect to the config file
        testlib.config_replace(self.default_site, "", append=True)

        subprocess.call(['sed', '-i', "s/DocumentRoot \\(.*\\)/DocumentRoot \\1" +
                                      "\\nRedirectMatch log $1\/" +
                                      self.evil_filename + "/", self.default_site])

        self._reload()

        self._download_file_lftp_get1("http://localhost/log", directory = self.tempdir)

        error = "Found the %s file." % bad_file_path
        self.assertFalse(os.path.exists(bad_file_path), error)

        error = "Didn't find the %s file." % good_file_path
        self.assertTrue(os.path.exists(good_file_path), error)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

