#!/usr/bin/python
#
#    test-awstats.py quality assurance test script for awstats
#    Copyright (C) 2010 Canonical Ltd.
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
# QRT-Packages: awstats apache2-mpm-prefork elinks
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py awstats
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-awstats.py -v'

'''


import unittest, subprocess, sys, os
import testlib
import testlib_httpd
import shutil
import tempfile

try:
    from private.qrt.Awstats import PrivateAwstatsTest
except ImportError:
    class PrivateAwstatsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class AwstatsTest(testlib_httpd.HttpdCommon, PrivateAwstatsTest):
    '''Test Awstats.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.awstats_apache = "/etc/apache2/conf.d/awstats"
        self.ports_file = "/etc/apache2/ports.conf"
        self.default_site = "/etc/apache2/sites-available/default"
        self.awstats_conf = "/etc/awstats/awstats.conf"
        self.apache_log = "/var/log/apache2/access.log"
        self.awstats_data = "/var/lib/awstats"

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testawstats-")

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])

        shutil.copy("/usr/share/doc/awstats/examples/apache.conf", self.awstats_apache)

        testlib.config_replace(self.apache_log, "", append=True)
        testlib.config_replace(self.awstats_conf, "", append=True)
        subprocess.call(['sed', '-i', 's/^SiteDomain=\"\"/SiteDomain=\"example.com\"/', self.awstats_conf])
        # elinks in testlib_httpd doesn't support frames
        subprocess.call(['sed', '-i', 's/^UseFramesWhenCGI=1/UseFramesWhenCGI=0/', self.awstats_conf])
        # turn off dns lookups
        subprocess.call(['sed', '-i', 's/^DNSLookup=1/DNSLookup=0/', self.awstats_conf])
        # Hardy has wrong location for log file
        if self.lsb_release['Release'] <= 8.04:
            subprocess.call(['sed', '-i', 's#/var/log/apache/access.log#/var/log/apache2/access.log#', self.awstats_conf])
        # Kill old awstats data (this is destructive!)
        testlib.recursive_rm(self.awstats_data, contents_only=True)

        testlib_httpd.HttpdCommon._setUp(self)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.awstats_apache):
            os.unlink(self.awstats_apache)
        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        testlib.config_restore(self.awstats_conf)
        testlib.config_restore(self.apache_log)
        subprocess.call(['chgrp', 'adm', self.apache_log])

        # Kill old awstats data (this is destructive!)
        testlib.recursive_rm(self.awstats_data, contents_only=True)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        testlib_httpd.HttpdCommon._tearDown(self)

    def test_aaa_daemons(self):
        '''Test daemon'''
        pidfile = "/var/run/apache2.pid"
        self.assertTrue(testlib.check_pidfile("apache2", pidfile))

    def test_aaa_status(self):
        '''Test status (apache2ctl)'''
        rc, report = testlib.cmd(['apache2ctl', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_aab_http(self):
        '''Test http'''
        self._test_url("http://localhost:8000/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.html_page), test_str)

    def test_awstats(self):
        '''Test awstats main page'''
        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "Statistics for")
        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "Error:", invert=True)
        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "Check config file", invert=True)

    def test_awstats_parsing(self):
        '''Test awstats logfile parsing'''

        shutil.copy("./awstats/access.log", self.apache_log)

        # Generate the logs
        rc, report = testlib.cmd(['/usr/lib/cgi-bin/awstats.pl', '-config=example.com', '-update'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "Statistics for")
        self._test_url("http://localhost:8000/cgi-bin/awstats.pl?month=01&year=2011", "/debs/testing/maverick/Release.gpg")

    def test_cve_2010_4369(self):
        '''Test CVE-2010-4369'''

        # Based on example from here:
        # http://sourceforge.net/tracker/?func=detail&aid=2537928&group_id=13764&atid=113764
        #
        hackfile = os.path.join(self.tempdir, "vuln.pm")
        escaped_tempdir = self.tempdir.replace("/", "\/")
        os.chmod(self.tempdir,0777)
        testlib.create_fill(hackfile, '''
#!/usr/bin/perl
print "Content-tpe: text/html\n\n";
print "<pre>HACKED!<\/pre>";
exit;

1;
''')

        bad_plugin_config = 's/^#LoadPlugin=\"tooltips\"/LoadPlugin=\"..\/..\/..\/..%s\/vuln\"/' % escaped_tempdir
        subprocess.call(['sed', '-i', bad_plugin_config, self.awstats_conf])

        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "HACKED", invert=True)
        self._test_url("http://localhost:8000/cgi-bin/awstats.pl", "config file contains a directive to load plugin")

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
