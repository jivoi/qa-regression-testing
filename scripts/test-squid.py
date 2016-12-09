#!/usr/bin/python
#
#    test-squid.py quality assurance test script
#    Copyright (C) 2008-2016 Canonical Ltd.
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
    $ sudo apt-get remove --purge squid
    $ sudo apt-get -y install squid squidclient elinks netcat
    $ sudo ./test-squid.py -v

  NOTE:
    The host running this script needs to have access to the internet

  TODO:
    acls
    ident
    purge (via squidclient)
    ...
    squidguard:
      - test with:
        $ echo "http://blocked.com 1.2.3.4/- - GET -" | squidGuard -c /etc/squid/squidGuard.conf -d
        if using a 'redirect', then the redirect URL is displayed, otherwise
        nothing
      - test block with the following in default acl in squidGuard.conf:
        pass     local none
        redirect http://www.example.com/redirected.html
      - test pass with the following in default acl in squidGuard.conf:
        pass     local all
        redirect http://www.example.com/redirected.html
      - test domains and urls with something like the following acl:
        dest bad {
            domainlist      test/domains
            urllist         test/urls
        }
        acl {
            default {
                pass !bad all
                redirect http://www.example.com/redirected.html
            }
        }

        then create /var/lib/squidguard/db/test/domains with:
        blocked.com

        Test with:
        $ echo "http://ok.com 1.2.3.4/- - GET -" | squidGuard -c /etc/squid/squidGuard.conf -d
        $ echo "http://blocked.com 1.2.3.4/- - GET -" | squidGuard -c /etc/squid/squidGuard.conf -d
'''

# QRT-Packages: squid3 squidclient elinks netcat pygopherd apparmor-utils
# QRT-Depends: testlib_httpd.py private/qrt/squid.py

import unittest
import os
import sys
import testlib
import testlib_httpd

try:
    from private.qrt.squid import PrivateSquidTest
except ImportError:
    class PrivateSquidTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class BasicTest(testlib_httpd.HttpdCommon, PrivateSquidTest):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''

        # Trusty uses upstart
        if self.lsb_release['Release'] == 14.04:
            self._set_initscript("squid3", initdaemon="upstart")
        elif self.lsb_release['Release'] >= 16.04:
            self._set_initscript("/etc/init.d/squid")
        else:
            self._set_initscript("/etc/init.d/squid3")

        testlib_httpd.HttpdCommon._setUp(self)

        self.gophermap = "/var/gopher/gophermap"

        self.aa_profile = "usr.sbin.squid3"
        self.aa_abs_profile = "/etc/apparmor.d/%s" % self.aa_profile
        self.version_with_apparmor = 12.10
        # This hack is only used until we have tests run both confined and
        # unconfined
        self.aa_unload_at_teardown = False

    def tearDown(self):
        '''Shutdown methods'''
        testlib_httpd.HttpdCommon._tearDown(self)
        testlib.config_restore(self.gophermap)

    def test_daemons(self):
        '''Test daemon'''

        if self.lsb_release['Release'] >= 16.04:
            pidfile = "/run/squid.pid"
        else:
            pidfile = "/run/squid3.pid"

        if self.lsb_release['Release'] >= 15.10:
            exe = "(squid-1)"
        else:
            exe = "squid3"

        self.assertTrue(testlib.check_pidfile(exe, pidfile))

    def test_http_proxy(self):
        '''Test http'''
        self._test_url_proxy("http://www.ubuntu.com/", "Canonical", "http://localhost:3128/")

    def test_https_proxy(self):
        '''Test https'''
        self._test_url_proxy("https://wiki.ubuntu.com/", "Community", "http://localhost:3128/")

    def test_ftp_proxy(self):
        '''Test ftp'''
        self._test_url_proxy("ftp://ftp.ubuntu.com/", "irectory", "http://localhost:3128/")

    def test_squidclient(self):
        '''Test squidclient'''
        urls = ['http://www.ubuntu.com/', 'https://wiki.ubuntu.com/', \
                'ftp://ftp.ubuntu.com/', 'gopher://127.0.0.1']
        for url in urls:
            rc, report = testlib.cmd(['squidclient', '-h', '127.0.0.1', '-p', '3128', '-r', url])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def test_CVE_2011_3205(self):
        '''Test parsing lines > 4096 in length (CVE-2011-3205)'''

        longline = "ABCDEF" * 4096

        testlib.config_replace(self.gophermap, """Welcome to Pygopherd!  You can place your documents
in /var/gopher for future use.  You can remove the gophermap
file there to get rid of this message, or you can edit it to
use other things.  (You'll need to do at least one of these
two things in order to get your own data to show up!)

%s

Some links to get you started:

1Pygopherd Home /devel/gopher/pygopherd gopher.quux.org 70
1Quux.Org Mega Server   /   gopher.quux.org 70
1The Gopher Project /Software/Gopher    gopher.quux.org 70
1Traditional UMN Home Gopher    /   gopher.tc.umn.edu   70

Welcome to the world of Gopher and enjoy!
""" %(longline), append=False)

        rc, report = testlib.cmd(['squidclient', '-h', '127.0.0.1', '-p', '3128', '-r', "gopher://127.0.0.1"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    # Run this last so if we enable the profile then we don't unload it
    def test_zz_apparmor(self):
        '''Test apparmor'''
        if self.lsb_release['Release'] < 12.10:
            self._skipped("No profile in 12.04 and under")
            return

        self.aa_unload_at_teardown = True

        # Currently while we have a profile, it is shipped disabled by default.
        # Verify that.
        rc, report = testlib.check_apparmor(self.aa_abs_profile, 12.10, is_running=False)
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

        self._stop()
        self._start()

        rc, report = testlib.check_apparmor(self.aa_abs_profile, 12.10, is_running=True)
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
