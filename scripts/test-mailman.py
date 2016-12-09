#!/usr/bin/python
#
#    test-mailman.py quality assurance test script for mailman
#    Copyright (C) 2010-2015 Canonical Ltd.
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
# QRT-Packages: apache2-mpm-prefork elinks postfix mailman procmail
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root
# QRT-Conflicts: apache2-mpm-event apache2-mpm-itk apache2-mpm-worker exim4

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    When installing mailman, be sure to install the english language files
    When postfix installs, select "local only"

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-mailman.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-mailman.py -v'
'''


import unittest, subprocess, sys, os, time, smtplib
import urllib, urllib2, cookielib, re, tempfile
import testlib
import testlib_httpd

try:
    from private.qrt.mailman import PrivateMailmanTest
except ImportError:
    class PrivateMailmanTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class MailmanTest(testlib_httpd.HttpdCommon, PrivateMailmanTest):
    '''Test Mailman.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.mailman_daemon = testlib.TestDaemon("/etc/init.d/mailman")
        self.mailman_cfg = '/etc/mailman/mm_cfg.py'
        self.mailman_aliases = '/var/lib/mailman/data/aliases'
        self.mailman_pid = '/var/run/mailman/mailman.pid'
        self.postfix_daemon = testlib.TestDaemon("/etc/init.d/postfix")
        self.postfix_mastercf = '/etc/postfix/master.cf'
        self.postfix_maincf = '/etc/postfix/main.cf'
        self.postfix_transport = '/etc/postfix/transportqrt'
        self.postfix_aliases = '/etc/aliases'
        self.ports_file = "/etc/apache2/ports.conf"
        self.mailman_site = "/etc/apache2/sites-enabled/mailman"
        self.tempdir = tempfile.mkdtemp()

        if self.lsb_release['Release'] >= 12.10:
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
        else:
            self.default_site = "/etc/apache2/sites-available/default"

        if self.lsb_release['Release'] >= 13.10:
            self.apache_pid = "/var/run/apache2/apache2.pid"
        else:
            self.apache_pid = "/var/run/apache2.pid"

        self.cj = cookielib.LWPCookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))

        # Make sure daemons are stopped before we begin
        self.postfix_daemon.stop()
        self.mailman_daemon.stop()

        testlib.config_replace(self.mailman_aliases, "", append=True)
        testlib.config_set(self.mailman_cfg,'MTA',"'Postfix'")
        subprocess.call(['/usr/lib/mailman/bin/genaliases'], stdout=subprocess.PIPE)
        subprocess.call(['chown', 'root:list', self.mailman_aliases])
        # Is this a packaging mistake?
        subprocess.call(['chown', 'list:list', '/var/lib/mailman/archives/private'])

        self._zap_lists()
        subprocess.call(['/usr/sbin/newlist', '-q', 'mailman@lists.example.com', 'root@example.com' ,'ubuntu'], stdout=subprocess.PIPE)

        self._setUp_postfix()
        self._setUp_apache()

        self.mailman_daemon.restart()

        self.user = testlib.TestUser(lower=True)
        self.s = None
        # Silently allow for this connection to fail, to handle the
        # initial setup of the postfix server.
        try:
            self.s = smtplib.SMTP('localhost', port=25)
        except:
            pass

    def tearDown(self):
        '''Clean up after each test_* function'''

        try:
            self.s.quit()
        except:
            pass
        self.user = None

        self._zap_lists()

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        testlib.config_restore(self.mailman_cfg)
        testlib.config_restore(self.mailman_aliases)

        self._tearDown_postfix()
        self._tearDown_apache()

        self.mailman_daemon.stop()

    def _zap_lists(self):
        '''Remove existing mailman lists.'''

        if os.path.exists('/var/lib/mailman/lists/testlist'):
            subprocess.call(['/usr/sbin/rmlist', '-a', 'testlist'], stdout=subprocess.PIPE)
        if os.path.exists('/var/lib/mailman/lists/mailman'):
            subprocess.call(['/usr/sbin/rmlist', '-a', 'mailman'], stdout=subprocess.PIPE)

    def _setUp_postfix(self):
        '''Create Postfix server configs.'''
        testlib.config_replace(self.postfix_mastercf, "", append=True)

        testlib.config_set(self.postfix_maincf,'mydestination','example.com, localhost.localdomain, localhost')

        # Move listener to localhost:25
        master = open('/etc/postfix/master.cf.new','w')
        for cfline in open(self.postfix_mastercf):
            if cfline.startswith('smtp') and 'smtpd' in cfline and 'inet' in cfline:
                master.write('127.0.0.1:25      inet  n       -       -       -       -       smtpd\n')
            else:
                master.write(cfline)
        master.write('''mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}''')
        master.close()
        os.rename('/etc/postfix/master.cf.new',self.postfix_mastercf)

        # Use mbox only
        testlib.config_comment(self.postfix_maincf,'home_mailbox')
        testlib.config_set(self.postfix_maincf,'mailbox_command','procmail -a "$EXTENSION"')

        # Config mailman
        testlib.config_set(self.postfix_maincf,'relay_domains','lists.example.com')
        testlib.config_set(self.postfix_maincf,'transport_maps','hash:%s' % self.postfix_transport)
        testlib.config_set(self.postfix_maincf,'mailman_destination_recipient_limit','1')
        testlib.config_set(self.postfix_maincf,'alias_maps','hash:%s, hash:%s' % (self.postfix_aliases,self.mailman_aliases))

        testlib.config_replace(self.postfix_transport, "lists.example.com      mailman:")
        subprocess.call(['postmap', self.postfix_transport], stdout=subprocess.PIPE)

        testlib.config_replace(self.postfix_aliases, '''mailman:              "|/var/lib/mailman/mail/mailman post mailman"
mailman-admin:        "|/var/lib/mailman/mail/mailman admin mailman"
mailman-bounces:      "|/var/lib/mailman/mail/mailman bounces mailman"
mailman-confirm:      "|/var/lib/mailman/mail/mailman confirm mailman"
mailman-join:         "|/var/lib/mailman/mail/mailman join mailman"
mailman-leave:        "|/var/lib/mailman/mail/mailman leave mailman"
mailman-owner:        "|/var/lib/mailman/mail/mailman owner mailman"
mailman-request:      "|/var/lib/mailman/mail/mailman request mailman"
mailman-subscribe:    "|/var/lib/mailman/mail/mailman subscribe mailman"
mailman-unsubscribe:  "|/var/lib/mailman/mail/mailman unsubscribe mailman"''', append=True)

        subprocess.call(['chown', 'root:list', self.postfix_aliases])
        subprocess.call(['newaliases'])

        # Restart server
        self.postfix_daemon.restart()
        # Postfix exits its init script before the master listener has started
        time.sleep(2)

    def _tearDown_postfix(self):
        '''Tear down Postfix'''

        self.postfix_daemon.stop()

        testlib.config_restore(self.postfix_mastercf)
        testlib.config_restore(self.postfix_maincf)
        testlib.config_restore(self.postfix_aliases)

        subprocess.call(['chown', 'root:root', self.postfix_aliases])

        if os.path.exists(self.postfix_transport):
            os.unlink(self.postfix_transport)
        if os.path.exists(self.postfix_transport + ".db"):
            os.unlink(self.postfix_transport + ".db")

    def _setUp_apache(self):
        '''Set up Apache'''

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])

        if os.path.exists(self.mailman_site):
            os.unlink(self.mailman_site)

        os.symlink("/etc/mailman/apache.conf", self.mailman_site)

        testlib_httpd.HttpdCommon._setUp(self)
        self._enable_mod("cgi")

    def _tearDown_apache(self):
        '''Tear down Apache'''

        if os.path.exists(self.mailman_site):
            os.unlink(self.mailman_site)

        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        testlib_httpd.HttpdCommon._tearDown(self)

    def _deliver_email(self, from_addr, to_addr, body):
        '''Perform mail delivery'''
        self.s.sendmail(from_addr, to_addr, body)

    def _check_email(self, user, pattern, timeout=30):
        '''Get mailman confirmation email'''
        re_pattern = re.compile(pattern)
        spool_file = '/var/mail/%s' % (user.login)
        result = None
        contents = ''
        while timeout > 0:
            if os.path.exists(spool_file):
                contents = open(spool_file).read()
                result = re_pattern.search(contents)
                if result != None:
                    break
            time.sleep(1)
            timeout -= 1
        self.assertTrue(timeout > 0, "Reached timeout searching for pattern in '%s'" % contents)
        return result

    def _search_mischief(self, pattern, timeout=30):
        '''Search mischief log file'''
        re_pattern = re.compile(pattern)
        log_file = '/var/log/mailman/mischief'
        result = None
        contents = ''
        while timeout > 0:
            if os.path.exists(log_file):
                contents = open(log_file).read()
                result = re_pattern.search(contents)
                if result != None:
                    break
            time.sleep(1)
            timeout -= 1
        self.assertTrue(timeout > 0, "Reached timeout searching for pattern in '%s'" % contents)
        return result

    def _get_confirmation(self, user):
        '''Get mailman confirmation email'''
        pattern = 'confirm (\w+)\n'
        result = self._check_email(user, pattern)
        return result.group(1)

    def _test_roundtrip_mail(self, user):
        '''Send and check email delivery'''

        body = '''From: Rooty <root>
To: "%s" <%s@example.com>
Subject: This is test 1

Hello, nice to meet you.
''' % (user.gecos, user.login)

        self._deliver_email('root', user.login + '@example.com', body)
        pattern = "Subject: This is test 1"
        self._check_email(user, pattern)

    def test_aaa_daemons(self):
        '''Test daemon'''

        self.assertTrue(testlib.check_pidfile("apache2", self.apache_pid))
        self.assertTrue(testlib.check_pidfile("python", self.mailman_pid))

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
        self._test_url("http://localhost:8000/cgi-bin/mailman/listinfo/mailman",
                       "About Mailman")

    def test_aac_sending_mail_direct(self):
        '''Test postfix mail delivery'''
        self._test_roundtrip_mail(self.user)

    def test_baa_mailman_subscribe(self):
        '''Test mailman subscription'''

        password = "Ubuntu"

        # Try and subscribe to the Mailman list
        values = { 'email': self.user.login + "@example.com",
                   'pw': password,
                   'pw-conf': password,
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/subscribe/mailman', data)
        result = self.opener.open(req).read()
        self.assertTrue('Mailman Subscription results' in result, result)

        # Parse the confirmation email
        conf = self._get_confirmation(self.user)

        # Now let's confirm via the web page
        values = { 'cookie': conf,
                   'realname': '',
                   'digests': '0',
                   'language': 'en',
                   'submit': 'Subscribe to list Mailman',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/confirm/mailman', data)
        result = self.opener.open(req).read()
        self.assertTrue('successfully confirmed your subscription request' in result, result)

        # Send an email to the list
        body = '''From: "%s" <%s@example.com>
To: "Mailman list" <mailman@lists.example.com>
Subject: This is mailman test

Yay! My first post. Ubuntu rocks!
''' % (self.user.gecos, self.user.login)

        self._deliver_email(self.user.login + '@example.com', 'mailman@lists.example.com', body)

        # See if it was delivered
        # Can't use pattern from body as newer mailman base64 encodes
        # bodies
        pattern = "This is mailman test"
        self._check_email(self.user, pattern)

    def test_cve_2010_3089(self):
        '''Test CVE-2010-3089'''

        tempconf = os.path.join(self.tempdir, 'templist-config')

        # Create a test list and insert XSS into description
        subprocess.call(['/usr/sbin/newlist', '-q', 'testlist@lists.example.com', 'root@example.com' ,'ubuntu'], stdout=subprocess.PIPE)
        subprocess.call(['/usr/sbin/config_list', '-o', tempconf, 'testlist'], stdout=subprocess.PIPE)
        testlib.config_set(tempconf,'description',"'<XSSTEST>'")
        subprocess.call(['/usr/sbin/config_list', '-i', tempconf, 'testlist'], stdout=subprocess.PIPE)

        request = "GET /cgi-bin/mailman/listinfo/testlist HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        self._test_raw(request, '<XSSTEST>', port=8000, invert=True)
        self._test_raw(request, '&lt;XSSTEST&gt;', port=8000)

    def test_cve_2015_2775(self):
        '''Test CVE-2015-2775'''

        # Kill the old log file
        log_file = "/var/log/mailman/mischief"
        if os.path.exists(log_file):
            os.unlink(log_file)

        # Create a test list with an invalid name
        rc, report = testlib.cmd(['/usr/sbin/newlist', '-q',
                                  'invalid/list/name@lists.example.com',
                                  'root@example.com' ,'ubuntu'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "Illegal list name"
        result = "Couldn't find '%s' in:" % search
        self.assertTrue(search in report, result + report)

        self._search_mischief("Hostile listname: invalid/list/name")

    def test_cve_2011_0707(self):
        '''Test CVE-2011-0707'''

        password = "Ubuntu"

        # Try and subscribe to the Mailman list
        values = { 'email': self.user.login + "@example.com",
                   'realname': '<XSSTEST>',
                   'pw': password,
                   'pw-conf': password,
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/subscribe/mailman', data)
        result = self.opener.open(req).read()
        self.assertTrue('Mailman Subscription results' in result, result)

        # Parse the confirmation email
        conf = self._get_confirmation(self.user)

        # Now let's confirm via the web page
        values = { 'cookie': conf,
                   'realname': '<XSSTEST>',
                   'digests': '0',
                   'language': 'en',
                   'submit': 'Subscribe to list Mailman',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/confirm/mailman', data)
        result = self.opener.open(req).read()
        self.assertTrue('successfully confirmed your subscription request' in result, result)

        # Kill email so we can parse the new confirmation string
        subprocess.call(['rm','-rf', '/var/mail/'+self.user.login])

        # Look at the unsubscribe page
        values = { 'email': self.user.login + "@example.com",
                   'password': password,
                   'language': 'en',
                   'login-unsub': 'Unsubscribe',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/options/mailman', data)
        result = self.opener.open(req).read()

        # Parse the confirmation email
        conf = self._get_confirmation(self.user)

        # Now let's confirm via the web page
        values = { 'cookie': conf,
                   'email': self.user.login + "@example.com",
                   'password': password,
                   'language': 'en',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('http://localhost:8000/cgi-bin/mailman/confirm/mailman', data)
        result = self.opener.open(req).read()

        self._word_find(result, '<XSSTEST>', invert=True)
        self._word_find(result, '&lt;XSSTEST&gt;')


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
