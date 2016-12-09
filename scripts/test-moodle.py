#!/usr/bin/python
#
#    test-moodle.py quality assurance test script for moodle
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
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
    Running the Moodle test requires that the Moodle instance is already
    configured.  The steps have not been automated yet...

        # php5 and mysql need to exist prior to moodle's debconf running...
        # install support tools too.
        apt-get install mysql-server php5-mysql libapache2-mod-php5 mimetex curl
        ## prompted for mysql root password

        # install moodle itself
        apt-get install moodle
        ## prompted for web server ("apache2")
        ## prompted for database type ("mysql-server")
        ## prompted for database host ("localhost")
        ## prompted for mysql admin user ("root")
        ## prompted for mysql admin password (above)
        ## prompted for moodle database user ("moodle")
        ## prompted for moodle database password ("m00dle")

        # edit apache config
        /etc/moodle/apache.conf
            allow from all

        # edit moodle config
        /etc/moodle/config.php
            $CFG->wwwroot = 'http://$(hostname)/moodle';

        # restart apache
        apache2ctl graceful

        http://$(hostname)/moodle/admin/   Yes, unattended...

        Admin:  admin/passw0rd, root@localhost, City, Country, Update.
        Site:   Moodle $RELEASE Test, $RELEASE-test, Description for ...

        Users, Accounts, Add a new user:
            tester/testpass, Test, User,
                $EMAIL_USER@$EMAIL_HOST, City, Country, Update

        Top level, Add a new course, Save changes

    Functional email routing needs to be working on the machine with Moodle
    installed.  This is $EMAIL_USER and $EMAIL_HOST above.  Tested with
    dovecot-imapd and postfix.  Local system having postfix installed with
    a relay host for $EMAIL_HOST's IP address is simplest.  Remote host just
    needs:
        sudo apt-get install postfix dovecot-imapd
        sudo adduser tester

    A world-writable directory is needed on the Moodle server to test for
    shell escape failures, with a script to verify and test the Moodle attack:

        mkdir -p /var/www/output
        chmod a+w /var/www/output
        ln -s /usr/bin/curl /usr/local/bin
        rsync -av moodle/cgi-bin/* /usr/lib/cgi-bin/
'''

# QRT-Depends: moodle

import unittest, sys, socket
import testlib, time
import urllib, urllib2, cookielib, libxml2, mechanize
import imaplib

moodle_host = None
email_host = None
email_user = None
email_pass = None

try:
    from private.qrt.Moodle import PrivateMoodleTest
except ImportError:
    class PrivateMoodleTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class MoodleTest(testlib.TestlibCase, PrivateMoodleTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.moodle_host = moodle_host
        self.email_host = email_host
        self.email_user = email_acct
        self.email_password = email_pass

        if not self.moodle_host:
            self.moodle_host = socket.gethostname()
        if not self.email_host:
            self.email_host = self.moodle_host
        self.siteurl = 'http://%s' % (self.moodle_host)
        self.baseurl = '%s/moodle' % (self.siteurl)

        self.cj = cookielib.LWPCookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))

        self.admin_username = 'admin'
        self.admin_password = 'passw0rd'
        self.admin_fullname = 'Admin'

        self.user = 'tester'
        self.user_password = 'testpass'
        self.user_fullname = 'Test User'

        # set by login
        self.session = None

    def tearDown(self):
        '''Clean up after each test_* function'''

    def fetch(self, path):
        url = '%s/%s' % (self.baseurl, path)
        #print url
        return self.opener.open(url).read()

    def login(self, user, password, fullname):
        '''Log into Moodle'''

        # Load a session cookie
        url = '%s/login/index.php' % (self.baseurl)
        self.opener.open(url).read()
        for c in self.cj:
            if c.name == 'MoodleSession':
                self.session = c.value

        # Log in
        values = { 'username': user,
                   'password': password,
                   'testcookies': '1',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request(url, data)
        html = self.opener.open(req).read()
        self.assertTrue('You are logged in as' in html)
        self.assertTrue(fullname in html)

    def add_user(self, username, password, first, last, email):
        '''Add a Moodle user (must be logged in as Administrator)'''
        # This isn't working.  :(
        sys.exit(1)

        br = mechanize.Browser()
        br.set_cookiejar(self.cj)

        br.open('%s/user/editadvanced.php?id=-1' % (self.baseurl))
        br.select_form(predicate=lambda form: form.method == 'POST')
        br['username'] = username
        br['newpassword'] = password
        br['firstname'] = first
        br['lastname'] = last
        br['email'] = email
        response = br.submit(name='submitbutton')

        print response.read()

    def test_can_login_admin(self):
        '''Login with Admin'''
        self.login(self.admin_username, self.admin_password, self.admin_fullname)

    def test_can_login_user(self):
        '''Login with regular user'''
        self.login(self.user, self.user_password, self.user_fullname)

    def test_can_send_email(self):
        '''Email delivery via password reset request'''

        # Log in
        imap = imaplib.IMAP4_SSL(self.email_host)
        ## why is this needed?  first time seems to frequently fail
        try:
            imap.login(self.email_user, self.email_password)
        except:
            imap.login(self.email_user, self.email_password)
        code, data = imap.select('INBOX')
        self.assertEqual(code, 'OK')
        msgs = int(data[0])
        # Delete all existing emails
        while msgs > 0:
            self.assertEqual(imap.store('1', '+FLAGS', '\\Deleted')[0], 'OK')
            msgs -= 1
        self.assertEqual(imap.expunge()[0], 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['']))

        # request password reset
        br = mechanize.Browser()
        br.set_cookiejar(self.cj)
        br.open('%s/login/forgot_password.php' % (self.baseurl))
        br.select_form(predicate=lambda form: form.method == 'POST')
        br['username'] = self.user
        html = br.submit(name='submitbutton').read()
        self.assertTrue('It contains easy instructions to confirm and complete this password change.' in html, html)

        # Wait 10 seconds for delivery
        timeout = 10
        while True:
            code, data = imap.select('INBOX')
            self.assertEqual(code, 'OK')
            #print data
            msgs = int(data[0])
            if msgs > 0:
                break
            timeout -= 1
            self.assertTrue(timeout > 0, "Timed out waiting for new email")
            time.sleep(1)

        # pull email
        code, data = imap.fetch('1', '(RFC822)')
        self.assertEqual(code, 'OK')
        email = data[0][1]

        # Verify Moodle email body
        self.assertTrue('To confirm this and have a new password sent to you via email' in email, email)

        # Delete and expunge message
        self.assertEqual(imap.store('1', '+FLAGS', '\\Deleted')[0], 'OK')
        self.assertEqual(imap.expunge()[0], 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['']))

        # Finish IMAP
        imap.close()
        imap.logout()

    def test_security_cve_phpmailer(self):
        '''CVE-2007-3215 phpmailer fixed'''

        # The email-validation routines already block the creation
        # of email addresses with executable content.  Since only the
        # admin user's email address would be used, the exposure is
        # tiny anyway.
        self._skipped("not exploitable without direct DB access")

    def _add_rss(self, url, parses_okay = True):
        # Make sure the attack URL is not in the list
        rssurl = 'blocks/rss_client/block_rss_client_action.php'
        html = self.fetch(rssurl)
        self.assertFalse(url in html, "RSS item already exists: %s" % (url))

        # FIXME: mechanize doesn't find the form?!
        #br = mechanize.Browser()
        #br.set_cookiejar(self.cj)
        #br.open('%s/%s' % (self.baseurl, rssurl))
        #br.select_form(predicate=lambda form: form.method == 'POST')
        #br['shared'] = 1
        #br['url'] = url
        #br.submit()
        values = { 'url': url,
                   'preferredtitle': '',
                   'shared': '1',
                   'act': 'addfeed',
                   'id': '1',
                   'blogid': '',
                   'user': '2',
                 }
        data = urllib.urlencode(values)
        req = urllib2.Request('%s/%s' % (self.baseurl, rssurl), data)
        html = self.opener.open(req).read()
        if parses_okay:
            self.assertTrue('News feed added' in html, html)
        else:
            self.assertTrue('There was an error loading this rss feed.' in html, html)

        # Verify the RSS item was added
        html = self.fetch(rssurl)
        self.assertTrue(url in html, "RSS item was not added: %s" % (url))

        # Delete the RSS item
        xml = libxml2.htmlParseDoc(html,None)
        delurl = xml.xpathEval("//a[contains(@href,'%s')]/../../../td/a/img[@title='Delete']/.." % (url))[0].prop('href')
        self.assertTrue('News feed deleted' in self.opener.open(delurl).read())

        # Verify the RSS item is gone
        html = self.fetch(rssurl)
        self.assertFalse(url in html, "RSS item was not deleted: %s" % (url))

    def test_security_cve_calendar(self):
        '''CVE-2009-0501 calendar fixed'''

        self.login(self.user, self.user_password, self.user_fullname)

        out = self.fetch('calendar/export.php')
        xml = libxml2.htmlParseDoc(out,None)
        authtoken = xml.xpathEval("//input[@name='authtoken']")[0].prop('value')

        # Valid calendar
        out = self.fetch('calendar/export_execute.php?preset_what=all&preset_time=weeknow&username=%s&authtoken=%s' % (self.user, authtoken))
        self.assertTrue('END:VCALENDAR' in out, out)

        # Bogus token
        out = self.fetch('calendar/export_execute.php?preset_what=all&preset_time=weeknow&username=%s&authtoken=0' % (self.user))
        self.assertEquals(out, 'Invalid authentication')

        # Bogus username
        out = self.fetch('calendar/export_execute.php?preset_what=all&preset_time=weeknow&username=does-not-exist&authtoken=0')
        self.assertEquals(out, 'Invalid authentication')

    def test_security_cve_snoopy(self):
        '''CVE-2008-4796 Snoopy curl escaping'''

        # The embedded Snoopy's path to curl is /usr/loca/bin/curl,
        # so the server needs to have fixed it first...

        cgi = '/usr/lib/cgi-bin/moodle_rss-touch.cgi'
        target = '%s/output/moodle_rss.log' % (self.siteurl)
        touch = '%s/cgi-bin/moodle_rss-touch.cgi' % (self.siteurl)
        rm = '%s/cgi-bin/moodle_rss-rm.cgi' % (self.siteurl)
        # remove target
        self.assertEquals('', self.opener.open(rm).read(),"rm CGI failed")
        # verify it is gone
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen, target)
        # create target
        self.assertEquals('', self.opener.open(touch).read(),"touch CGI failed")
        # verify target
        self.assertEquals('', self.opener.open(target).read(), "log missing")
        # remove target
        self.assertEquals('', self.opener.open(rm).read(),"rm CGI failed")
        # verify it is gone
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen, target)

        self.login(self.admin_username, self.admin_password, self.admin_fullname)

        # Add a valid RSS feed
        self._add_rss('http://feeds.launchpad.net/announcements.atom', parses_okay = True)
        # Add the evil RSS feed
        self._add_rss('https://launchpad.net/$(%s)' % (cgi), parses_okay = False)

        # Verify target was not created
        self.assertRaises(urllib2.HTTPError, urllib2.urlopen, target)

# Manually validated
    def Atest_security_cve_tex_filter(self):
        '''CVE-2009-1171 TeX filtering fixed'''

        # Log in as admin
        self.login(self.user, self.user_password, self.user_fullname)
        # Enable TeX filter
        filterurl = 'admin/filters.php'
        html = self.fetch(fetchurl)
        self.assertTrue('TeX Notation' in html, "TeX Filter missing")

        xml = libxml2.htmlParseDoc(html,None)
        showurls = xml.xpathEval("//a[contains(@href,'%s')]" % ('action=show&amp;filterpath=filter/%2Ftex'))
        hideurls = xml.xpathEval("//a[contains(@href,'%s')]" % ('action=show&amp;filterpath=filter/%2Ftex'))
        if len(showurls)==1 and len(hideurls)==0:
            assertTrue('TeX Notation' in self.fetch(showurls[0].prop('href')), "Could not enable TeX filter")
        elif len(showurls)==0 and len(hideurls)==1:
            # Already enabled
            pass

        # $$ \input{/etc/moodle/config.php}$$
        self.assertTrue(False)

# Manually validated
    def Atest_security_html2text(self):
        '''html2text update functional'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_cve_wiki(self):
        '''CVE-2008-5432 Wiki fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa080010_hotpot(self):
        '''MSA080010 hotpot fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa080004_install(self):
        '''MSA080004 install fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa08003_login(self):
        '''MSA080003 login-as fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa080015_deleted_user(self):
        '''MSA080015 deleted user profiles not visible'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa080021_text_cleaning(self):
        '''MSA080021 text is cleaned'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa080023_message_csrf(self):
        '''MSA080023 message CSRF fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl11759_group_creation(self):
        '''MDL-11759 group creation fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl09288_mnet(self):
        '''MDL-9288 mnet fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl11857_restore(self):
        '''MDL-11857 restore fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl12079_essay_questions(self):
        '''MDL-12079 essay questions fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl12793_param_host(self):
        '''MDL-12793 PARAM HOST fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_mdl14806_wiki_params(self):
        '''MDL-14806 wiki params fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa090001(self):
        '''MSA090001 fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa090002(self):
        '''MSA090002 fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa090004(self):
        '''MSA090004 fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa090007(self):
        '''MSA090007 fixed'''
        self.assertTrue(False)

# Manually validated
    def Atest_security_msa090008(self):
        '''MSA090008 fixed'''
        self.assertTrue(False)



if __name__ == '__main__':
    if len(sys.argv)<5:
        print >>sys.stderr, "Usage: %s MOODLE_HOST EMAIL_HOST EMAIL_ACCT EMAIL_PASSWORD" % (sys.argv[0])
    moodle_host = sys.argv[1]
    email_host = sys.argv[2]
    email_acct = sys.argv[3]
    email_pass = sys.argv[4]

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MoodleTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
