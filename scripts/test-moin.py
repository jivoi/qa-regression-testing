#!/usr/bin/python
#
#    test-moin.py quality assurance test script
#    Copyright (C) 2009-2012 Canonical Ltd.
#    Author: Martin Pitt <martin.pitt@ubuntu.com>
#            Jamie Strandboge <jamie@canonical.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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

    How to run against a Dapper or Hardy schroot:
        schroot -c hardy -u root -- sh -c 'apt-get -y install python python-moinmoin apache2 && ./test-moin.py -v'

    How to run against a Jaunty+ schroot:
        schroot -c jaunty -u root -- sh -c 'apt-get -y install python python-moinmoin apache2 python-gdchart2 && ./test-moin.py -v'

    TODO:
       - add editmoin test
       - much more...
       - TextCha (1.7 and higher) with CVE-2010-1238 reproducer
'''
# QRT-Packages: python-moinmoin apache2 python python-gdchart2
# QRT-Privilege: root

import unittest, subprocess, urllib, urllib2
import testlib
import os
import re
import time
import sys
import cookielib
import cgi

class MoinTest(testlib.TestlibCase):
    '''Test moin.'''

    def setUp(self):
        '''Setup moin testing'''
        self.farmconfig = "/etc/moin/farmconfig.py"
        self.mywiki = '/etc/moin/mywiki.py'
        self.datadir = "/var/lib/mywiki"
        self.wwwdir = "/var/www/mywiki"

        self.cookies = "/tmp/cookies.lwp"
        testlib.create_fill(self.cookies, "#LWP-Cookies-2.0")

        self.user = "foo"
        self.passwd = "moinPassword"

        self.adminuser = "adminuser"
        self.adminpasswd = "moinPassword"

        self.headers = {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

    def tearDown(self):
        '''Tear down moin testing'''
        self._logout()
        os.unlink(self.cookies)

    def _get_ticket(self, html):
        '''Returns the ticket from a page'''
        ticket = ""
        for line in html.splitlines():
            if '<input type="hidden" name="ticket" ' in line:
                try:
                    ticket = line.split('name="ticket"')[1].split('"')[1]
                except:
                    ticket = ""

        return ticket

    def _get_page(self, url, data='', headers='', initial_setup=False):
        '''Fetches the given url and returns the html as a string'''
        if headers == '':
            headers = self.headers

        #try:
        #    if data != '':
	#        req = urllib2.Request(url, data, headers)
        #    else:
	#        req = urllib2.Request(url, headers=headers)
        #    handle = urllib2.urlopen(req)
        #    html = handle.read()
        #except:
        #    raise

        cj = cookielib.LWPCookieJar(filename=self.cookies)
        cj.load()

        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)

        try:
            if data != '':
                req = urllib2.Request(url, data, headers)
            else:
                req = urllib2.Request(url, headers=headers)
        except:
            raise

        tries = 0
        failed = True
        while tries < 3:
            try:
                handle = urllib2.urlopen(req)
                failed = False
                break
            except urllib2.HTTPError, e:
                if (e.code == 404 and initial_setup == True):
                    # Moin 1.9+ returns 404 when the languages have not
                    # been set up yet. We need to ignore this in order
                    # to be able to add the new users
                    failed = False
                    break
                if e.code != 503:
                    # for debugging
                    #print >>sys.stderr, 'Error retrieving page "url=%s", "data=%s"' % (url, data)
                    raise
            tries += 1
            time.sleep(2)

        self.assertFalse(failed, 'Could not retrieve page "url=%s", "data=%s"' % (url, data))

        if initial_setup == False:
            try:
                html = handle.read()
            except:
                raise
        else:
            html = ''

        cj.save()

        return html

    def _delete_page(self, pagename, pagetext=''):
        '''Delete a moin page (must be logged in already)'''
        # first go to the page
        url = 'http://localhost/MyWiki/%s' % (pagename)
        html = self._get_page(url)
        self.assertTrue(html.find(pagetext)>=0, 'Could not find "%s\n%s"' % (pagetext, html))

        # get a ticket
        url = 'http://localhost/MyWiki/%s?action=DeletePage' % (pagename)
        html = self._get_page(url)
        s = "Really delete this page"
        self.assertTrue(html.find(s)>=0, 'Could not find "%s"' % (s))

        ticket = self._get_ticket(html)
        self.assertTrue(ticket != "", "Could not find ticket")

        # delete the page
        html = ""
        url = "http://localhost/MyWiki/%s?action=DeletePage&ticket=%s&comment=&delete=Delete" % (pagename, ticket)
        try:
            html = self._get_page(url)
        except urllib2.HTTPError, e:
            if e.code != 404:
                raise

        if pagetext != '':
            # check if it is really gone
            url = 'http://localhost/MyWiki/%s' % (pagename)
            try:
                self._get_page(url)
            except urllib2.HTTPError, e:
                if e.code != 404:
                    raise
            html = ""

        return html

    def _rename_page(self, pagename, newname, pagetext=''):
        '''Rename page (requires login)'''
        url = 'http://localhost/MyWiki/%s' % (pagename)
        html = self._get_page(url)
        self.assertTrue(html.find(cgi.escape(pagetext))>=0, 'Could not find "%s\n%s"' % (cgi.escape(pagetext), html))

        url = 'http://localhost/MyWiki/%s?action=RenamePage' % (pagename)
        html = self._get_page(url)
        s = "reason for the renaming"
        self.assertTrue(html.find(s)>=0, 'Could not find "%s\n%s"' % (s, html))

        ticket = self._get_ticket(html)
        self.assertTrue(ticket != "", "Could not find ticket")

        #url = "http://localhost/MyWiki/%s?action=RenamePage&ticket=%s&newpagename=%s&comment=&rename=Rename%%20Page" % (pagename, ticket, newname)
        #self._get_page(url)

        url = "http://localhost/MyWiki/%s" % (pagename)
        data = "action=RenamePage&ticket=%s&newpagename=%s&comment=&rename=Rename%%20Page" % (ticket, newname)
        self._get_page(url, data)

        time.sleep(1)
        url = 'http://localhost/MyWiki/%s' % (newname)
        html = self._get_page(url)
        if pagetext != '':
            wikitext = re.sub(pagename, pagename + "</a>", pagetext)
            self.assertTrue(html.find(pagetext)>=0 or html.find(wikitext)>=0, 'Could not find "%s" or "%s"' % (pagetext, wikitext))

        return html

    def _login(self, user='', passwd='', initial_setup=False):
        '''Login to moin'''
        if user == '':
            user = self.user
            passwd = self.passwd
        url = 'http://localhost/MyWiki/FrontPage'
        data = "action=login&name=%s&password=%s&login=Login" % (user, passwd)
        html = self._get_page(url, data, initial_setup=initial_setup)
        s = 'Login</a>'
        self.assertFalse(html.find(s) >=0, "Login unsuccessful (Found '%s'" % (s))

        time.sleep(1)

    def _logout(self):
        '''Logout of moin'''
        url = 'http://localhost/MyWiki/FrontPage?action=logout&logout=logout'
        if self.lsb_release['Release'] < 7.10:
            url = 'http://localhost/MyWiki/FrontPage?action=userform&logout=Logout'
        # just do the action without checking the html
        html = ""
        try:
            html = self._get_page(url)
        except urllib2.HTTPError:
            pass
        return html

    def _add_moin_user(self, username, password, email='', initial_setup=False):
        '''Adds a user to moin'''
        url = 'http://localhost/MyWiki/UserPreferences'
        if self.lsb_release['Release'] >= 8.10:
            url = 'http://localhost/MyWiki/FrontPage?action=newaccount'

        html = self._get_page(url)
        s = 'Login</a>'
        self.assertTrue(html.find(s) >=0, "Could not find '%s'" % (s))

        ticket = self._get_ticket(html)
        #self.assertTrue(ticket != "", "Could not find ticket")

        if email == '':
            email = '%s@example.com' % (username)

        data = 'action=userform&name=%s&password=%s&password2=%s&email=%s&create=Create%%20Profile' % (username, password, password, email)
        if self.lsb_release['Release'] == 8.10:
            data = 'action=newaccount&name=%s&password1=%s&password2=%s&email=%s&create_only=Create%%20Profile' % (username, password, password, email)

        if self.lsb_release['Release'] >= 9.04:
            data = 'action=newaccount&name=%s&password1=%s&password2=%s&email=%s&create=Create%%20Profile' % (username, password, password, email)

        if ticket != "":
            data += "&ticket=%s" % (ticket)

        html = self._get_page(url, data, initial_setup=initial_setup)

        if initial_setup == False:
            s = "This user name already belongs to somebody else"
            self.assertTrue(html.find(s)<0, 'Found "%s"' % (s))

            s = "User account created"
            self.assertTrue(html.find(s) >=0, "Create account unsuccessful (could not find '%s'" % (s))

        self._logout()

    def _add_moin_page(self, title, content, user='', passwd='', check=True):
        '''Add a page to moin'''
        html = self._login(user, passwd)

        newpage = title
        url = 'http://localhost/MyWiki/%s?action=edit' % (newpage)
        html = self._get_page(url)
        s = 'Use the Preview button to extend the locking period'
        self.assertTrue(html.find(s) >=0, "Could not find '%s'" % (s))

        ticket = self._get_ticket(html)
        if self.lsb_release['Release'] >= 7.10:
            self.assertTrue(ticket != "", "Could not find ticket")

        time.sleep(3)
        url = 'http://localhost/MyWiki/%s#preview' % (newpage)
        data = "action=edit&rev=0&button_save=Save%%20Changes&editor=text&savetext=%s&comment=&category=&rstrip=1" % (urllib.quote_plus(content))
        if ticket != "":
            data += "&ticket=%s" % (ticket)

        html = self._get_page(url, data)
        #wikitext = re.sub(pagename, pagename + "</a>", pagetext)
        if check:
            search_str = re.sub('#acl .*\n', '', content)
            self.assertTrue(html.find(cgi.escape(search_str)) >=0, "Could not find '%s'" % (cgi.escape(search_str)))
        self._logout()

    def onetime_setUp(self):
        subprocess.call(['/bin/mkdir', '-p', self.wwwdir, self.datadir], stdout=subprocess.PIPE)
        subprocess.call(['/bin/cp', '-r', '/usr/share/moin/server/moin.cgi', self.wwwdir], stdout=subprocess.PIPE)
        subprocess.call(['/bin/cp', '-r', '/usr/share/moin/data','/usr/share/moin/underlay', self.datadir], stdout=subprocess.PIPE)
        subprocess.call(['/bin/chown', '-R', 'www-data:', self.wwwdir, self.datadir], stdout=subprocess.PIPE)

        testlib.config_replace('/etc/apache2/apache2.conf','''
Alias /static/ "/usr/share/moin/htdocs/"
Alias /wiki/ "/usr/share/moin/htdocs/"
ScriptAlias /MyWiki "%s/moin.cgi"
''' % (self.wwwdir), append=True)

        testlib.config_replace(self.farmconfig, "", True)
        subprocess.call(['sed', '-i', 's#^\\(\s*\\)("mywiki",.*#\\1("mywiki",    r"^.*/MyWiki/.*$"),#g', self.farmconfig])
        subprocess.call(['sed', '-i', 's/^\\(\s*\\)#superuser = .*/\\1superuser = [u"adminuser", ]\\n\\1acl_rights_before = u"adminuser:read,write,delete,revert,admin"\\n/g', self.farmconfig])
        subprocess.call(['sed', '-i', 's/^\\(\s*\\)#chart_options =/\\1chart_options =/g', self.farmconfig])

        # Turn on mail so subscription tests work
        if self.lsb_release['Release'] >= 10.04:
            subprocess.call(['sed', '-i', 's/^\\(\s*\\)#mail_smarthost = .*/\\1mail_smarthost = "localhost"/g', self.farmconfig])
            subprocess.call(['sed', '-i', 's/^\\(\s*\\)#mail_from = .*/\\1mail_from = u"Test Wiki <noreply@localhost>"/g', self.farmconfig])

        testlib.config_replace(self.mywiki, "", True)
        surge_protection = 'surge_action_limits = None'
        # acl_hierarchic is needed for the CVE-2009-4762 test
        acl_hierarchic = 'acl_hierarchic = True'
        backup_users = 'backup_users = [\'adminuser\']'
        if self.lsb_release['Release'] < 8.04:
             surge_protection = ''
        if self.lsb_release['Release'] < 9.04:
             acl_hierarchic = ''
        subprocess.call(['sed', '-i', 's#^\\(\s*\\)data_dir = .*#\\1data_dir = \'' + self.datadir + '/data\'\\n\\1data_underlay_dir = \'' + self.datadir + '/underlay\'\\n\\1show_traceback = 0\\n\\1url_prefix_static = \'/static\'\\n\\1' + surge_protection + '\\n\\1' + acl_hierarchic + '\\n\\1' + backup_users + '#g', self.mywiki])

        subprocess.call(['/etc/init.d/apache2', 'stop'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(subprocess.call(['/etc/init.d/apache2', 'restart'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0)

        if self.lsb_release['Release'] >= 10.04:
            # We need to ignore 404 errors as the language packs have not
            # been installed yet
            self._add_moin_user(self.user, self.passwd, initial_setup=True)
            self._add_moin_user(self.adminuser, self.adminpasswd, initial_setup=True)
            # Install language packs
            self._login(self.adminuser, self.adminpasswd, initial_setup=True)
            html = self._get_page("http://localhost/MyWiki/LanguageSetup?action=language_setup&target=English--all_pages.zip&language=English")
            self._logout()
        else:
            self._add_moin_user(self.user, self.passwd)
            self._add_moin_user(self.adminuser, self.adminpasswd)


    def onetime_tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore(self.mywiki)
        testlib.config_restore(self.farmconfig)
        testlib.config_restore('/etc/apache2/apache2.conf')

        testlib.recursive_rm(self.datadir)
        testlib.recursive_rm(self.wwwdir)

    def test_00_basic_page(self):
        '''FrontPage'''
        self.onetime_setUp()
        html = urllib.urlopen('http://localhost/MyWiki/').read()
        self.assertTrue(html.find('FrontPage')>=0, 'Could not find "FrontPage"')

    def test_add_user(self):
        '''Add user'''
        user = "testuser"
        passwd = "testpass"
        self._add_moin_user(user, passwd)

    def test_add_page(self):
        '''Add page'''
        pagename = "TestPage"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)

    def test_rename_page(self):
        '''Rename page'''
        pagename = "TestRenamePage"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)
        newpage = pagename + "New"

        html = self._login()
        self._rename_page(pagename, newpage, pagetext)
        self._logout()

    def test_delete_page(self):
        '''Delete page'''
        pagename = "TestDeletePage"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)

        html = self._login()
        self._delete_page(pagename, pagetext)
        self._logout()

    def test_login(self):
        '''Login and logout'''
        html = self._login()
        time.sleep(3)
        html = self._logout()
        s = "Login</a>"
        self.assertTrue(html.find(s) >=0, "Logout unsuccessful (could not find '%s'" % (s))

    def test_acls(self):
        '''ACLs'''
        # create page as adminuser
        pagename = "TestAclPage"
        pagetext = '''#acl adminuser:read,write
TestAclPage stuff'''
        self._add_moin_page(pagename, pagetext, self.adminuser, self.adminpasswd)
        time.sleep(3)

        # try to access the page as regular user
        self._login()
        try:
            html = self._get_page("http://localhost/MyWiki/%s" % pagename)
        except urllib2.HTTPError, e:
            if e.code == 403:
                return
            raise

        self._logout()
        if self.lsb_release['Release'] <= 8.04:
            not_successful='You are not allowed to view this page.'
            self.assertTrue(html.find(not_successful) >=0, "Could not find '%s' in page." % (not_successful))
        else:
            self.fail("Error: could read page protected by ACLs")

    def test_textcha(self):
        '''TextCha'''
        if self.lsb_release['Release'] >= 8.10:
            return self._skipped("TODO")
        else:
            return self._skipped("textcha not available in moin 1.5")

    def test_za_CVE_2007_2423(self):
        '''CVE-2007-2423'''
        html = self._get_page('http://localhost/MyWiki/FrontPage?action=AttachFile&do=%3Cblink%3EWarning%3C/blink%3E')
        str1 = 'Unsupported upload action:'
        str2 = 'Unsupported AttachFile sub-action:'
        self.assertTrue(html.find(str1)>=0 or html.find(str2)>=0, 'Could not find "%s" or "%s"' % (str1, str2))
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag')

    def test_za_CVE_2010_2487_1(self):
        '''CVE-2010-2487, Test 1'''
        html = self._get_page('http://localhost/MyWiki/NonExistantUser?action=edit&template=<blink>Warning</blink>')
        str1 = 'Template &lt;blink&gt;Warning&lt;/blink&gt; not found'
        self.assertTrue(html.find(str1)>=0, 'Could not find "%s" in "%s".' % (str1,html))
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag')

    def test_za_CVE_2010_2487_2(self):
        '''CVE-2010-2487, Test 2'''

        self._login(self.adminuser, self.adminpasswd)

        url = 'http://localhost/MyWiki/?action=backup&do=<blink>Warning</blink>'

        if self.lsb_release['Release'] >= 10.04:
            data = "action=backup&do=<blink>Warning</blink>"
            html = self._get_page(url,data)
        else:
            html = self._get_page(url)
        str1 = 'Unknown backup subaction: &lt;blink&gt;Warning&lt;/blink&gt;.'
        self.assertTrue(html.find(str1)>=0, 'Could not find "%s" in "%s".' % (str1,html))
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag')

        self._logout()

    def test_za_CVE_2010_2969_1(self):
        '''CVE-2010-2969, Test 1'''

        if self.lsb_release['Release'] <= 8.04:
            return self._skipped("chart not available in moin 1.5")

        html = self._get_page('http://localhost/MyWiki/?action=chart&type=<blink>Warning</blink>')
        str1 = 'Bad chart type "&lt;blink&gt;Warning&lt;/blink&gt;"!'
        self.assertTrue(html.find(str1)>=0, 'Could not find "%s" in "%s".' % (str1,html))
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag')

    def test_za_CVE_2008_0780(self):
        '''CVE-2008-0780'''
        # split url and data for POST
        url = 'http://localhost/MyWiki/UserPreferences'
        data = "action=userform&name=foo</tt></p><blink>WARNING</blink>&password=pass&password2=&email=&login=Login"
        if self.lsb_release['Release'] >= 6.10:
            url = 'http://localhost/MyWiki/FrontPage'
            data = "action=login&password=pass&name=foo</tt></p><blink>WARNING</blink><p>&login=Login"
        html = self._get_page(url, data)

        s = "Login</a>"
        self.assertTrue(html.find(s)>=0, 'Found "%s"' % (s))
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag')

    def test_za_CVE_2009_0260(self):
        '''CVE-2009-0260'''
        self._login()
        html = self._get_page('http://localhost/MyWiki/WikiSandBox?rename=mytest.png&action=AttachFile&drawing=mytest%22%3E%3Cblink%3EWARNING%20rename%3C/blink%3E%3Cp%20class=%22rename=mytest.png%22%3E%3Cblink%3EWARNING%20rename%3C/blink%3E%3Cp%20class=%22&action=AttachFile&drawing=mytest')
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag (rename)')

        html = self._get_page('http://localhost/MyWiki/WikiSandBox?rename=mytest.png&action=AttachFile&drawing=mytest%22%3E%3Cblink%3EWARNING%20rename%3C/blink%3E%3Cp%20class=%22')
        self.assertTrue(html.find('<blink>')==-1, 'Found unescaped html tag (drawing/basename)')
        self._logout()

    def test_za_CVE_2008_0781(self):
        '''CVE-2008-0781'''
        if self.lsb_release['Release'] >= 8.10:
            return self._skipped("Reproducer causes 1.7 to Server Error (and it's fixed anyway")
        pagename = "TestCVE20080781"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)

        self._login()
        url = 'http://localhost/MyWiki/%s' % (pagename)
        data = "action=AttachFile&file=mytest.zip&rename=%22%3E%3Cblink%3EWARNING%3C/blink%3E%3Cp class=%22&overwrite=1&do=upload"
        html = self._get_page(url, data)
        self._logout()
        self.assertTrue(html.find('<blink>') < 0, 'Found unescaped html tag')

    def test_za_CVE_2008_0782(self):
        '''CVE-2008-0782'''
        if self.lsb_release['Release'] < 6.10:
            return self._skipped("Reproducer doesn't work on Dapper")
        user = "nonexistent"
        passwd = "nopass"
        file = '../../../../..' + self.wwwdir + '/p0wned'

        url = 'http://localhost/MyWiki/UserPreferences/'
        data = "action=userform&name=%s&aliasname=bar&password=%s&password2=%s&email=%s@example.com&css_url=&edit_rows=20&theme_name=modern&editor_default=text&editor_ui=freechoice&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&save=Save" % (user, passwd, passwd, user)
        if self.lsb_release['Release'] >= 8.10:
            url = 'http://localhost/MyWiki/FrontPage?action=userprefs&sub=prefs'
            data = 'action=userprefs&handler=prefs&name=%s&aliasname=bar&email=%s@example.com&jid=&css_url=&edit_rows=20&theme_name=modern&datetime_fmt=&language=&wikiname_add_spaces=&remember_last_visit=&edit_on_double_click=&mailto_author=&remember_me=1&show_comments=1&show_toolbar=1&show_page_trail=1&show_nonexist_qm=1&show_topbottom=&quicklinks=&save=Save' % (user, user)

        headers = { 'Cookie' : 'MOIN_ID=' + file }
        try:
            html = self._get_page(url, data, headers)
        except urllib2.HTTPError, e:
            raise
            if e.code != 404:
                return
            raise

        self.assertFalse(os.path.exists(self.wwwdir + '/p0wned'), "Found '%s'" % (self.wwwdir + '/p0wned'))

    def test_za_CVE_2008_1098(self):
        '''CVE-2008-1098'''

        # doesn't affect 1.7 and it was too hard to prove it was fixed on
        # 1.7
        if self.lsb_release['Release'] >= 8.10:
            return

        pagename = "TestCVE20081098<blink>WARNING</blink>"
        pagetext = "TestCVE20081098 stuff"
        try:
            self._add_moin_page(pagename, pagetext)
        except urllib2.HTTPError, e:
            if e.code != 503:
                raise

        self._login()
        url = 'http://localhost/MyWiki/%s' % (pagename)
        html = self._get_page(url)
        self.assertTrue(html.find(cgi.escape(pagetext))>=0, 'Could not find "%s\n%s"' % (cgi.escape(pagetext), html))

        url = 'http://localhost/MyWiki/%s?action=RenamePage' % (pagename)
        html = self._get_page(url)
        s = "reason for the renaming"
        self.assertTrue(html.find(s)>=0, 'Could not find "%s\n%s"' % (s, html))

        ticket = self._get_ticket(html)
        self.assertTrue(ticket != "", "Could not find ticket")

        url = "http://localhost/MyWiki/%s?action=RenamePage&ticket=%s&newpagename=%s&comment=&rename=Rename%%20Page" % (pagename, ticket, pagename)
        html = self._get_page(url)

        self.assertFalse(re.search('<blink>.*already exists', html), 'Found unescaped html tag')
        self._logout()

    def test_za_CVE_2009_1482(self):
        '''CVE-2009-1482'''
        if self.lsb_release['Release'] < 8.10:
            return self._skipped("Only applies to moin 1.7 and later")
        pagename = "TestCVE20091482"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)

        self._login()
        url = 'http://localhost/MyWiki/%s' % (pagename)
        data = "action=AttachFile&file=mytest.zip&rename=%22%3E%3Cblink%3EWARNING%3C/blink%3E%3Cp class=%22&do=upload"

        # First time fails as we don't actually have a file to upload
        try:
            html = self._get_page(url, data)
        except:
            pass

        html = self._get_page(url, data)
        self.assertTrue(html.find('<blink>') < 0, 'Found unescaped html tag')
        self._logout()

    def test_za_CVE_2010_0668(self):
        '''CVE-2010-0668'''
        # enable mail for subscriptions
        subprocess.call(['sed', '-i', 's/^\\(\s*\\)#mail_smarthost = .*/\\1mail_smarthost = "127.0.0.1"/g', self.farmconfig])
        subprocess.call(['sed', '-i', 's/^\\(\s*\\)#mail_from = .*/\\1mail_from = u"mywiki@localhost.localdomain"/g', self.farmconfig])

        print ""
        base = "http://localhost/MyWiki"

        # login as admin for these tests
        self._logout()
        self._login(self.adminuser, self.adminpasswd)

        print " AttachFile"
        html = self._get_page("%s/FrontPage?action=AttachFile" % (base))
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")

        html = self._get_page("%s/FrontPage?action=AttachFile&file=mytest.zip&do=upload" % (base))
        search = "Please use the interactive user interface"
        self.assertTrue(html.find(search) >=0, "Could not find '%s' in\n%s" % (search, html))

        print " Despam"
        pagename = "TestPage" # this page gets deleted
        if self.lsb_release['Release'] >= 8.10:
            if self.lsb_release['Release'] == 8.10:
                url = "%s?action=Despam&editor=('interwiki'%%2C+('Self'%%2C+u'%s'))" % (pagename, self.adminuser)
            else:
                url = "%s?action=Despam&editor=('interwiki'%%2C+(u'Self'%%2C+u'%s'))" % (pagename, self.adminuser)
        else:
            if self.lsb_release['Release'] == 6.06:
                url = '%s?action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent+nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>' % (pagename, self.user, self.user, self.user, self.user)
            else:
                url = '%s?action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>' % (pagename, self.user, self.user, self.user, self.user)
        html = self._get_page("%s/%s" % (base, url))
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket in %s/%s:\n%s" % (base, url, html))
        ticket = self._get_ticket(html)

        url = "TestPage"
        if self.lsb_release['Release'] >= 8.10:
            if self.lsb_release['Release'] == 8.10:
                data = "action=Despam&editor=%%28%%27interwiki%%27%%2C%%20%%28%%27Self%%27%%2C%%20u%%27%s%%27%%29%%29&ok=Revert%%20all!" % (self.user)
            else:
                data = "action=Despam&editor=%%28%%27interwiki%%27%%2C%%20%%28u%%27Self%%27%%2C%%20u%%27%s%%27%%29%%29&ok=Revert%%20all!" % (self.user)
        else:
            url = "TestPage"
            if self.lsb_release['Release'] == 6.06:
                data = "action=Despam&editor=%%3Cspan%%20title%%3D%%22%s%%20%%40%%20localhost%%5B127.0.0.1%%5D%%22%%3E%%3Ca%%20class%%3D%%22nonexistent%%20nonexistent%%22%%20href%%3D%%22/MyWiki/%s%%22%%20title%%3D%%22%s%%20%%40%%20localhost%%5B127.0.0.1%%5D%%22%%3E%s%%3C/a%%3E%%3C/span%%3E&ok=Revert%%20all!" % (self.user, self.user, self.user, self.user)
            else:
                data = "action=Despam&editor=%%3Cspan%%20title%%3D%%22%s%%20%%40%%20localhost%%5B127.0.0.1%%5D%%22%%3E%%3Ca%%20class%%3D%%22nonexistent%%22%%20href%%3D%%22/MyWiki/%s%%22%%20title%%3D%%22%s%%20%%40%%20localhost%%5B127.0.0.1%%5D%%22%%3E%s%%3C/a%%3E%%3C/span%%3E&ok=Revert%%20all!" % (self.user, self.user, self.user, self.user)
        # enforce ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Begin reverting") >=0, "Did not require ticket")
        # uses ticket successfully
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertTrue(html.find("Begin reverting") >=0, "Did not use ticket" + html)

        self._logout()


        print " New account"
        username = "cve20100668"
        password = "moinPassword"
        email = "%s@example.com" % username
        if self.lsb_release['Release'] >= 8.10:
            url = 'FrontPage?action=newaccount'
            if self.lsb_release['Release'] == 8.10:
                data = 'action=newaccount&name=%s&password1=%s&password2=%s&email=%s&create_only=Create%%20Profile' % (username, password, password, email)
            else:
                data = 'action=newaccount&name=%s&password1=%s&password2=%s&email=%s&create=Create%%20Profile' % (username, password, password, email)
        else:
            url = 'UserPreferences'
            data = 'action=userform&name=%s&password=%s&password2=%s&email=%s&create=Create%%20Profile' % (username, password, password, email)
        html = self._get_page("%s/%s" % (base, url))
        s = 'Login</a>'
        self.assertTrue(html.find(s) >=0, "Could not find '%s'" % (s))
        # has ticket
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        # enforces ticket
        html = self._get_page("%s/%s" % (base, url), data)
        if self.lsb_release['Release'] >= 8.10:
            # 8.10 and higher simply doesn't create the user
            url2 = 'FrontPage'
            data2 = "action=login&name=%s&password=%s&login=Login" % (username, password)
            html = self._get_page("%s/%s" % (base, url2), data2)
            s = 'Login</a>'
            self.assertTrue(html.find(s) >=0, "Login successful (Could not find '%s'" % (s))
            time.sleep(1)
            self._logout()
            self._login(self.adminuser, self.adminpasswd)
        else:
            self.assertTrue(html.find("Please use interactive interface") >=0, "Did not require ticket")
        # uses ticket successfully
        html = self._get_page("%s/%s" % (base, url))
        ticket = self._get_ticket(html)
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Please use interactive interface") >=0, "Did not use ticket")
        s = "This user name already belongs to somebody else"
        self.assertTrue(html.find(s)<0, 'Found "%s"' % (s))
        s = "User account created"
        self.assertTrue(html.find(s) >=0, "Create account unsuccessful (could not find '%s'" % (s))


        if self.lsb_release['Release'] >= 8.10:
            print " SyncPages"
            html = self._get_page("%s/FrontPage?action=SyncPages" % (base))
            self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        else:
            print " SyncPages (skipped for moin 1.5)"

        print " Change Password"
        if self.lsb_release['Release'] >= 8.10:
            url = "SystemAdmin?action=userprefs&sub=changepass"
            data = "action=userprefs&password1=%s&password2=%s&save=Change%%20password" % (self.adminpasswd, self.adminpasswd)
        else:
            url = 'UserPreferences'
            data = "action=userform&name=%s&aliasname=bar&password=%s&password2=%s&email=&css_url=&edit_rows=20&theme_name=modern&editor_default=text&editor_ui=freechoice&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&save=Save" % (self.adminuser, self.adminpasswd, self.adminpasswd)
        # has ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        # enforces ticket
        inverted = False
        if self.lsb_release['Release'] >= 8.10:
            url = "SystemAdmin"
            inverted = True
        html = self._get_page("%s/%s" % (base, url), data)
        s = "Please use interactive interface"
        if self.lsb_release['Release'] >= 8.10:
            s = "password has been changed"
        self.assertTrue(html.find(s) >=0 or inverted, "Could not find '%s' (inverted=%s) in\n%s" % (s, str(inverted), html))
        # uses ticket successfully
        html = self._get_page("%s/%s" % (base, url))
        ticket = self._get_ticket(html)
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Please use interactive interface") >=0, "Did not use ticket")


        print " Subscriptions"
        self._logout()
        self._login(self.adminuser, self.adminpasswd)
        subpage = "FooBar"
        if self.lsb_release['Release'] >= 10.04:
            url = '%s/%s?action=userprefs&sub=notification' % (base, self.adminuser)
            data = 'action=userprefs&handler=notification&subscribe%%3Aemail%%3APageDeletedEvent=on&subscribe%%3Aemail%%3APageCopiedEvent=on&subscribe%%3Aemail%%3APageChangedEvent=on&subscribe%%3Aemail%%3AFileAttachedEvent=on&subscribe%%3Aemail%%3APageRevertedEvent=on&subscribe%%3Aemail%%3APageRenamedEvent=on&subscribed_pages=%s&save=Save&action=userprefs&handler=prefs' % (subpage)
        elif self.lsb_release['Release'] >= 8.10:
            url = '%s/%s?action=userprefs&sub=notification' % (base, self.adminuser)
            data = 'action=userprefs&handler=prefs&name=%s&aliasname=&email=&jid=&css_url=&edit_rows=20&theme_name=modern&datetime_fmt=&language=&wikiname_add_spaces=&remember_last_visit=&edit_on_double_click=&mailto_author=&remember_me=1&show_comments=1&show_toolbar=1&show_page_trail=1&show_nonexist_qm=1&show_topbottom=&quicklinks=&subscribed_pages=%s&save=Save' % (self.adminuser, subpage)
        else:
            url = 'UserPreferences'
            data = "action=userform&handler=prefs&name=%s&aliasname=bar&password=&password2=&email=&css_url=&edit_rows=20&theme_name=modern&editor_default=text&editor_ui=freechoice&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&subscribed_pages=%s&save=Save" % (self.adminuser, subpage)
        html = self._get_page("%s/%s" % (base, url))
        s = 'Subscribed wiki pages'
        self.assertTrue(html.find(s) >=0, "Could not find '%s' in\n%s" % (s, html))
        # has ticket
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        # enforces ticket
        inverted = False
        if self.lsb_release['Release'] >= 8.10:
            url = "FrontPage"
            inverted = True
        html = self._get_page("%s/%s" % (base, url), data)
        s = "Please use interactive interface"
        if self.lsb_release['Release'] >= 8.10:
            s = "settings saved"
        self.assertTrue(html.find(s) >=0 or inverted, "Could not find '%s' (inverted=%s)in\n%s" % (s, str(inverted), html))
        # uses ticket successfully
        html = self._get_page("%s/%s" % (base, url))
        ticket = self._get_ticket(html)
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Please use interactive interface") >=0, "Did not use ticket")


        print " Preferences (change email)"
        email = "%s_alt@example.com" % self.adminuser
        if self.lsb_release['Release'] >= 10.04:
            url = '/%s?action=userprefs&sub=prefs' % (self.adminuser)
            data = 'action=userprefs&handler=prefs&name=%s&aliasname=&email=%s&jid=&css_url=&edit_rows=20&theme_name=modern&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&quicklinks=&save=Save&action=userprefs&handler=prefs' % (self.adminuser, email)
        elif self.lsb_release['Release'] >= 8.10:
            url = 'FrontPage?action=userprefs&sub=prefs'
            data = 'action=userprefs&handler=prefs&name=%s&aliasname=&email=%s&jid=&css_url=&edit_rows=20&theme_name=modern&datetime_fmt=&language=&wikiname_add_spaces=&remember_last_visit=&edit_on_double_click=&mailto_author=&remember_me=1&show_comments=1&show_toolbar=1&show_page_trail=1&show_nonexist_qm=1&show_topbottom=&quicklinks=&save=Save' % (self.adminuser, email)
        else:
            url = 'UserPreferences'
            data = "action=userform&name=%s&aliasname=bar&password=&password2=&email=%s&css_url=&edit_rows=20&theme_name=modern&editor_default=text&editor_ui=freechoice&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&&save=Save" % (self.adminuser, email)
        html = self._get_page("%s/%s" % (base, url))
        # has ticket
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        # enforces ticket
        inverted = False
        if self.lsb_release['Release'] >= 8.10:
            inverted = True
        if self.lsb_release['Release'] < 10.04:
            html = self._get_page("%s/%s" % (base, url), data)
            s = "Please use interactive interface"
            if self.lsb_release['Release'] >= 8.10:
                s = "preferences saved"
            self.assertTrue(html.find(s) >=0 or inverted, "Could not find '%s' (inverted=%s)in\n%s" % (s, str(inverted), html))
        # uses ticket successfully
        html = self._get_page("%s/%s" % (base, url))
        ticket = self._get_ticket(html)
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Please use interactive interface") >=0, "Did not use ticket")


        # this should be last since it logs us in as 'foo'
        print " Select user"
        if self.lsb_release['Release'] >= 8.10:
            url = 'SystemAdmin?sysadm=users'
            data = "action=userprefs&selected_user=%s&select_user=Select%%20User" % (self.user)
        else:
            url = 'UserPreferences'
            # this switches users, we need to have a ticket here
            data = "action=userform&selected_user=%s&select_user=Select%%20User" % (self.user)
        # has ticket
        html = self._get_page("%s/%s" % (base, url))
        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket")
        # enforces ticket
        inverted = False
        if self.lsb_release['Release'] >= 8.10:
            url = "FrontPage"
            inverted = True
        html = self._get_page("%s/%s" % (base, url), data)
        s = "Please use interactive interface"
        if self.lsb_release['Release'] >= 8.10:
            s = "change the settings of the selected user account"
        self.assertTrue(html.find(s) >=0 or inverted, "Could not find '%s' (inverted=%s)in\n%s" % (s, str(inverted), html))
        # uses ticket successfully
        html = self._get_page("%s/%s" % (base, url))
        ticket = self._get_ticket(html)
        data += "&ticket=%s" % ticket
        html = self._get_page("%s/%s" % (base, url), data)
        self.assertFalse(html.find("Please use interactive interface") >=0, "Did not use ticket")

    def test_za_CVE_2010_0828(self):
        '''CVE-2010-0828'''
        base = "http://localhost/MyWiki"

        self._logout()
        self._login(self.user, self.passwd)
        pagename = "TestXSS0828<blink>gotcha</blink>"
        pagetext = "%s stuff" % (pagename)
        self._add_moin_page(pagename, pagetext)

        # login as admin for these tests
        self._logout()
        self._login(self.adminuser, self.adminpasswd)

        # get ticket
        if self.lsb_release['Release'] >= 8.10:
            if self.lsb_release['Release'] == 8.10:
                url = "%s?action=Despam&editor=('interwiki'%%2C+('Self'%%2C+u'%s'))" % ("FrontPage", self.user)
            else:
                url = "%s?action=Despam&editor=('interwiki'%%2C+(u'Self'%%2C+u'%s'))" % ("FrontPage", self.user)
        else:
            if self.lsb_release['Release'] == 6.06:
                url = '%s?action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent+nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>' % ("FrontPage", self.user, self.user, self.user, self.user)
            else:
                url = '%s?action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>' % ("FrontPage", self.user, self.user, self.user, self.user)
        html = self._get_page("%s/%s" % (base, url))
        s = "TestXSS0828"
        self.assertTrue(html.find(s) >=0, "Could not find '%s' in:\n%s" % (s, html))

        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket in %s/%s:\n%s" % (base, url, html))
        ticket = self._get_ticket(html)


        self.assertTrue(self._get_ticket(html) != "", "Could not find ticket in %s/%s:\n%s" % (base, url, html))
        ticket = self._get_ticket(html)

        if self.lsb_release['Release'] >= 8.10:
            if self.lsb_release['Release'] == 8.10:
                url = "FrontPage"
                data = "action=Despam&editor=('interwiki'%%2C+('Self'%%2C+u'%s'))&ok=Revert%%20all%%21" % (self.user)
            else:
                url = "FrontPage"
                data = "action=Despam&editor=('interwiki'%%2C+(u'Self'%%2C+u'%s'))&ok=Revert%%20all%%21" % (self.user)
        else:
            if self.lsb_release['Release'] == 6.06:
                url = "FrontPage"
                data = 'action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent+nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>&ok=Revert%%20all%%21' % (self.user, self.user, self.user, self.user)
            else:
                url = "FrontPage"
                data = 'action=Despam&editor=<span+title%%3D"%s+%%40+localhost[127.0.0.1]"><a+class%%3D"nonexistent"+href%%3D"/MyWiki/%s"+title%%3D"%s+%%40+localhost[127.0.0.1]">%s</a></span>&ok=Revert%%20all%%21' % (self.user, self.user, self.user, self.user)
        if ticket != "":
            data += "&ticket=%s" % (ticket)

        html = self._get_page("%s/%s" % (base, url), data)
        s = "Pages to revert"
        self.assertTrue(html.find(s) >=0, "Could not find '%s' in:\n%s" % (s, html))
        s = "<blink>"
        self.assertFalse(html.find(s) >=0, "Found '%s' in:\n%s" % (s, html))

    def test_za_CVE_2010_1238(self):
        '''CVE-2010-1238'''
        if self.lsb_release['Release'] >= 8.10:
            return self._skipped("TODO")
        else:
            return self._skipped("textcha not available in moin 1.5")

    def test_za_CVE_2009_4762(self):
        '''CVE-2009-4762'''
        if self.lsb_release['Release'] < 9.04:
            return self._skipped("hierarchical ACLs not available in moin < 1.6.0")
        # create a top level page with permissive acls
        pagename = "TestTopAclPage"
        pagetext = '''#acl All:read,write
TestTopAclPage stuff'''
        self._add_moin_page(pagename, pagetext, self.adminuser, self.adminpasswd)
        time.sleep(3)

        # create a second level page with acls
        pagename = "TestTopAclPage/TestSecondAclPage"
        pagetext = '''#acl adminuser:read,write
secondacl stuff'''
        self._add_moin_page(pagename, pagetext, self.adminuser, self.adminpasswd)
        time.sleep(3)

        # try to access the page as regular user
        self._login()
        try:
            html = self._get_page("http://localhost/MyWiki/%s" % pagename)
        except urllib2.HTTPError, e:
            if e.code == 403:
                return
            raise
        # We shouldn't get here
        self._logout()
        self.fail("Error: could read page protected by ACLs")

    def test_za_CVE_2012_4404(self):
        '''CVE-2012-4404'''

        # create a new group called 'AllGroup'
        pagename = "AllGroup"
        pagetext = '''#format wiki
This is an example Group
 * BlahUser'''
        self._add_moin_page(pagename, pagetext, self.adminuser, self.adminpasswd, check=False)
        time.sleep(3)

        # create a top level page with restricted acls
        pagename = "TestTopGroupPage"
        pagetext = '''#acl AllGroup:read,write
TestTopGroupPage stuff'''
        self._add_moin_page(pagename, pagetext, self.adminuser, self.adminpasswd)
        time.sleep(3)

        # try to access the page as regular user
        self._login()
        try:
            html = self._get_page("http://localhost/MyWiki/%s" % pagename)
        except urllib2.HTTPError, e:
            if e.code == 403:
                return
            raise
        # We shouldn't get here
        self._logout()
        self.fail("Error: could read page protected by ACLs")


    def test_zz_finished(self):
        '''Shutdown'''
        #subprocess.call(['bash'])
        self.onetime_tearDown()
        subprocess.call(['/etc/init.d/apache2', 'stop'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertTrue(subprocess.call(['/etc/init.d/apache2', 'restart'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0)

if __name__ == '__main__':
    unittest.main()
