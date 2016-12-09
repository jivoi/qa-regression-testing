#!/usr/bin/python
#
#    test-django.py quality assurance test script for python-django
#    Copyright (C) 2010-2016 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Seth Arnold <seth.arnold@canonical.com>
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
# QRT-Packages: libapache2-mod-wsgi libapache2-mod-python python-django python-django-doc elinks python-pexpect
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: apache2:!precise apache2-mpm-prefork:precise
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py django
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-PKG.py -v'

    TODO:
    - database connectivity (http://www.howtoforge.com/installing-django-on-debian-etch-apache2-mod_python)
    - csrf in 1.1 and 1.2 (http://docs.djangoproject.com/en/dev/ref/contrib/csrf/ (all the MIDDLEWARE stuff should be in settings.py))
    - django-admin stuff (eg PYTHONPATH=$PYTHONPATH:/tmp/foo DJANGO_SETTINGS_MODULE=settings django-admin validate)
    - go through other tutorials:
      http://docs.djangoproject.com/en/1.2/intro/tutorial01/ (mostly done)
      http://docs.djangoproject.com/en/1.2/intro/tutorial02/ (mostly done)
      http://docs.djangoproject.com/en/1.2/intro/tutorial03/
    - lots more
'''

import unittest, subprocess, sys, os
import pexpect
import socket
import tempfile
import testlib
import testlib_httpd
import time
import urllib2

try:
    from private.qrt.Django import PrivateDjangoTest
except ImportError:
    class PrivateDjangoTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class DjangoTest(testlib_httpd.HttpdCommon, PrivateDjangoTest):
    '''Test django'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

        self.current_dir = os.getcwd()

        if self.lsb_release['Release'] < 14.04:
            self._disable_mod("wsgi")
            self._enable_mod("python")
        else:
            self._disable_mod("python")
            self._enable_mod("wsgi")

        if self.lsb_release['Release'] < 14.04:
            self.apache_site = "/etc/apache2/sites-available/testlib_django"
        else:
            self.apache_site = "/etc/apache2/sites-available/testlib_django.conf"

        self.apache_site_name = "testlib_django"
        self.base_url = "http://localhost"
        self.tmpdir = ""
        self.django_project_topdir = ""
        self.django_project_manage_dir = ""
        self.django_project_dir = ""

        self.static_alias = "/static/"
        self.static_alias_dir = "/usr/share/pyshared/django/contrib/admin/static/"
        if self.lsb_release['Release'] == 10.04:
            self.static_alias = "/media/"
            self.static_alias_dir = "/usr/share/pyshared/django/contrib/admin/media/"
        elif self.lsb_release['Release'] == 12.04:
            self.static_alias = "/static/admin/"
            self.static_alias_dir = "/usr/share/pyshared/django/contrib/admin/media/"

    def tearDown(self):
        '''Clean up after each test_* function'''

        os.chdir(self.current_dir)

        if os.path.exists(self.apache_site):
            self._disable_site(self.apache_site_name)
            os.unlink(self.apache_site)

        self._tearDown()

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _add_site(self, filename, name, contents):
        '''Add site to apache'''
        testlib.create_fill(filename, contents, mode=0644)
        if self.lsb_release['Release'] >= 14.04:
            self._disable_site('000-default')
        else:
            self._disable_site('default')
        self._enable_site(name)

    def _fetch_page(self, url, data=None, initial_setup=False):
        '''GET/POST to a page. If data=None, it is a GET, otherwise a POST.'''
        headers = {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
        try:
            if data == None:
                req = urllib2.Request(url, headers=headers)
            else:
                req = urllib2.Request(url, data=data, headers=headers)
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

        try:
            html = handle.read()
        except:
            raise

        return html

    def _set_paths(self):
        '''Setup paths for projects'''
        self.django_project_topdir = os.path.join(self.tmpdir,
                                                  self.apache_site_name)
        self.django_project_dir = self.django_project_topdir
        self.django_project_manage_dir = self.django_project_dir
        if self.lsb_release['Release'] >= 14.04:
            # django 1.4 uses a different hierarchy
            self.django_project_topdir = os.path.join(self.tmpdir, self.apache_site_name)
            self.django_project_dir = os.path.join(self.django_project_topdir,
                                                   self.apache_site_name)
            self.django_project_manage_dir = self.django_project_topdir


    def _add_project(self, verbose=False):
        '''Add a project'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)

        self._set_paths()

        if verbose:
            print "  django-admin (startproject)"
        os.chdir(self.tmpdir)
        rc, report = testlib.cmd(['django-admin', 'startproject', self.apache_site_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(self.current_dir)

        pypath = self.tmpdir
        if self.lsb_release['Release'] >= 14.04:
            pypath = self.django_project_topdir

        # https://docs.djangoproject.com/en/1.3/howto/deployment/modpython/

        contents = ''

        contents_modpython = '''
Alias %s "%s"
<Location "/%s/">
    SetHandler python-program
    PythonHandler django.core.handlers.modpython
    SetEnv DJANGO_SETTINGS_MODULE %s.settings
    PythonOption django.root /%s
    PythonDebug On
    PythonPath "['%s'] + sys.path"
</Location>
''' % (self.static_alias,
       self.static_alias_dir,
       self.apache_site_name,
       self.apache_site_name,
       self.apache_site_name,
       pypath)

        contents_wsgi = '''WSGIScriptAlias /%s %s/wsgi.py
WSGIPythonPath %s

Alias %s "%s"

<Directory %s>
Require all granted
</Directory>

<Directory %s>
<Files wsgi.py>
Require all granted
</Files>
</Directory>
''' % (self.apache_site_name,
       self.django_project_dir,
       self.django_project_topdir,
       self.static_alias,
       self.static_alias_dir,
       self.static_alias_dir,
       self.django_project_dir)

        if self.lsb_release['Release'] < 14.04:
            contents = contents_modpython
        else:
            contents = contents_wsgi

        self._add_site(self.apache_site, self.apache_site_name, contents)
        self._test_url("%s/" % self.base_url, "ERROR", invert=True)

        # Not sure what we're trying to test here, but it doesn't work
        # on 14.04+
        if self.lsb_release['Release'] < 14.04:
            url = "/%s/" % self.apache_site_name
            search = "It worked"
            if verbose:
                print "  %s (%s)" % (url, search)
            self._test_url("%s%s" % (self.base_url, url), "It worked")

        settings = os.path.join(self.django_project_dir, "settings.py")
        sqlite3 = os.path.join(self.django_project_dir, "db.sqlite3")
        if self.lsb_release['Release'] >= 14.04:
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),#\\1'NAME': '%s',#g" % sqlite3, settings])
        elif self.lsb_release['Release'] == 12.04:
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'ENGINE': 'django.db.backends.',#\\1'ENGINE': 'django.db.backends.sqlite3',#g", settings])
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'NAME': '',#\\1'NAME': '%s',#g" % sqlite3, settings])
        else:
            subprocess.call(['sed', '-i', "s#^DATABASE_ENGINE = ''#DATABASE_ENGINE = 'sqlite3'#g", settings])
            subprocess.call(['sed', '-i', "s#^DATABASE_NAME = ''#DATABASE_NAME = '%s'#g" % sqlite3, settings])

        os.chdir(self.django_project_manage_dir)
        if verbose:
            print "  sync database"
        child = pexpect.spawn('python ./manage.py syncdb')
        report = ""
        child.expect('.*ould you like to create one now.*:', timeout=10)
        child.sendline('no')
        report += child.before + child.after
        child.expect(pexpect.EOF, timeout=None)
        report += child.before
        child.kill(0)

        # Now add a superuser
        self._add_superuser()

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if self.lsb_release['Release'] >= 15.04:
            for search in ['Running migrations']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)
        else:
            for search in ['Creating table', 'Installing index']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)

        self.assertTrue(os.path.exists(sqlite3), "'%s' does not exist" % (sqlite3))

        # Needed for database changes via web forms
        testlib.cmd(['chown', 'www-data:www-data', sqlite3])
        testlib.cmd(['chown', 'www-data:www-data', os.path.dirname(sqlite3)])

        os.chdir(self.current_dir)

    def _add_app(self, name="testme", verbose=False):
        '''Add app with name'''
        os.chdir(self.django_project_manage_dir)
        project = os.path.basename(self.django_project_topdir)

        if verbose:
            print "  startapp"
        rc, report = testlib.cmd(['python', './manage.py', 'startapp', name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # update the urls.py for index
        urls = os.path.join(self.django_project_dir, "urls.py")
        pats = '%s.%s' % (project, name)
        if self.lsb_release['Release'] >= 14.04:
            pats = name
        if self.lsb_release['Release'] < 16.04:
            subprocess.call(['sed', '-i', "s#patterns('',#patterns('%s',#g" % (pats), urls])
            subprocess.call(['sed', '-i', "s#^)#    url(r'^%s/$', 'views.index'),\\n)#g" % name, urls])
            subprocess.call(['sed', '-i', "s#^)#    url(r'^%s/404$', 'views.test404'),\\n)#g" % name, urls])
        else:
            #subprocess.call(['sed', '-i', "s#patterns('',#patterns('%s',#g" % (pats), urls])
            subprocess.call(['sed', '-i', "s#^]#    url(r'^%s/$', '%s.views.index'),\\n]#g" % (name, name), urls])
            subprocess.call(['sed', '-i', "s#^]#    url(r'^%s/404$', '%s.views.test404'),\\n]#g" % (name, name), urls])

        # Make sure python gets regenerated
        if os.path.exists(urls + "c"):
            os.unlink(urls + "c")

        # update the view.py for index
        views = os.path.join(self.django_project_topdir, name, "views.py")
        index_str = "Hello, world. You're at the %s index." % name
        contents = '''
from django.http import HttpResponse
from django.http import Http404

def index(request):
    return HttpResponse("%s")

def test404(request):
    raise Http404
''' % index_str
        open(views, 'w').write(contents)
        self._reload()

        url = "/%s/nonexistent" % self.apache_site_name
        search = "Page not found"
        if verbose:
            print "  %s (%s)" % (url, search)
        self._test_url("%s%s" % (self.base_url, url), search)

        url = "/%s/404" % self.apache_site_name
        search = "Page not found"
        if verbose:
            print "  %s (%s)" % (url, search)
        self._test_url("%s%s" % (self.base_url, url), search)

        url = "/%s/%s/" % (self.apache_site_name, name)
        search = index_str
        if verbose:
            print "  %s (%s)" % (url, search)
        self._test_url("%s%s" % (self.base_url, url), search)

        os.chdir(self.current_dir)

    def _add_page(self, appname, pagename, contents, search):
        '''Add page to django project'''
        os.chdir(self.django_project_dir)

        # update the urls.py for pagename
        urls = os.path.join(self.django_project_dir, "urls.py")
        if self.lsb_release['Release'] < 16.04:
            subprocess.call(['sed', '-i', "s#^)#    url(r'^%s/%s/$', '%s.%s'),\\n)#g" % (appname, pagename, pagename, pagename), urls])
        else:
            subprocess.call(['sed', '-i', "s#^]#    url(r'^%s/%s/$', '%s.%s.%s'),\\n]#g" % (appname, pagename, appname, pagename, pagename), urls])

        # Make sure python gets regenerated
        os.unlink(urls + "c")

        # create the pagename
        page = os.path.join(self.django_project_topdir, appname, "%s.py" % pagename)
        open(page, 'w').write(contents)
        self._reload()

        url = "/%s/%s/%s/" % (self.apache_site_name, appname, pagename)
        print "  %s (%s)" % (url, search)
        self._test_url("%s%s" % (self.base_url, url), search)

        os.chdir(self.current_dir)

    def _add_superuser(self, username=None, email=None, password="pass"):
        '''Add superuser'''
        os.chdir(self.django_project_manage_dir)

        if not username:
            username = "ubuntu"
        if not email:
            email = "%s@%s.local" % (username, socket.gethostname())

        # Requires setting the password later
        #rc, report = testlib.cmd(['python', './manage.py', 'createsuperuser',
        #                          '--username=%s' % username,
        #                          '--email=%s' % email,
        #                          '--noinput'])

        # Hacky, but does not require setting the password later
        os.chmod('./manage.py', 0755)
        rc, report = testlib.cmd_pipe(['echo', "from django.contrib.auth.models import User; User.objects.create_superuser('%s', '%s', '%s')" % (username, email, password)],
                                      ['./manage.py', 'shell'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "User: %s" % username
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        os.chdir(self.current_dir)

    def _test_url(self, url="http://localhost/", content="", invert=False, source=False):
	'''Override what is in testlib_httpd as the first hit of an updated
           page returns an error.'''
        self._get_page(url)
        testlib_httpd.HttpdCommon._test_url(self, url=url, content=content, invert=invert, source=source)

    def test_basic(self):
        '''Test basic install'''
        # https://wiki.ubuntu.com/Django

        if testlib.dpkg_compare_installed_version('python-django', 'ge', '1.2'):
            self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
            rc, report = testlib.cmd(['tar', '-C', self.tmpdir, '-xf', './django/django-examples.tar.gz'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            # http://thecodeship.com/deployment/deploy-django-apache-virtualenv-and-mod_wsgi/
            wsgi_py='''
import os
import sys
sys.path.append('%s')
sys.path.append('%s/examples')

os.environ['DJANGO_SETTINGS_MODULE'] = 'examples.settings'

#import django.core.handlers.wsgi
#application = django.core.handlers.wsgi.WSGIHandler()
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
''' % (self.tmpdir, self.tmpdir)
            open(self.tmpdir + "/examples/wsgi.py", "w").write(wsgi_py)
            os.chmod(self.tmpdir, 0755)

        django_examples = self.tmpdir
        if os.path.exists(os.path.join(django_examples, "examples")):
            # TODO: disable the csrf protections for now. We shouldn't have
            # todo this...
            views = os.path.join(django_examples, "examples/hello/views.py")
            if os.path.exists(views):
                subprocess.call(['sed', '-i', 's/^from django.utils.html import escape/from django.utils.html import escape\\nfrom django.views.decorators.csrf import csrf_exempt/g', views])
                subprocess.call(['sed', '-i', 's/^def post_data/@csrf_exempt\\ndef post_data/g', views])
        else:
            django_examples = "/usr/share/doc/python-django-doc"

        contents = ''

        contents_modpython = '''<Location "/">
    SetHandler python-program
    PythonHandler django.core.handlers.modpython
    PythonDebug On
    PythonPath "['%s'] + sys.path"
    SetEnv DJANGO_SETTINGS_MODULE examples.settings
</Location>
''' % (django_examples)

        contents_wsgi = '''WSGIScriptAlias / %s/examples/wsgi.py
WSGIPythonPath %s/examples

<Directory %s/examples>
<Files wsgi.py>
Require all granted
</Files>
</Directory>
''' % (self.tmpdir, self.tmpdir, self.tmpdir)

        if self.lsb_release['Release'] <= 12.04:
            contents = contents_modpython
        else:
            contents = contents_wsgi

        if self.lsb_release['Release'] >= 14.04:
            subprocess.call(['sed', '-i', 's/\.defaults import \*/ import patterns, include/',
                os.path.join(django_examples, "examples/urls.py")])
            subprocess.call(['sed', '-i', 's/\.defaults import \*/ import patterns/',
                os.path.join(django_examples, "examples/hello/urls.py")])

        self._add_site(self.apache_site, self.apache_site_name, contents)
        self._test_url("%s/" % self.base_url, "ERROR", invert=True)

        urls = (
                ('/', 'Django examples'),
                ('/hello/html/', 'Hello, world.'),
                ('/hello/text/', 'Hello, world.'),
                ('/hello/write/', "Here's a paragraph."),
                ('/hello/write/', "Here's another paragraph."),
                ('/hello/metadata/', 'All about you'),
                ('/hello/metadata/', 'HTTP_HOST'),
                ('/hello/getdata/', 'First name'),
                ('/hello/getdata/?first_name=foo&last_name=bar', 'GET data found'),
                ('/hello/getdata/?first_name=foo&last_name=bar', "first_name: u'foo'"),
                ('/hello/getdata/?first_name=foo&last_name=bar', "last_name: u'bar'"),
                ('/hello/postdata/', 'First name'),
               )

        print "\nExample urls:"
        for url, search in urls:
            print "  %s (%s)" % (url, search)
            self._test_url("%s/%s" % (self.base_url, url), search)

        posturls = (
                    ('/hello/postdata/', 'action=&first_name=foo&last_name=bar', "POST data found"),
                    ('/hello/postdata/', 'action=&first_name=foo&last_name=bar', "u'foo'"),
                    ('/hello/postdata/', 'action=&first_name=foo&last_name=bar', "u'bar'"),
                   )
        for url, data, search in posturls:
            print "  %s (%s)" % (url, search)
            results = self._fetch_page("%s%s" % (self.base_url, url), data)
            self._word_find(results, search)

    def test_project(self):
        '''Test project'''
        # http://docs.djangoproject.com/en/1.2/intro/tutorial01/

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)

        self._set_paths()

        print ""
        print "  django-admin (startproject)"
        os.chdir(self.tmpdir)
        rc, report = testlib.cmd(['django-admin', 'startproject', self.apache_site_name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(self.current_dir)

        pypath = self.tmpdir
        if self.lsb_release['Release'] >= 14.04:
            pypath = self.django_project_topdir

        contents = ''

        contents_modpython = '''
Alias %s "%s"
<Location "/">
    SetHandler python-program
    PythonHandler django.core.handlers.modpython
    PythonDebug On
    SetEnv DJANGO_SETTINGS_MODULE %s.settings
    PythonPath "['%s'] + sys.path"
</Location>
''' % (self.static_alias, self.static_alias_dir, self.apache_site_name,
       pypath)

        contents_wsgi = '''WSGIScriptAlias / %s/wsgi.py
WSGIPythonPath %s

<Directory %s>
<Files wsgi.py>
Require all granted
</Files>
</Directory>
''' % (self.django_project_dir,
       self.django_project_topdir,
       self.django_project_dir)

        if self.lsb_release['Release'] <= 12.04:
            contents = contents_modpython
        else:
            contents = contents_wsgi

        self._add_site(self.apache_site, self.apache_site_name, contents)
        self._test_url("%s/" % self.base_url, "ERROR", invert=True)

        url = "/"
        search = "It worked"
        print "  %s (%s)" % (url, search)
        self._test_url("%s%s" % (self.base_url, url), "It worked")

        settings = os.path.join(self.django_project_dir, "settings.py")
        sqlite3 = os.path.join(self.django_project_dir, "db.sqlite3")

        if self.lsb_release['Release'] >= 14.04:
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),#\\1'NAME': '%s',#g" % sqlite3, settings])
        elif self.lsb_release['Release'] == 12.04:
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'ENGINE': 'django.db.backends.',#\\1'ENGINE': 'django.db.backends.sqlite3',#g", settings])
            subprocess.call(['sed', '-i', "s#^\\(\s*\\)'NAME': '',#\\1'NAME': '%s',#g" % sqlite3, settings])
        else:
            subprocess.call(['sed', '-i', "s#^DATABASE_ENGINE = ''#DATABASE_ENGINE = 'sqlite3'#g", settings])
            subprocess.call(['sed', '-i', "s#^DATABASE_NAME = ''#DATABASE_NAME = '%s'#g" % sqlite3, settings])

        os.chdir(self.django_project_manage_dir)

        print "  create database"
        if self.lsb_release['Release'] < 15.04:
            child = pexpect.spawn('python ./manage.py syncdb')
            report = ""
            child.expect('.*ould you like to create one now.*:', timeout=10)
            child.sendline('no')
            report += child.before + child.after
            child.expect(pexpect.EOF, timeout=None)
            report += child.before
            child.kill(0)

            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            for search in ['Creating table', 'Installing index']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)
        else:
            rc, report = testlib.cmd(['python', './manage.py', 'migrate'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            for search in ['Running migrations']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)

        self.assertTrue(os.path.exists(sqlite3), "'%s' does not exist" % (sqlite3))
        # Needed for database changes via web forms
        testlib.cmd(['chown', 'www-data:www-data', sqlite3])
        testlib.cmd(['chown', 'www-data:www-data', os.path.dirname(sqlite3)])

        print "  startapp"
        appname = "polls"
        rc, report = testlib.cmd(['python', './manage.py', 'startapp', appname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  create sql model"
        models = os.path.join(self.django_project_topdir, appname, "models.py")
        contents = '''from django.db import models

class Poll(models.Model):
    question = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

class Choice(models.Model):
    poll = models.ForeignKey(Poll)
    choice = models.CharField(max_length=200)
    votes = models.IntegerField()

'''
        testlib.create_fill(models, contents, mode=0644)
        subprocess.call(['sed', '-i', "s#^INSTALLED_APPS = (#INSTALLED_APPS = (\\n    'polls',#g", settings])
        # remove settings.pyc so it gets updated after the above change. For
        # some reason, even a sleep for a couple of seconds isn't good enough
        # and we would get races.
        os.unlink(settings + "c")

        if self.lsb_release['Release'] < 15.04:
            print "  manage.py sql"
            rc, report = testlib.cmd(['python', './manage.py', 'sql', appname])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            for search in ['polls_poll', 'question', 'pub_date', 'choice', 'votes']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)

            # FIXME: This doesn't actually do anything, why is it here?
            #for cmd in ['validate', 'sqlcustom', 'sqlclear', 'sqlindexes', 'sqlall']:
            #    print "  manage.py %s" % cmd
            #    rc, report = testlib.cmd(['python', './manage.py', 'sql', appname])
            #    expected = 0
            #    result = 'Got exit code %d, expected %d\n' % (rc, expected)
            #    self.assertEquals(expected, rc, result + report)
        else:
            print "  manage.py makemigrations"
            rc, report = testlib.cmd(['python', './manage.py', 'makemigrations', appname])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            for search in ['Create model Choice', 'Create model Poll',
                           'Add field poll']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)

        print "  update database"
        if self.lsb_release['Release'] < 15.04:
            rc, report = testlib.cmd(['python', './manage.py', 'syncdb'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            terms = ['Creating table polls_poll', 'Creating table polls_choice']
            if self.lsb_release['Release'] == 10.04:
                terms.append('Installing index for polls.Choice model')
            else:
                terms.append('Installing index')

            for search in terms:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)
        else:
            rc, report = testlib.cmd(['python', './manage.py', 'migrate'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            for search in ['Running migrations']:
                result = 'Could not find "%s"\n' % search
                self.assertTrue(search in report, result + report)

        self.assertTrue(os.path.exists(sqlite3), "'%s' does not exist" % (sqlite3))
        # Needed for database changes via web forms
        testlib.cmd(['chown', 'www-data:www-data', sqlite3])
        testlib.cmd(['chown', 'www-data:www-data', os.path.dirname(sqlite3)])

        os.chdir(self.current_dir)

    def test_simple(self):
        '''Test simple site'''
        print ""
        self._add_project(verbose=True)
        appname = "mycoolapp"
        self._add_app(name=appname, verbose=True)

        pagename = "foo"
        search = "I added a page!"
        contents = '''
from django.http import HttpResponse
def %s(request):
    return HttpResponse("%s")
''' % (pagename, search)
        self._add_page(appname, pagename, contents, search)

        os.chdir(self.current_dir)

    def test_admin(self):
        '''Test admin page'''
        # https://docs.djangoproject.com/en/1.3/intro/tutorial02/
        print ""
        self._add_project(verbose=True)
        self._add_app(verbose=True)

        if self.lsb_release['Release'] < 15.04:
            settings = os.path.join(self.django_project_dir, "settings.py")
            subprocess.call(['sed', '-i', "s#^INSTALLED_APPS = (#INSTALLED_APPS = (\\n    'django.contrib.admin',#g", settings])
            # remove settings.pyc so it gets updated after the above change. For
            # some reason, even a sleep for a couple of seconds isn't good enough
            # and we would get races.
            os.unlink(settings + "c")

            os.chdir(self.django_project_manage_dir)
            print "  update database"
            rc, report = testlib.cmd(['python', './manage.py', 'syncdb'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # update the urls.py for index
            urls = os.path.join(self.django_project_dir, "urls.py")
            subprocess.call(['sed', '-i', "s#^urlpatterns\\(.*\\)#from django.contrib import admin\\nadmin.autodiscover()\\n\\nurlpatterns\\1#g", urls])
            subprocess.call(['sed', '-i', "s#^)#    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),\\n)#g", urls])
            subprocess.call(['sed', '-i', "s#^)#    url(r'^admin/', include(admin.site.urls)),\\n)#g", urls])
            if self.lsb_release['Release'] >= 14.04:
                subprocess.call(['sed', '-i', "s#^)#)\\nurlpatterns += patterns('',\\n    url(r'^admin/password_reset/$', 'django.contrib.auth.views.password_reset', name='admin_password_reset'),\\n    (r'^admin/password_reset/done/$', 'django.contrib.auth.views.password_reset_done'),\\n    (r'^reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$', 'django.contrib.auth.views.password_reset_confirm'),\\n    (r'^reset/done/$', 'django.contrib.auth.views.password_reset_complete'),\\n)#g", urls])

            # Make sure python gets regenerated
            os.unlink(urls + "c")
            self._reload()

	# For now, just this since we need to add an admin username/password to
        # the db in _add_project()
        terms = ['Django administration', 'Username', 'Password']
        if self.lsb_release['Release'] in [14.04, 14.10]:
            terms.append("Forgotten your password or username")

        for i in terms:
            print "  searching for '%s'" % i
            self._test_url("%s/%s/admin/" % (self.base_url, self.apache_site_name), i)
            if self.lsb_release['Release'] < 15.04:
                self._test_url("%s/%s/admin/doc/" % (self.base_url, self.apache_site_name), i)

        os.chdir(self.current_dir)

    def _run_tests_on_session_page(self, appname, pagename="sessiontest"):
        '''Add a session test page'''
        search = "POST:"
        contents = '''
from django import http
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def %s(request):
    response = 'POST:<table>'
    for k,v in request.POST.items():
        response += '<tr><td>%%s</td><td>%%s</td></tr>' %% (k, v)
    response += '</table>'

    response += 'Session:<table>'
    for k,v in request.session._session.items():
        response += '<tr><td>%%s</td><td>%%s</td></tr>' %% (k, v)
    response += '</table>'

    response += ' <form method="post" action=""> <input type="text" name="new_key" /> <input type="text" name="new_value" /> <input type="submit" /> </form>'

    new_key = request.POST.get('new_key', False)
    new_value = request.POST.get('new_value', False)

    if new_key and new_value:
        request.session[new_key] = new_value

    return http.HttpResponse(response)
''' % (pagename)

        self._add_page(appname, pagename, contents, search)

        url = "/%s/%s/%s/" % (self.apache_site_name, appname, pagename)
        terms = ['somekey', 'somevalue']
        print "  %s (%s)" % (url, ",".join(terms))
        results = self._fetch_page("%s%s" % (self.base_url, url), 'new_key=somekey&new_value=somevalue')
        for search in terms:
            self._word_find(results, search)

    def test_cached_sessions_db(self):
        '''Test database backed cached session'''
        # https://docs.djangoproject.com/en/dev/topics/http/sessions/
        # https://docs.djangoproject.com/en/dev/topics/cache/

        if testlib.dpkg_compare_installed_version('python-django', 'lt', '1.2'):
            return self._skipped("TODO: cache tests on django 1.1")

        # first create a project (which uses a database backed session)
        self._add_project()

        # now add an app to it
        appname = "mycoolsessiontest"
        # http://localhost/testlib_django/<appname>/
        self._add_app(name=appname)

        os.chdir(self.django_project_manage_dir)

        print ""
        print "  createcachetable"
        db_table = "testlib-session-cachetable"
        rc, report = testlib.cmd(['python', './manage.py', 'createcachetable', db_table])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        settings = os.path.join(self.django_project_dir, "settings.py")
        contents = '''
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': '%s',
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
''' % db_table
        contents = file(settings).read() + contents
        open(settings, 'w').write(contents)
        testlib.config_replace(settings, contents, append=True)
        # remove settings.pyc so it gets updated after the above change. For
        # some reason, even a sleep for a couple of seconds isn't good enough
        # and we would get races.
        os.unlink(settings + "c")

        print "  update database"
        rc, report = testlib.cmd(['python', './manage.py', 'syncdb'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._run_tests_on_session_page(appname)

        os.chdir(self.current_dir)

    def test_cached_sessions_file(self):
        '''Test file backed cached session'''
        # https://docs.djangoproject.com/en/dev/topics/http/sessions/
        # https://docs.djangoproject.com/en/dev/topics/cache/

        if testlib.dpkg_compare_installed_version('python-django', 'lt', '1.2'):
            return self._skipped("TODO: cache tests on django 1.1")

        # first create a project (which uses a database backed session)
        self._add_project()

        # now add an app to it
        appname = "mycoolsessiontest"
        # http://localhost/testlib_django/<appname>/
        self._add_app(name=appname)

        db_cache = os.path.join(self.tmpdir, 'cache')
        os.mkdir(db_cache)
        testlib.cmd(['chown', 'www-data:www-data', db_cache])

        settings = os.path.join(self.django_project_dir, "settings.py")
        contents = '''
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '%s',
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
''' % (os.path.join(self.tmpdir, 'cache'))
        contents = file(settings).read() + contents
        open(settings, 'w').write(contents)
        testlib.config_replace(settings, contents, append=True)
        # remove settings.pyc so it gets updated after the above change. For
        # some reason, even a sleep for a couple of seconds isn't good enough
        # and we would get races.
        os.unlink(settings + "c")

        os.chdir(self.django_project_manage_dir)

        print ""
        print "  update database"
        rc, report = testlib.cmd(['python', './manage.py', 'syncdb'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._run_tests_on_session_page(appname)

        os.chdir(self.current_dir)

    def test_project_testsuite(self):
        '''Test project testsuite'''
        print ""
        self._add_project(verbose=True)
        appname = "mycoolapp"
        self._add_app(name=appname, verbose=True)

        pagename = "foo"
        search = "I added a page!"
        contents = '''
from django.http import HttpResponse
def %s(request):
    return HttpResponse("%s")
''' % (pagename, search)
        self._add_page(appname, pagename, contents, search)

        settings = os.path.join(self.django_project_dir, "settings.py")
        if self.lsb_release['Release'] == 10.04:
            # 1.1 needs this (https://code.djangoproject.com/ticket/7756)
            subprocess.call(['sed', '-i', "s#^INSTALLED_APPS = (#INSTALLED_APPS = (\\n    'django.contrib.admin',#g", settings])
        os.chdir(self.django_project_manage_dir)
        print "  manage.py test"
        rc, report = testlib.cmd(['python', './manage.py', 'test', '-v', '2', '--noinput'])
        os.chdir(self.current_dir)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        terms = ['Creating test database', 'OK']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in :\n%s" % (search, report))
        self.assertFalse('FAILED' in report, "Found 'FAILED' in\n%s" % report)

    def test_project_lp1080204(self):
        '''Test LP: #1080204'''
        print ""
        self._add_project(verbose=True)
        appname = "mycoolapp"
        self._add_app(name=appname, verbose=True)

        pagename = "foo"
        search = "I added a page!"
        contents = '''
from django.http import HttpResponse
def %s(request):
    return HttpResponse("%s")
''' % (pagename, search)
        self._add_page(appname, pagename, contents, search)

        settings = os.path.join(self.django_project_dir, "settings.py")
        if self.lsb_release['Release'] == 10.04:
            # 1.1 needs this (https://code.djangoproject.com/ticket/7756)
            subprocess.call(['sed', '-i', "s#^INSTALLED_APPS = (#INSTALLED_APPS = (\\n    'django.contrib.admin',#g", settings])
        subprocess.call(['sed', '-i', "s#^ADMINS \\(.*\\)#ADMINS \\1\\n    ('Test Admin', 'testadmin@localhost'),#g", settings])

        os.chdir(self.django_project_manage_dir)
        print "  manage.py test"
        rc, report = testlib.cmd(['python', './manage.py', 'test', '-v', '2', '--noinput'])
        os.chdir(self.current_dir)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        terms = ['Creating test database', 'OK']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in :\n%s" % (search, report))
        self.assertFalse('FAILED' in report, "Found 'FAILED' in\n%s" % report)

    def _test_stub(self):
        '''Test stub for defining new tests'''
        print ""
        self._add_project(verbose=True)
        appname = "mystubapp"
        self._add_app(name=appname, verbose=True)

        pagename = "stub"
        search = "I added a stub page!"
        contents = '''
from django.http import HttpResponse
def %s(request):
    return HttpResponse("%s")
''' % (pagename, search)
        self._add_page(appname, pagename, contents, search)

        os.chdir(self.current_dir)

        print "\nbase_url: %s" % self.base_url
        print "tmpdir: %s" % self.tmpdir
        print "django_project_topdir: %s" % self.django_project_topdir
        print "django_project_manage_dir: %s" % self.django_project_manage_dir
        print "django_project_dir: %s" % self.django_project_dir
        subprocess.call(['bash'])


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DjangoTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
    print "INFO: please also test with MAAS"
