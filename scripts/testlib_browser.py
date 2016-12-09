#!/usr/bin/python
#
#    testlib_browser.py quality assurance test library for browsers
#    Copyright (C) 2008-2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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

# QRT-Depends: testlib_browser
# QRT-Packages: gimp flashplugin-installer totem-mozilla gstreamer0.10-plugins-bad gstreamer0.10-plugins-ugly apturl ssl-cert gnutls-bin apache2 apache2-utils
# Try to use icedtea6-plugin on <= 12.04, and icedtea-7-plugin on >=12.10
# QRT-Alternates: icedtea-7-plugin:!precise icedtea6-plugin:lucid icedtea6-plugin:oneiric icedtea6-plugin:precise libreoffice:!lucid

# TODO:
#  - java is flaky with chromium (and disabled on 14.04 and higher)
#  - java reloads are flaky with konqueror
#  - ssl test on webkit based browsers (ie, use ca-certificates)
#  - epiphany LP: #599796 (need to kill totem-plugin-viewer manually)
#  - nss for chromium: http://code.google.com/p/chromium/wiki/LinuxCertManagement
#  - http://kb.mozillazine.org/Chrome_URLs, http://kb.mozillazine.org/Dev_:_Firefox_Chrome_URLs
#  - http://lifehacker.com/#!5045164/google-chromes-full-list-of-special-about-pages
#  - http://www.chromeplugins.org/google/chrome-tips-tricks/about-chrome-more-internal-urls-7793.html
#  - epiphany migrate profile
#  - http://peter.sh/experiments/chromium-command-line-switches/ has a bunch of
#    chromium command line switches. Some might be interesting
#  - webm on natty and higher

import subprocess, sys, os, shutil, time
import hashlib
import tempfile
import testlib
import testlib_data
import testlib_ssl

exes = []
use_existing = False
include_skipped = False
tabs = False

class BrowserCommon(testlib_data.DataCommon):
    def _setUp(self):
        '''Set up prior to each test_* function'''
        global exes
        global use_existing
        self.exes = exes # exes is set in the including test script
        testlib_data.DataCommon._setUp(self)
        self.mozdir = os.path.join(os.path.expanduser('~'), '.mozilla')
        self.epidir = os.path.join(os.path.expanduser('~'), '.gnome2/epiphany/mozilla')
        self.chromium_dirs = [os.path.join(os.path.expanduser('~'), '.config/chromium'),
                              os.path.join(os.path.expanduser('~'), './.cache/chromium')]
        self.konq_dirs = [os.path.join(os.path.expanduser('~'), '.kde/share/apps/konqueror'),
                          os.path.join(os.path.expanduser('~'), '.kde/share/apps/nsplugins'),
                          os.path.join(os.path.expanduser('~'), '.kde/share/apps/kwallet'),
                          os.path.join(os.path.expanduser('~'), '.kde/share/apps/khtml')]
        self.rekonq_dirs = [os.path.join(os.path.expanduser('~'), '.kde/share/apps/rekonqu'),
                            os.path.join(os.path.expanduser('~'), '.kde/share/apps/kcookiejar'),
                            os.path.join(os.path.expanduser('~'), '.kde/share/apps/kwallet'),
                            os.path.join(os.path.expanduser('~'), '.kde/share/apps/kssl')]


        if "chromium-browser" in self.exes:
            self.chromium_created_first_run = False
            self._set_chromium_first_run()

        self.backup_ext = '.testlib.bak'
        self.use_accessibility = "false"	# not a python boolean

        self._move_browser_dirs(use_existing)
        if self.lsb_release['Release'] >= 14.04:
            self.www_root = "/var/www/html"
        else:
            self.www_root = "/var/www"
        self.tmpdir = ""
        self.apacheconf = ""

    def _tearDown(self):
        '''Clean up after each test_* function'''
        for d in [self.mozdir, self.epidir] + self.chromium_dirs + self.konq_dirs + self.rekonq_dirs:
            bakdir = d + self.backup_ext
            if os.path.exists(bakdir):
                if os.path.exists(d):
                    testlib.recursive_rm(d)
                shutil.move(bakdir, d)

        # Remove the chromium directories if we created them in _setUp()
        if hasattr(self, 'chromium_created_first_run') and self.chromium_created_first_run:
            for d in self.chromium_dirs:
                if os.path.exists(d):
                    testlib.recursive_rm(d)

        if self._has_gconftool():
            self._set_accessibility(self.use_accessibility, save_previous=False)

        if os.path.exists(self.tmpdir):
            if self.tmpdir.startswith(self.www_root):
                subprocess.call(['sudo', 'rm', '-rf', self.tmpdir])
            else:
                testlib.recursive_rm(self.tmpdir)

        if os.path.exists(self.apacheconf):
            subprocess.call(['sudo', 'rm', '-f', self.apacheconf])

    def _set_chromium_first_run(self):
        '''Try to setup chromium for the first run'''
        first_run = os.path.join(os.path.expanduser('~'), '.config/chromium', 'First Run')
        if os.path.exists(first_run):
            self.chromium_created_first_run = False
            return

        for d in self.chromium_dirs:
            if os.path.exists(os.path.dirname(first_run)):
                # just bail if configuration already exists
                self.chromium_created_first_run = False
                return

        # At this point, we don't have any chromium directories, so create them
        # and the first run file
        for d in self.chromium_dirs:
            os.mkdir(d)
        testlib.cmd(['touch', first_run])
        self.chromium_created_first_run = True

    def _set_exes(self, executables=[]):
        '''Executables to test'''
        self.exes = executables

    def _has_gconftool(self):
        '''Check if we have gconftool-2'''
        rc, output = testlib.cmd(['which', 'gconftool-2'])
        expected = 0
        if rc == expected:
            return True
        return False

    def _move_browser_dirs(self, use_existing=False):
        '''Move the .mozilla directory out of the way'''
        if not use_existing:
            for exe in self.exes:
		# we need to kill off kwalletd so our password store is not
                # remembered
                if exe.startswith('konqueror') or exe.startswith('rekonq'):
                    testlib.cmd(['killall', 'kwalletd'])

        for d in [self.mozdir, self.epidir] + self.chromium_dirs + self.konq_dirs + self.rekonq_dirs:
            bakdir = d + self.backup_ext
            do_copy = use_existing
            if hasattr(self, 'chromium_created_first_run') and self.chromium_created_first_run and d in self.chromium_dirs:
                do_copy = True
            if os.path.exists(d):
                if not os.path.exists(bakdir):
                    if do_copy:
                        try:
                            shutil.copytree(d, bakdir, symlinks=True)
                        except shutil.Error:
                            # print "WARN: could not copy:\n%s" % (d)
                            pass
                    else:
                        shutil.move(d, bakdir)
                else:
                    if not do_copy:
                        testlib.recursive_rm(d)

    def _urlcmd(self, command, url, expected=0, warnonly=False):
        '''Execute command with the given url'''
        rc, report = testlib.cmd(command + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if command[0].startswith("epiphany") and rc == -11:
            # epiphany return -11 sometimes on exit. ignore it, but notify
            print >>sys.stderr, "WARN: '%s' exited with '%d'. ignoring" % (command[0], rc)
        elif command[0].startswith("rekonq"):
            if rc != 3 and rc != 0:
                # rekonq usually exits with 3. Ignore others but notify
                print >>sys.stderr, "WARN: '%s' exited with '%d'. ignoring" % (command[0], rc)
        elif warnonly:
            if rc != expected:
                print >>sys.stderr, "WARN: '%s' exited with '%d'. ignoring" % (command[0], rc)
        else:
            self.assertEquals(expected, rc, result + report)

    def _set_accessibility(self, use, save_previous=True):
        '''Set accessibility via gconf'''
        if not self._has_gconftool():
            self._skipped("gconftool not present")
            return

        if save_previous:
            rc, output = testlib.cmd(['gconftool-2', '--get', '/desktop/gnome/interface/accessibility'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + output)

            if output.lower() == "true":
                self.use_accessibility = "true"
            else:
                self.use_accessibility = "false"

        rc, report = testlib.cmd(['gconftool-2', '--set', '--type=bool', '/desktop/gnome/interface/accessibility', use])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _make_tmpdir_in_www(self, owner=None, perms=0755):
        '''Make a tmpdir in /var/www'''
        # create the dir and the pathname in /var/www
        tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        rel = os.path.basename(tmpdir)
        self.tmpdir = os.path.join(self.www_root, rel)

        # adjust the perms
        os.chmod(tmpdir, perms)
        if owner != None:
            subprocess.call(['sudo', 'chown', owner, tmpdir])

        # move the new directory into place
        rc, report = testlib.cmd(['sudo', 'mv', tmpdir, self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return rel

class TestImages(BrowserCommon):
    '''Test viewing of various image files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_gif(self):
        '''Test GIF'''
        for exe in self.exes:
            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "gif", 1, expected_rc=ex)

    def test_jpg(self):
        '''Test JPG'''
        for exe in self.exes:
            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "jpg", 1, expected_rc=ex)

    # This is handled
    def test_png(self):
        '''Test PNG'''
        for exe in self.exes:
            global include_skipped
            if not include_skipped and exe.startswith('firefox'):
                print "  skipping %s (handled via 'Save image'. To enable use --include-skipped)" % exe
                continue
            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "png", 1, expected_rc=ex)

    def test_tiff(self):
        '''Test TIFF'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "tiff", 1, expected_rc=ex)

    def test_pdf(self):
        '''Test PDF'''
        for exe in self.exes:
            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "pdf", 1, expected_rc=ex)


class TestFiles(BrowserCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_office_docs(self):
        '''Test Office documents'''
        for exe in self.exes:
            ex = 0
            if exe.startswith("rekonq") and self.lsb_release['Release'] == 11.04:
                ex = 3
            self._cmd([exe], "doc", 1, expected_rc=ex)
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            self._cmd([exe], "xls", 1, expected_rc=ex)
            self._cmd([exe], "odp", 1, expected_rc=ex)
            self._cmd([exe], "odt", 1, expected_rc=ex)
            self._cmd([exe], "ods", 1, expected_rc=ex)
            self._cmd([exe], "rtf", 1, expected_rc=ex)

    def test_archives(self):
        '''Test Archive files'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            if exe.startswith("rekonq"):
                print "skipping rekonq"
                continue
            self._cmd([exe], "tar", 1)

class TestPages(BrowserCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def _make_root_file(self, path, contents):
        '''Make a file somewhere'''
        self.assertFalse(os.path.exists(path), "%s already exists. aborting" % path)

        tmp = tempfile.mktemp(prefix='testlib', dir='/tmp')
        testlib.create_fill(tmp, contents)

        rc, report = testlib.cmd(['sudo', 'mv', tmp, path])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        subprocess.call(['sudo', 'chown', "root:root", path])

    def _setup_password_test(self, user, password, msg=None, digest=False):
        '''Set for password tests'''
        rel = self._make_tmpdir_in_www() # assigns self.tmpdir

        contents = '''<Directory %s/>
        AllowOverride All
</Directory>
''' % (self.tmpdir)
        if self.lsb_release['Release'] >= 13.10:
            conf = "/etc/apache2/conf-enabled/testlib.conf"
        else:
            conf = "/etc/apache2/conf.d/testlib"
        self._make_root_file(conf, contents)
        self.apacheconf = conf

        htaccess = os.path.join(self.tmpdir, '.htaccess')
        passwd_file = os.path.join(self.tmpdir, '.passwd')
        realm = '/%s/' % rel
        if digest:
            contents = '''AuthUserFile %s
AuthName '%s'
AuthType Digest
AuthDigestProvider file
require user %s
''' % (passwd_file, realm, user)
        else:
            contents = '''AuthUserFile %s
AuthName "'%s'"
AuthType Basic
require user %s
''' % (passwd_file, msg, user)

        self._make_root_file(htaccess, contents)

        if digest:
            rc, report = testlib.cmd(['sudo', 'a2enmod', 'auth_digest'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # reload apache
        rc, report = testlib.cmd(['sudo', '/etc/init.d/apache2', 'reload'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # create the htpasswd file
        if digest:
            m = hashlib.md5()
            m.update("%s:%s:%s" % (user, realm, password))
            contents = "%s:%s:%s\n"  % (user, realm, m.hexdigest())
            self._make_root_file(passwd_file, contents)
        else:
            rc, report = testlib.cmd(['sudo', 'htpasswd', '-b', '-c', passwd_file, user, password])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        return rel

    def test_bookmarks(self):
        '''Test Bookmarks'''
        for exe in self.exes:
            print >>sys.stdout, "Add bookmark, drag and drop into manager... ",
            sys.stdout.flush()
            self._urlcmd([exe], "http://127.0.0.1/")

    def test_file_url(self):
        '''Test file:///'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            self._urlcmd([exe], "file:///")

    def test_redirect(self):
        '''Test redirect (http -> https)'''
        bare_url = "wiki.ubuntu.com"
        for exe in self.exes:
            print >>sys.stdout, "See if redirected to https://%s" % (bare_url),
            sys.stdout.flush()
            self._urlcmd([exe], "http://%s" % (bare_url))

    def test_live_bookmarks(self):
        '''Test Live Bookmarks'''
        if self.lsb_release['Release'] < 7.10:
            return self._skipped("USN RSS too new (TODO: Dapper url)")

        for exe in self.exes:
            if exe.startswith('epiphany') or exe.startswith('chromium') or exe.startswith('konqueror') or exe.startswith('rekonq'):
                print "skipping %s" % exe
                continue
            self._urlcmd([exe], "http://www.ubuntu.com/usn/rss.xml")

    def test_javascript_google(self):
        '''Test maps.google.com'''
        for exe in self.exes:
            self._urlcmd([exe], "http://maps.google.com/")

    # TODO
    def _test_safe_browsing(self):
        '''Test www.mozilla.com/firefox/its-an-attack.html (safe-browsing)'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            if exe.startswith('konqueror') or exe.startswith('rekonq'):
                print "skipping %s" % exe
                continue
            self._urlcmd([exe], "http://www.mozilla.com/firefox/its-an-attack.html")

    def test_code_200(self):
        '''Test 200 (It works!)'''
        for exe in self.exes:
            global include_skipped
            if not include_skipped:
                self._skipped("skipping (handled via Bookmarks. To enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/")

    def test_code_200_indexes(self):
        '''Test 200 (Index of...)'''
        rel = self._make_tmpdir_in_www()
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/%s" % rel)

    def test_password_basic(self):
        '''Test Basic Auth (username: test, password: pass)'''
        global use_existing

        rel = self._setup_password_test('test', 'pass', msg='Basic auth test')
        for exe in self.exes:
            if not use_existing:
                print ""
                print "  enter password (have browser remember password)"
                self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)
                print "  use saved password (no prompt/filled in)"
            self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)

    def test_password_digest(self):
        '''Test Digest Auth (username: test, password: pass)'''
        global use_existing

        rel = self._setup_password_test('test', 'pass', digest=True)
        for exe in self.exes:
            if not use_existing:
                print ""
                print "  enter password (have browser remember password)"
                self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)
                print "  use saved password (no prompt/filled in)"
            self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)

        rc, report = testlib.cmd(['sudo', 'a2dismod', 'auth_digest'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # reload apache
        rc, report = testlib.cmd(['sudo', '/etc/init.d/apache2', 'reload'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_code_401(self):
        '''Test 401 (Authorization required)'''
        rel = self._setup_password_test('test', 'you will never guess me','Press cancel to test 401 Authorization Required')
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)

    def test_code_403(self):
        '''Test 403 (Forbidden)'''
        rel = self._make_tmpdir_in_www(perms=0700)
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/%s" % rel)

    def test_code_404(self):
        '''Test 404 (Not Found)'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/nonexistent")

    def test_code_500(self):
        '''Test 500 (Internal Server Error)'''
        rel = self._setup_password_test('test', 'pass', msg='If you are reading this, something went wrong. This should be an Internal Server Error')
        htaccess = os.path.join(self.tmpdir, ".htaccess")
        contents = open(htaccess).read()
        contents += "\nAuthInvalidDierctiveForInternelServerError 500\n"
        subprocess.call(['sudo', 'rm', '-f', htaccess])
        self._make_root_file(htaccess, contents)
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue
            self._urlcmd([exe], "http://127.0.0.1/%s/" % rel)


class TestAbout(BrowserCommon):
    '''Test about: specific items'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_about_plugins(self):
        '''Test about:plugins (should see flash, java, totem and any other additional plugins)'''
        for exe in self.exes:
            if exe.startswith('chromium'):
                print "Skipping '%s' (see test_about_pages())" % exe
                continue
            elif exe.startswith('konqueror'):
                print "Skipping '%s' (see via Settings/Configure Konqueror/Web Browsing/Plugins" % exe
                continue
            elif exe.startswith('rekonq'):
                print "Skipping '%s'" % exe
                continue
            self._urlcmd([exe], "about:plugins")

    def test_about_pages(self):
        '''Test about: pages'''
        print ""
        global include_skipped
        for exe in self.exes:
            about_pages = []
            if exe.startswith('firefox') or exe.startswith('seamonkey') or (exe.startswith('epiphany') and self.lsb_release['Release'] < 9.10):
                # http://kb.mozillazine.org/About_protocol_links
                about_pages = ['about:', 'about:blank', 'about:buildconfig', 'about:cache', 'about:cache?device=memory', 'about:cache?device=disk', 'about:config', 'about:credits', 'about:license', 'about:mozilla']
                if not exe.startswith('epiphany'):
                    about_pages.append('about:logo')
                    about_pages.append('about:neterror')
                    about_pages.append('about:robots')
                # about:support only in firefox 3.6 and seamonkey 2.1
                if exe.startswith('firefox') and not (self.lsb_release['Release'] == 9.04 and exe == "firefox-3.5"):
                    about_pages.append('about:support')
            elif exe.startswith('chromium'):
                if not include_skipped:
                    self._skipped("skipping chromium (to enable use --include-skipped)")
                    continue

                # chromium has about: pages, but you must navigate to them
                testpage = os.path.join(self.tmpdir, "testlib-about.html")
                contents = "<html>\n<body>\n<h1>Chromium about: pages</h1>\n"
                contents += "<p>To test, please click and drag each URL to the navigation bar, then click the 'Back' button</p>\n"
                contents += "<ul>\n"
                # http://googlesystem.blogspot.com/2008/09/google-chromes-about-pages.html
                # also about:stats, about:network, about:internets
                # put histograms and crash last since they behave differently
                for p in ['about:blank', 'about:cache', 'about:dns', 'about:memory', 'about:plugins', 'about:version', 'chrome://extensions', 'about:histograms', 'about:crash', 'chrome://downloads', 'chrome://net-internals' ]:
                    contents += "<li><a href='%s'>%s</a></li>\n" % (p, p)
                contents += "</ul>\n"
                contents += "</body>\n</html>"
                testlib.create_fill(testpage, contents)
                about_pages = [testpage]
            else:
                print "Skipping about: pages for '%s'" % (exe)
                continue
            extra_pages = []
            if exe.startswith('firefox'):
                extra_pages = ['about:home']
            if tabs: 
                p = about_pages + extra_pages
                p.insert(0, exe)
                print "  %s" % p
                self.shell_cmd(p)
            else:
                for p in about_pages + extra_pages:
                    print "  %s" % p
                    self._urlcmd([exe], p)


class TestDesktop(BrowserCommon):
    '''Test desktop integration'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        rel = self._make_tmpdir_in_www() # assigns self.tmpdir
        self.url = "http://127.0.0.1/%s" % rel
        img = "well-formed.png"
        subprocess.call(['sudo', 'cp', './data/%s' % img, self.tmpdir])
        self.imgurl = "%s/%s" % (self.url, img)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_apturl(self):
        '''Test apturl (may fail on Hardy or with lots of extensions/plugins)'''
        for exe in self.exes:
            if not exe.startswith('firefox'):
                print "  skipping %s" % exe
                continue
            self._urlcmd([exe], "apt:dpkg")

    def test_gnome(self):
        '''Test gnome (use 'Image as Background')'''

        for exe in self.exes:
            if not exe.startswith('firefox') and not exe.startswith('epiphany'):
                print "  skipping %s" % exe
                continue
            print >>sys.stdout, "right click on image and use 'Set As Desktop Background'... ",
            sys.stdout.flush()
            self._urlcmd([exe], self.imgurl)

    def test_printing(self):
        '''Test printing (print Index to file or PDF)'''
        for exe in self.exes:
            self._urlcmd([exe], self.url)

    def test_save_image(self):
        '''Test Save Image'''
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            print >>sys.stdout, "right click on image and use 'Save Image As'... ",
            sys.stdout.flush()
            self._urlcmd([exe], self.imgurl)

    def test_existing_profile(self):
        '''Test migrate of existing profile'''

        print ""
        for exe in self.exes:
            if exe.startswith("epiphany"):
                self._skipped("TODO: epiphany migration")
                continue
            if exe.startswith("konqueror"):
                self._skipped("TODO: konqueror migration")
                continue
            if exe.startswith("rekonq"):
                self._skipped("TODO: rekonq migration")
                continue
            pages = []
            migrated_pages = [] # used for tabs
            if exe.startswith('firefox') or exe.startswith('seamonkey'):
                pages.append('about:cache')         # for first start
            migrated_pages.append('http://www.ubuntu.com/')  # http
            migrated_pages.append('https://launchpad.net/')  # https direct
            migrated_pages.append('http://wiki.ubuntu.com/') # http redirect to https
            pages = pages + migrated_pages;
            if exe.startswith('firefox') or exe.startswith('seamonkey'):
                pages.append('about:cache')         # make sure the cache has new stuff in it

            if os.path.exists(self.mozdir):
                testlib.recursive_rm(self.mozdir)

            # Hardy -> Maverick do a 3.0/3.5 - > 3.6 transition
            dot_tar = './testlib_browser/dot_mozilla.tar.gz'
            if self.lsb_release['Release'] == 11.04:
                # Natty does a 4 -> 5 transition
                dot_tar = './testlib_browser/dot_mozilla4.tar.gz'

            if exe.startswith('seamonkey'):
                dot_tar = './testlib_browser/dot_mozilla_seamonkey.tar.gz'
            elif exe.startswith('chromium'):
                dot_tar = './testlib_browser/dot_chromium.tar.gz'

            rc, report = testlib.cmd(['tar', '-C', os.environ["HOME"], '-zxv', '-f', dot_tar])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            count = 0
            print " %s:" % exe

            if tabs:
                print "  Verify Disk cache number of entries != 0 (TODO: doesn't always work)"
                self._urlcmd([exe], 'about:cache')
                p = migrated_pages;
                print "  QRT: %s" % (p)
                p.insert(0,exe)
                self.shell_cmd(p)
                self._urlcmd([exe], 'about:cache')
            else:
                for p in pages:
                    if count == 0 and p == 'about:cache':
                        print "  Verify Disk cache number of entries != 0 (TODO: doesn't always work)"
                    else:
                        print "  QRT%d: %s" % (count, p)
                    self._urlcmd([exe], p)
                    count += 1


class TestSSL(BrowserCommon):
    '''Test SSL'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self.crt = ""
        self.listener = None

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

        # kill server now
        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)

        # Restore /etc/hosts
        path = "/etc/hosts"
        pathbackup = path + '.autotest'
        if os.path.exists(pathbackup):
            print "  (restoring %s)" % (path)
            subprocess.call(['sudo', 'mv', '-f', pathbackup, path])

        # Restore certificate
        if self.crt != "":
            crtbackup = self.crt + '.autotest'
            if os.path.exists(crtbackup):
                print "  (restoring %s)" % (self.crt)
                subprocess.call(['sudo', 'cp', '-f', crtbackup, self.crt])

    def test_https(self):
        '''Test https (https://www.google.com - should show locked icon next to the url)'''
        for exe in self.exes:
            self._urlcmd([exe], "https://www.google.com/")

    def test_https_ev(self):
        '''Test https EV (https://www.paypal.com - should show locked icon PayPal, Inc [US] next to the lock)'''
        for exe in self.exes:
            self._urlcmd([exe], "https://www.paypal.com")

    def test_https_mixed(self):
        '''Test https with mixed HTTP/HTTPS (https://ie.microsoft.com/testdrive/browser/mixedcontent/assets/woodgrove.htm - should show the mixed icon)'''
        for exe in self.exes:
            self._urlcmd([exe], "https://ie.microsoft.com/testdrive/browser/mixedcontent/assets/woodgrove.htm")

    def test_certificate_by_hostname(self):
        '''Test certificates'''
        # Update /etc/hosts for the certificate tests
        path = "/etc/hosts"
        pathbackup = path + '.autotest'
        if os.path.exists(path) and not os.path.exists(pathbackup):
            print "\n  (backing up %s)" % (path)
            subprocess.call(['sudo', 'cp', path, pathbackup])
        print "  (adjusting %s to contain an entry for 'server')" % (path)
        subprocess.call(['sudo', 'sed', '-i', 's/^\\(127.0.0.1.*\\)/\\1 server client/g', "/etc/hosts"])

        (self.tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        self.crt = os.path.join(self.www_root, "%s.crt" % os.path.basename(cacert_pem))
        crtbackup = self.crt + '.autotest'
        if os.path.exists(self.crt) and not os.path.exists(crtbackup):
            print "  (backing up %s)" % (self.crt)
            subprocess.call(['sudo', 'cp', self.crt, crtbackup])
        print "  (copying %s to %s)" % (cacert_pem, self.crt)
        subprocess.call(['sudo', 'cp', '-f', cacert_pem, self.crt])

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (srvkey_pem, srvcert_pem, self.crt)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        for exe in self.exes:
            if exe.startswith('chromium'): # browsers without a certificate store
                print >>sys.stdout, " %s:" % (exe)
                # should warn
                print >>sys.stdout, "  warn about cert (close the browser)..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://server:4443/"])

                print >>sys.stdout, " %s:" % (exe)
                # should warn
                print >>sys.stdout, "  warn about cert (accept the certificate)..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://server:4443/"])

            else: # browsers with a certificate store
                print >>sys.stdout, " %s:" % (exe)
                # should warn
                print >>sys.stdout, "  warn about cert..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://server:4443/"])

                # should prompt to import (do so)
                print >>sys.stdout, "  import (do so)..."
                sys.stdout.flush()
                testlib.cmd([exe, "http://server/%s" % (os.path.basename(self.crt))])

                # should open normally
                print >>sys.stdout, "  no warning..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://server:4443/"])

    def test_certificate_by_ip(self):
        '''Test certificate by IP'''
        (self.tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl(server_hostname="127.0.0.1")

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (srvkey_pem, srvcert_pem, cacert_pem)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        for exe in self.exes:
            if exe.startswith('chromium'): # browsers without a certificate store
                print >>sys.stdout, " %s:" % (exe)
                print >>sys.stdout, "  warn about cert (close the browser)..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://127.0.0.1:4443/"])

                print >>sys.stdout, " %s:" % (exe)
                print >>sys.stdout, "  warn about cert (accept the certificate)..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://127.0.0.1:4443/"])

            else: # browsers with a certificate store
                print >>sys.stdout, " %s:" % (exe)
                print >>sys.stdout, "  warn about cert (examine cert and accept permanently)..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://127.0.0.1:4443/"])

                # should open normally
                print >>sys.stdout, "  no warning..."
                sys.stdout.flush()
                testlib.cmd([exe, "https://127.0.0.1:4443/"])


class TestPlugins(BrowserCommon):
    '''Test various plugins'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0775)

    def tearDown(self):
        '''Clean up after each test_* function'''
        www_link = os.path.join(self.www_root, os.path.basename(self.tmpdir))
        if self.tmpdir != "" and os.path.exists(www_link):
            subprocess.call(['sudo', 'rm', '-f', www_link])
        self._tearDown()

    def _embed_file(self, path, media, width="352", height="288"):
        '''Create html page with player embedded. Requires javascript'''
        contents = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
 <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
 <title>Multimedia Player</title>
 <style type="text/css">
body {
 background: black;
 background-color: black;
 color: white;
}
a {
 color: silver;
}
p {
 text-align: center;
 margin-top: 0;
 border-top: 0;
 padding-top: 0;
}
div {
 position: absolute;
 top: 50%%;
 left: 50%%;
 height: 300px;
 width: 310px;
 margin-top: -150px;
 margin-left: -155px;
}
</style>
<script language="JavaScript" type="text/javascript">
// initialize global variables
var detectableWithVB = false;
var pluginFound = false;

function goURL(myURL) {
    window.location.replace(myURL);
    return;
}
function redirectCheck(pluginFound, redirectURL, redirectIfFound) {
    // check for redirection
    if( redirectURL && ((pluginFound && redirectIfFound) ||i
         (!pluginFound && !redirectIfFound)) ) {
        // go away
        goURL(redirectURL);
        return pluginFound;
    } else {
        // stay here and return result of plugin detection
        return pluginFound;
    }
}

function detectQuickTime(redirectURL, redirectIfFound) {
    pluginFound = detectPlugin('QuickTime');
    // if not found, try to detect with VisualBasic
    if(!pluginFound && detectableWithVB) {
        pluginFound = detectQuickTimeActiveXControl();
    }
    return redirectCheck(pluginFound, redirectURL, redirectIfFound);
}

function detectWindowsMedia(redirectURL, redirectIfFound) {
    pluginFound = detectPlugin('Windows Media Player');
    // if not found, try to detect with VisualBasic
    if(!pluginFound && detectableWithVB) {
        pluginFound = detectActiveXControl('MediaPlayer.MediaPlayer.1');
    }
    return redirectCheck(pluginFound, redirectURL, redirectIfFound);
}

function detectPlugin() {
    // allow for multiple checks in a single pass
    var myPlugins = detectPlugin.arguments;
    // consider pluginFound to be false until proven true
    var pluginFound = false;
    // if plugins array is there and not fake
    if (navigator.plugins && navigator.plugins.length > 0) {
        var pluginsArrayLength = navigator.plugins.length;
        // for each plugin...
        for (pluginsArrayCounter=0; pluginsArrayCounter < pluginsArrayLength; pluginsArrayCounter++ ) {
            // loop through all desired names and check each against the current plugin name
            var numFound = 0;
            for(namesCounter=0; namesCounter < myPlugins.length; namesCounter++) {
                // if desired plugin name is found in either plugin name or description
                if( (navigator.plugins[pluginsArrayCounter].name.indexOf(myPlugins[namesCounter]) >= 0) ||
                    (navigator.plugins[pluginsArrayCounter].description.indexOf(myPlugins[namesCounter]) >= 0) ) {
                    // this name was found
                    numFound++;
                }
            }
            // now that we have checked all the required names against this one plugin,
            // if the number we found matches the total number provided then we were successful
            if(numFound == myPlugins.length) {
                pluginFound = true;
                // if we've found the plugin, we can stop looking through at the rest of the plugins
                break;
            }
        }
    }
    return pluginFound;
} // detectPlugin

// simply checks if Windows Media Player is available, then outputs code
// compatible with WMP in a variety of browsers (IE, Firefox, Linux+MPlayer,
// ...).  If not WMP, then tries Quicktime, and outputs code compatible on
// Windows/IE/Quicktime and OSX Safari.  Otherwise, bails with download
// link.
function getPlayer(srcFile, width, height) {
  var objTypeTag = "";
  var plugin = "none";
  var pluginWidth = width;
  var pluginHeight = parseInt(height);
  var pluginWidth = parseInt(width);
  var options = "";

  if (detectWindowsMedia()) {
    objTypeTag = "application/x-mplayer2";
    plugin = "Windows Media Player";
    // showcontrols:  46 pixels
    // showstatusbar: 26 pixels
    // showdisplay:   74 pixels
    pluginHeight = parseInt(height) + 72;
  } else if (detectQuickTime()) {
    objTypeTag = "audio/mpeg"
    plugin = "QuickTime";
    pluginHeight = parseInt(height) + 46;
  } else {
    objTypeTag = "none";
    plugin = "none";
  }
  //document.writeln("<p>Using " + plugin + " with width " + pluginWidth + " and height of " + pluginHeight + "</p>");
  if (objTypeTag == "none") {
     document.writeln("<p>Couldn't find a suitable plugin.");
     document.writeln("<a href='" + srcFile + "' target='_blank'>Click here to download the file.</a></p>");
  } else {
    document.writeln("<div>");
    if (objTypeTag == "application/x-mplayer2") {
     /* windows media player */
     options = options + "<param name='autostart' value='1'>";
     options = options + "<param name='showstatusbar' value='1'>";
     options = options + "<param name='showcontrols' value='1'>";
     options = options + "<param name='showdisplay' value='0'>";

     document.writeln("<object width='" + pluginWidth + "' height='" + pluginHeight + "' classid='clsid:22D6F312-B0F6-11D0-94AB-0080C74C7E95' type='application/x-oleobject' codebase='http://activex.microsoft.com/activex/controls/mplayer/en/nsmp2inf.cab#Version=6,4,5,715' standby='Loading Microsoft Windows Media Player components...'>");
     document.writeln("<param name='src' value='" + srcFile + "'>");
     document.writeln(options);
     document.writeln("   <embed src='" + srcFile + "' width='" + pluginWidth + "' height='" + pluginHeight + "' autostart='1' autoplay='1' showcontrols='1' showstatusbar='0' type='" + objTypeTag + "'>");
     document.writeln("   </embed>");
     document.writeln("</object>");
    } else {
     /* if not WMP, then do a simple tag */
     options = options + "<param name='autoplay' value='true'>";
     options = options + "<param name='controller' value='true'>";
     document.writeln("<object width='" + pluginWidth + "' height='" + pluginHeight + "classid='clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B' codebase='http://www.apple.com/qtactivex/qtplugin.cab'>");
     document.writeln("<param name='src' value='" + srcFile + "'>");
     document.writeln(options);
     document.writeln("  <embed src='" + srcFile + "' width='" + pluginWidth + "' height='" + pluginHeight + "' type='" + objTypeTag + "' autoplay='true' autostart='true' controller='true' pluginspage='http://www.apple.com/quicktime/download/'></embed>");
     document.writeln("</object>");
    }
    document.writeln("<p style='margin-top: 2em;'>");
    document.writeln("<a href='" + srcFile + "' target='_blank'>Download</a></p>");
    document.writeln("</div>");
  }

  document.close();
}
</script>
</head>
<body>
 <script language="JavaScript" type="text/javascript">
   <!--
   // Call external JavaScript file to embed player
   getPlayer("%s", "%s", "%s");
   // -->
 </script>
</body>
</html>''' % (media, width, height)
        testlib.create_fill(path, contents)

    def test_flash(self):
        '''Test flash (dailymotion.com)'''
        # Youtube moved to html5 only
        if self.lsb_release['Release'] < 7.10:
            return self._skipped("Dapper flash not supported (too old)")

        for exe in self.exes:
            self._urlcmd([exe], "http://www.dailymotion.com/us")

    def _mediacmd(self, exe, ext, fn, alltests=True):
        '''Test file:// and embedded'''
        def print_skipped_media(fn):
            print "  skipped for '%s' (to enable, use --include-skipped)" % fn


        if (exe.startswith('konqueror') or exe.startswith('rekonq')) and not os.path.exists('/usr/bin/kmplayer'):
            print "  skipping '%s' with '%s' (run: apt-get install kmplayer mplayer)" % (ext, exe)
            return

        # konqueror can't handle ogv via file://
        if exe.startswith('konqueror') and ext == "ogv":
            print "  skipping file:// with '%s' and '%s'" % (ext, exe),
        elif exe.startswith('rekonq') and ext in ['avi', 'ogv', 'mpg', 'ogg', 'oga']:
            print "  skipping file:// with '%s' and '%s'" % (ext, exe),
        else:
            print "  file://",
            if alltests or ext == "ogv" or ext == "avi":
                self._cmd([exe], ext, 1)
            else:
                print_skipped_media(fn)

        testpage = os.path.join(self.tmpdir, "media.html")
        shutil.copy(fn, self.tmpdir)
        self._embed_file(testpage, os.path.basename(fn))
        if alltests or ext == "ogg" or ext == "oga":
            print "\n  embedded file:// %s ..."  % (os.path.basename(fn))
            self._urlcmd([exe], "file://%s" % (testpage))
        else:
            print_skipped_media(fn)

        if exe.startswith('chromium'):
            print "  skipping embedded with '%s'" % (exe)
            return

        # firefox on 12.04 and higher doesn't work with these
        if exe.startswith('firefox') and ext == "ogv" and self.lsb_release['Release'] >= 12.04:
            print "  skipped embedded (relative/full) due to LP: #1063427"
            return
        if os.path.isdir(self.www_root):
            subprocess.call(['sudo', 'ln', '-sf', self.tmpdir, self.www_root])
            if alltests or ext == "mpg":
                print "  embedded (relative path) http:// %s (requires sudo) ..."  % (os.path.basename(fn))
                self._urlcmd([exe], "http://127.0.0.1/%s" % (os.path.join(os.path.basename(self.tmpdir), os.path.basename(testpage))))

                print "  embedded (full URL) http:// %s (requires sudo) ..."  % (os.path.basename(fn))
                self._embed_file(testpage, "http://127.0.0.1/%s" % (os.path.join(os.path.basename(self.tmpdir), os.path.basename(fn))))
                self._urlcmd([exe], "http://127.0.0.1/%s" % (os.path.join(os.path.basename(self.tmpdir), os.path.basename(testpage))))
            else:
                print_skipped_media(fn)
        else:
            self._skipped("could not find '%s', skipping http tests" % self.www_root)

    def test_avi(self):
        '''Test AVI'''
        print ""
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            self._mediacmd(exe, "avi", "./data/rfbproxy-jaunty.avi", include_skipped)

    def test_mpg(self):
        '''Test MPEG'''
        print ""
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            self._mediacmd(exe, "mpg", "./data/rfbproxy-jaunty.mpg", include_skipped)

    def test_ogg(self):
        '''Test Ogg'''
        print ""
        for exe in self.exes:
            global include_skipped
            if exe.startswith('chromium') and not include_skipped:
                self._skipped("skipping chromium (to enable use --include-skipped)")
                continue

            # ogg
            if self.lsb_release['Release'] < 8.10:
                print "  file://",
                self._cmd([exe], "ogg", 1)
            else:
                self._mediacmd(exe, "ogg", "./data/Edison_Phonograph_1.ogg", include_skipped)

            # oga
            if self.lsb_release['Release'] < 7.10:
                self._skipped("oga not supported (Dapper)")
            else:
                if exe.startswith('konqueror'):
                    self._skipped("oga not supported in '%s'" % exe)
                elif self.lsb_release['Release'] < 8.10:
                    print "  file://",
                    self._cmd([exe], "oga", 1)
                else:
                    self._mediacmd(exe, "oga", "./data/patas_de_trapo.oga", include_skipped)

            # ogv
            self._mediacmd(exe, "ogv", "./data/rfbproxy-jaunty.ogv", include_skipped)

    def test_html5(self):
        '''Test HTML5'''
        testpage = os.path.join(self.tmpdir, "5.html")

        for i in ["./data/rfbproxy-jaunty.ogv", "./data/rfbproxy-jaunty.webm", "./data/sound-file.webm"]:
            shutil.copy(i, self.tmpdir)
            fn = os.path.join(self.tmpdir, os.path.basename(i))
            contents = "<!DOCTYPE html>\n<video src='%s' width='320' height='240' controls autoplay></video>\n<p>%s</p>" % (fn, os.path.basename(i))
            testlib.create_fill(testpage, contents)

            urls = ['file://%s' % testpage]
            print ""
            for url in urls:
                print "  %s (%s)" % (url, os.path.basename(i)),
                sys.stdout.flush()
                for exe in self.exes:
                    if exe.startswith('konqueror') and self.lsb_release['Release'] < 10.04:
                        print "  skipping %s with '%s'" % (os.path.basename(i), exe)
                        continue
                    elif exe.startswith('rekonq'):
                        print "  skipping %s with '%s'" % (os.path.basename(i), exe)
                        continue
                    elif i.endswith("webm") and not exe.startswith("chromium"):
                        if not exe.startswith('firefox') or self.lsb_release['Release'] < 10.04:
                            print "  skipping webm with '%s'" % (exe)
                            continue
                    self._urlcmd([exe], url, 0)

            os.unlink(testpage)


class TestJavaPlugin(BrowserCommon):
    '''Test java plugin'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_java(self):
        '''Test Java (may crash on close with firefox. OpenJDK is sometimes slow)'''
        global include_skipped
        testpage = os.path.join(self.tmpdir, "java.html")
        contents = '''<html>
<body>
<p> Java enabled:
<script>document.write(" " + navigator.javaEnabled() );</script>
</p>
</body>
</html>'''
        testlib.create_fill(testpage, contents)

        urls = ['file://%s' % testpage]
        reduced_urls = ['http://javatester.org/version.html']
        if self.lsb_release['Release'] > 12.04: # this doesn't work with
                                                # openjdk-6 any more
                                                # TODO: openjdk-7
            reduced_urls.append('http://www.java.com/en/download/testjava.jsp')

        all_urls = urls + reduced_urls + ['http://www.w3.org/People/mimasa/test/object/java/clock', 'http://www.gnu.org/software/classpath/'] # 'http://decloak.net/']

        print ""
        for exe in self.exes:
            test_urls = all_urls
            if not include_skipped:
               if exe.startswith('chromium') or exe.startswith('firefox'):
                   test_urls = urls + reduced_urls
               elif exe.startswith('rekonq'):
                   test_urls = urls

            for url in test_urls:
                print "  %s" % (url),
                sys.stdout.flush()
                warnonly = False
                if exe.startswith('firefox') or exe.startswith('seamonkey'):
		    # sigh... closing firefox on a java page sometimes causes
                    # java to crash
                    warnonly = True
                self._urlcmd([exe], url, 0, warnonly)

    def test_java_lp728798(self):
        '''Test Java LP: #728798 (perform several reloads per page, OpenJDK is sometimes slow)'''
        urls = ['http://www.java.com/de/download/help/testvm.xml']
        # dither test
        # LP: #1063430 'http://www.oracle.com/technetwork/java/example1-142050.html']

        global include_skipped

        print ""
        for url in urls:
            print "  %s (also try after reload)" % (url),
            sys.stdout.flush()
            for exe in self.exes:
                if exe.startswith('chromium') and not include_skipped:
                    self._skipped("skipping chromium (to enable use --include-skipped)")
                    continue
                warnonly = False
                if exe.startswith('firefox') or exe.startswith('seamonkey'):
		    # sigh... closing firefox on a java page sometimes causes
                    # java to crash
                    warnonly = True
                elif exe.startswith('rekonq'):
                    print " skipping on rekonq"
                    continue
                self._urlcmd([exe], url, 0, warnonly)


class TestIcedTeaPlugin(BrowserCommon):
    '''Test icedtea plugin. This is a superset of TestJavaPlugin'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_icedtea_version(self):
        '''Show icedtea and openjdk versions'''
        for s in ['openjdk', 'icedtea']:
            print " dpkg -l | grep %s" % (s)
            rc, report = testlib.cmd_pipe(['dpkg', '-l'], ['grep', s])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for line in report.splitlines():
                tmp = line.split()
                print "  %s: %s" % (tmp[1], tmp[2])

    def test_icedtea(self):
        '''Test IcedTea URLs (may crash on close with firefox. OpenJDK is sometimes slow)'''
        global include_skipped
        testpage = os.path.join(self.tmpdir, "java.html")
        contents = '''<html>
<body>
<p> Java enabled:
<script>document.write(" " + navigator.javaEnabled() );</script>
</p>
</body>
</html>'''
        testlib.create_fill(testpage, contents)

        urls = ['file://%s' % testpage]
        meta_urls = []

        # previous security updates needed a newer icedtea-web to work with
        # the new openjdk, but this was only updated on 12.04 and higher
        if self.lsb_release['Release'] < 12.04:
            self._skipped("icedtea-web tests on 10.04")
        else:
            urls += [
                'http://www.w3.org/People/mimasa/test/object/java/clock',
                'http://www.gnu.org/software/classpath/',
                'http://javatester.org/version.html',
                'http://dan-ball.jp/en/javagame/dust/ja/',
                'http://netalyzr.icsi.berkeley.edu/',
                'http://caff.de/applettest/Signed.html',
               ]
            # this doesn't work with openjdk anymore
            # if self.lsb_release['Release'] > 12.04:
            #    urls.append('http://www.java.com/en/download/testjava.jsp')
            meta_urls += [
                'http://icedtea.classpath.org/wiki/IcedTea-Web-Tests',
                # 'http://lggwg.com/main/download', # broken
                # 'http://pscode.org/jws/api.html', # flaky
                # 'http://decloak.net/',
               ]

        print ""
        for exe in self.exes:
            for url in urls + meta_urls:
                if url in meta_urls:
                    print "  %s (try a few random links)" % (url),
                else:
                    print "  %s" % (url),
                sys.stdout.flush()
                warnonly = False
                if exe.startswith('firefox') or exe.startswith('seamonkey'):
		    # sigh... closing firefox on a java page sometimes causes
                    # java to crash
                    warnonly = True
                elif exe.startswith('chromium') and self.lsb_release['Release'] >= 12.04:
                    print >>sys.stdout, "\n  Skipped: NPAPI removed (LP: #1309508)\n"
                    continue

                self._urlcmd([exe], url, 0, warnonly)

    def test_icedtea_lp1171506(self):
        '''Test LP: #1171506
           - should see a login page for the bank
           - test with icedtea-6-plugin and icedtea-7-plugin
        '''
        if self.lsb_release['Release'] < 12.04:
            self._skipped("icedtea-web tests on 10.04")
            return
        url = 'https://www2.bancobrasil.com.br/aapf/login.jsp'
        for exe in self.exes:
            warnonly = False
            if exe.startswith('firefox') or exe.startswith('seamonkey'):
                # sigh... closing firefox on a java page sometimes causes
                # java to crash
                warnonly = True
            elif exe.startswith('chromium') and self.lsb_release['Release'] >= 14.04:
                print >>sys.stdout, "\n  Skipped: NPAPI removed (LP: #1309508)\n"
                continue
            self._urlcmd([exe], url, 0, warnonly)


class TestVersion(BrowserCommon):
    '''Test browser version'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_version(self):
        '''Show installed browser version'''
        for exe in self.exes:
            search = []
            if exe.startswith('firefox'):
                search.append('firefox')
                if self.lsb_release['Release'] < 11.04:
                    search.append('xulrunner')
            elif exe.startswith('epiphany'):
                search.append('epiphany')
                if self.lsb_release['Release'] >= 9.10:
                    search.append('webkit')
                else:
                    search.append('xulrunner')
            elif exe.startswith('chromium'):
                search.append('chromium')
            elif exe.startswith('seamonkey'):
                search.append('seamonkey')
            elif exe.startswith('konqueror'):
                search.append('webkit')
                search.append('kdelibs')
                search.append('libqtcore')
            elif exe.startswith('rekonq'):
                search.append('webkit')
                search.append('kdelibs')
                search.append('libqtcore')
            print ""
            for s in search:
                print " dpkg -l | grep %s" % (s)
                rc, report = testlib.cmd_pipe(['dpkg', '-l'], ['grep', s])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                for line in report.splitlines():
                    tmp = line.split()
                    print "  %s: %s" % (tmp[1], tmp[2])

            # Now test --version
            if exe.startswith('chromium'):
                continue
            print "\n %s --version:" % (exe)
            rc, report = testlib.cmd([exe, '--version'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            print report


class TestAppArmor(BrowserCommon):
    '''Test AppArmor profile'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_browser_path(self):
        '''Make sure applications can start the browser'''
        # Quick test for Jaunty and earlier
        if self.lsb_release['Release'] < 9.10:
            profile = "/etc/apparmor.d/usr.bin.firefox"
            self.assertFalse(os.path.exists(profile), "Found '%s'" % (profile))
            return 0

        abstractions = ""
        if not os.path.exists("/etc/apparmor.d/abstractions/ubuntu-browsers"):
            self._skipped("Could not find /etc/apparmor.d/abstractions/ubuntu-browsers")
        abstractions += "  #include <abstractions/ubuntu-browsers>\n"
        if os.path.exists("/etc/apparmor.d/abstractions/ubuntu-helpers"):
            abstractions += "  #include <abstractions/ubuntu-helpers>\n"

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        exe = os.path.join(self.tmpdir, "exe")
        profile = os.path.join(self.tmpdir, "profile")

        contents = '''
#include <tunables/global>

%s {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
%s
  /** r,
  /bin/bash ix,
}
''' % (exe, abstractions)
        testlib.create_fill(profile, contents)

        contents = '''#!/bin/bash
set -e
/usr/bin/firefox || exit 1
exit 0
'''
        testlib.create_fill(exe, contents)
        os.chmod(exe, 0775)

        rc, report = testlib.cmd(['sudo', 'apparmor_parser', '-r', profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print >>sys.stdout, "\n  (if the browser opens in a few seconds, please close it)"
        sys.stdout.flush()
        rc, report = testlib.cmd([exe])
        expected = 0
        result = 'Got exit code %d, expected %d. Does the firefox path match what\nis in the ubuntu-browsers abstraction? Script output:\n' % (rc, expected)
        # unload the profile before seeing if the script failed

        # unload the profile before seeing if the script failed
        rc2, report2 = testlib.cmd(['sudo', 'apparmor_parser', '-R', profile])
        expected = 0
        result2 = 'Got exit code %d, expected %d\n' % (rc2, expected)
        self.assertEquals(expected, rc2, result2 + report2)

        self.assertEquals(expected, rc, result + report)

    def test_package_upgrade(self):
        '''Test apparmor for 3.6.4 upgrades (uses sudo)'''
        # Quick test for Jaunty and earlier
        if self.lsb_release['Release'] < 9.10:
            profile = "/etc/apparmor.d/usr.bin.firefox"
            self.assertFalse(os.path.exists(profile), "Found '%s'" % (profile))
            return 0

        versions = {
            #'hardy': '3.0~b5+nobinonly-0ubuntu3',
            #'jaunty': '3.0.8+nobinonly-0ubuntu3',
            'karmic': '3.5.3+build1+nobinonly-0ubuntu6',
            'lucid': '3.6.3+nobinonly-0ubuntu4',
            'default': '3.6.3+nobinonly-0ubuntu4'
        }

        last_version = versions['default']
        if versions.has_key(str(self.lsb_release['Codename'])):
            last_version = str(versions[self.lsb_release['Codename']])

        print ""
        for exe in self.exes:
            if not exe.startswith('firefox'):
                print "  skipping %s" % exe
                continue

            print "  test profile from %s" % (last_version)
            rc, report = testlib.cmd(['sudo', 'sh', '-x', './testlib_browser/firefox-apparmor-profile.sh', last_version])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

