#!/usr/bin/python
#
#    test-subversion.py quality assurance test script for Subversion
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
# QRT-Packages: subversion libapache2-svn elinks sudo apache2-utils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: apache2:!precise apache2-mpm-prefork:precise
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-subversion.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-subversion.py -v'
'''


import unittest, subprocess, sys, os
import testlib
import testlib_httpd
import tempfile

use_private = True
try:
    from private.qrt.Subversion import SubversionPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class SubversionCommon:
    '''Common Subversion stuff.'''

    def run_svnadmin(self, command, arguments=None, user=None):
        '''Runs the svnadmin command'''
        cmd = []

        if user:
            cmd.extend(["sudo", "-H", "-u", user])

        cmd.extend(["svnadmin", command])

        if arguments:
            cmd.extend(arguments)

        (rc, report) = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def run_svn(self, command, arguments=None, change_dir=True, user=None, expected=0):
        '''Runs the svn command'''
        cmd = []

        if user:
            cmd.extend(["sudo", "-u", user])

        cmd.extend(["svn", command])

        if arguments:
            cmd.extend(arguments)

        if change_dir == True:
            os.chdir(self.working_dir)

        (rc, report) = testlib.cmd(cmd)

        if change_dir == True:
            os.chdir(self.current_dir)

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def word_find(self, report, content, invert=False):
        '''Check for a specific string'''
        if invert == False:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(content in report, warning + report)
        else:
            warning = 'Found "%s"\n' % content
            self.assertFalse(content in report, warning + report)


class SubversionTest(testlib.TestlibCase, SubversionCommon):
    '''Test Subversion.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="subversion-")
        self.test_repo = os.path.join(self.tempdir, 'testrepo')
        self.working_dir = os.path.join(self.tempdir, 'workingdir')
        self.test_file = os.path.join(self.working_dir, "test-subversion.py")

        os.mkdir(self.working_dir)

        self.current_dir = os.getcwd()

        # Set up default test repo
        self.run_svnadmin("create", [self.test_repo])
        self.run_svn("import", ["-m", "Initial commit", "./test-subversion.py",
                                "file://" + self.test_repo + "/test-subversion.py"],
                                change_dir=False)
        self.run_svn("checkout", ["file://" + self.test_repo, self.working_dir])

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_00_list(self):
        '''Test svn list'''
        result = self.run_svn("list")
        self.word_find(result, "test-subversion.py")

    def test_01_content(self):
        '''Test if content matches'''

        (rc, report) = testlib.cmd(["/usr/bin/diff", '-q', "./test-subversion.py",
                                    self.test_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_02_modify(self):
        '''Test modifying contents'''

        commit_log = "This is a test commit."

        # Modify our file
        subprocess.call(['sed', '-i', 's/test/xylophone/g', self.test_file])

        # Check the status
        result = self.run_svn("status")
        self.word_find(result, "test-subversion.py")

        # Commit
        self.run_svn('commit', ['-m', commit_log])

        # Check the status
        result = self.run_svn("status")
        self.word_find(result, "test-subversion.py", invert=True)

        # Update
        result = self.run_svn("update")
        self.word_find(result, "At revision")

        # Check the log
        result = self.run_svn("log")
        self.word_find(result, commit_log)

    def test_03_blame(self):
        '''Test blame command'''
        result = self.run_svn("blame", [self.test_file])
        self.word_find(result, "root")

class SubversionApacheTest(testlib_httpd.HttpdCommon, SubversionCommon):
    '''Test libapache2-svn functionality with apache'''
    def setUp(self):
        '''Setup mechanisms'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="subversion-")
        self.ports_file = "/etc/apache2/ports.conf"

        if self.lsb_release['Release'] >= 14.04:
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
        else:
            self.default_site = "/etc/apache2/sites-available/default"

        self.subversion_servers = "/etc/subversion/servers"

        self.current_dir = os.getcwd()

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])

        testlib_httpd.HttpdCommon._setUp(self)

        # create the svn repo
        self.svn_dir = os.path.join(self.tempdir, 'svn')
        self.co_dir = os.path.join(self.tempdir, 'co')
        self.working_dir = os.path.join(self.co_dir, 'example')
        self.svn_repo = os.path.join(self.svn_dir, 'example')
        self.svn_user = "foo"
        self.svn_password = "bar"
        self.svn_topurl = "http://" + self.svn_user + ":" + self.svn_password + "@localhost:8000/svn/example"
        self.htpasswd = os.path.join(self.tempdir, 'htpasswd.svn')
        os.mkdir(self.svn_dir)
        os.mkdir(self.co_dir)

        # adjust permissions
        subprocess.call(['chown', 'www-data:www-data', self.svn_dir])
        subprocess.call(['chmod', '770', self.svn_dir])
        subprocess.call(['chown', 'www-data:www-data', self.co_dir])
        subprocess.call(['chmod', '770', self.co_dir])
        subprocess.call(['chmod', '750', self.tempdir])
        subprocess.call(['chgrp', 'www-data', self.tempdir])

        self._enable_mod("dav")
        self._enable_mod("dav_svn")

        # adjust to old behavior
        if self.lsb_release['Release'] >= 9.10:
            testlib.config_replace(self.subversion_servers, "store-plaintext-passwords = yes", append=True)

        # create the repository
        self.run_svnadmin("create", [self.svn_repo], user="www-data")

        # import some stuff
        self.run_svn("import", ['/etc/apache2', 'file://' + self.svn_repo + '/testlib',
                     '-m', '"initial commit"'], user="www-data", change_dir=False)

        self._add_basic_auth_user(self.svn_user, self.svn_password, self.htpasswd)

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#<Location /svn>\\nDAV svn\\nSVNParentPath ' + self.svn_dir + '\\nAuthType Basic\\nAuthName "Subversion Repository"\\nAuthUserFile ' + self.htpasswd + '\\nRequire valid-user\\n</Location>\\n</VirtualHost>#', self.default_site])

        self._restart()


    def tearDown(self):
        '''Shutdown methods'''
        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        self._disable_mod("dav_svn")
        self._disable_mod("dav")

        testlib_httpd.HttpdCommon._tearDown(self)

        if os.path.exists(self.subversion_servers):
            testlib.config_restore(self.subversion_servers)

        os.chdir(self.current_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _add_basic_auth_user(self, user, password, file):
        '''Add user to htpasswd for basic auth'''
        cmd = ['htpasswd', '-b']
        if not os.path.exists(file):
            cmd.append('-c')
        cmd += [file, user, password]
        (rc, report) = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_00_daemons(self):
        '''Test daemon'''

        if self.lsb_release['Release'] >= 14.04:
            pidfile = "/var/run/apache2/apache2.pid"
        else:
            pidfile = "/var/run/apache2.pid"

        self.assertTrue(testlib.check_pidfile("apache2", pidfile))

    def test_10_status(self):
        '''Test status (apache2ctl)'''
        rc, report = testlib.cmd(['apache2ctl', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_20_http(self):
        '''Test http'''
        self._test_url("http://localhost:8000/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.html_page), test_str)

    def test_21_mod_svn(self):
        '''Test mod svn'''
        self._test_url(self.svn_topurl + "/testlib", "ports.conf")

    def test_21_mod_svn_checkin(self):
        '''Test mod svn checkin'''

        self.run_svn("co", ['--username', self.svn_user,
                            '--password', self.svn_password,
                            'http://localhost:8000/svn/example',
                            self.working_dir],
                            user="www-data", change_dir = False)

        (rc, report) = testlib.cmd(['sudo', '-u', 'www-data', 'cp', '/etc/passwd',
                                     self.working_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.run_svn("add", ['passwd'],
                            user="www-data")

        result = self.run_svn("diff", user="www-data")
        self.word_find(result, "root")

        self.run_svn("ci", ['--username', self.svn_user,
                            '--password', self.svn_password,
                            '-m', 'added passwd'],
                            user="www-data")

        # try to diff to nonexistent version
        result = self.run_svn("diff", ['-r', '1:3',
                                       '--username', self.svn_user,
                                       '--password', self.svn_password],
                                       user="www-data", expected=1)
        self.word_find(result, "No such revision 3")

        result = self.run_svn("diff", ['-r', '1:2',
                                       '--username', self.svn_user,
                                       '--password', self.svn_password],
                                       user="www-data")
        self.word_find(result, "root")


if __name__ == '__main__':
    os.environ['LANG']='C'

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SubversionTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SubversionApacheTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SubversionPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
