#!/usr/bin/python
#
#    test-git-core.py quality assurance test script for PKG
#    Copyright (C) 2008-2015 Canonical Ltd.
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
# QRT-Packages: git
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: git

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''

import unittest, subprocess, sys
import testlib
import tempfile, os.path, re

use_private = True
try:
    from private.qrt.git import PrivateGitTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class GitRepo(object):
    '''Sets up a basic Git repo'''

    def __init__(self):
        self.repodir = None
        self.testfile = None

    def setup(self):
        self.repodir = tempfile.mkdtemp(dir='/tmp',prefix="git-")
        self.testfile = 'test-git.py'
        subprocess.call(['/bin/cp', '-r', os.path.join('./', self.testfile), self.repodir], stdout=subprocess.PIPE)

gitrepo = GitRepo()

class GitTest(testlib.TestlibCase):
    '''Test git.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def gitcommand(self, command):
        '''Run a git command'''

        # Change to the repo dir before calling git
        self.current_dir = os.path.abspath('.')
        os.chdir(gitrepo.repodir)

        (rc, report) = testlib.cmd(["/usr/bin/git"] + command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)

        os.chdir(self.current_dir)

        self.assertEquals(expected, rc, result + report)
        return [rc, report]

    def onetime_setUp(self):
        '''Set up once'''
        # Set up the Repo
        gitrepo.setup()

        # Do the initial checkin
        self.gitcommand(['init'])

        self.gitcommand(['add', '.'])
        self.gitcommand(['commit', '-m', 'This is the initial commit.'])

    def _regex_find(self, report, content, invert=False):
        '''Check for a specific regex'''

        if invert == False:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(re.search(content, report), warning + report)
        else:
            warning = 'Found "%s"\n' % content
            self.assertFalse(re.search(content, report), warning + report)

    def try_clone(self):
        '''Make sure a clone matches'''
        self.tempdir = '/tmp/git-temp-' + testlib.random_string(8)

        giturl = 'file://' + gitrepo.repodir + '/.git'

        (rc, report) = testlib.cmd(["/usr/bin/git", 'clone', giturl, self.tempdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/diff", '-q', os.path.join(gitrepo.repodir, gitrepo.testfile),
                                                           os.path.join(self.tempdir, gitrepo.testfile)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        testlib.recursive_rm(self.tempdir)
        self.assertEquals(expected, rc, result + report)

    def onetime_tearDown(self):
        '''Clean up once'''
        #subprocess.call(['bash'])
        testlib.recursive_rm(gitrepo.repodir)

    def test_00_starting(self):
        '''Startup'''
        self.onetime_setUp()
        self.try_clone()

    def test_aa_branch(self):
        '''Test creating a branch'''
        self.gitcommand(['branch', 'testbranch'])
        (rc, report) = self.gitcommand(['branch'])
        self._regex_find(report, 'testbranch')

    def test_ab_commit(self):
        '''Test a commit'''
        # Switch to our test branch
        self.gitcommand(['checkout', 'testbranch'])

        # Modify our file
        subprocess.call(['sed', '-i', 's/test/xylophone/g', os.path.join(gitrepo.repodir, gitrepo.testfile)])
        self.gitcommand(['commit', '-a', '-m', 'This is a commit to our test branch.'])

    def test_ac_log(self):
        '''Test the log command'''
        # Make sure we can see our last commit.
        (rc, report) = self.gitcommand(['log'])
        self._regex_find(report, 'This is a commit to our test branch')

    def test_ad_shortlog(self):
        '''Test the shortlog command'''
        # Make sure we can see our last commit.
        (rc, report) = self.gitcommand(['shortlog'])
        self._regex_find(report, 'This is a commit to our test branch')

    def test_ae_diff(self):
        '''Test a diff on two branches'''
        # Switch to our test branch
        self.gitcommand(['checkout', 'testbranch'])

        # Compare with master and make sure we see the changes
        (rc, report) = self.gitcommand(['diff', 'master'])
        self._regex_find(report, 'xylophone')

    def test_af_grep(self):
        '''Test a grep'''
        # Perform a grep and make sure we see the changes
        (rc, report) = self.gitcommand(['grep', 'xylophone'])
        self._regex_find(report, 'xylophone')

    def test_ag_merge(self):
        '''Test merging the branches'''
        self.gitcommand(['checkout', 'master'])

        self.gitcommand(['merge', 'testbranch'])

        # Make sure it's commited to master
        (rc, report) = self.gitcommand(['log'])
        self._regex_find(report, 'This is a commit to our test branch')

        # See if the files match
        self.try_clone()

        # Delete the experimental branch
        self.gitcommand(['branch', '-d', 'testbranch'])

        # Make sure it got deleted
        (rc, report) = self.gitcommand(['branch'])
        self._regex_find(report, 'testbranch', invert=True)

    def test_zz_finished(self):
        '''Shutdown'''
        self.onetime_tearDown()

class CVE_2014_9390(testlib.TestlibCase):
    '''Test CVE-2014-9390.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        cve = 'CVE-2014-9390'
        self.current_dir = os.getcwd()
        self.testdir = tempfile.mkdtemp(dir='/tmp',prefix="git-")
        subprocess.call(['/bin/tar', 'xzf', os.path.join('./git', cve, 'clean.git.tar.gz'), '-C', self.testdir], stdout=subprocess.PIPE)
        subprocess.call(['/bin/tar', 'xzf', os.path.join('./git', cve, 'evil.git.tar.gz'), '-C', self.testdir], stdout=subprocess.PIPE)
        self.cleanrepo = os.path.join(self.testdir, 'clean.git')
        self.evilrepo = os.path.join(self.testdir, 'evil.git')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        testlib.recursive_rm(self.testdir)

    def _test_git_fsck(self, repo, search_string, expected_to_be_found):
        os.chdir(repo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "fsck", "-v"])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Output '%s' does not contain '%s'" % (report, search_string)
        self.assertEquals(search_string in report, expected_to_be_found, result)

    def test_aa_git_fsck(self):
        '''Make sure git fsck does not warn about .git in clean repo'''
        expected = "contains '.git'"
        self._test_git_fsck(self.cleanrepo, expected, False)

    def test_ab_git_fsck(self):
        '''Make sure git fsck warns about .git in evil repo'''
        expected = "warning in tree 0afc4ee87fadc1723459d2f4f73f32afe4ea5a3b: hasDotgit: contains '.git'"
        if self.lsb_release['Release'] < 16.04:
            expected = "warning in tree 0afc4ee87fadc1723459d2f4f73f32afe4ea5a3b: contains '.git'"
        self._test_git_fsck(self.evilrepo, expected, True)

    def _test_git_push(self, fsckObjects_value, expected_rc):
        os.chdir(self.cleanrepo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "config", "--local", "receive.fsckObjects", fsckObjects_value])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(self.evilrepo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "push", self.cleanrepo, "master:test"])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

    def test_ba_git_push(self):
        '''Make sure git push from evil to clean works when receive.fsckObjects is false'''
        self._test_git_push("false", 0)

    def test_bb_git_push(self):
        '''Make sure git push from evil to clean fails when receive.fsckObjects is true'''
        self._test_git_push("true", 1)

    def _test_git_pull(self, fsckObjects_value, expected_rc):
        os.chdir(self.cleanrepo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "config", "--local", "transfer.fsckObjects", fsckObjects_value])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/git", "pull", self.evilrepo, "master:test"])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

    def test_ca_git_pull(self):
        '''Make sure git pull from evil to clean works when transfer.fsckObjects is false'''
        self._test_git_pull("false", 0)

    def test_ca_git_pull(self):
        '''Make sure git pull from evil to clean fails when transfer.fsckObjects is true'''
        self._test_git_pull("true", 1)

    def _test_git_fetch(self, fsckObjects_value, expected_rc):
        os.chdir(self.cleanrepo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "config", "--local", "fetch.fsckObjects", fsckObjects_value])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/git", "fetch", self.evilrepo])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

    def test_da_git_fetch(self):
        '''Make sure git fetch from evil to clean works when fetch.fsckObjects is false'''
        self._test_git_fetch("false", 0)

    def test_db_git_fetch(self):
        '''Make sure git fetch from evil to clean fails when fetch.fsckObjects is true'''
        self._test_git_fetch("true", 128)

    def test_ea_git_am(self):
        '''Make sure git am fails when the patch contains a .GIT path'''
        os.chdir(self.cleanrepo)
        (rc, report) = testlib.cmd(["/usr/bin/git", "am", "../test.patch"])
        expected = 128
        if self.lsb_release['Release'] < 16.04:
            expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GitTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CVE_2014_9390))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PrivateGitTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
