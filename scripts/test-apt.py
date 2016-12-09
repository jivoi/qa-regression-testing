#!/usr/bin/python
#
#    test-apt.py quality assurance test script for apt
#    Copyright (C) 2009-2013 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c './test-apt.py -v'

    TODO:
      - test https transport
      - try to incorporate http://people.ubuntu.com/~mvo/apt/auth-test-suit/
      - fix testsuite for natty and quantal
'''

# QRT-Packages: lighttpd
# QRT-Depends: apt
# QRT-Privilege: root

import unittest, subprocess, sys, os
import tempfile
import testlib

class PkgTest(testlib.TestlibCase):
    '''Test apt.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.sources_list = "/etc/apt/sources.list.d/testlib.list"
        if os.path.exists(self.sources_list):
            os.unlink(self.sources_list)
            self._update()
        self.topdir = os.getcwd()

        self.builder = None
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None

        if os.path.exists(self.sources_list):
            os.unlink(self.sources_list)
            self._update()
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _update(self):
        '''apt-get update'''
        rc, report = testlib.cmd(['apt-get', 'update'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _upgrade(self, distupgrade=False):
        '''apt-get upgrade'''
        self._update()

        type = "upgrade"
        if distupgrade:
            type = "dist-upgrade"

        rc, report = testlib.cmd(['apt-get', '-y', '--force-yes', type])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _add_archive_canonical_com(self):
        apt_contents = "deb http://archive.canonical.com/ubuntu %s partner\n" % self.lsb_release['Codename']
        open(self.sources_list, 'w').write(apt_contents)
        self._update()

    def _get_apt_list_fn(self, type):
        list_dir = "/var/lib/apt/lists"
        suffix = ""
        fn = ""
        if type == "Packages":
            suffix = "_partner"
            fn = "archive.canonical.com_ubuntu_dists_%s%s_binary-%s_%s" % (self.lsb_release['Codename'], suffix, self.dpkg_arch, type)
        else:
            fn = "archive.canonical.com_ubuntu_dists_%s%s_%s" % (self.lsb_release['Codename'], suffix, type)
        return os.path.join(list_dir, fn)

    def _ac_version_installed(self, pkg, vers):
        '''Checks if version of package is installed using apt-cache'''
        rc, output = testlib.cmd(['apt-cache', 'policy', pkg])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + output)

        for line in output.splitlines():
            if '***' in line:
                if vers == line.split()[1]:
                    return True
        return False

    def test_update(self):
        '''Testing update (archive.canonical.com)'''
        self._add_archive_canonical_com()

        for f in ['Release', 'Release.gpg', 'Packages']:
            self.assertTrue(os.path.exists(self._get_apt_list_fn(f)), "'%s' does not exist" % (f))

    def test_upgrade(self):
        '''Testing upgrade'''
        pkgs = dict()
        pkgs['dapper']   = 'libpng12-0 1.2.8rel-5'
        pkgs['hardy']    = 'libpng12-0 1.2.15~beta5-3'
        pkgs['jaunty']   = 'libpng12-0 1.2.27-2ubuntu2'
        pkgs['karmic']   = 'libpng12-0 1.2.37-1'
        pkgs['lucid']    = 'libpng12-0 1.2.42-1ubuntu2'
        pkgs['maverick'] = 'libpng12-0 1.2.44-1'
        pkgs['natty']    = 'libpng12-0 1.2.44-1ubuntu3'
        pkgs['oneiric']  = 'libpng12-0 1.2.46-3ubuntu1'
        pkgs['precise']  = 'python-feedparser 5.1-0ubuntu3'
        pkgs['saucy']    = 'chkrootkit 0.49-4.1ubuntu1'
        pkgs['trusty']   = 'chkrootkit 0.49-4.1ubuntu1'

        print >>sys.stdout, ""
        sys.stdout.flush()

        rel = self.lsb_release['Codename'].lower()
        if not pkgs.has_key(rel):
            self._skipped("Don't have package for '%s'" % (rel))
            return

        # ensure that we have official repos
        apt_contents = "deb http://archive.ubuntu.com/ubuntu %s main\n" % (rel)
        apt_contents += "deb http://archive.ubuntu.com/ubuntu %s-security main\n" % (rel)
        open(self.sources_list, 'w').write(apt_contents)
        self._update()

        pkg, vers = pkgs[rel].split()

        for dist_upgrade in [False, True]:
            print >>sys.stdout, "  downgrade %s to %s" % (pkg, vers)
            rc, report = testlib.cmd(['apt-get', '-y', '--force-yes', 'install', "%s=%s" % (pkg, vers)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self._ac_version_installed(pkg, vers), "%s=%s is not installed" % (pkg, vers))

            if dist_upgrade:
                print >>sys.stdout, "  apt-get dist-upgrade"
            else:
                print >>sys.stdout, "  apt-get upgrade"
            self._upgrade(dist_upgrade)
            self.assertFalse(self._ac_version_installed(pkg, vers), "%s was not upgraded" % (pkg))

    def test_goodsig_consistency(self):
        '''Verify gpgv sets GOODSIG only on valid signatures'''
        self._add_archive_canonical_com()

        release_file = self._get_apt_list_fn('Release')
        rc, report = testlib.cmd(['gpgv', '--status-fd', '1', '--keyring', '/etc/apt/trusted.gpg', release_file + ".gpg", release_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        err = "Could not find GOODSIG\n"
        self.assertTrue("[GNUPG:] GOODSIG" in report, err + report)

        for i in ['expired', 'revoked']:
            release_file = "./apt/repo-%s/Release" % (i)
            rc, report = testlib.cmd(['gpgv', '--status-fd', '1', '--keyring', './apt/keyring/pubring.gpg', release_file + ".gpg", release_file])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            err = "Found GOODSIG\n"
            self.assertFalse("[GNUPG:] GOODSIG" in report, err + report)

            search_str = ""
            if i == "expired":
                search_str = "[GNUPG:] KEYEXPIRED"
            elif i == "revoked":
                search_str = "[GNUPG:] REVKEYSIG"
            err = "Couldn't find '%s' in report" % (search_str)
            self.assertTrue(search_str in report, err + report)

    def test_badsig(self):
        '''Verify gpgv sets BADSIG on bad signatures'''
        for i in ['', '-expired', '-revoked']:
            release_file = "./apt/repo-bad%s/Release" % (i)
            rc, report = testlib.cmd(['gpgv', '--status-fd', '1', '--keyring', './apt/keyring/pubring.gpg', release_file + ".gpg", release_file])
            expected = 1
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            err = "Did not find BADSIG\n"
            self.assertTrue("[GNUPG:] BADSIG" in report, err + report)

    def test_356012(self):
        '''Test bug 356012'''
        os.chdir('./apt')
        os.chmod('./keyring/', 0700)

        #subprocess.call(['bash'])
        rc, report = testlib.cmd(['./test.sh'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search_str = "ERROR"
        self.assertFalse(search_str in report, result + report)

    def test_784473(self):
        '''Test bug 784473 (CVE-2011-1829)'''

        # This test is disabled, as InRelease parsing was found to have
        # security issues, and was disabled.
        return self._skipped("InRelease support was disabled by a USN")

        if self.lsb_release['Release'] < 11.04:
            return self._skipped('InRelease only supported on natty+')

        os.chdir('./apt')
        os.chmod('./keyring/', 0700)

        #subprocess.call(['bash'])
        rc, report = testlib.cmd(['./test-lp784473.sh'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search_str = "ERROR"
        self.assertFalse(search_str in report, result + report)

    def test_aptkey_list(self):
        '''Test apt-key list'''
        rc, report = testlib.cmd(['apt-key', 'list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search_str = "Ubuntu Archive Automatic Signing Key"
        self.assertTrue(search_str in report, result + report)

    def test_aptkey_netupdate(self):
        '''Test apt-key net-update (TODO: adjust for expected failure)'''

        # This test is disabled, as net-update was deemed insecure and was
        # disabled in the USN-1477-1 security update.
        # See LP: #1013639 (and 857472, 1013128)
        return self._skipped("apt-get net-update was disabled by USN-1477-1")

        kr_fn = "/usr/share/apt/ubuntu-archive.gpg"
        rc, report = testlib.cmd(['sha1sum', kr_fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        orig = report

        cached_fn = "/var/lib/apt/keyrings/ubuntu-archive-keyring.gpg"
        if os.path.exists(cached_fn):
            os.unlink(cached_fn)

        rc, report = testlib.cmd(['apt-key', 'net-update'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(os.path.exists(cached_fn), "Could not find '%s'\n%s" % (cached_fn, report))
        search_str = "Ubuntu Archive Automatic Signing Key"
        self.assertTrue(search_str in report, result + report)

        # verify the master didn't change
        rc, report = testlib.cmd(['sha1sum', kr_fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        curr = report
        self.assertEquals(orig, curr, "'%s' changed:\n%s\n%s" % (kr_fn, orig, curr))

    def _test_zz_testsuite(self):
        '''Test testsuite'''
        if self.lsb_release['Release'] < 11.04:
            return self._skipped("testsuite doesn't work on this release")

        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = None
        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

        build_dir = testlib.prepare_source('apt', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        print ""
#        print "  clean"
#        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'clean'])
#        expected = 0
#        result = 'Got exit code %d, expected %d\n' % (rc, expected)
#        self.assertEquals(expected, rc, result + report)

        print "  build"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'build'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Only Precise and higher have a usable testsuite
        print "  tests",
        if self.lsb_release['Release'] < 12.04:
            print "(skipped in this release)"
        else:
            print ""
            rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', 'test'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            failure_txt = ""
            for line in report.splitlines():
                if "FAIL" in line:
                    failure_txt += line + "\n"

            self.assertTrue(failure_txt == "", "Found failures in report:\n%s\nLines with failures:\n%s" % (report, failure_txt))

        # Only Natty and higher have integration tests
        print "  integration tests",
        if self.lsb_release['Release'] < 11.04:
            print "(skipped in this release)"
        else:
            print ""

            testlib.cmd(['sudo', '-H', '-u', self.builder.login, 'mkdir', '-m', '0700', os.path.join("/home", self.builder.login, ".gnupg")])

            if self.lsb_release['Release'] >= 12.04:
                rc, report = testlib.cmd(['sudo', '-H', '-u', self.builder.login, 'make', '-C', 'test/integration', 'test'])
            else:
                os.chdir(os.path.join(build_dir, 'test', 'integration'))
                rc, report = testlib.cmd(['sudo', '-H', '-u', self.builder.login, './run-tests'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Attempt to parse test output of the form (as seen by pyunit, not
            # terminal output):
            #  Testcase test-apt-get-autoremove:  P P P P P P P P P P P
            #  Testcase test-apt-get-changelog:  P P P P P
            #  -E: changelog download failed
            #  +E: changelog for this version is not (yet) available; try https://launchpad.net/ubuntu/+source/apt/+changelog
            #  ###FAILED###
            #  ...

            efails = [ 'test-apt-key-net-update:' ] # LP: #1013639
            efails = []

            if self.lsb_release['Release'] >= 12.04:
                efails += [
                           'test-apt-get-changelog:',
                           'test-bug-593360-modifiers-in-names:',
                           'test-bug-601016-description-translation:',
                           'test-bug-612099-multiarch-conflicts:',
                           'test-bug-64141-install-dependencies-for-on-hold:',
                           'test-conflicts-loop:',
                           'test-ubuntu-bug-859188-multiarch-reinstall:',
                          ]
            elif self.lsb_release['Release'] == 11.10:
                efails += [
                           'test-apt-get-changelog:',
                           'test-apt-get-download:',
                           'test-bug-407511-fail-invalid-default-release:',
                           'test-bug-470115-new-and-tighten-recommends:',
                           'test-bug-549968-install-depends-of-not-installed:',
                           'test-bug-590041-prefer-non-virtual-packages:',
                           'test-bug-601016-description-translation:',
                           'test-bug-612099-multiarch-conflicts:',
                           'test-bug-618288-multiarch-same-lockstep:',
                           'test-bug-632221-cross-dependency-satisfaction:',
                           'test-bug-64141-install-dependencies-for-on-hold:',
                           'test-compressed-indexes:',
                           'test-disappearing-packages:',
                           'test-handling-broken-orgroups:',
                           'test-release-candidate-switching:',
                           'test-ubuntu-bug-802901-multiarch-early-remove:',
                           'test-ubuntu-bug-806274-install-suggests:',
                           'test-ubuntu-bug-835625-multiarch-lockstep-installed-first:',
                          ]
            elif self.lsb_release['Release'] == 11.04:
                efails += [
                           'test-bug-590041-prefer-non-virtual-packages:',
                           'test-bug-595691-empty-and-broken-archive-files:',
                           'test-bug-601016-description-translation:',
                           'test-bug-64141-install-dependencies-for-on-hold:',
                           'test-compressed-indexes:',
                           'test-disappearing-packages:',
                           'test-pdiff-usage:',
                          ]


            failure_txt = ""
            testcase_txt = ""
            in_testcase = False
            for line in report.splitlines():
                testcase_txt += line + "\n"
                if line.startswith("Testcase"):
                    in_testcase = True
                    testcase_txt = line + "\n"
                    continue
                elif in_testcase and '###FAILED###' in line:
                    ex_fail = False
                    for e in efails:
                        if e in testcase_txt.splitlines()[0]:
                            ex_fail = True
                            break
                    if not ex_fail:
                        testcase_txt += line + "\n"
                        failure_txt += testcase_txt + "\n"

            self.assertTrue(failure_txt == "", "Found failures in report:\n%s\nLines with failures:\n%s" % (report, failure_txt))

if __name__ == '__main__':
    # simple
    unittest.main()
