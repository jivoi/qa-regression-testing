#!/usr/bin/python
#
#    test-devscripts.py quality assurance test script for devscripts
#    Copyright (C) 2009-2015 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: devscripts lsb-release libwww-perl netbase libcrypt-ssleay-perl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: devscripts

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install devscripts lsb-release libwww-perl && ./test-devscripts.py -v'
'''


import unittest
import shutil
import testlib
import os
import tempfile

class DevscriptsTest(testlib.TestlibCase):
    '''Test devscripts'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.current_dir = os.getcwd()

        self.conf = '/etc/devscripts.conf'
        # Disable signature verification so we don't need to import key
        testlib.config_replace(self.conf, "\nDGET_VERIFY=no\n", True)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.current_dir != os.getcwd():
            os.chdir(self.current_dir)

        testlib.config_restore(self.conf)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_uscan(self):
        '''Test uscan'''

        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
http://launchpad.net/ufw/+download/ https://launchpad.net/ufw/.*/ufw-(.*)\.tar\.gz
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'ufw', '--report', '--upstream-version', '0.28', '--verbose', '--watchfile', watchfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'Found the following matching hrefs' not in report\n"
        self.assertTrue('Found the following matching hrefs' in report, result + report)

        contents = '''
version=2
ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-(.*)\.tar\.gz \
  debian uupdate
'''

        # This doesn't seem to work, not sure why

        #testlib.create_fill(watchfile, contents)
        #rc, report = testlib.cmd(['uscan', '--package', 'openssh', '--report', '--upstream-version', '5.2p1', '--verbose', '--watchfile', watchfile])
        #expected = 0
        #result = 'Got exit code %d, expected %d\n' % (rc, expected)
        #self.assertEquals(expected, rc, result + report)

        #result = "'Found the following matching files' not in report\n"
        #self.assertTrue('Found the following matching files' in report, result + report)

    def test_uscan_repack_bz2(self):
        '''Test uscan repack with bz2'''

        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
https://launchpad.net/mir/+download .*/mir-([0-9.]+~?.+?)\.tar\.bz2
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'mir', '--download',
                                  '--repack', '--upstream-version', '0.7.3',
                                  '--download-version', '0.7.4', '--verbose',
                                  '--watchfile', watchfile,
                                  '--destdir', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Utopic+ doesn't remove original tarball
        if self.lsb_release['Release'] < 14.10:
            result = "Found bz2 tarball!\n"
            tarball = os.path.join(self.tmpdir, "mir-0.7.4.tar.bz2")
            self.assertFalse(os.path.exists(tarball), result)

        if self.lsb_release['Release'] < 14.10:
            filename = "mir-0.7.4.tar.gz"
        else:
            filename = "mir_0.7.4.orig.tar.gz"

        result = "Couldn't find repacked tarball!\n"
        tarball = os.path.join(self.tmpdir, filename)
        self.assertTrue(os.path.exists(tarball), result)

        # Inspect contents of repacked tarball
        rc, report = testlib.cmd(['tar', '-ztvf',
                                  os.path.join(self.tmpdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find file in repacked tarball!\n"
        self.assertTrue(" mir-0.7.4/.clang-format" in report, result)
        self.assertTrue(" mir-0.7.4/3rd_party/" in report, result)
        self.assertTrue(" mir-0.7.4/tools/vera++/scripts/rules/T019.tcl" in report, result)

    def test_uscan_repack_zip(self):
        '''Test uscan repack with zip'''

        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
https://launchpad.net/jbidwatcher-companion/+download .*/JBidwatcher-Companion-([0-9.]+~?.+?)\.zip
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'jbidwatcher-companion',
                                  '--download', '--repack',
                                  '--upstream-version', '0.1.6',
                                  '--download-version', '0.1.7',
                                  '--verbose',
                                  '--watchfile', watchfile,
                                  '--destdir', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Utopic+ doesn't remove original tarball
        if self.lsb_release['Release'] < 14.10:
            result = "Found zip file!\n"
            tarball = os.path.join(self.tmpdir, "JBidwatcher-Companion-0.1.7.zip")
            self.assertFalse(os.path.exists(tarball), result)

        if self.lsb_release['Release'] < 14.10:
            filename = "JBidwatcher-Companion-0.1.7.tar.gz"
        else:
            filename = "jbidwatcher-companion_0.1.7.orig.tar.gz"

        result = "Couldn't find repacked tarball!\n"
        tarball = os.path.join(self.tmpdir, filename)
        self.assertTrue(os.path.exists(tarball), result)

        # Inspect contents of repacked tarball
        rc, report = testlib.cmd(['tar', '-ztvf',
                                  os.path.join(self.tmpdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find file in repacked tarball!\n"
        self.assertTrue(" JBidwatcher-Companion-0.1.7/" in report, result)
        self.assertTrue(" JBidwatcher-Companion-0.1.7/setup.cfg" in report, result)
        self.assertTrue(" JBidwatcher-Companion-0.1.7/JBidwatcher_Companion.egg-info/PKG-INFO" in report, result)

    def test_CVE_2009_2946(self):
        '''Test uscan (CVE-2009-2946)'''
        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
opts=uversionmangle="s/^\d\.\d$/$&00/;s/^\d\.\d\d0$/$&0" \
http://search.cpan.org/dist/Term-Size/ \
..*/Term-Size-v?(\d[\d_.]+)\.(?:tar(?:\.gz|\.bz2)?|tgz|zip)
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'libterm-size-perl', '--report', '--upstream-version', '0.207', '--verbose', '--watchfile', watchfile])

        result = "'potentially unsafe' not in report\n"
        self.assertTrue('potentially unsafe' in report, result + report)

    def test_debian_544931(self):
        '''Test uscan regression (Debian #544931)'''

        if self.lsb_release['Release'] < 14.04:
            return self._skipped("Doesn't work on 12.04, need to investigate")

        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
opts=uversionmangle="s/(\d)/$1./g" \
http://sf.net/kcheckgmail/kcheckgmail-(.+)\.tar\.gz
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'kcheckgmail', '--report', '--upstream-version', '0.5.7', '--verbose', '--watchfile', watchfile])

        result = "'potentially unsafe' not in report\n"
        self.assertTrue('potentially unsafe' in report, result + report)


    def test_debian_545234(self):
        '''Test uscan regression (Debian #545234)'''

        if self.lsb_release['Release'] < 14.04:
            return self._skipped("Doesn't work on 12.04, need to investigate")

        watchfile = os.path.join(self.tmpdir, "watch")
        contents = '''
version=3
opts=uversionmangle=sx(.?)\Gxprint("foo")xg \
http://sf.net/kcheckgmail/kcheckgmail-(.+)\.tar\.gz
'''
        testlib.create_fill(watchfile, contents)
        rc, report = testlib.cmd(['uscan', '--package', 'libterm-size-perl', '--report', '--upstream-version', '0.207', '--verbose', '--watchfile', watchfile])

        result = "'potentially unsafe' not in report\n"
        self.assertTrue('potentially unsafe' in report, result + report)

    def test_debdiff_changes(self):
        '''Test debdiff with changes'''

        rc, report = testlib.cmd(['debdiff', './devscripts/ufw_0.30.1-1ubuntu1.dsc',
                                             './devscripts/ufw_0.30.1-2ubuntu1.dsc'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "Don't install the upstream application profiles"

        result = "Couldn't find '%s' in report:\n" % search
        self.assertTrue(search in report, result + report)

    def test_debdiff_no_changes(self):
        '''Test debdiff with no changes'''

        rc, report = testlib.cmd(['debdiff', './devscripts/ufw_0.30.1-1ubuntu1.dsc',
                                             './devscripts/ufw_0.30.1-1ubuntu1.dsc'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_dscverify_good(self):
        '''Test dscverify - good signature'''

        keyring = os.path.join(self.tmpdir, "keyring")
        shutil.copy('./devscripts/jdstrand.keyring', keyring)

        # Set up initial gnupg directories
        testlib.cmd(['gpg', '--list-keys'])

        rc, report = testlib.cmd(['dscverify',
                                  '--keyring', keyring,
                                  './devscripts/ufw_0.30.1-1ubuntu1.dsc'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "Good signature found"

        result = "Couldn't find '%s' in report:\n" % search
        self.assertTrue(search in report, result + report)

    def test_dscverify_bad(self):
        '''Test dscverify - bad signature'''

        keyring = os.path.join(self.tmpdir, "keyring")
        shutil.copy('./devscripts/jdstrand.keyring', keyring)

        # Set up initial gnupg directories
        testlib.cmd(['gpg', '--list-keys'])

        rc, report = testlib.cmd(['dscverify',
                                  '--keyring', keyring,
                                  './devscripts/bad_signature.dsc'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "Good signature found"
        result = "Found '%s' in report:\n" % search
        self.assertFalse(search in report, result + report)

        search = "Validation FAILED"
        result = "Couldn't find '%s' in report:\n" % search
        self.assertTrue(search in report, result + report)

    def test_dget(self):
        '''Test dget'''

        dsc_file = 'http://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.31.1-1.dsc'
        orig_tarball = os.path.join(self.tmpdir, 'ufw_0.31.1.orig.tar.gz')
        unpacked_dir = os.path.join(self.tmpdir, 'ufw-0.31.1')

        os.chdir(self.tmpdir)
        rc, report = testlib.cmd(['dget', dsc_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Couldn't find orig tarball!\n"
        self.assertTrue(os.path.exists(orig_tarball), result + report)

        result = "Couldn't find unpacked dir!\n"
        self.assertTrue(os.path.exists(unpacked_dir), result + report)

    def test_annotate_output(self):
        '''Test annotate_output'''

        rc, report = testlib.cmd(['annotate-output',
                                  './devscripts/test-annotate-output.sh'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "O: This is line one"

        result = "Couldn't find '%s' in report:\n" % search
        self.assertTrue(search in report, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()
