#!/usr/bin/python
#
#    test-pkg.py quality assurance test script for dpkg
#    Copyright (C) 2010-2014 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#            Jamie Strandboge <jamie@ubuntu.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: build-essential
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: dpkg private/qrt/dpkg.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install build-essential  && ./test-pkg.py -v'
'''


import unittest, sys, os
import testlib
import tempfile

try:
    from private.qrt.dpkg import PrivateDpkgTest
except ImportError:
    class PrivateDpkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class DpkgTest(testlib.TestlibCase, PrivateDpkgTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.tempdir = tempfile.mkdtemp(prefix='test-dpkg-')
        self.topdir = os.getcwd()
        os.chdir(self.tempdir)

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_sane_dsc(self):
        '''Unpacks a dsc file normally'''
        self.assertShellExitEquals(0,['dpkg-source','-x',os.path.join(self.fs_dir,'dpkg/normal/hello_2.4-3.dsc')])
        self.assertTrue(os.path.exists('hello-2.4'))
        self.assertTrue(os.path.exists('hello-2.4/debian'))
        self.assertTrue(os.path.exists('hello-2.4/debian/changelog'))
        self.assertFalse(os.path.exists('non-sense'))

    def _test_malicious_unpack(self, expected, target, package):
        if os.path.exists(target):
            os.unlink(target)
        self.assertFalse(os.path.exists(target))
        self.assertShellExitEquals(expected,['dpkg-source','-x',os.path.join(self.fs_dir,'dpkg/%s' % (package))])
        self.assertFalse(os.path.exists(target), msg="Found %s" % (target))

    def test_malicious_diff_dot_dot(self):
        '''Does not unpack source packages and follow ".." dirs (CVE-2010-0396)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/i-append-to-you', 'through-dot-dot/hello_2.4-3.dsc')

    def test_malicious_diff_symlink(self):
        '''Does not unpack source packages and follow symlink dirs (CVE-2010-0396)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/i-append-to-you-also', 'through-symlink/hello_2.4-3.dsc')

    def test_v3_flaws1(self):
        '''Does not unpack malicious source-format-3.0 packages 1/4 (CVE-2010-1679)'''
        expected = 2
        if self.lsb_release['Release'] <= 11.04:
            expected = 9
        elif self.lsb_release['Release'] <= 12.04:
            expected = 25
        self._test_malicious_unpack(expected, '/tmp/allyourbase.txt', 'v3/evilpackage_1-1.dsc')

    def test_v3_flaws2(self):
        '''Does not unpack malicious source-format-3.0 packages 2/4 (CVE-2010-1679)'''
        expected = 2
        self._test_malicious_unpack(expected, '/tmp/all-your-base.txt', 'v3/evilpackage_2-1.dsc')

    def test_v3_flaws3(self):
        '''Does not unpack malicious source-format-3.0 packages 3/4 (CVE-2010-1679)'''
        expected = 2
        self._test_malicious_unpack(expected, '/tmp/all-your-base.txt', 'v3/evilpackage_3-1.dsc')

    def test_v3_flaws4(self):
        '''Does not unpack malicious source-format-3.0 packages 4/4 (CVE-2010-1679)'''
        expected = 0
        self._test_malicious_unpack(expected, '/tmp/rooted.txt', 'v3/evilpackage_4-1.dsc')

    def test_cve_2014_0471(self):
        '''Does not unpack malicious package (CVE-2014-0471)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/moo',
                                    'CVE-2014-0471/evilpackage_4-1.dsc')

    def test_cve_2014_0471_2(self):
        '''Does not unpack malicious package (CVE-2014-0471) Test 2'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/moo',
                                    'CVE-2014-0471-2/evilpackage_4-1.dsc')

    def test_debbug746306(self):
        '''Correctly handles malicious package (Deb Bug #746306)'''

        if self.lsb_release['Release'] == 10.04:
            expected = 9
        elif self.lsb_release['Release'] == 12.04:
            expected = 25
        else:
            expected = 2

        self._test_malicious_unpack(expected,
                                    os.path.join(self.tempdir,
                                                 'i-should-not-be-here'),
                                    'debbug746306/exploto_0.1.dsc')

    def test_ghost_hunk(self):
        '''Correctly handles ghost hunk'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/ghost-hunk',
                                    'ghost-hunk/hello_2.4-3.dsc')

    def test_CVE_2014_3865_1(self):
        '''Correctly handles index with only +++ (CVE-2014-3865)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/index-file',
                                    'index-+++/hello_2.4-3.dsc')

    def test_CVE_2014_3865_2(self):
        '''Correctly handles index alone (CVE-2014-3865)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/index-file',
                                    'index-alone/hello_2.4-3.dsc')

    def test_CVE_2014_3864(self):
        '''Correctly handles partial header (CVE-2014-3864)'''
        expected = 29
        self._test_malicious_unpack(expected, '/tmp/partial-file',
                                    'partial/hello_2.4-3.dsc')

if __name__ == '__main__':
    # simple
    unittest.main()
