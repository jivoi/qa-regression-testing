#!/usr/bin/python
#
#    test-telepathy-gabble.py quality assurance test script for PKG
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: build-essential pkg-config dbus-x11 python-twisted-words
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
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
     - See what is wrong with the Lucid and Karmic tests (there are a few
       failures)
'''


import unittest, subprocess, sys, os, tempfile
import testlib

try:
    from private.qrt.TelepathyGabble import PrivateTelepathyGabbleTest
except ImportError:
    class PrivateTelepathyGabbleTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TelepathyGabbleTest(testlib.TestlibCase, PrivateTelepathyGabbleTest):
    '''Test telepathy-gabble'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.builder = testlib.TestUser()
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)
        self.patch_system = "quiltv3"
        if self.lsb_release['Release'] < 10.10:
            self.patch_system = "cdbs"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_testsuite_setup(self):
        '''Test build test suite'''
        #subprocess.call(['bash'])
        os.environ['PYTHON'] = "/usr/bin/python"
        build_dir = testlib.prepare_source('telepathy-gabble', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)),
                                      self.patch_system)
        os.chdir(build_dir)

        print ""
        print "  make clean"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', 'clean'])

        print "  configure"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, './configure', '--prefix=%s' % self.tmpdir, '--enable-debug'])

        print "  make (will take a while)"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make'])

        print "  make check (will take a while)",
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if self.lsb_release['Release'] >= 10.10:
            self.assertEquals(expected, rc, result + report)

            search = "FAIL"
            self.assertFalse(search in report, "Found '%s' in:\n%s" % (search, report))

            print ""
        elif rc != expected:
            # FIXME
            print "WARN: make check failed with exit code '%s'" % (str(rc))

        search_terms = []
        if self.lsb_release['Release'] < 10.04:
            # FIXME
            search_terms.append('3 of 142 tests failed') # karmic
        elif self.lsb_release['Release'] < 10.10:
            # FIXME
            search_terms = ['4 of 9 tests failed']
            search_terms.append('All 147 tests passed') # lucid
        elif self.lsb_release['Release'] < 11.04:
            search_terms = ['All 9 tests passed']
            search_terms.append('All 199 tests passed') # maverick
        elif self.lsb_release['Release'] >= 11.04:
            search_terms = ['All 9 tests passed']
            search_terms.append('All 212 tests passed') # natty and higher

        for s in search_terms:
            self.assertTrue(s in report, "Could not find '%s' in:\n%s" % (s, report))

    def test_testsuite_zz_cleanup(self):
        '''Cleanup build test suite'''
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)

if __name__ == '__main__':
    # simple
    unittest.main()

