#!/usr/bin/python
#
#    test-nss.py quality assurance test script for nss
#    Copyright (C) 2013 Canonical Ltd.
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
# QRT-Packages: libnss3
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: libnss3-1d
# files and directories required for the test to run:
# QRT-Depends: nss/ private/qrt/nss.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-nss.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-nss.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-nss.tar.gz
    # cd /tmp/qrt-test-nss ; ./install-packages ./test-nss.py
    # ./test-nss.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-nss.py>

    TODO: enable the testsuite. See QRT/notes_testing/nss/README for details
'''

import unittest
import glob
import os
import shutil
#import sys
import testlib
import tempfile

#try:
#    from private.qrt.nss import PrivateNssTest
#except ImportError:
#    class PrivateNssTest(object):
#        '''Empty class'''
#    print >>sys.stdout, "Skipping private tests"

#class PkgNss(testlib.TestlibCase, PrivateNssTest):
class PkgNss(testlib.TestlibCase):
    '''Test nss'''

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
            self.patch_system = "quilt"

        # Some tests needs tools that are built but not shipped in packages so
        # let's keep the build_dir around for them
        self.cached_build_topdir = os.path.join(self.topdir, "build")

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _get_cached_build_dir(self):
        '''Find the cached build dir'''
        build_dir = None
        if os.path.exists(self.cached_build_topdir):
            build_dir = glob.glob('%s/nss-*' % self.cached_build_topdir)[0]
        return build_dir

    def test_aa_build_source(self):
        '''Build nss'''
        if os.path.exists(self.cached_build_topdir):
            print ""
            build_dir = self._get_cached_build_dir()
            print "  using cached build: %s" % build_dir
            return

        build_dir = testlib.prepare_source('nss', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)),
                                      self.patch_system)
        os.chdir(build_dir)

        print ""
        print "  debian/rules clean"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'clean'])

        print "  debian/rules build (this may take a while)"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'build'])

        self.cached_build_dir = os.path.join(self.cached_build_topdir, os.path.basename(build_dir))
        os.makedirs(self.cached_build_topdir)
        shutil.move(build_dir, self.cached_build_dir)

        os.chdir(self.topdir)

    def test_turktrust_revocation(self):
        '''Test TURKTRUST revocation'''
        build_dir = self._get_cached_build_dir()
        vfychain = glob.glob('%s/mozilla/dist/bin/vfychain' % build_dir)[0]
        #import subprocess
        #subprocess.call(['sudo', '-u', self.builder.login, 'bash'])
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login,
                                  vfychain,
                                  '-u', '1', # usage: SSL server
                                  './nss/turktrust/turktrust-google-1.der',
                                  './nss/turktrust/turktrust-google-2.der',
                                  './nss/turktrust/turktrust-google-3.der'
                                 ])
        self.assertFalse(rc == 0, "Exited with '0':\n%s" % report)

        rc, report = testlib.cmd(['sudo', '-u', self.builder.login,
                                  vfychain,
                                  '-u', '3', # usage: usage: SSL Server CA
                                  './nss/turktrust/turktrust-intermediate-2.der',
                                  './nss/turktrust/turktrust-google-3.der'
                                 ])
        self.assertFalse(rc == 0, "Exited with '0':\n%s" % report)

    def _test_zz_cleanup_build(self):
        '''Cleanup caches'''
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)
        if os.path.exists(self.cached_build_topdir):
            testlib.recursive_rm(self.cached_build_topdir)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
