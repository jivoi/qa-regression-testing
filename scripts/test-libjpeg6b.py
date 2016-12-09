#!/usr/bin/python
#
#    test-libjpeg6b.py quality assurance test script for libjpeg6b
#    Copyright (C) 2013 Canonical Ltd.
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
# QRT-Packages: libjpeg-progs dpatch
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data libjpeg
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
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''

import os
import subprocess
import sys
import unittest
import testlib
import tempfile

use_private = True
try:
    from private.qrt.libjpeg6b import Libjpeg6bPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"


class Libjpeg6bTest(testlib.TestlibCase):
    '''Test libjpeg6b.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(dir='/tmp',prefix="libjpeg6b-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_cjpeg(self):
        '''Test cjpeg utility'''

        samples = ( 'well-formed.ppm', )

        for infile in samples:
            outfilename = os.path.join(self.tmpdir, infile[:infile.find('.')+1] + "jpg")

            (rc, report) = testlib.cmd(["/bin/sh", "-c",
                                        "cjpeg ./data/" + infile + " > " + outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(outfilename, 'JPEG image data, JFIF standard 1.01')

    def test_djpeg(self):
        '''Test djpeg utility'''

        samples = (
                    ('.bmp', '-bmp', 'PC bitmap, Windows 3.x format, 80 x 72 x 24'),
                    ('.gif', '-gif', 'GIF image data, version 87a, 80 x 72'),
                    ('.pnm', '-pnm', 'Netpbm PPM "rawbits" image data')
                  )

        for fileext, option, mimetype in samples:
            outfilename = os.path.join(self.tmpdir, "output" + fileext)

            (rc, report) = testlib.cmd(["/bin/sh", "-c",
                                        "djpeg " + option + " ./data/well-formed.jpg > " + outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(outfilename, mimetype)

    def test_jpegtran(self):
        '''Test jpegtran utility'''

        samples = (
                    ('.1.jpg', '-optimize', 'JPEG image data, JFIF standard 1.01'),
                    ('.2.jpg', '-progressive', 'JPEG image data, JFIF standard 1.01'),
                    ('.3.jpg', '-grayscale', 'JPEG image data, JFIF standard 1.01')
                  )

        for fileext, option, mimetype in samples:
            outfilename = os.path.join(self.tmpdir, "output" + fileext)

            (rc, report) = testlib.cmd(["/bin/sh", "-c",
                                        "jpegtran " + option + " ./data/well-formed.jpg > " + outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(outfilename, mimetype)

    def test_cve_2013_6629(self):
        '''Test CVE-2013-6629'''

        outfilename = os.path.join(self.tmpdir, "output-6629.jpg")

        sample = "./libjpeg/CVE-2013-6629/55.jpg"

        (rc, report) = testlib.cmd(["/bin/sh", "-c",
                                    "jpegtran -grayscale " + sample + " > " + outfilename])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_error = "Invalid component ID 3 in SOS"
        result = 'Could not find "%s" in report "%s"\n' % (expected_error, report)
        self.assertTrue(expected_error in report, result)

    def test_cve_2013_6630(self):
        '''Test CVE-2013-6630'''

        outfilename = os.path.join(self.tmpdir, "output-6630.jpg")

        sample = "./libjpeg/CVE-2013-6630/turbo-dht.jpg"

        (rc, report) = testlib.cmd(["/bin/sh", "-c",
                                    "jpegtran -grayscale " + sample + " > " + outfilename])
        expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_error = "Corrupt JPEG data: bad Huffman code"
        result = 'Could not find "%s" in report "%s"\n' % (expected_error, report)
        self.assertTrue(expected_error in report, result)


class Libjpeg6bTestSuite(testlib.TestlibCase):
    '''Testsuite for libjpeg6b.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.tmpdir = tempfile.mkdtemp(prefix='libjpeg6b', dir='/tmp')
        self.builder = testlib.TestUser()
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)
        self.patch_system = "quiltv3"
        if self.lsb_release['Release'] == 10.04:
            self.patch_system = "dpatch"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)

    def test_testsuite(self):
        '''(TestSuite) internal test suite'''

        build_dir = testlib.prepare_source('libjpeg6b', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)),
                                      self.patch_system)
        os.chdir(build_dir)

        package_version = testlib.get_changelog_version(build_dir)

        print ""
        print "Package version is %s" % package_version
        print "  clean"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'clean'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  build (this will take a while)"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'build'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  tests (this will take considerably longer)"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', '-C', build_dir, 'test'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':

    ubuntu_version = testlib.manager.lsb_release["Release"]

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Libjpeg6bTestSuite))

    # only lucid has libjpeg-progs from libjpeg6b...the later releases
    # will actually pull in the tools from libjpeg-turbo
    if ubuntu_version == 10.04:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Libjpeg6bTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Libjpeg6bPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
