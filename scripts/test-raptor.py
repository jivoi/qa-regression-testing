#!/usr/bin/python
#
#    test-raptor.py quality assurance test script for raptor
#    Copyright (C) 2012-2013 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: raptor-utils build-essential dpkg-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/Raptor.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-raptor.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-raptor.py -v'
'''


import unittest, subprocess, sys, os
import tempfile
import testlib

# Support testing both raptor and raptor2
app = ''

try:
    from private.qrt.Raptor import PrivateRaptorTest
except ImportError:
    class PrivateRaptorTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class RaptorTest(testlib.TestlibCase, PrivateRaptorTest):
    '''Test raptor.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.builder = None
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = None
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)

    def test_version(self):
        '''Test version'''
        rc, report = testlib.cmd(['rapper', '-v'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2012_0037(self):
        '''Test CVE-2012-0037'''
        fn_entity = os.path.join(self.tmpdir, "ent.txt")
        s_entity = 'testlib string ABCDEFGHIJ'
        contents = "!!%s!!\n" % s_entity
        testlib.create_fill(fn_entity, contents)

        fn = os.path.join(self.tmpdir, "xmlent1.rdf")
        contents = '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE rdf [
   <!ENTITY myentity SYSTEM "%s">
]>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="http://example.org/">
    <ns0:comment xmlns:ns0="http://www.w3.org/2000/01/rdf-schema#">&myentity;</ns0:comment>
  </rdf:Description>
</rdf:RDF>
''' % (os.path.basename(fn_entity))
        testlib.create_fill(fn, contents)

        os.chdir(self.tmpdir)
        rc, report = testlib.cmd(['rapper', '-q', '-i', 'rdfxml', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "http://example.org/"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

        self.assertFalse(s_entity in report, "Found '%s' in report:\n%s" % (s_entity, report))


    def test_testsuite(self):
        '''Test testsuite'''
        # useful for testing (ie get shell after setUp())
        #subprocess.call(['bash'])

        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

        build_dir = testlib.prepare_source(app, \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        print ""
        print "  clean"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'clean'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  build"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'fakeroot', 'debian/rules', 'build'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  tests"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # raptor has a few expected failures in the rdfa testsuite and a couple
        # other places
        efails = ['Checking 0094.xhtml FAILED',
                  'Checking 0101.xhtml FAILED',
                  'Checking 0102.xhtml FAILED',
                  'Checking 0103.xhtml FAILED',
                  'Checking bad-15.rdf FAILED - parsing succeeded but should have failed (NFC test)',
                  'Checking bad-16.rdf FAILED - parsing succeeded but should have failed (NFC test)',
                  'Checking bad-17.rdf FAILED - parsing succeeded but should have failed (NFC test)',
                  '4 tests FAILED:  0094.xhtml 0101.xhtml 0102.xhtml 0103.xhtml',
                 ]

        failure_txt = ""
        for line in report.splitlines():
            if line in efails:
                continue
            if "FAIL" in line:
                failure_txt += line + "\n"

        self.assertTrue(failure_txt == "", "Found failures in report:\n%s\nLines with failures (besides '%s'):\n%s" % (report, ",".join(efails), failure_txt))

if __name__ == '__main__':

    # You can run this normally, which will run raptor, or run it for
    # raptor2 by specifying raptor2 on the command line. Alternatively, you
    # can also use the test-raptor2.py test script.
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        app = 'raptor'
    else:
        app = sys.argv[1]
        del sys.argv[1]

    print "Using binary: %s" % app

    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RaptorTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
