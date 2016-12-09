#!/usr/bin/python
#
#    test-libxml2.py quality assurance test script for libxml2
#    Copyright (C) 2008-2015 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
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

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release bzip2 libxml2-utils  && ./test-libxml2.py -v'
'''

# QRT-Depends: libxml2 results/libxml2 private/qrt/libxml2.py data
# QRT-Packages: bzip2 libxml2-utils libxml2-dev build-essential python-lxml gnome-doc-utils gettext

import unittest, sys, os, tempfile
import glob
import shutil
import testlib

try:
    from private.qrt.libxml2 import PrivateLibxml2Test
except ImportError:
    class PrivateLibxml2Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class Libxml2Test(testlib.TestlibCase, PrivateLibxml2Test):
    '''Test libxml2 parsing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.tempdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_basic_xml_parsing(self):
        '''Basic XML parsing'''
        os.chdir('libxml2/xmltest')
        rc, out = testlib.cmd(['./go.sh'])
        self.assertEquals(rc, 0, out)

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testlib-")
        fn = os.path.join(self.tempdir, "xmltest-basic.out")
        run_output = open(fn, 'w')
        run_output.write(out)
        run_output.flush()

        expected_output = os.path.join(self.tempdir, 'expected.xml')
        shutil.copy('../../results/libxml2/%s.xmltest' % (self.lsb_release['Codename']), expected_output)
        rc, report = testlib.cmd(['diff','-u',expected_output,run_output.name])
        expected = 0
        # after USN-1376-1, the output may be different due to hash table
        # randomization. Sometimes it is the same, sometimes not, so
        # account for that.
        if rc == 1:
            #print "INFO: patching expected results"
            testlib.config_patch(expected_output, '''
--- expected.xml.orig	2009-08-11 15:44:49.000000000 -0500
+++ expected.xml	2012-02-27 14:17:43.766397958 -0600
@@ -2704,8 +2704,8 @@
 Checking ./xmltest/valid/sa/076.xml ...
 <?xml version="1.0"?>
 <!DOCTYPE doc [
-<!NOTATION n1 SYSTEM "http://www.w3.org/" >
 <!NOTATION n2 SYSTEM "http://www.w3.org/" >
+<!NOTATION n1 SYSTEM "http://www.w3.org/" >
 <!ELEMENT doc (#PCDATA)>
 <!ATTLIST doc a NOTATION (n1 | n2) #IMPLIED>
 ]>
''')
            rc, report = testlib.cmd(['diff','-u',expected_output,run_output.name])

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(rc, expected, result + report)

    def test_basic_xmlcatalog_create(self):
        '''Basic xmlcatalog create'''
        os.chdir('libxml2/xmltest')
        rc, out = testlib.cmd(['./go-catalog.sh'])
        self.assertEquals(rc, 0, out)

        # Vivid gives a different result, but not worth fixing test
        if self.lsb_release['Release'] == 15.04:
            return

        run_output = tempfile.NamedTemporaryFile(prefix='xmltest-')
        run_output.write(out)
        run_output.flush()

        self.assertShellExitEquals(0, ['diff','-u','./xmlcatalog.result', run_output.name])

    def test_xml_testsuite(self):
        '''xml test suite'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testlib-")

        origdir = os.getcwd()

        version = "20080827"
        shutil.copy('./data/xmlts%s.tar.gz' % version, self.tempdir)
        os.chdir(self.tempdir)
        (rc, report) = testlib.cmd(["tar", "zxf", 'xmlts%s.tar.gz' % version])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        os.chdir(origdir)

        topdir = os.path.join(self.tempdir, "xmlconf")

        #
        # Valid xml
        #
        valid = []
        valid += glob.glob(os.path.join(topdir, 'ibm/valid/P*'))

        for d in ['xmltest/valid/ext-sa',
                  'xmltest/valid/not-sa',
                  'xmltest/valid/sa',
                  'sun/valid']:
            valid.append(os.path.join(topdir, d))

        count = 0
        passed = 0
        failures = 0
        expected_failures = 0
        expected_failures_fns = []
        if self.lsb_release['Release'] < 9.10 and self.lsb_release['Release'] > 6.06:
            expected_failures_fns.append('sun/valid/ext02.xml')

        print "\n valid/well-formed:"
        for d in valid:
            for f in os.listdir(d):
                if not f.endswith('.xml') and not f.endswith('.html'):
                    continue

                fn = os.path.join(d, f)
                (rc, report) = testlib.cmd(["xmllint", "--valid", fn])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                if expected == rc:
                    passed += 1
                else:
                    if fn.split(r''+topdir+'/')[1] in expected_failures_fns:
                        expected_failures += 1
                    else:
                        failures += 1
                        print "  FAIL: %s" % (fn)
                count += 1

        print "  %d passed (%d expected failures), %d failures out of %d files" % (passed, expected_failures, failures, count)
        self.assertTrue(failures == 0, "Found failures with valid content")

        #
        # Invalid xml
        #
        invalid = []
        invalid += glob.glob(os.path.join(topdir, 'ibm/invalid/P*'))

        for d in ['xmltest/invalid',
                  'xmltest/invalid/not-sa',
                  'sun/invalid',
                  ]:
            invalid.append(os.path.join(topdir, d))

        count = 0
        passed = 0
        failures = 0
        expected_failures = 0
        expected_failures_fns = ['ibm/invalid/P32/ibm32i03.xml',
                                 'sun/invalid/not-sa05.xml',
                                 'sun/invalid/not-sa06.xml',
                                 'sun/invalid/not-sa07.xml',
                                 'sun/invalid/not-sa09.xml',
                                 'sun/invalid/not-sa10.xml',
                                 'sun/invalid/not-sa11.xml',
                                 'sun/invalid/not-sa12.xml']

        if self.lsb_release['Release'] < 9.10:
            expected_failures_fns.append('ibm/invalid/P32/ibm32i01.xml')
            expected_failures_fns.append('xmltest/invalid/not-sa/022.xml')
            expected_failures_fns.append('sun/invalid/not-sa04.xml')

        print " invalid/not well-formed:"
        for d in invalid:
            for f in os.listdir(d):
                if not f.endswith('.xml') and not f.endswith('.html'):
                    continue

                fn = os.path.join(d, f)
                (rc, report) = testlib.cmd(["xmllint", "--valid", fn])
                unexpected = 0
                result = 'Got unexpected exit code %d\n' % (unexpected)
                if unexpected == rc:
                    if fn.split(r''+topdir+'/')[1] in expected_failures_fns:
                        expected_failures += 1
                    else:
                        failures += 1
                        print "  FAIL: %s" % (fn)
                else:
                    passed += 1
                count += 1

        print "  %d passed (%d expected failures), %d failures out of %d files" % (passed, expected_failures, failures, count)
        self.assertTrue(failures == 0, "Found failures with invalid content")
        result = "Found %d expected failures, should have had %d" % (expected_failures, len(expected_failures_fns))
        self.assertTrue(expected_failures == len(expected_failures_fns), result)

        #
        # Not well-formed xml
        #
        not_well_formed = []
        not_well_formed += glob.glob(os.path.join(topdir, 'ibm/not-wf/P*'))

        for d in ['ibm/not-wf/misc',
                  'xmltest/not-wf/ext-sa',
                  'xmltest/not-wf/not-sa',
                  'xmltest/not-wf/sa',
                  'sun/not-wf']:
            not_well_formed.append(os.path.join(topdir, d))

        count = 0
        passed = 0
        failures = 0
        expected_failures = 0
        expected_failures_fns = []
        if self.lsb_release['Release'] > 8.04:
            expected_failures_fns = [
                                 'ibm/not-wf/P89/ibm89n05.xml',
                                 'ibm/not-wf/P89/ibm89n03.xml',
                                 'ibm/not-wf/P89/ibm89n04.xml',
                                 'ibm/not-wf/P85/ibm85n126.xml',
                                 'ibm/not-wf/P85/ibm85n70.xml',
                                 'ibm/not-wf/P85/ibm85n161.xml',
                                 'ibm/not-wf/P85/ibm85n117.xml',
                                 'ibm/not-wf/P85/ibm85n14.xml',
                                 'ibm/not-wf/P85/ibm85n06.xml',
                                 'ibm/not-wf/P85/ibm85n93.xml',
                                 'ibm/not-wf/P85/ibm85n142.xml',
                                 'ibm/not-wf/P85/ibm85n23.xml',
                                 'ibm/not-wf/P85/ibm85n69.xml',
                                 'ibm/not-wf/P85/ibm85n190.xml',
                                 'ibm/not-wf/P85/ibm85n186.xml',
                                 'ibm/not-wf/P85/ibm85n32.xml',
                                 'ibm/not-wf/P85/ibm85n151.xml',
                                 'ibm/not-wf/P85/ibm85n26.xml',
                                 'ibm/not-wf/P85/ibm85n73.xml',
                                 'ibm/not-wf/P85/ibm85n63.xml',
                                 'ibm/not-wf/P85/ibm85n184.xml',
                                 'ibm/not-wf/P85/ibm85n107.xml',
                                 'ibm/not-wf/P85/ibm85n111.xml',
                                 'ibm/not-wf/P85/ibm85n141.xml',
                                 'ibm/not-wf/P85/ibm85n55.xml',
                                 'ibm/not-wf/P85/ibm85n121.xml',
                                 'ibm/not-wf/P85/ibm85n36.xml',
                                 'ibm/not-wf/P85/ibm85n31.xml',
                                 'ibm/not-wf/P85/ibm85n45.xml',
                                 'ibm/not-wf/P85/ibm85n167.xml',
                                 'ibm/not-wf/P85/ibm85n47.xml',
                                 'ibm/not-wf/P85/ibm85n96.xml',
                                 'ibm/not-wf/P85/ibm85n11.xml',
                                 'ibm/not-wf/P85/ibm85n98.xml',
                                 'ibm/not-wf/P85/ibm85n181.xml',
                                 'ibm/not-wf/P85/ibm85n135.xml',
                                 'ibm/not-wf/P85/ibm85n132.xml',
                                 'ibm/not-wf/P85/ibm85n153.xml',
                                 'ibm/not-wf/P85/ibm85n85.xml',
                                 'ibm/not-wf/P85/ibm85n52.xml',
                                 'ibm/not-wf/P85/ibm85n119.xml',
                                 'ibm/not-wf/P85/ibm85n77.xml',
                                 'ibm/not-wf/P85/ibm85n87.xml',
                                 'ibm/not-wf/P85/ibm85n60.xml',
                                 'ibm/not-wf/P85/ibm85n140.xml',
                                 'ibm/not-wf/P85/ibm85n139.xml',
                                 'ibm/not-wf/P85/ibm85n130.xml',
                                 'ibm/not-wf/P85/ibm85n50.xml',
                                 'ibm/not-wf/P85/ibm85n48.xml',
                                 'ibm/not-wf/P85/ibm85n30.xml',
                                 'ibm/not-wf/P85/ibm85n86.xml',
                                 'ibm/not-wf/P85/ibm85n162.xml',
                                 'ibm/not-wf/P85/ibm85n103.xml',
                                 'ibm/not-wf/P85/ibm85n35.xml',
                                 'ibm/not-wf/P85/ibm85n17.xml',
                                 'ibm/not-wf/P85/ibm85n171.xml',
                                 'ibm/not-wf/P85/ibm85n163.xml',
                                 'ibm/not-wf/P85/ibm85n61.xml',
                                 'ibm/not-wf/P85/ibm85n112.xml',
                                 'ibm/not-wf/P85/ibm85n09.xml',
                                 'ibm/not-wf/P85/ibm85n158.xml',
                                 'ibm/not-wf/P85/ibm85n78.xml',
                                 'ibm/not-wf/P85/ibm85n94.xml',
                                 'ibm/not-wf/P85/ibm85n131.xml',
                                 'ibm/not-wf/P85/ibm85n128.xml',
                                 'ibm/not-wf/P85/ibm85n21.xml',
                                 'ibm/not-wf/P85/ibm85n56.xml',
                                 'ibm/not-wf/P85/ibm85n106.xml',
                                 'ibm/not-wf/P85/ibm85n147.xml',
                                 'ibm/not-wf/P85/ibm85n71.xml',
                                 'ibm/not-wf/P85/ibm85n20.xml',
                                 'ibm/not-wf/P85/ibm85n41.xml',
                                 'ibm/not-wf/P85/ibm85n49.xml',
                                 'ibm/not-wf/P85/ibm85n80.xml',
                                 'ibm/not-wf/P85/ibm85n108.xml',
                                 'ibm/not-wf/P85/ibm85n134.xml',
                                 'ibm/not-wf/P85/ibm85n187.xml',
                                 'ibm/not-wf/P85/ibm85n127.xml',
                                 'ibm/not-wf/P85/ibm85n34.xml',
                                 'ibm/not-wf/P85/ibm85n150.xml',
                                 'ibm/not-wf/P85/ibm85n46.xml',
                                 'ibm/not-wf/P85/ibm85n65.xml',
                                 'ibm/not-wf/P85/ibm85n191.xml',
                                 'ibm/not-wf/P85/ibm85n68.xml',
                                 'ibm/not-wf/P85/ibm85n97.xml',
                                 'ibm/not-wf/P85/ibm85n51.xml',
                                 'ibm/not-wf/P85/ibm85n75.xml',
                                 'ibm/not-wf/P85/ibm85n64.xml',
                                 'ibm/not-wf/P85/ibm85n67.xml',
                                 'ibm/not-wf/P85/ibm85n152.xml',
                                 'ibm/not-wf/P85/ibm85n66.xml',
                                 'ibm/not-wf/P85/ibm85n156.xml',
                                 'ibm/not-wf/P85/ibm85n83.xml',
                                 'ibm/not-wf/P85/ibm85n12.xml',
                                 'ibm/not-wf/P85/ibm85n189.xml',
                                 'ibm/not-wf/P85/ibm85n25.xml',
                                 'ibm/not-wf/P85/ibm85n101.xml',
                                 'ibm/not-wf/P85/ibm85n27.xml',
                                 'ibm/not-wf/P85/ibm85n166.xml',
                                 'ibm/not-wf/P85/ibm85n122.xml',
                                 'ibm/not-wf/P85/ibm85n62.xml',
                                 'ibm/not-wf/P85/ibm85n146.xml',
                                 'ibm/not-wf/P85/ibm85n90.xml',
                                 'ibm/not-wf/P85/ibm85n172.xml',
                                 'ibm/not-wf/P85/ibm85n15.xml',
                                 'ibm/not-wf/P85/ibm85n137.xml',
                                 'ibm/not-wf/P85/ibm85n92.xml',
                                 'ibm/not-wf/P85/ibm85n37.xml',
                                 'ibm/not-wf/P85/ibm85n168.xml',
                                 'ibm/not-wf/P85/ibm85n175.xml',
                                 'ibm/not-wf/P85/ibm85n19.xml',
                                 'ibm/not-wf/P85/ibm85n169.xml',
                                 'ibm/not-wf/P85/ibm85n129.xml',
                                 'ibm/not-wf/P85/ibm85n88.xml',
                                 'ibm/not-wf/P85/ibm85n72.xml',
                                 'ibm/not-wf/P85/ibm85n144.xml',
                                 'ibm/not-wf/P85/ibm85n118.xml',
                                 'ibm/not-wf/P85/ibm85n149.xml',
                                 'ibm/not-wf/P85/ibm85n40.xml',
                                 'ibm/not-wf/P85/ibm85n104.xml',
                                 'ibm/not-wf/P85/ibm85n116.xml',
                                 'ibm/not-wf/P85/ibm85n53.xml',
                                 'ibm/not-wf/P85/ibm85n44.xml',
                                 'ibm/not-wf/P85/ibm85n03.xml',
                                 'ibm/not-wf/P85/ibm85n13.xml',
                                 'ibm/not-wf/P85/ibm85n195.xml',
                                 'ibm/not-wf/P85/ibm85n102.xml',
                                 'ibm/not-wf/P85/ibm85n76.xml',
                                 'ibm/not-wf/P85/ibm85n110.xml',
                                 'ibm/not-wf/P85/ibm85n198.xml',
                                 'ibm/not-wf/P85/ibm85n174.xml',
                                 'ibm/not-wf/P85/ibm85n89.xml',
                                 'ibm/not-wf/P85/ibm85n179.xml',
                                 'ibm/not-wf/P85/ibm85n193.xml',
                                 'ibm/not-wf/P85/ibm85n160.xml',
                                 'ibm/not-wf/P85/ibm85n58.xml',
                                 'ibm/not-wf/P85/ibm85n133.xml',
                                 'ibm/not-wf/P85/ibm85n124.xml',
                                 'ibm/not-wf/P85/ibm85n183.xml',
                                 'ibm/not-wf/P85/ibm85n165.xml',
                                 'ibm/not-wf/P85/ibm85n43.xml',
                                 'ibm/not-wf/P85/ibm85n159.xml',
                                 'ibm/not-wf/P85/ibm85n192.xml',
                                 'ibm/not-wf/P85/ibm85n29.xml',
                                 'ibm/not-wf/P85/ibm85n84.xml',
                                 'ibm/not-wf/P85/ibm85n120.xml',
                                 'ibm/not-wf/P85/ibm85n113.xml',
                                 'ibm/not-wf/P85/ibm85n115.xml',
                                 'ibm/not-wf/P85/ibm85n39.xml',
                                 'ibm/not-wf/P85/ibm85n197.xml',
                                 'ibm/not-wf/P85/ibm85n105.xml',
                                 'ibm/not-wf/P85/ibm85n182.xml',
                                 'ibm/not-wf/P85/ibm85n38.xml',
                                 'ibm/not-wf/P85/ibm85n57.xml',
                                 'ibm/not-wf/P85/ibm85n04.xml',
                                 'ibm/not-wf/P85/ibm85n173.xml',
                                 'ibm/not-wf/P85/ibm85n164.xml',
                                 'ibm/not-wf/P85/ibm85n16.xml',
                                 'ibm/not-wf/P85/ibm85n176.xml',
                                 'ibm/not-wf/P85/ibm85n54.xml',
                                 'ibm/not-wf/P85/ibm85n196.xml',
                                 'ibm/not-wf/P85/ibm85n24.xml',
                                 'ibm/not-wf/P85/ibm85n18.xml',
                                 'ibm/not-wf/P85/ibm85n138.xml',
                                 'ibm/not-wf/P85/ibm85n07.xml',
                                 'ibm/not-wf/P85/ibm85n194.xml',
                                 'ibm/not-wf/P85/ibm85n59.xml',
                                 'ibm/not-wf/P85/ibm85n145.xml',
                                 'ibm/not-wf/P85/ibm85n185.xml',
                                 'ibm/not-wf/P85/ibm85n08.xml',
                                 'ibm/not-wf/P85/ibm85n136.xml',
                                 'ibm/not-wf/P85/ibm85n188.xml',
                                 'ibm/not-wf/P85/ibm85n148.xml',
                                 'ibm/not-wf/P85/ibm85n33.xml',
                                 'ibm/not-wf/P85/ibm85n95.xml',
                                 'ibm/not-wf/P85/ibm85n82.xml',
                                 'ibm/not-wf/P85/ibm85n10.xml',
                                 'ibm/not-wf/P85/ibm85n22.xml',
                                 'ibm/not-wf/P85/ibm85n170.xml',
                                 'ibm/not-wf/P85/ibm85n143.xml',
                                 'ibm/not-wf/P85/ibm85n79.xml',
                                 'ibm/not-wf/P85/ibm85n177.xml',
                                 'ibm/not-wf/P85/ibm85n91.xml',
                                 'ibm/not-wf/P85/ibm85n178.xml',
                                 'ibm/not-wf/P85/ibm85n05.xml',
                                 'ibm/not-wf/P85/ibm85n154.xml',
                                 'ibm/not-wf/P85/ibm85n114.xml',
                                 'ibm/not-wf/P85/ibm85n180.xml',
                                 'ibm/not-wf/P85/ibm85n155.xml',
                                 'ibm/not-wf/P85/ibm85n123.xml',
                                 'ibm/not-wf/P85/ibm85n100.xml',
                                 'ibm/not-wf/P85/ibm85n99.xml',
                                 'ibm/not-wf/P85/ibm85n109.xml',
                                 'ibm/not-wf/P85/ibm85n28.xml',
                                 'ibm/not-wf/P85/ibm85n74.xml',
                                 'ibm/not-wf/P85/ibm85n81.xml',
                                 'ibm/not-wf/P85/ibm85n42.xml',
                                 'ibm/not-wf/P85/ibm85n157.xml',
                                 'ibm/not-wf/P85/ibm85n125.xml',
                                 'ibm/not-wf/P86/ibm86n04.xml',
                                 'ibm/not-wf/P86/ibm86n03.xml',
                                 'ibm/not-wf/P86/ibm86n02.xml',
                                 'ibm/not-wf/P86/ibm86n01.xml',
                                 'ibm/not-wf/P87/ibm87n10.xml',
                                 'ibm/not-wf/P87/ibm87n37.xml',
                                 'ibm/not-wf/P87/ibm87n14.xml',
                                 'ibm/not-wf/P87/ibm87n64.xml',
                                 'ibm/not-wf/P87/ibm87n29.xml',
                                 'ibm/not-wf/P87/ibm87n31.xml',
                                 'ibm/not-wf/P87/ibm87n38.xml',
                                 'ibm/not-wf/P87/ibm87n52.xml',
                                 'ibm/not-wf/P87/ibm87n28.xml',
                                 'ibm/not-wf/P87/ibm87n57.xml',
                                 'ibm/not-wf/P87/ibm87n53.xml',
                                 'ibm/not-wf/P87/ibm87n32.xml',
                                 'ibm/not-wf/P87/ibm87n60.xml',
                                 'ibm/not-wf/P87/ibm87n63.xml',
                                 'ibm/not-wf/P87/ibm87n08.xml',
                                 'ibm/not-wf/P87/ibm87n11.xml',
                                 'ibm/not-wf/P87/ibm87n85.xml',
                                 'ibm/not-wf/P87/ibm87n24.xml',
                                 'ibm/not-wf/P87/ibm87n50.xml',
                                 'ibm/not-wf/P87/ibm87n23.xml',
                                 'ibm/not-wf/P87/ibm87n16.xml',
                                 'ibm/not-wf/P87/ibm87n02.xml',
                                 'ibm/not-wf/P87/ibm87n39.xml',
                                 'ibm/not-wf/P87/ibm87n51.xml',
                                 'ibm/not-wf/P87/ibm87n77.xml',
                                 'ibm/not-wf/P87/ibm87n49.xml',
                                 'ibm/not-wf/P87/ibm87n43.xml',
                                 'ibm/not-wf/P87/ibm87n27.xml',
                                 'ibm/not-wf/P87/ibm87n09.xml',
                                 'ibm/not-wf/P87/ibm87n03.xml',
                                 'ibm/not-wf/P87/ibm87n07.xml',
                                 'ibm/not-wf/P87/ibm87n61.xml',
                                 'ibm/not-wf/P87/ibm87n62.xml',
                                 'ibm/not-wf/P87/ibm87n48.xml',
                                 'ibm/not-wf/P87/ibm87n36.xml',
                                 'ibm/not-wf/P87/ibm87n78.xml',
                                 'ibm/not-wf/P87/ibm87n70.xml',
                                 'ibm/not-wf/P87/ibm87n44.xml',
                                 'ibm/not-wf/P87/ibm87n75.xml',
                                 'ibm/not-wf/P87/ibm87n06.xml',
                                 'ibm/not-wf/P87/ibm87n30.xml',
                                 'ibm/not-wf/P87/ibm87n66.xml',
                                 'ibm/not-wf/P87/ibm87n18.xml',
                                 'ibm/not-wf/P87/ibm87n81.xml',
                                 'ibm/not-wf/P87/ibm87n74.xml',
                                 'ibm/not-wf/P87/ibm87n80.xml',
                                 'ibm/not-wf/P87/ibm87n58.xml',
                                 'ibm/not-wf/P87/ibm87n35.xml',
                                 'ibm/not-wf/P87/ibm87n83.xml',
                                 'ibm/not-wf/P87/ibm87n34.xml',
                                 'ibm/not-wf/P87/ibm87n72.xml',
                                 'ibm/not-wf/P87/ibm87n05.xml',
                                 'ibm/not-wf/P87/ibm87n22.xml',
                                 'ibm/not-wf/P87/ibm87n12.xml',
                                 'ibm/not-wf/P87/ibm87n82.xml',
                                 'ibm/not-wf/P87/ibm87n33.xml',
                                 'ibm/not-wf/P87/ibm87n45.xml',
                                 'ibm/not-wf/P87/ibm87n25.xml',
                                 'ibm/not-wf/P87/ibm87n19.xml',
                                 'ibm/not-wf/P87/ibm87n20.xml',
                                 'ibm/not-wf/P87/ibm87n73.xml',
                                 'ibm/not-wf/P87/ibm87n59.xml',
                                 'ibm/not-wf/P87/ibm87n40.xml',
                                 'ibm/not-wf/P87/ibm87n55.xml',
                                 'ibm/not-wf/P87/ibm87n84.xml',
                                 'ibm/not-wf/P87/ibm87n69.xml',
                                 'ibm/not-wf/P87/ibm87n41.xml',
                                 'ibm/not-wf/P87/ibm87n21.xml',
                                 'ibm/not-wf/P87/ibm87n67.xml',
                                 'ibm/not-wf/P87/ibm87n01.xml',
                                 'ibm/not-wf/P87/ibm87n71.xml',
                                 'ibm/not-wf/P87/ibm87n42.xml',
                                 'ibm/not-wf/P87/ibm87n68.xml',
                                 'ibm/not-wf/P87/ibm87n13.xml',
                                 'ibm/not-wf/P87/ibm87n17.xml',
                                 'ibm/not-wf/P87/ibm87n54.xml',
                                 'ibm/not-wf/P87/ibm87n04.xml',
                                 'ibm/not-wf/P87/ibm87n56.xml',
                                 'ibm/not-wf/P87/ibm87n79.xml',
                                 'ibm/not-wf/P87/ibm87n15.xml',
                                 'ibm/not-wf/P87/ibm87n76.xml',
                                 'ibm/not-wf/P87/ibm87n26.xml',
                                 'ibm/not-wf/P87/ibm87n46.xml',
                                 'ibm/not-wf/P87/ibm87n47.xml',
                                 'ibm/not-wf/P88/ibm88n05.xml',
                                 'ibm/not-wf/P88/ibm88n08.xml',
                                 'ibm/not-wf/P88/ibm88n09.xml',
                                 'ibm/not-wf/P88/ibm88n15.xml',
                                 'ibm/not-wf/P88/ibm88n04.xml',
                                 'ibm/not-wf/P88/ibm88n13.xml',
                                 'ibm/not-wf/P88/ibm88n16.xml',
                                 'ibm/not-wf/P88/ibm88n14.xml',
                                 'ibm/not-wf/P88/ibm88n10.xml',
                                 'ibm/not-wf/P88/ibm88n06.xml',
                                 'ibm/not-wf/P88/ibm88n03.xml',
                                 'ibm/not-wf/P88/ibm88n11.xml',
                                 'ibm/not-wf/P88/ibm88n12.xml',
                                 'ibm/not-wf/misc/432gewf.xml',
                                 'xmltest/not-wf/not-sa/011.xml',
                                ]

        if self.lsb_release['Release'] < 9.10:
            expected_failures_fns.append('xmltest/not-wf/not-sa/009.xml')
            expected_failures_fns.append('xmltest/not-wf/not-sa/011.xml')
            expected_failures_fns.append('ibm/not-wf/misc/432gewf.xml')

        if self.lsb_release['Release'] < 8.04:
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n18.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n06.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n09.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n26.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n27.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n12.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n24.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n14.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n20.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n23.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n29.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n03.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n05.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n02.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n25.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n10.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n11.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n07.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n19.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n16.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n04.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n15.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n08.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n13.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n21.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n17.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n28.xml')
            expected_failures_fns.append('ibm/not-wf/P02/ibm02n22.xml')


        print " not well-formed:"
        for d in not_well_formed:
            for f in os.listdir(d):
                if not f.endswith('.xml') and not f.endswith('.html'):
                    continue

                fn = os.path.join(d, f)
                (rc, report) = testlib.cmd(["xmllint", "--valid", fn])
                unexpected = 0
                result = 'Got unexpected exit code %d\n' % (unexpected)
                if unexpected == rc:
                    if fn.split(r''+topdir+'/')[1] in expected_failures_fns:
                        expected_failures += 1
                    else:
                        failures += 1
                        print "  FAIL: %s" % (fn)
                else:
                    passed += 1
                count += 1

        print "  %d passed (%d expected failures), %d failures out of %d files" % (passed, expected_failures, failures, count)
        self.assertTrue(failures == 0, "Found failures with not well-formed content")
        result = "Found %d expected failures, should have had %d" % (expected_failures, len(expected_failures_fns))
        self.assertTrue(expected_failures == len(expected_failures_fns), result)

    def test_lp686363(self):
        '''Test LP: #686363'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testlib-")
        shutil.copy('./libxml2/upstream-638618.c', self.tempdir)
        source = os.path.join(self.tempdir, 'upstream-638618.c')
        binary = os.path.join(self.tempdir, 'upstream-638618')

        rc, report = testlib.cmd(['xml2-config', '--cflags'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        cflags = report.split()

        rc, report = testlib.cmd(['xml2-config', '--libs'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        libs = report.split()

        rc, report = testlib.cmd(['gcc', source, '-o', binary] + cflags + libs)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if self.lsb_release['Release'] < 12.04 and rc != expected:
            self._skipped("XFAIL until LP: #686363 is backported to this release")
        else:
            self.assertEquals(expected, rc, result + report)

    def test_cve_2013_0338(self):
        '''Test Entities Expansion DoS (CVE-2013-0338)'''

        rc, report = testlib.cmd(['xmllint', '--noent', './libxml2/CVE-2013-0338.xml'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

    def test_lp1201849(self):
        '''Test LP: #1201849'''

        rc, report = testlib.cmd(['./libxml2/lp1201849.py'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

    def test_lp1321869(self):
        '''Test LP: #1321869'''

        rc, report = testlib.cmd(['xmllint', '--valid', '--noout',
                                  '--dtdvalid', './libxml2/lp1321869/a.dtd',
                                  './libxml2/lp1321869/a.xml'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

        rc, report = testlib.cmd(['xmllint', '--postvalid', '--noout',
                                  '--dtdvalid', './libxml2/lp1321869/a.dtd',
                                  './libxml2/lp1321869/a.xml'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

    def test_lp1321869_2(self):
        '''Test LP: #1321869 #2'''

        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="testlib-")
        output = os.path.join(self.tempdir, 'output.xml')
        os.chdir('libxml2/lp1321869-2')

        rc, report = testlib.cmd(['xml2po', '-e', '-p', 'fi.po',
                                  '-o', output, 'test.xml'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

        rc, report = testlib.cmd(['xmllint', '--noout', '--xinclude',
                                  '--noent', '--postvalid', output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

        bad_error = 'parser error'
        result = 'Found %s in output: "%s"' % (bad_error, report)
        self.assertFalse(bad_error in report, result)

if __name__ == '__main__':
    unittest.main()
