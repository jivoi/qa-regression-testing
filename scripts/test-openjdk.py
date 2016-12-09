#!/usr/bin/python
#
#    test-openjdk.py quality assurance test script for OpenJDK
#    Copyright (C) 2008-2012 Canonical Ltd.
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
    This is intended to be run via test-openjdk6.py or test-openjdk7.py
    TODO:
     - add volanomark
'''

import unittest, os, sys
import tempfile
import testlib
import testlib_browser

jdk = None

class OpenJDKTest(testlib.TestlibCase):
    '''Test eclipse'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        global jdk

        self.tmpdir = None
        self.cwd = os.getcwd()

        arch = testlib.get_arch()
        if arch == "x86_64":
            arch = "amd64"
        elif arch == "i686":
            arch = "i386"

        if self.lsb_release['Release'] >= 12.04:
            jdkpath = "/usr/lib/jvm/java-6-openjdk-%s/jre/lib" % arch
            if jdk == "openjdk-7":
                jdkpath = "/usr/lib/jvm/java-7-openjdk-%s/jre/lib" % arch
            elif jdk == "openjdk-8":
                jdkpath = "/usr/lib/jvm/java-8-openjdk-%s/jre/lib" % arch
        else:
            jdkpath = "/usr/lib/jvm/java-6-openjdk/jre/lib"
            if jdk == "openjdk-7":
                jdkpath = "/usr/lib/jvm/java-7-openjdk/jre/lib"
            elif jdk == "openjdk-8":
                jdkpath = "/usr/lib/jvm/java-8-openjdk-%s/jre/lib" % arch

        self.jdkpath = os.path.join(jdkpath, arch)

        # 'server' is the default for amd64 and 'client' for i386, but don't
        # list the default here. It will be used when applications are called
        # with no arguments. 'cacao' fails everywhere. 'jamvm' fails on 12.04
        # and higher
        self.vms = ['zero']
        if arch == "x86_64": # server is the default for amd64, so test client
            self.vms.append("client")
        else:                # client is the default for amd64, so test server
            self.vms.append("server")
        if self.lsb_release['Release'] < 12.04:
            self.vms.append('jamvm')

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.tmpdir is not None and os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)
        os.chdir(self.cwd)

    def test_aa_java_version(self):
        '''Test java version'''
        rc, report = testlib.cmd(['java', '-version'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        print >>sys.stdout, "$ java -version\n%s" % report
        sys.stdout.flush()

    def test_eclipse(self):
        '''Test eclipse'''
        print >>sys.stdout, "(For each test, create a new project and fiddle with stuff)"
        sys.stdout.flush()

        failures = dict()
        for i in ['default'] + self.vms:
            print >>sys.stdout, "  %s..." % i,
            sys.stdout.flush()

            vm = "%s/%s/libjvm.so" % (self.jdkpath, i)
            if i != 'default' and not os.path.exists(vm):
                print >>sys.stdout, "skipped (couldn't find %s)" % vm
                continue

            args = ['eclipse']
            if i != 'default':
                args.append('-vm')
                args.append(vm)
                #print >>sys.stdout, " (using %s)" % vm,
                sys.stdout.flush()

            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            if rc != expected:
                failures[i] = report
                print >>sys.stdout, "FAIL"
            else:
                print >>sys.stdout, "ok"

        result = ""
        for k in failures.keys():
            result += "\n= %s =\n%s\n\n" % (k, failures[k])
        self.assertTrue(len(failures) == 0, result)

    def test_netbeans(self):
        '''Test netbeans'''
        if self.lsb_release['Codename'] == "oneiric":
            return self._skipped("netbeans does not exist in 11.10")
        elif self.lsb_release['Codename'] == "utopic" or \
             self.lsb_release['Codename'] == "trusty" or \
             self.lsb_release['Codename'] == "precise" or \
             self.lsb_release['Codename'] == "lucid":
            return self._skipped("netbeans does not work on 10.04, 12.04 or 14.04")

        print >>sys.stdout, "(For each test, create a new project and fiddle with stuff)"
        sys.stdout.flush()

        failures = dict()
        for i in ['default'] + self.vms:
            print >>sys.stdout, "  %s..." % i,
            sys.stdout.flush()

            vm = "%s/%s/libjvm.so" % (self.jdkpath, i)
            if i != 'default' and not os.path.exists(vm):
                print >>sys.stdout, "skipped (couldn't find %s)" % vm
                continue

            args = ['netbeans']
            if i != 'default':
                args.append('-J-%s' % i)
                #print >>sys.stdout, " (using %s)" % vm,
                sys.stdout.flush()

            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            if rc != expected:
                failures[i] = report
                print >>sys.stdout, "FAIL"
            else:
                print >>sys.stdout, "ok"

        result = ""
        for k in failures.keys():
            result += "\n= %s =\n%s\n\n" % (k, failures[k])
        self.assertTrue(len(failures) == 0, result)

    # The yy_* tests should happen last to make sure we see the failures after
    # all the prompted manual tests
    def test_yy_regression_lp1283828(self):
        '''Test LP: #1283828'''
        contents = '''
/*
 * Copyright (c) 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 8017173
 * @summary Check that an XMLCipher with RSA_OAEP Key Transport algorithm can
 *    be instantiated
 * @compile -XDignore.symbol.file GetInstance.java
 * @run main GetInstance
 */
import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.encryption.XMLCipher;

public class GetInstance {

    private static final String RSA_OAEP =
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    public static void main(String[] args) throws Exception {
        Init.init();
        XMLCipher.getInstance(RSA_OAEP);
    }
}
'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib')
        java_fn = os.path.join(self.tmpdir, "GetInstance.java")
        testlib.create_fill(java_fn, contents, mode=0644)
        os.chdir(self.tmpdir)

        # compile the java file
        args = ['javac', '-XDignore.symbol.file', 'GetInstance.java']
        rc, report = testlib.cmd(args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

        # run the java file
        args = ['java', 'GetInstance']
        rc, report = testlib.cmd(args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue(report == "", "Unexpected output:\n%s" % report)

if __name__ == '__main__':

    import optparse
    parser = optparse.OptionParser()
    parser.add_option("--jdk", dest="jdk",
                      help="openjdk to test (default=openjdk-6",
                      metavar="OPENJDK",
                      default="openjdk-6")
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Verbose", action="store_true")
    (options, args) = parser.parse_args()

    jdk = options.jdk

    suite = unittest.TestSuite()

    # Our tests
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenJDKTest))

    # The browser tests
    testlib_browser.include_skipped = True
    testlib_browser.use_existing = False
    testlib_browser.exes = ['firefox', 'chromium-browser']
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestIcedTeaPlugin))

    # The other tests

    # Ignore options.verbose, we need '2' for the tests but want the option
    # since people are used to it.
    verbosity = 2

    rc = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

