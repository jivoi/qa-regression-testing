#!/usr/bin/python
#
#    test-rng.py quality assurance test script for rng (Random Number
#    Generator)
#    Copyright (C) 2009 Canonical Ltd.
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install bind9utils openssl gnutls-bin openssh-client rng-tools sudo libssl-dev dieharder && ./test-rng.py -v'

    Can also run with:
    $ ./test-rng.py --all (same as './test-rng.py -v')
    $ ./test-rng.py --all --report
    $ ./test-rng.py -t help
    $ ./test-rng.py -t collide
    $ ./test-rng.py -t dieharder

    TODO:
     - libgcrypt specific test (though certtool uses it)
'''

# QRT-Depends: rng-tools
# QRT-Packages: bind9utils openssl gnutls-bin openssh-client rng-tools sudo libssl-dev dieharder libgnutls-dev build-essential

show_report = False

import unittest, sys, os
import tempfile
import testlib

class RngTest(testlib.TestlibCase):
    '''Test Random Number Generator for generated collisions'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.tries = 1000000
        self.tmpdir = tempfile.mkdtemp(prefix='test-rng', dir='/tmp')

    def _tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _report(self, pkgs):
        '''Show a versions report for the packages'''
        global show_report

        if show_report:
            print ""
            print "  Release: %s\n  Checked packages:" % (str(self.lsb_release['Release']))
            for p in pkgs:
                if p == "linux":
                    rc, report = testlib.cmd(["cat", "/proc/version_signature"])
                    report = "Linux: " + report
                else:
                    rc, report = testlib.cmd(['dpkg-query', '-W', '-f=    ${Package}: ${Version}', p])
                print report

    def _start_rngd(self):
        '''Start rngd with /dev/urandom'''
        rc, report = testlib.cmd(['pgrep', '-l', '-u', 'root', 'rngd'])
        if rc == 0:
            return self._skipped("Not starting rngd: already running")

        self.announce("Starting rngd...")
        rc, report = testlib.cmd(['sudo', 'rngd', '-r', '/dev/urandom'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class OpenSSLRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self._report(['openssl', 'libssl0.9.8'])

    def test_openssl(self):
        '''Test openssl'''
        for type in ['RSA', 'DSA']:
            rc, report = testlib.cmd(['./rng/openssl.sh', str(self.tries), type, '1024', self.tmpdir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

class GnuTLSRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        pkgs = ['gnutls-bin', 'libgcrypt11']
        if self.lsb_release['Release'] == 6.06:
            pkgs.append('libgnutls12')
        elif self.lsb_release['Release'] >= 7.10 and self.lsb_release['Release'] < 8.10:
            pkgs.append('libgnutls13')
        else:
            pkgs.append('libgnutls26')
        self._report(pkgs)

    def test_gnutls(self):
        '''Test gnutls'''
        for type in ['RSA', 'DSA']:
            rc, report = testlib.cmd(['./rng/certtool.sh', str(self.tries), type, '1024', self.tmpdir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

class GnuPGRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()
        self._start_rngd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self._report(['gnupg'])

    def test_gpg(self):
        '''Test gnupg'''
        for type in ['RSA', 'DSA']:
            rc, report = testlib.cmd(['./rng/gnupg.sh', str(self.tries), type, '1024', self.tmpdir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

class DNSSECRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self._report(['bind9utils'])

    def test_dnssec(self):
        '''Test dnssec-keygen'''
        rc, report = testlib.cmd(['./rng/dnssec-keygen.sh', str(self.tries), 'RSASHA1', '1024', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class SshRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self._report(['openssh-client'])

    def test_ssh(self):
        '''Test ssh-keygen'''
        for type in ['RSA', 'DSA']:
            rc, report = testlib.cmd(['./rng/ssh-keygen.sh', str(self.tries), type, '1024', self.tmpdir])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

class KernelRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        self._report(['linux'])

    def test_random(self):
        '''Test /dev/random'''
        self._start_rngd()

        rc, report = testlib.cmd(['./rng/kernel.sh', str(self.tries), '/dev/random', '1024', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_urandom(self):
        '''Test /dev/urandom'''
        rc, report = testlib.cmd(['./rng/kernel.sh', str(self.tries), '/dev/urandom', '1024', self.tmpdir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class LibgcryptRngTest(RngTest):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def test_libgcrypt(self):
        '''Test libgcrypt'''
        return self._skipped("TODO")

class DieharderRngTest(testlib.TestlibCase):
    '''Test Random Number Generator with "dieharder"'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('rng')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _test_dieharder(self, generator, xfail=[]):
        results = 0
        failures = 0
        self.assertShellExitEquals(0, ["make"])
        rc, output = testlib.cmd(["./dieharder.sh", generator])
        self.assertEquals(rc, 0, "dieharder failed to run:\n" + output)
        report = ""
        for chunk in output.split("\n\n"):
            if '\nAssessment: ' in chunk:
                results += 1

                status = chunk.split('\nAssessment: ', 1)[1].split('\n')[0]
                state = status.split()[0]
                if state != "PASSED":
                    details, name = status.split(" for ", 1)
                    if name in xfail:
                        self.announce('XFAIL %s: %s' % (name, details))
                    else:
                        failures += 1
                        report += chunk
        self.assertTrue(results > 0, "Did not see results:\n" + output)
        self.announce("%d tests" % (results))
        self.assertEquals(failures, 0, "Saw RNG failures:\n" + report)

class DieharderKernelRngTest(DieharderRngTest):
    '''Test dieharder against kernel RNG'''
    def test_generator(self):
        '''Clean run of dieharder against kernel RNG'''
        self._test_dieharder("kernel")

class DieharderGlibcRngTest(DieharderRngTest):
    '''Test dieharder against glibc RNG'''
    def test_generator(self):
        '''Clean run of dieharder against glibc RNG'''
        self._test_dieharder("glibc", ['Diehard Birthdays Test','RGB Permutations Test'])

class DieharderOpenSSLRngTest(DieharderRngTest):
    '''Test dieharder against OpenSSL RNG'''
    def test_generator(self):
        '''Clean run of dieharder against OpenSSL RNG'''
        self._test_dieharder("openssl", ['Diehard Birthdays Test','RGB Permutations Test'])

class DieharderGnuTLSRngTest(DieharderRngTest):
    '''Test dieharder against GnuTLS RNG'''
    def test_generator(self):
        '''Clean run of dieharder against GnuTLS RNG'''
        self._test_dieharder("gnutls")


if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-t", "--test", dest="tests", help="Test name (use 'help' to see a list)", metavar="NAME", action="append")
    parser.add_option("-a", "--all", dest="all", help="Run all tests", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-r", "--report", dest="report", help="Report installed packages", action="store_true")
    (options, args) = parser.parse_args()

    if options.report:
        show_report = True

    # put kernel and gnupg first, since it uses sudo and may prompt
    collide_tests = ['collide-kernel', 'collide-gnupg', 'collide-openssh', 'collide-openssl', 'collide-gnutls', 'collide-dnssec']
    dieharder_tests = ['dieharder-kernel','dieharder-glibc','dieharder-openssl','dieharder-gnutls']
    all_tests = collide_tests + dieharder_tests
    tests = all_tests
    if options.tests:
        if options.tests[0] == 'help':
            print "Available RNG tests:"
            print "\tcollide"
            print "\t\t" + "\n\t\t".join(collide_tests)
            print "\tdieharder"
            print "\t\t" + "\n\t\t".join(dieharder_tests)
            sys.exit(1)
        elif options.tests[0] == "collide":
            tests = collide_tests
        elif options.tests[0] == "dieharder":
            tests = dieharder_tests
        elif not options.all:
            tests = options.tests

    suite = unittest.TestSuite()

    for t in tests:
        if t == "collide-openssh":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SshRngTest))
        elif t == "collide-openssl":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenSSLRngTest))
        elif t == "collide-gnutls":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GnuTLSRngTest))
        elif t == "collide-gnupg":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GnuPGRngTest))
        elif t == "collide-dnssec":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DNSSECRngTest))
        elif t == "collide-kernel":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(KernelRngTest))
        elif t == "collide-libgcrypt":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibgcryptRngTest))
        elif t == "dieharder-kernel":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DieharderKernelRngTest))
        elif t == "dieharder-glibc":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DieharderGlibcRngTest))
        elif t == "dieharder-openssl":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DieharderOpenSSLRngTest))
        elif t == "dieharder-gnutls":
            suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DieharderGnuTLSRngTest))
        else:
            print >>sys.stderr, "Skipping '%s'. Please specify '%s', 'collide', 'dieharder', or 'all'" % (t, "', '".join(all_tests))
            continue

    verbosity = 1
    if options.verbose or options.report:
        verbosity = 2

    rc = unittest.TextTestRunner(verbosity=verbosity).run(suite)

    #code, report = testlib.cmd(['pgrep', '-l', '-u', 'root', 'rngd'])
    #if code == 0:
    #    print "Trying to kill rngd..."
    #    testlib.cmd(['sudo', 'killall', 'rngd'])

    if not rc.wasSuccessful():
        sys.exit(1)
