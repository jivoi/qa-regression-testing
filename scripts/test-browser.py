#!/usr/bin/python
#
#    test-browser.py quality assurance test script for Firefox, etc
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
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install <QRT-Packages from testlib_browser.py>
    2. for java:
       apt-get install sun-java5-plugin (dapper)
       apt-get install sun-java6-plugin (gutsy)
       apt-get install icedtea-java7-plugin (hardy)
       apt-get install icedtea6-plugin (intrepid)
    3. Run test-browser.py for various browsers. Eg:
       $ ./test-browser.py -v                     # defaults to firefox
       $ ./test-browser.py -e chromium-browser
       $ ./test-browser.py -e konqueror
       $ ./test-browser.py -e epiphany-browser
       $ ./test-browser.py -e rekonq

       '-E' uses an existing configuration, which can be convenient for some
       setup outside of the test. Repeated chromium runs can do:
       $ find $HOME -type d -name chromium -exec rm -rf {} \; ; chromium-browser ; ./test-browser.py -E -e chromium-browser -v

  NOTES:
    This is based on https://wiki.ubuntu.com/MozillaTeam/QA

    Make sure all browser windows are closed before running

    Make sure you start firefox at least once after upgrading before running
    this script

    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test. Watch the test
    output for what to do.

  Hardy, Intrepid, Jaunty:
    The postscript and pdf files created via the print dialog don't seem to be
    readble by evince (amd64 and i386)

  Hardy:
    Set as Desktop Background does not seem to work on i386

  Dapper and Gutsy:
    Firefox recognizes the OO.o documents, but doesn't launch OO.o with the
    proper arguments when using file:///

  Dapper:
    Uses totem-xine-firefox-plugin

  TODO:
   - extensions
   - webapps test
'''

# QRT-Depends: testlib_data.py testlib_ssl.py testlib_browser.py private/qrt/firefox.py

import unittest, sys, time
import testlib
import testlib_browser

try:
    from private.qrt.firefox import PrivateFirefoxTest
except ImportError:
    class PrivateFirefoxTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TestFirefoxPrivate(testlib_browser.BrowserCommon, PrivateFirefoxTest):
    '''Private tests'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()


if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-e", "--exe", dest="exe", help="Browser to test", metavar="EXES", action="append")
    parser.add_option("-t", "--test", dest="tests", help="Test name (use 'help' to see a list)", metavar="NAME", action="append")
    parser.add_option("-a", "--all", dest="all", help="Run all tests", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-E", "--use-existing", dest="use_existing", help="use existing", action="store_true")
    parser.add_option("--include-skipped", dest="include_skipped", help="Run all available tests rather than reduced tests", action="store_true")
    parser.add_option("--tabs", dest="tabs", help="Open up tests in multiple tabs when possible", action="store_true")
    (options, args) = parser.parse_args()

    all_tests = ['about', 'desktop', 'files', 'images', 'pages', 'plugins', 'java', 'ssl', 'private']

    if options.include_skipped:
        testlib_browser.include_skipped = True

    if options.tabs:
        testlib_browser.tabs = True

    testlib_browser.exes = ['firefox']
    if options.exe:
        testlib_browser.exes = []
        for e in options.exe:
            rc, output = testlib.cmd(['which', e])
            expected = 0
            if rc == expected:
                # konqueror tests don't work well unless kdeinit4 is running
                if e.startswith("konqueror") or e.startswith("rekonq"):
                    if not testlib.is_kdeinit_running():
                        continue
                testlib_browser.exes.append(e)
            else:
                print >>sys.stderr, ("Skipping '%s': not found" % (e))

    for e in testlib_browser.exes:
        if e.startswith("firefox") and "apparmor" not in all_tests:
            all_tests.append("apparmor")

    testlib_browser.use_existing = False
    if options.use_existing:
        testlib_browser.use_existing = options.use_existing

    if len(testlib_browser.exes) == 0:
        print >>sys.stderr, "ERROR: Could not find any browsers to test. Aborting"
        sys.exit(1)

    tests = all_tests
    if options.tests:
        if options.tests[0] == 'help':
            print "Available tests:"
            print "  " + "\n  ".join(all_tests + ['icedtea-plugin'])
            sys.exit(1)
        if "all" not in options.tests:
            tests = options.tests

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestVersion))

    for t in tests:
       if t == 'files':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestFiles))
       elif t == 'desktop':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestDesktop))
       elif t == 'images':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestImages))
       elif t == 'pages':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestPages))
       elif t == 'plugins':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestPlugins))
       elif t == 'java':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestJavaPlugin))
       elif t == 'icedtea-plugin':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestIcedTeaPlugin))
       elif t == 'ssl':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestSSL))
       elif t == 'about':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestAbout))
       elif t == 'apparmor':
          suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testlib_browser.TestAppArmor))
       elif t == 'private':
          if "firefox" in testlib_browser.exes:
              suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFirefoxPrivate))
          else:
              print >>sys.stderr, "No private tests for: %s (skipping)" % (testlib_browser.exes)
       else:
            print >>sys.stderr, "Skipping '%s'. Please specify '%s', or 'all'" % (t, "', '".join(all_tests))
            continue

    # Ignore options.verbose, we need '2' for the tests but want the option
    # since people are used to it.
    verbosity = 2
    #if options.verbose:
    #    verbosity = 2

    if 'files' in tests:
        print "Please launch then minimize OpenOffice.org/Libreoffice now, so that"
        print "it is loaded into memory. Note that office documents may appear in"
        print "the minimized window."
        time.sleep(3)

    rc = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

