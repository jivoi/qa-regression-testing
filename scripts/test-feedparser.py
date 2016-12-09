#!/usr/bin/python
#
#    test-feedparser.py quality assurance test script for feedparser
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: python-feedparser python3-feedparser
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/FeedParser.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'

    NOTE: while we could do a lot with this, feedparser has a significant test
          suite that is enabled in the build, so we just try a few things here.
'''


import unittest, sys, os
import testlib
import tempfile
import feedparser

try:
    from private.qrt.FeedParser import PrivateFeedParserTest
except ImportError:
    class PrivateFeedParserTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class FeedParserTest(testlib.TestlibCase, PrivateFeedParserTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        feedparser.USER_AGENT = "testlib/0.1 +https://launchpad.net/qa-regression-testing"
        self.usn_url = 'http://www.ubuntu.com/usn/rss.xml'

        self.tmpdir = tempfile.mkdtemp(dir='/tmp', prefix="testlib-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _run_python_script(self, v):
        '''Run python script'''
        script = os.path.join(self.tmpdir, 'script.py')
        contents = '''#!/usr/bin/python%d
import feedparser
import sys
feedparser.USER_AGENT = "testlib/0.1 +https://launchpad.net/qa-regression-testing"
f = feedparser.parse('%s')
if not 'status' in f:
    print("Could not find 'status' in parsed output")
    sys.exit(1)
elif f['status'] != 200:
    print("html status '" + f['status'] + "' != 200")
    sys.exit(1)
sys.exit(0)
''' % (v, self.usn_url)
        testlib.create_fill(script, contents, mode=0755)

        rc, report = testlib.cmd([script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_python2(self):
        '''Test python2'''
        self._run_python_script(2)

    def test_python3(self):
        '''Test python3'''
        self._run_python_script(3)

    def test_parse_usn(self):
        '''Test parsing USN rss'''
        url = 'http://www.ubuntu.com/usn/rss.xml'
        f = feedparser.parse('http://www.ubuntu.com/usn/rss.xml')
        for i in ['feed', 'href', 'status', 'updated', 'etag']:
            self.assertTrue(i in f, "Could not find '%s' in:\n%s" % (i, f))

        furl = f['href']
        self.assertEquals(url, furl, "'%s' does not match '%s'" % (furl, url))

        self.assertEquals(f['status'], 200, "Status '%s' does not equal '%d'" % (f['status'], 200))

        furl = f['feed']['links'][0]['href'] + 'rss.xml'
        self.assertEquals(url, furl, "'%s' does not match '%s'" % (furl, url))

        for i in ['id', 'link', 'summary', 'summary_detail']:
            self.assertTrue(i in f['entries'][0], "Could not find '%s' in:\n%s" % (i, f['entries'][0]))

        furl = f['entries'][0]['links'][0]['href']
        search = os.path.dirname(url) + "/usn-"
        self.assertTrue(furl.startswith(search), "Could not find '%s' in:\n%s" % (search, furl))


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(FeedParserTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
