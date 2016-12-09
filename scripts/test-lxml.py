#!/usr/bin/python
#
#    test-lxml.py quality assurance test script for lxml
#    Copyright (C) 2014 Canonical Ltd.
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
# QRT-Packages: python-lxml

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    TODO: this only tests a few functions as a sanity check, add more stuff
'''


import os
import subprocess
import sys
import unittest
import testlib
import re

from lxml.html import fromstring, tostring
from lxml.html.clean import clean, clean_html, Cleaner
from lxml.html import document_fromstring, fragment_fromstring, tostring
from lxml.etree import Comment

try:
    from private.qrt.Lxml import PrivateLxmlTest
except ImportError:
    class PrivateLxmlTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class LxmlTest(testlib.TestlibCase, PrivateLxmlTest):
    '''Test lxml.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _no_ws(self, content):
        '''strips out all the whitespace'''
        content = content.replace(' ', '')
        content = content.replace('\n', '')
        return content

    def _compare(self, old, new):
        '''Compares content with no whitespace'''
        old = self._no_ws(old)
        new = self._no_ws(new)
        if old == new:
            return True
        return False

    def test_find_class(self):
        '''Test find_class'''

        h = document_fromstring('''
<html><head></head>
<body>
   <a class="vcard
 fn   url" href="foobar">P1</a>
   <a class="not-fn vcard" href="baz">P2</a>
 </body></html>''')

        output = tostring(h, encoding=unicode)

        expected = '''<html><head></head><body>
   <a class="vcard
 fn   url" href="foobar">P1</a>
   <a class="not-fn vcard" href="baz">P2</a>
 </body></html>'''

        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertTrue(self._compare(output, expected), error)

        output = [e.text for e in h.find_class('fn')]
        expected = ['P1']
        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertEquals(output, expected, error)

        output = [e.text for e in h.find_class('vcard')]
        expected = ['P1', 'P2']
        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertEquals(output, expected, error)

    def test_find_rel_links(self):
        '''Test find_rel_links'''

        h = document_fromstring('''
 <a href="1">test 1</a>
 <a href="2" rel="tag">item 2</a>
 <a href="3" rel="tagging">item 3</a>
 <a href="4" rel="TAG">item 4</a>''')

        output = [e.attrib['href'] for e in h.find_rel_links('tag')]
        expected = ['2', '4']
        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertEquals(output, expected, error)

        output = [e.attrib['href'] for e in h.find_rel_links('nofollow')]
        expected = []
        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertEquals(output, expected, error)

    def test_allow_tags(self):
        '''Test allow_tage'''

        html = """
            <html>
            <head>
            </head>
            <body>
            <p>some text</p>
            <table>
            <tr>
            <td>hello</td><td>world</td>
            </tr>
            <tr>
            <td>hello</td><td>world</td>
            </tr>
            </table>
            <img>
            </body>
            </html>
            """

        html_root = document_fromstring(html)
        cleaner = Cleaner(
            remove_unknown_tags = False,
            allow_tags = ['table', 'tr', 'td'])
        result = cleaner.clean_html(html_root)

        self.assertEquals(12-5+1, len(list(result.iter())))

    def test_cleaner(self):
        '''Test cleaner'''

        doc = '''<html>
   <head>
     <script type="text/javascript" src="evil-site"></script>
     <link rel="alternate" type="text/rss" src="evil-rss">
     <style>
       body {background-image: url(javascript:do_evil)};
       div {background-image: url(data:text/html;base64,PHNjcmlwdD5hbGVydCgidGVzdCIpOzwvc2NyaXB0Pg==)};
       div {color: expression(evil)};
     </style>
   </head>
   <body onload="evil_function()">
     <!-- I am interpreted for EVIL! -->
     <a href="javascript:evil_function()">a link</a>
     <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgidGVzdCIpOzwvc2NyaXB0Pg==">data</a>
     <a href="#" onclick="evil_function()">another link</a>
     <p onclick="evil_function()">a paragraph</p>
     <div style="display: none">secret EVIL!</div>
     <object> of EVIL! </object>
     <iframe src="evil-site"></iframe>
     <form action="evil-site">
       Password: <input type="password" name="password">
     </form>
     <a href="evil-site">spam spam SPAM!</a>
     <img src="evil!">
   </body>
 </html>'''

        output = Cleaner(page_structure=False, safe_attrs_only=False).clean_html(doc)
        expected = '''<html><head><style>/* deleted */</style></head><body>
     
     <a href="">a link</a>
     <a href="">data</a>
     <a href="#">another link</a>
     <p>a paragraph</p>
     <div style="display: none">secret EVIL!</div>
      of EVIL! 
     
     
       Password: 
     <a href="evil-site">spam spam SPAM!</a>
     <img src="evil!"></body></html>'''

        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertTrue(self._compare(output, expected), error)

    def test_cve_2014_3146(self):
        '''Test CVE-2014-3146'''

        doc = '''<html>
   <head>
     <script type="text/javascript" src="evil-site"></script>
     <link rel="alternate" type="text/rss" src="evil-rss">
     <style>
       body {background-image: url(javascript:do_evil)};
       div {background-image: url(data:text/html;base64,PHNjcmlwdD5hbGVydCgidGVzdCIpOzwvc2NyaXB0Pg==)};
       div {color: expression(evil)};
     </style>
   </head>
   <body onload="evil_function()">
     <a href="j\x01a\x02v\x03a\x04s\x05c\x06r\x07i\x0Ep t:evil_function()">a control char link</a>
   </body>
 </html>'''

        output = Cleaner(page_structure=False, safe_attrs_only=False).clean_html(doc)
        expected = '''<html><head><style>/* deleted */</style></head><body>
     <a href="">a control char link</a>
   </body></html>'''

        error = "Got '%s', expected '%s'\n" % (output, expected)
        self.assertTrue(self._compare(output, expected), error)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
