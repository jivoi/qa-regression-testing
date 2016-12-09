#!/usr/bin/python
#
#    test-mako.py quality assurance test script for mako
#    Copyright (C) 2010 Canonical Ltd.
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
# QRT-Packages: python-mako
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release python-mako && ./test-mako.py -v'
'''


import unittest, sys, os, tempfile
import testlib
from mako.template import Template

try:
    from private.qrt.mako import PrivateMakoTest
except ImportError:
    class PrivateMakoTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class MakoTest(testlib.TestlibCase, PrivateMakoTest):
    '''Test mako.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libhx-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_template(self):
        '''Test a simple template'''

        expected = "Ubuntu Rocks!"

        mytemplate = Template("${thing} Rocks!")
        result=mytemplate.render(thing="Ubuntu")

        report = "Template '%s' doesn't match '%s'!" % (result,expected)
        self.assertTrue(result == expected, report)

    def test_template_file(self):
        '''Test a simple template from a file'''

        expected = "Ubuntu Rocks!"
        template = "${thing} Rocks!"
        template_file = os.path.join(self.tempdir, "template_file")
        testlib.create_fill(template_file, template)

        mytemplate = Template(filename=template_file)
        result=mytemplate.render(thing="Ubuntu")

        report = "Template '%s' doesn't match '%s'!" % (result,expected)
        self.assertTrue(result == expected, report)

    def test_html_escaping(self):
        '''Test html escaping'''

        expected = "&lt;blink&gt;Ubuntu&lt;/blink&gt;&#34;&#39; Rocks!"

        mytemplate = Template("${thing | h} Rocks!")
        result=mytemplate.render(thing="<blink>Ubuntu</blink>\"'")

        report = "Template '%s' doesn't match '%s'!" % (result,expected)
        self.assertTrue(result == expected, report)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
