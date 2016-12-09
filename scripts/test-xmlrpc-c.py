#!/usr/bin/python
#
#    test-xmlrpc-c.py quality assurance test script for xmlrpc-c
#    Copyright (C) 2010 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: xml-rpc-api2txt xml-rpc-api2cpp
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install xml-rpc-api2txt xml-rpc-api2cpp  && ./test-xmlrpc-c.py -v'

    TODO:
     - http://tldp.org/HOWTO/XML-RPC-HOWTO/xmlrpc-howto-c.html, especially the
       cgi script
'''


import unittest
import testlib

class XmlRPCCTest(testlib.TestlibCase):
    '''Test xmlrpc-c.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_api2txt(self):
        '''Test xml-rpc-api2txt'''
        rc, report = testlib.cmd(['xml-rpc-api2txt', 'http://xmlrpc-c.sourceforge.net/api/sample.php'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

        for i in ['array system.listMethods', 'string system.methodHelp']:
            result = "Could not find '%s' in report:\n" % (i)
            self.assertTrue(i in report, result + report)

    def test_api2cpp(self):
        '''Test xml-rpc-api2cpp'''
        rc, report = testlib.cmd(['xml-rpc-api2cpp', 'http://xmlrpc-c.sourceforge.net/api/sample.php', 'system', 'SystemProxy'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

        for i in ['XmlRpcValue /*array*/ SystemProxy::listMethods', 'string SystemProxy::methodHelp']:
            result = "Could not find '%s' in report:\n" % (i)
            self.assertTrue(i in report, result + report)


if __name__ == '__main__':
    # simple
    unittest.main()
