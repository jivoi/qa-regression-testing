#!/usr/bin/python
#
#    test-cyrus-sasl2.py quality assurance test script for cyrus-sasl2
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Kees Cook
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
# QRT-Packages: libsasl2-dev libsasl2-modules-gssapi-heimdal
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: cyrus-sasl2

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install libsasl2-dev libsasl2-modules-gssapi-heimdal && ./test-cyrus-sasl2.py -v'

cyrus-sasl2-heimdal was added to verify installability (it used to depend
on exact versions of cyrus-sasl2).

'''


import unittest, subprocess, sys, os
import testlib

try:
    from private.qrt.CyrusSasl2 import PrivateCyrusSasl2Test
except ImportError:
    class PrivateCyrusSasl2Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class CyrusSasl2Test(testlib.TestlibCase, PrivateCyrusSasl2Test):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('cyrus-sasl2')

    def tearDown(self):
        '''Clean up after each test_* function'''
        subprocess.call(['make','clean'], stdout=subprocess.PIPE)
        os.chdir(self.fs_dir)

    def test_encode64(self):
        '''Verify sasl_base64 is always NULL terminated (CVE-2009-0688)'''
        self.assertShellExitEquals(0, ['make','clean'])
        self.assertShellExitEquals(0, ['make','base64'])
        self.assertShellExitEquals(0, ['./base64'])

    def test_heimdal(self):
        '''libsasl2-modules-gssapi-heimdal installed'''
        self.assertTrue(os.path.exists('/usr/share/doc/libsasl2-modules-gssapi-heimdal'))

if __name__ == '__main__':
    # simple
    unittest.main()
