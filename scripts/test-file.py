#!/usr/bin/python
#
#    test-file.py quality assurance test script for file
#    Copyright (C) 2009-2015 Canonical Ltd.
#    Author: Steve Beattie <sbeattie@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install file && ./test-file.py -v'
'''


import unittest, sys, tempfile, re
import testlib
import os

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class FileTest(testlib.TestlibCase, PrivatePkgTest):
    '''Test file package functionality.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="qrt-file-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_file(self, filename, expected_rc = 0, magic = None):
        '''Runs file on a file and returns result'''

        if magic == None:
            rc, report = testlib.cmd(['file', '-b', filename])
        else:
            rc, report = testlib.cmd(['file', '-b', '-m', magic, filename])

        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        return report

    def test_lp248619(self):
        '''Test mistaken identification of files as erlang JAM files LP: #248619'''
        bad_output = "Erlang"
        filename = os.path.join(self.tempdir, 'lp248619')
        testlib.create_fill(filename, contents="1/2 Tue")

        report = self._run_file(filename)
        result = "Found '%s' in report" % bad_output
        self.assertFalse(bad_output in report, result + report)

    def test_cve_2014_1943_1(self):
        '''Test CVE-2014-1943 Part 1'''
        bad_contents = "\x45\x52\x00\x00\x00\x00\x00\x00"
        filename = os.path.join(self.tempdir, 'cve-2014-1943-1')
        testlib.create_fill(filename, contents=bad_contents)

        self._run_file(filename)

    def test_cve_2014_1943_2(self):
        '''Test CVE-2014-1943 Part 2'''

        bad_contents = "\x01" * 250000
        magic = "0           byte        x\n" + \
                ">(1.b)      indirect    x\n"

        filename = os.path.join(self.tempdir, 'cve-2014-1943-2')
        magic_fn = os.path.join(self.tempdir, 'magic')

        testlib.create_fill(filename, contents=bad_contents)
        testlib.create_fill(magic_fn, contents=magic)

        self._run_file(filename, expected_rc = 1, magic=magic_fn)

    def test_cdf_files(self):
        '''Test CDF files'''

        if self.lsb_release['Release'] == 10.04:
            desc = 'CDF V2 Document'
        else:
            desc = 'Composite Document File V2 Document'

        samples = ( ('oo-presenting-ubuntu.ppt', desc + ', Little Endian, Os: Windows, Version 1.0, Code page: -535, Last Saved By: Clemens, Revision Number: 77, Total Editing Time: 13:03:38, Create Time/Date: Wed Oct  5 14:05:14 2005, Last Saved Time/Date: Wed Apr  2 20:01:39 2008'),
                    ('oo-tables.doc', desc + ', Little Endian, Os: Windows, Version 1.0, Code page: -535, Author: Jamie Strandboge, Last Saved By: Jamie Strandboge, Revision Number: 1, Create Time/Date: Tue Sep 29 21:39:33 2009, Last Saved Time/Date: Tue Sep 29 21:43:49 2009'),
                    ('oo-trig.xls', desc + ', Little Endian, Os 0, Version: 1.0, Code page: -535, Revision Number: 4, Total Editing Time: 17:59, Last Printed: 02:05, Last Saved Time/Date: Thu Mar  9 11:40:46 2006, Create Time/Date: Thu Mar  9 11:15:03 2006'),
                    ('oo-derivatives.doc', desc + ', Little Endian, Os: Windows, Version 1.0, Code page: -535, Last Saved By: Henrik, Revision Number: 5, Last Printed: (Sat Dec 31 22:00:00 2112|Wed Dec 31 18:59:59 1969), Create Time/Date: Wed Mar  8 20:43:06 2006, Last Saved Time/Date: Mon Apr  3 21:37:39 2006')
                      )

        for infile, description in samples:
            report = self._run_file("./data/" + infile)

            result = 'file returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), description)
            self.assertNotEquals(None, re.search(description, report), result)

    def test_deb742265(self):
        '''Test perl script detection regression Debian #742265'''

        if self.lsb_release['Release'] == 10.04:
            search = "a /usr/bin/perl -w script text executable"
        elif self.lsb_release['Release'] == 12.04:
            search = "a /usr/bin/perl -w script, ASCII text executable"
        elif self.lsb_release['Release'] == 14.04:
            search = "Perl script, ASCII text executable"
        elif self.lsb_release['Release'] == 14.10:
            search = "awk script, ASCII text"
        else:
            search = "awk or perl script, ASCII text"

        filename = os.path.join(self.tempdir, 'deb742265.pl')
        testlib.create_fill(filename, contents='''#!/usr/bin/perl -w
use strict;

BEGIN {
   if ( !$ENV{'PERL_MODULES'} ) {
      $ENV{'PERL_MODULES'}= '/srv/fai/config/perl_modules';
   }
   unshift @INC, $ENV{'PERL_MODULES'};
}

use FAI;
use NFS::Clients;
''')

        report = self._run_file(filename)
        result = "Did not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def test_awk(self):
        '''Test awk script detection'''

        if self.lsb_release['Release'] == 10.04:
            search = "awk script text executable"
        else:
            search = "awk script, ASCII text executable"

        filename = os.path.join(self.tempdir, 'awktest.awk')
        testlib.create_fill(filename, contents='''#!/bin/awk -f
BEGIN {

# Do something

	i=1;
	while (i <= 10) {
		printf "This is number ", i;
		i = i+1;
	}

# end
exit;
}
''')

        report = self._run_file(filename)
        result = "Did not find '%s' in report" % search
        self.assertTrue(search in report, result + report)

    def test_elf(self):
        '''Test ELF file detection'''

        extra_space = ""

        if self.lsb_release['Release'] == 14.04:
            extra_space = " "

        if self.dpkg_arch == 'amd64':
            search = "ELF 64-bit LSB %sexecutable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs)" % extra_space
        else:
            search = "ELF 32-bit LSB %sexecutable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs)" % extra_space

        report = self._run_file("/bin/bash")
        result = "Did not find '%s' in report" % search
        self.assertTrue(search in report, result + report)


if __name__ == '__main__':
    # simple
    unittest.main()
