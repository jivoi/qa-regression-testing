#!/usr/bin/python
#
#    test-libcompress-raw-zlib-perl.py quality assurance test script for libcompress-raw-zlib-perl
#    Copyright (C) 2009 Canonical Ltd.
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
# QRT-Packages: perl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data

'''
    How to run against a clean schroot named 'jaunty':

        test the version built into perl first (intrepid +):
        schroot -c jaunty -u root -- sh -c 'apt-get -y install lsb-release perl  && ./test-libcompress-raw-zlib-perl.py -v'

        test the libcompress-raw-zlib-perl package:
        schroot -c jaunty -u root -- sh -c 'apt-get -y install lsb-release libcompress-raw-zlib-perl  && ./test-libcompress-raw-zlib-perl.py -v'
'''

import unittest, sys, tempfile, os
import testlib

use_private = True
try:
    from private.qrt.libcompressrawzlibperl import LibcompressRawZlibPerlPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibcompressRawZlibPerlTest(testlib.TestlibCase):
    '''Test libcompress-raw-zlib-perl.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp', prefix="test-lrzp-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_script(self, contents, expected=0, args=[]):
        '''Run a perl script, expecting exit code 0'''
        handle, name = testlib.mkstemp_fill(contents+'\n')
        self.assertShellExitEquals(expected, ['/usr/bin/perl'] + args, stdin = handle)
        os.unlink(name)

    def _get_md5(self, filename):
        '''Checks the mime type of the file specified'''

        (rc, report) = testlib.cmd(["/usr/bin/md5sum", filename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report.split()[0]

    def test_deflate_and_inflate(self):
        '''Test deflate and inflate'''

        input_file = './data/patas_de_trapo.oga'
        output_file = os.path.join(self.tempdir, 'output.deflated')
        other_output_file = os.path.join(self.tempdir, 'output.inflated')

        # Get original file's md5
        md5sum = self._get_md5(input_file)

        # Test deflation
        self._run_script('''use Compress::Raw::Zlib;
my $x = new Compress::Raw::Zlib::Deflate
or die "Cannot create a deflation stream\n" ;

local *IN;
local *OUT;

open(IN, "%s") or die;
open(OUT, "> %s") or die;

my $input = '' ;
my ($output, $status) ;

while (read(IN, $input, 4096)) {
  $status = $x->deflate($input, $output) ;
  print OUT $output if $status == Z_OK;
  last if $status != Z_OK ;
}

$status = $x->flush($output) ;
print OUT $output;

die "deflation failed: $status\n"
  unless $status == Z_OK ;

close(IN);
close(OUT);
''' % (input_file, output_file))
        self.assertTrue(os.path.exists(output_file))

        # Test inflation
        self._run_script('''use Compress::Raw::Zlib;
my $x = new Compress::Raw::Zlib::Inflate()
or die "Cannot create an inflation stream\n" ;

local *IN;
local *OUT;

open(IN, "%s") or die;
open(OUT, "> %s") or die;

my $input = '' ;
my ($output, $status) ;

while (read(IN, $input, 4096)) {
  $status = $x->inflate($input, $output) ;
  print OUT $output;
  last if $status != Z_OK ;
}

die "inflation failed: $status\n"
  unless $status == Z_STREAM_END ;

close(IN);
close(OUT);
''' % (output_file, other_output_file))

        self.assertTrue(os.path.exists(other_output_file))

        # Compare with original md5
        self.assertTrue(md5sum == self._get_md5(other_output_file))
       
if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibcompressRawZlibPerlTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibcompressRawZlibPerlPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
