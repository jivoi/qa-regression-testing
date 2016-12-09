#!/usr/bin/python
#
#    test-libhtml-parser-perl.py quality assurance test script for libhtml-parser-perl
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
# QRT-Packages: libhtml-parser-perl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:

'''
    How to run against a clean schroot named 'jaunty':
        schroot -c jaunty -u root -- sh -c 'apt-get -y install lsb-release libhtml-parser-perl  && ./test-libhtml-parser-perl.py -v'
'''

import unittest, sys, tempfile, os
import testlib

use_private = True
try:
    from private.qrt.libhtmlparserperl import LibhtmlParserPerlPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class LibhtmlParserPerlTest(testlib.TestlibCase):
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
        handle, name = testlib.mkstemp_fill(contents+'\n', dir=self.tempdir)
        self.assertShellExitEquals(expected, ['/usr/bin/perl'] + args, stdin = handle)
        os.unlink(name)

    def test_parsing(self):
        '''Test parsing'''

        # Example found here: http://www.perlmeme.org/tutorials/html_parser.html
        self._run_script('''
package MyParser;
use base qw(HTML::Parser);

# we use these three variables to count something
our ($text_elements, $start_tags, $end_tags);

# here HTML::text/start/end are overridden 
sub text	{ $text_elements++  }
sub start	{ $start_tags++	    }
sub end	{ $end_tags++	    }

package main;

# Test the parser

my $html = <<EOHTML;
<html>
  <head>
    <title>Bla</title>
  </head>
  <body>
    Here's the body.
  </body>
</html>
EOHTML

my $parser = MyParser->new;
$parser->parse( $html );	# parse() is also inherited from HTML::Parser

exit(100) if $MyParser::text_elements ne 7;
exit(150) if $MyParser::start_tags ne 4;
exit(200) if $MyParser::end_tags ne 4;
''')


    def test_cve_2009_3627(self):
        '''Test CVE-2009-3627'''

        self._run_script('''
package MyParser;
use base qw(HTML::Parser);

sub start { 
  my ($self, $tagname, $attr, $attrseq, $origtext) = @_;
    if ($tagname eq 'a') {
      if ($attr->{ name } ne "Attention Home\\x{3BF}\\x{3C9}n\\x{4E9}rs...1\\x{455}t T\\x{456}\\x{43C}e E\\x{3BD}\\x{4E9}\\x{433}") {
        exit(100);
      }
    }
}

package main;

my $html = <<EOHTML;
<html>
  <head>
    <title>Bla</title>
  </head>
  <body>
    <a href="/blah" name="Attention Home&#959&#969n&#1257rs...1&#1109t T&#1110&#1084e E&#957&#1257&#1075">blah</a>
  </body>
</html>
EOHTML

my $parser = MyParser->new;
$parser->parse( $html );
''')


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibhtmlParserPerlTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibhtmlParserPerlPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
