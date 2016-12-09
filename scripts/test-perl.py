#!/usr/bin/python
#
#    test-perl.py quality assurance test script for perl
#    Copyright (C) 2008-2016 Canonical Ltd.
#    Author: Original author unknown
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
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
    How to run against dapper and hardy schroots:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release libarchive-tar-perl perl  && ./test-perl.py -v'

    How to run against intrepid and later schroots:
        schroot -c intrepid -u root -- sh -c 'apt-get -y install lsb-release perl  && ./test-perl.py -v'

'''
# QRT-Packages: perl
# QRT-Depends: data
# Disabled-QRT-Alternates: libarchive-tar-perl

import unittest, os, tempfile, shutil
import testlib

class PerlTest(testlib.TestlibCase):
    '''Test perl.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _run_script(self, contents, expected=0, args=[], taint_check=False):
        '''Run a perl script, expecting exit code 0'''
        handle, name = testlib.mkstemp_fill(contents+'\n')
        if taint_check:
            args = ['-T'] + args
        self.assertShellExitEquals(expected, ['/usr/bin/perl'] + args, stdin = handle)
        os.unlink(name)

    def test_rmtree_ugly_perms(self):
        '''File::Path::rmtree handles ugly directory permissions'''
        expected = 0
        dir = tempfile.mkdtemp(prefix='test-perl-')
        file(dir+'/mongoose','w').write("testing")
        os.chmod(dir, 0400)

        self._run_script('''use File::Path;
File::Path::rmtree("%s");''' % (dir))

    def test_filetemp_removal(self):
        '''File::Path::rmtree of current directory (debian bug 479317)'''

        # via File::Temp
        expected = 0
        self._run_script('''use File::Temp;
my $t=File::Temp::tempdir(TMPDIR => 1, CLEANUP => 1);
mkdir("$t/foo");
chdir "$t/foo";
exit(0);''', expected=expected)

        # via rmtree itself
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.chdir(dir)
        self._run_script('''use File::Path; File::Path::rmtree("%s");''' % (dir))
        # newer perl rmtree does not delete tree when it contains $cwd
        shutil.rmtree(dir)

    def test_symlink_without_dir(self):
        '''Archive::Tar will not unpack through symlink to non-existing directory'''
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.chdir(dir)
        self._run_script('''use Archive::Tar;
my $tar = Archive::Tar->new;
$tar->read('%s/data/bad-symlink-following-without-dir.tar');
$tar->extract();''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertFalse(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/orig/x'))
        shutil.rmtree(dir)

    def test_symlink_with_dir_internal(self):
        '''Archive::Tar will not unpack through symlink to existing internal directory'''
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.chdir(dir)
        self._run_script('''use Archive::Tar;
my $tar = Archive::Tar->new;
$tar->read('%s/data/bad-symlink-following-with-dir.tar');
$tar->extract();''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/orig/x'))
        shutil.rmtree(dir)

    def test_symlink_with_dir_external(self):
        '''Archive::Tar will not unpack through symlink to existing external directory (CVE-2007-4829)'''
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.chdir(dir)
        self.assertFalse(os.path.exists('/tmp/x'))
        self._run_script('''use Archive::Tar;
my $tar = Archive::Tar->new;
$tar->read('%s/data/bad-symlink-following-absolute-path.tar');
$tar->extract();''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/link/x'))
        self.assertFalse(os.path.exists('/tmp/x'))
        shutil.rmtree(dir)

    def test_symlink_to_dotdot(self):
        '''Archive::Tar will not unpack through symlink to dot dot (CVE-2007-4829)'''
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.mkdir(dir+'/deeper')
        os.chdir(dir+'/deeper')
        self._run_script('''use Archive::Tar;
my $tar = Archive::Tar->new;
$tar->read('%s/data/bad-symlink-following-with-dotdot.tar');
$tar->extract();''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/evil'))
        self.assertFalse(os.path.exists('../zomg'))
        shutil.rmtree(dir)

    def test_rmtree(self):
        '''File::Path::rmtree works'''
        dir = tempfile.mkdtemp(prefix='test-perl-')
        os.mkdir(dir+'/deeper')
        file(dir+'/deeper/cow','w').write('Hello')
        os.mkdir(dir+'/deeper/more')
        self.assertTrue(os.path.exists(dir))
        self.assertTrue(os.path.exists(dir+'/deeper'))
        self.assertTrue(os.path.exists(dir+'/deeper/cow'))
        self.assertTrue(os.path.exists(dir+'/deeper/more'))
        self._run_script('''use File::Path; File::Path::rmtree("%s");''' % (dir))
        self.assertFalse(os.path.exists(dir))
        self.assertFalse(os.path.exists(dir+'/deeper'))
        self.assertFalse(os.path.exists(dir+'/deeper/cow'))
        self.assertFalse(os.path.exists(dir+'/deeper/more'))

    def test_rmtree_does_not_chdir_away(self):
        '''File::Path::rmtree has stable cwd'''
        self._run_script('''use File::Path;
use File::Temp;
use Cwd 'getcwd';

my $t=File::Temp::tempdir(TMPDIR => 1);
chdir($t);
mkdir("cow");
mkdir("cow/more");
exit(100) if getcwd ne $t;
chdir("cow");
exit(150) if getcwd ne $t."/cow";
chdir("/");
exit(200) if getcwd ne "/";
File::Temp::rmtree($t);
exit(300) if getcwd ne "/";''')

    def test_giant_utf8(self):
        '''Giant invalid UTF-8 (CVE-2009-3626)'''
        self._run_script('''use strict;

# Here is a HTML snippet from a malicious/obfuscated mail message.
# Note the last character has an invalid and huge UTF-8 code
# (as a result of an unrelated bug in HTML::Parser).
#
my $t = '<a>Attention Home&#959&#969n&#1257rs...1&#1109t '.
        'T&#1110&#1084e E&#957&#1257&#1075075</a>';

$t =~ s/&#(\d+)/chr($1)/ge;    # convert HTML entities to UTF8
$t .= substr($ENV{PATH},0,0);  # make it tainted

# show character codes in the resulting string
print join(", ", map {ord} split(//,$t)), "\n";

# The following regexp evaluation crashes perl 5.10.1 on FreeBSD.
# Note that $t must be tainted and must have the UTF8 flag on,
# otherwise the crash seems to be avoided.

$t =~ /( |\b)(http:|www\.)/i;''', taint_check=True)

    def test_cve_2011_1487(self):
        '''Test CVE-2011-1487'''
        self._run_script('''use Scalar::Util qw(tainted);
$t=$0;
$u=lc($t);
exit(100) if not tainted($t);
exit(200) if not tainted($u);
exit(0);''', taint_check=True)

    def test_cve_2015_8607(self):
        '''Test CVE-2015-8607'''

        if self.lsb_release['Release'] < 15.04:
            return self._skipped('not supported by Perl < 5.20')

        self._run_script('''use File::Spec;
use Scalar::Util qw/tainted/;
my $tainted = substr($ENV{PATH}, 0, 0);
exit(10) if not tainted(File::Spec->canonpath($tainted . Cwd::getcwd));
exit(20) if not tainted(File::Spec->canonpath($tainted));
(Cwd::getcwd() =~ /^(.*)/);
my $untainted = $1;
exit(30) if tainted($untainted);
exit(40) if tainted(File::Spec->canonpath($untainted));
exit(0);''', taint_check=True)

    def test_crypt_des(self):
        '''Test crypt() des for sanity'''
        self._run_script('''use strict;
my $expected = "rl0uE0e2WKB0.";
my $result = crypt("password", "rl");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_md5(self):
        '''Test crypt() md5 for sanity'''
        self._run_script('''use strict;
my $expected = "\$1\$unsalted\$8S6Ef60Q2XdTO55WgWVwq1";
my $result = crypt("password", "\$1\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha256(self):
        '''Test crypt() sha256 for sanity'''
        self._run_script('''use strict;
my $expected = "\$5\$unsalted\$DDDvuqyWf1V/bpMwIOTpqiBEOZAD2t7kBADIHqlYv78";
my $result = crypt("password", "\$5\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha256_rounds(self):
        '''Test crypt() sha256 with rounds argument for sanity'''
        self._run_script('''use strict;
my $expected = "\$5\$rounds=12345\$unsalted\$AtGanTBqHthUdl6wPa8iIIN56WuMEoqTtdqZSHGMW17";
my $result = crypt("password", "\$5\$rounds=12345\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha256_under_1000_rounds(self):
        '''Test crypt() sha256 with rounds argument < 1000 for sanity'''
        self._run_script('''use strict;
my $expected = "\$5\$rounds=1000\$unsalted\$pRX4qQOrvChvxvNT3DUkgq.kv9ZjPsEyoK.jEmZ0qW1";
my $result = crypt("password", "\$5\$rounds=123\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
my $result = crypt("password", "\$5\$rounds=321\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha512(self):
        '''Test crypt() sha512 for sanity'''
        self._run_script('''use strict;
my $expected = "\$6\$unsalted\$ARewARAdmd36hrY2NPq13DHODD1UcF0CJNX18ep7n8ZeAbM6lX8hJOe63H5yG/sBj9XSS5g/omjAtTgnNinhr1";
my $result = crypt("password", "\$6\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha512_rounds(self):
        '''Test crypt() sha512 with rounds argument for sanity'''
        self._run_script('''use strict;
my $expected = "\$6\$rounds=12345\$unsalted\$gwhZ2z6MRLZ2pqDU9k.7c0692t38UgRo7zqaVc7dNPIpdMiOCE0wLHngYiBGGLfYy0u1nj/q7l8mde8GixEs7.";
my $result = crypt("password", "\$6\$rounds=12345\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_crypt_sha512_under_1000_rounds(self):
        '''Test crypt() sha512 with rounds argument < 1000 for sanity'''
        self._run_script('''use strict;
my $expected = "\$6\$rounds=1000\$unsalted\$egWem9Oa2.adDYrSI7ZeWWdl1eU.dUPxP/T4z7dOvPhSagScAmnR59JDblSUJks/bYJAZg7mEdIvKzilT7Nv01";
my $result = crypt("password", "\$6\$rounds=345\$unsalted\$");
my $result = crypt("password", "\$6\$rounds=543\$unsalted\$");
die "Expected $expected; got $result" unless $result eq $expected;
''')

    def test_CVE_2012_5526(self):
	'''CVE-2012-5526: CGI.pm p3p and cookie crlf handling'''
	self._run_script('''use strict; use warnings; use CGI; my $cgi = CGI->new;
eval {$cgi->header(  -p3p => ["foo\r\nbar"] ); };
if ($@ =~ /contains a newline/) {
	exit(0);
} else {
	exit(1);
}
''')
	self._run_script('''use strict; use warnings; use CGI; my $cgi = CGI->new;
eval { $cgi->header( -cookie => ["foo\r\nbar"] ); };
if ($@ =~ /contains a newline/) {
	exit(0);
} else {
	exit(1);
}
''')

    def test_CVE_2012_5195(self):
	'''CVE-2012-5195: Perl's x operator on huge inputs'''
        rc, report = testlib.cmd(['/usr/bin/perl', '-e', '''print "v"x(2**31+1) ."=1";'''])
        expected = [1, 12, 255] # 1 or 12 out of mem; 255 panic: memory wrap; 128+sigsegv ==> fail
        self.assertTrue(rc in expected)

    def test_CVE_2011_3597(self):
	'''CVE-2011-3597: Digest::new() injection'''
	self._run_script('''use strict; use warnings; use Digest;
my $input = q{MD;5;print qq[I own you\n]};
eval { Digest->new($input)};
if ($@ !~ /print/) { exit(1); }
exit(0);
''')

    def test_CVE_2012_6329(self):
	'''CVE-2012-6329'''

        if self.lsb_release['Release'] >= 14.04:
            return self._skipped('not supported by trusty+')

        # test stolen from here:
        # https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2012-6329
	self._run_script('''use strict;
use warnings;
use utf8;
use encoding ':locale';

package My::Localize;
use base 'Locale::Maketext';
1;

package My::Localize::cs_cz;
use base 'My::Localize';
our %Lexicon = (
    '_AUTO' => 1,
    'Hello [_1]!' => 'Ahoj, [_1]!'
);
1;

package My;
our $VERSION = '42';
my $lh = My::Localize->get_handle('cs_CZ') or die "No lexicon exists!";
print $lh->maketext('Hello [_1]!', 'foo'), "\n";

use POSIX;
print $lh->maketext('Hello [POSIX::printf,qq{HIT\n}]!', 1), "\n";
''', expected=255)

    def test_CVE_2013_7422(self):
	'''CVE-2013-7422: Integer underflow in regcomp.c'''
	self._run_script(r"/\7777777777/")

    def test_CVE_2014_4330(self):
	'''CVE-2014-4330: denial of service in Data::Dumper'''

        if self.lsb_release['Release'] == 12.04:
            expected = 255
        else:
            expected = 9

	self._run_script('''use Data::Dumper;
my $s = {};
my $x;
$s = { s => $s } for 1 .. 1000;
$x = Dumper($s);
''', expected=expected)

    def test_CVE_2016_2381(self):
	'''CVE-2016-2381: environment variable confusion'''

        # This just checks if $ENV still works
        os.environ['QRTPERLTEST'] = "ubunturocks!"

        rc, report = testlib.cmd(['/usr/bin/perl', '-e', '''print $ENV{"QRTPERLTEST"};'''])
        del os.environ['QRTPERLTEST']

        self.assertTrue(rc == 0)
        self.assertTrue("ubunturocks!" in report)


if __name__ == '__main__':
    # simple
    unittest.main()
