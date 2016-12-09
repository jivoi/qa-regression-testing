#!/usr/bin/python
#
#    test-libconfig-inifiles-perl.py quality assurance test script for
#    libconfig-inifiles-perl
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
# QRT-Packages: libconfig-inifiles-perl
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'

   TODO:
   - not much. The build has the testsuite enabled, so just test CVE fixes
'''


import unittest, sys, os
import tempfile
import testlib

class PkgTest(testlib.TestlibCase):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_CVE_2012_2451(self):
        '''Test CVE-2012-2451'''
        ini = os.path.join(self.tempdir, "test.ini")
        ini2 = os.path.join(self.tempdir, "test2.ini")
        ini2new = os.path.join(self.tempdir, "%s-new" % ini2)
        target = os.path.join(self.tempdir, "target")
        target_text = "testlib text"
        script = os.path.join(self.tempdir, "test.pl")

        contents = '''[MySection]
MyKey=Foo
'''
        testlib.config_replace(ini, contents)

        contents = '''#!/usr/bin/perl
use Config::IniFiles;
my $cfg = Config::IniFiles->new( -file => "%s");
$cfg->WriteConfig("%s");
''' % (ini, ini2)
        testlib.config_replace(script, contents)
        os.chmod(script, 0755)

        testlib.config_replace(target, target_text)

        # setup the attack
        os.symlink(target, ini2new)

        rc, report = testlib.cmd([script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        target_contents = open(target).read()
        self.assertTrue(target_contents == target_text, "Could not find '%s':\n%s" % (target_text, target_contents))

        old = open(ini).read()
        new = open(ini2).read()
        self.assertTrue(old == new, "File contents differ:\n%s\n\nvs:\n%s" % (old, new))

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
