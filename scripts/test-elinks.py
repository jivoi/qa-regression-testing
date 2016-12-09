#!/usr/bin/python
#
#    test-elinks.py quality assurance test script for elinks
#    Copyright (C) 2008 Canonical Ltd.
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

'''
  How to run in a clean virtual machine:
    1. apt-get -y install elinks smbclient
    2. ./test-elinks.py -v (as non-root)

  Dapper:
    To test smb:// need to create a share somewhere. The easiest thing to do
    is use 'net usershare' in a VM with samba 3.0.23 or higher that this
    script can connect to. Eg, on a hardy VM, can configure the usershare
    with:
      $ sudo apt-get install samba
      $ sudo adduser <username> sambashare (logout and back in as <username>)
      $ mkdir $HOME/foobar
      $ net usershare add foobar $HOME/foobar 'test share' 'Everyone:F' guest_ok=y
      $ smbclient -N -L localhost | grep foobar
      $ echo "It worked!" > $HOME/foobar/test.txt
      $ echo "Gotcha!" > $HOME/foobar/p0wnd # for testing CVE-2006-5925

    If it worked, then run this script with:
      $ ./test-elinks.py -v smb://<host with usershare>/foobar

    When done testing, remove the share with:
      $ net usershare delete foobar

    Please note that the test for CVE-2006-5925 is interactive.
'''

# QRT-Depends: data
# QRT-Packages: elinks ca-certificates lsb-release smbclient

import unittest, subprocess, sys, os, shutil, time
import testlib
import tempfile

smb_url = ""

class TestURLs(testlib.TestlibCase):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.exes = ['elinks']
        self.elinksdir = os.path.join(os.path.expanduser('~'), '.elinks')
        self.elinksdir_bak = self.elinksdir + '.testlib.bak'
        self._move_elinks_dir()
        self.tempdir = tempfile.mkdtemp()
        self.topdir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        if os.path.exists(self.elinksdir_bak):
            if os.path.exists(self.elinksdir):
                testlib.recursive_rm(self.elinksdir)
            shutil.move(self.elinksdir_bak, self.elinksdir)
        os.chdir(self.topdir)

    def _move_elinks_dir(self):
        '''Move the .elinks directory out of the way'''
        if os.path.exists(self.elinksdir):
            if not os.path.exists(self.elinksdir_bak):
                shutil.move(self.elinksdir, self.elinksdir_bak)
            else:
                testlib.recursive_rm(self.elinksdir)

    def _elinks_cmd(self, url, search='', expected=0, extra_args=[], use_home=False):
        '''Execute elinks with the given url'''
        command = ['elinks', '-dump', '-no-connect']
        if not use_home:
            command += ['-no-home']
        if len(extra_args) > 0:
            command += extra_args
        rc, report = testlib.cmd(command + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != '':
            result = 'Could not find \'%s\'\n' % (search)
            self.assertTrue(search in report, result + report)

    def test_file(self):
        '''Test file'''
        self._elinks_cmd("./data/well_formed_xhtml1.0.html", search='Sample content')

    def test_ftp(self):
        '''Test http (ftp.debian.org)'''
        self._elinks_cmd("ftp://ftp.debian.org/", search='FTP directory ftp://ftp.debian.org/')

    def test_http(self):
        '''Test http (ubuntu.com)'''
        self._elinks_cmd("http://www.ubuntu.com/")

    def test_http_intl(self):
        '''Test http (www.google.de)'''
        self._elinks_cmd("http://www.google.de/")
        self._elinks_cmd("./data/www.google.de.html", search='Datenschutz')

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''
        if self.lsb_release['Release'] < 9.04:
            return self._skipped("bug #1022 not fixed in 8.10 and earlier")

        self._elinks_cmd("https://launchpad.net/", extra_args=['-eval', 'set connection.ssl.cert_verify = 1'])

    def test_https_noverify(self):
        '''Test https no verify (wiki.ubuntu.com)'''
        self._elinks_cmd("https://wiki.ubuntu.com/")

    def test_https_selfsigned(self):
        '''Test https self-signed (alioth.debian.org)'''
        self._elinks_cmd("https://alioth.debian.org/account/login.php", "SSL error", 1, ['-eval', 'set connection.ssl.cert_verify = 1'])

    def test_smb(self):
        '''Test smb'''
        url = smb_url
        if url == '':
            return self._skipped("smb://... not specified")

        expected = 3
        search = "URL protocol not supported"
        if self.lsb_release['Release'] < 8.04:
            expected = 0
            search = "References"
        self._elinks_cmd(url, search, expected)

        url += "/test.txt"
        if self.lsb_release['Release'] < 8.04:
            expected = 0
            search = "It worked!"
        self._elinks_cmd(url, search, expected)

    def test_smb_CVE_2006_5925(self):
        '''Test CVE-2006-5925'''
        if smb_url == '':
            return self._skipped("smb://... not specified")

        os.chdir(self.tempdir)
        contents = '''
<html>
<a href='%s/%s" YYY; lcd ..; lcd ..; lcd ..; lcd ..; lcd .. ; lcd tmp; lcd %s ; get %s ; exit; '>Test CVE-2006-5925</a>
</html>
''' % (smb_url, "test.txt", os.path.basename(self.tempdir), "p0wnd.txt")
        url = os.path.join(self.tempdir, "CVE-2006-5925.html")
        testlib.create_fill(url, contents)

        os.chdir(self.tempdir)
        expected = 0
        search = "foobar"
        self._elinks_cmd(url, search, expected)

        print ""
        print "  Please select the 'Test CVE-2006-5925' link, then press 'q' to exit elinks"
        time.sleep(3)
        subprocess.call(['elinks', '-no-connect', '-no-home', url])

        result = 'Found \'p0wnd.txt\'\n'
        self.assertFalse(os.path.exists(os.path.join(self.tempdir, "p0wnd.txt")), result)


if __name__ == '__main__':
    suite = unittest.TestSuite()

    for i in sys.argv:
        if i.startswith("smb://"):
            smb_url = i
            sys.argv.remove(i)

    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFiles))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestURLs))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
