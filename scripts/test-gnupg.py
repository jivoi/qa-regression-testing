#!/usr/bin/python
#
#    gnupg.py quality assurance test script
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
# QRT-Packages: gnupg valgrind
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root
# QRT-Depends: gnupg private/qrt/gnupg.py
# QRT-Alternates: haveged:!lucid

'''
    How to run against a clean schroot named 'precise':
        schroot -c precise -u root -- sh -c 'apt-get -y install lsb-release gnupg && ./gnupg.py -v'

    BUGS: This tests sigs and encryption using kees@ubuntu.com's key.  It
          would be better to have some "role" key on the keyservers to use.
'''

import unittest, subprocess, os, os.path, sys
import tempfile
import __builtin__

import testlib

# Support testing both gnupg and gnupg2
app = ''

user = None

try:
    from private.qrt.gnupg import PrivateGnupgTest
except ImportError:
    class PrivateGnupgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class GnupgTest(testlib.TestlibCase, PrivateGnupgTest):
    '''Test gpg functionality.'''

    def onetime_setUp(self):
        '''Create test scenario.

        create a new gpg key
        '''

        global user

        # start noise-generator for gaining randomness
        noise = os.fork()
        if noise == 0:
            while True:
                subprocess.call(['/bin/ls','-lR','/proc'],stdout=file('/dev/null','a'),stderr=subprocess.STDOUT)

        user = testlib.TestUser()
        # hack to get the user in the GnupgPrivateTests module
        __builtin__.user = user

        if app == 'gpg2' and self.lsb_release['Release'] >= 16.04:
            cfg, tmpname = testlib.mkstemp_fill('''%echo Generating a standard key
Key-Type: RSA
Key-Length: 2048
Name-Real: Mr T Ester
Name-Comment: test key
Name-Email: tester@example.com
Expire-Date: 0
Passphrase: ""
# Do a commit here, so that we can later print "done" :-)
%commit
%echo done
''')
        else:
            cfg, tmpname = testlib.mkstemp_fill('''%echo Generating a standard key
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Mr T Ester
Name-Comment: test key
Name-Email: tester@example.com
Expire-Date: 0
#Passphrase: testing
# Do a commit here, so that we can later print "done" :-)
%commit
%echo done
''')

        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/'+app+' --gen-key --batch', user.login], stdin=cfg)
        if rc != 0:
            print out
        cfg.close()
        os.unlink(tmpname)

        # stop noise-generator
        os.kill(noise,15)

    def onetime_cleanUp(self):
        global user
        user = None

    def test_00_keyring_exists(self):
        '''Secret key creation (move the mouse around for entropy!)'''
        self.onetime_setUp()

        if app == 'gpg2' and self.lsb_release['Release'] >= 16.04:
            self.assertEquals(os.path.exists('/home/'+user.login+'/.gnupg/pubring.kbx'),True)
        else:
            self.assertEquals(os.path.exists('/home/'+user.login+'/.gnupg/secring.gpg'),True)

    def test_01_key_exportable(self):
        '''Public key is exportable'''
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' -a --export tester@example.com | fgrep -q -- "-----END PGP PUBLIC KEY BLOCK-----"', user.login])
        
    def _test_encryption_decryption(self,recipient='tester@example.com'):
        '''File can be encrypted'''

        plain_string = '''This is a simple plain text.'''
        plain, plain_name = testlib.mkstemp_fill(plain_string)
        os.chmod(plain_name,0644)
        self.assertEquals(file(plain_name,"r").readline(),plain_string)

        # Encrypt        
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' -a -r '+recipient+' --always-trust --encrypt '+plain_name, user.login])
        self.assertEquals(os.path.exists(plain_name+'.asc'),True)
        os.unlink(plain_name)
        self.assertEquals(os.path.exists(plain_name),False)

        # Decrypt
        if recipient == 'tester@example.com':
            self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' '+plain_name+'.asc', user.login])
            self.assertEquals(os.path.exists(plain_name),True)
            self.assertEquals(file(plain_name,"r").readline(),plain_string)
            os.unlink(plain_name)
        else:
            self.assertShellExitNotEquals(0, ['/bin/su','-c','/usr/bin/'+app+' '+plain_name+'.asc', user.login])

        os.unlink(plain_name+'.asc')

    def test_02_self_encryption(self):
        '''File can be encrypted to ourself'''
        self._test_encryption_decryption()

    def test_03_recv_keys(self):
        '''Test that public keys can be loaded by default from the network.'''
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --keyserver keyserver.ubuntu.com --recv-keys 0xDC6DC026', user.login])
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --fingerprint kees@ubuntu.com | fgrep -q -- "Key fingerprint = A5C3 F68F 229D D60F 723E  6E13 8972 F4DF DC6D C026"', user.login])

    def test_04_check_sigs(self):
        '''Sigs can be checked against public keys'''
        # This test depends on test_03_recv_keys succeeding
        sig, tmpname = testlib.mkstemp_fill('''-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

This is a short plaintext.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)
Comment: Kees Cook <kees@outflux.net>

iQIcBAEBCgAGBQJNthcDAAoJEIly9N/cbcAmd8YP/0suYkU03kguBZAvXGuuPcgc
Z6RHwxW4yFM+/jyEDKCbjOzb371PKE+cPCbhOK2Va50Oi3jX92OwbiU8XiZqjUH3
gkj/4XyHRd7JCTi8gHiGjO5ko4LSyi/7DxoxtBC1aGVwYnHNtem/DT0thEPxsMAQ
TWFAi7KYrgM0u296L76Fdyx2yRpsb3TQxXcp7Z8BUTaOW2Wirqk9vmj7ZY7OnJo0
8HsZPQ7wnZyOrznPT8qJ/Wdc84jkOFLoqPik01sjNCD7wkVaiRjocWl7lQPTAC3F
ild1FfzrTesdrytgceQI49bZtdoGXAtwA+8F7bcpwiqtKnBhZ6+FB/6kQQ749kfU
2+LC5fcTtmWY6hcnQTQwAYp5qUZGmqwWT6Lylff+N0BJeseARTHyaXldOJkY+fwW
X9K5flIbug3FBwI+VfCdcVxN51z4owit3x+ZbqEj1Us3dswkzLTntDHNItpr+VSi
l9ioE5nARHs4NLen6EyCWkAOYs/XrttyS+fNNaurdH+etERmEamL+HO4dT9KJOWo
5JywObhL0YU32GvUHdSkkrcFlv06YlYAx6DTNG2PA+rMirikdtl9V/NGQaHX0rFS
u8x+12SzE9l54RpvSMGAny9Z8jNQytCeM3BPxtApA07Oe1eSGgXjQhpEVyF5+CVG
OtnFyZk3fPe8w0Oqiwj7
=mswH
-----END PGP SIGNATURE-----
''')
        sig.close()
        os.chmod(tmpname,0644)
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --verify '+ tmpname, user.login])
        os.unlink(tmpname)

    def test_04_check_sigs_bad(self):
        '''Bad signatures are detected'''
        # This test depends on test_03_recv_keys succeeding
        sig, tmpname = testlib.mkstemp_fill('''-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

This is an evil plaintext.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFF7xtsH/9LqRcGPm0RAhkTAJ9BG1sdMyBISDiBQVX8bS5k4YaGcACeIV8i
wrhmLbkm5ONbPbLWtiPk1HY=
=073p
-----END PGP SIGNATURE-----
''')
        sig.close()
        os.chmod(tmpname,0644)
        self.assertShellExitNotEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --verify '+ tmpname, user.login])
        os.unlink(tmpname)

    def test_05_remote_encryption(self):
        '''Test that a file can be encrypted to someone else'''
        # This test depends on test_03_recv_keys succeeding
        self._test_encryption_decryption('kees@ubuntu.com')

    def test_10_check_inline_forgery(self):
        '''Prepended plaintext detected as forgery (CVE-2007-1263)'''

        dir = tempfile.mkdtemp()
        os.chown(dir, user.uid, user.gid)
        signed_target = os.path.join(dir,'original.gpg')
        forged_target = os.path.join(dir,'forged.gpg')

        # Build signed plaintext
        plain_text = 'Original message\n'
        plain, tmpname = testlib.mkstemp_fill(plain_text)
        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/'+app+' --sign --output '+signed_target, user.login], stdin=plain)
        self.assertEquals(rc, 0, out)
        plain.close()
        os.unlink(tmpname)

        # Build forged packet
        evil_text = 'This is a forged addition\n'
        evil, tmpname = testlib.mkstemp_fill(evil_text)
        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/'+app+' -z0 --store --output '+forged_target, user.login], stdin=evil)
        self.assertEquals(rc, 0, out)
        evil.close()
        os.unlink(tmpname)

        # Merge into test case, and test
        forgery, test_target = testlib.mkstemp_fill(file(forged_target).read()+file(signed_target).read())
        self.assertShellExitNotEquals(0, ['/bin/su','-c','/usr/bin/'+app, user.login], stdin=forgery)
        forgery.close()

        os.unlink(test_target)
        os.unlink(forged_target)
        os.unlink(signed_target)
        os.rmdir(dir)

    def test_11_long_keyids(self):
        '''Test that gnupg uses long keyids when requesting keys.'''
        # See http://www.asheesh.org/note/debian/short-key-ids-are-bad-news.html

        # Specifying a short ID should get us two keys
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --keyserver keyserver.ubuntu.com --recv-keys 0x70096AD1 2>&1 | grep -q -- "Total number processed: 2"', user.login])

        # Specifying a long ID should get us only one key
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --keyserver keyserver.ubuntu.com --recv-keys 0xEC4B033C70096AD1 2>&1 | grep -q -- "Total number processed: 1"', user.login])

    def test_9000_cve_2012_6085(self):
        '''Test CVE-2012-6085 corrupted keyring'''

        # This needs to be the last test, since it will corrupt the keyring
        # if it fails

        # Make sure we can read keyring
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --list-keys', user.login])

        # Try importing the keyring
        expected = 0
        if app == 'gpg2' and self.lsb_release['Release'] < 15.04:
            expected = 2
        self.assertShellExitEquals(expected, ['/bin/su','-c','/usr/bin/'+app+' --import ./gnupg/CVE-2012-6085/fuzz-1617.pkr', user.login])

        # See if we can still read the keyring without error
        self.assertShellExitEquals(0, ['/bin/su','-c','/usr/bin/'+app+' --list-keys', user.login])

    def test_9999_cleanup(self):
        self.onetime_cleanUp()

if __name__ == '__main__':
    # You can run this normally, which will run gpg, or run it for gpg2
    # by specifying gpg2 on the command line. Alternatively, you can
    # also use the test-gnupg2.py test script.
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        app = 'gpg'
    else:
        app = sys.argv[1]
        del sys.argv[1]

    # hack to get the global variable in the GnupgPrivateTests module
    __builtin__.app = app

    print "Using binary: %s" % app

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GnupgTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

