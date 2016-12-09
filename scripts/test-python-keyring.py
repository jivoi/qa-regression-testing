#!/usr/bin/python
#
#    test-python-keyring.py quality assurance test script for python-keyring
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: python-keyring python-gnomekeyring
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:


'''
    This test should be run in a virtual machine (VM) with a desktop
    session and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

'''


import unittest, sys, os
from stat import *
import testlib
import keyring
import gnomekeyring

try:
    from private.qrt.PythonKeyring import PrivatePythonKeyringTest
except ImportError:
    class PrivatePythonKeyringTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class StubbedCryptedFileKeyring(keyring.backend.CryptedFileKeyring):
    '''Gets rid of password prompts'''
    def _get_new_password(self):
        return 'ubuntu'

    def _unlock(self):
        self.keyring_key = 'ubuntu'

    def _migrate(self, keyring_password='ubuntu'):
        super(StubbedCryptedFileKeyring, self)._migrate(keyring_password = keyring_password)

class PythonKeyringTest(testlib.TestlibCase, PrivatePythonKeyringTest):
    '''Test Python Keyring.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.service = 'qrt-script'
        self.userA = 'myuser'
        self.pwA = 'mypassword'
        self.userB = 'myseconduser'
        self.pwB = 'anotherpassword'
        self.pwC = 'ubuntu'

        self.uncrypted = os.path.expanduser('~/.local/share/python_keyring/keyring_pass.cfg')
        self.crypted = os.path.expanduser('~/.local/share/python_keyring/crypted_pass.cfg')
        self.old_uncrypted = os.path.expanduser('~/keyring_pass.cfg')
        self.old_crypted = os.path.expanduser('~/crypted_pass.cfg')
        self.keyring_files = [ self.uncrypted, self.crypted,
                               self.old_uncrypted, self.old_crypted ]

        for keyring_file in self.keyring_files:
            filename = os.path.expanduser(keyring_file)
            if os.path.exists(filename):
                testlib.config_replace(filename, "", append=True)
                # Erase the new empty file
                os.unlink(filename)

    def tearDown(self):
        '''Clean up after each test_* function'''

        for keyring_file in self.keyring_files:
            filename = os.path.expanduser(keyring_file)
            if os.path.exists(filename):
                os.unlink(filename)
                testlib.config_restore(filename)
        self._clean_gnome_keyring()

    def _password_test(self):
        keyring.set_password(self.service, self.userA, self.pwA)
        password = keyring.get_password(self.service, self.userA)

        error = "Password obtained: '%s' was not expected: '%s'" % (password, self.pwA)
        self.assertEquals(password, self.pwA, error)

        # Add a second one
        keyring.set_password(self.service, self.userB, self.pwB)
        password = keyring.get_password(self.service, self.userB)

        error = "Second password obtained: '%s' was not expected: '%s'" % (password, self.pwB)
        self.assertEquals(password, self.pwB, error)

        # Change first one
        keyring.set_password(self.service, self.userA, self.pwC)
        password = keyring.get_password(self.service, self.userA)
        error = "Changed password obtained: '%s' was not expected: '%s'" % (password, self.pwC)
        self.assertEquals(password, self.pwC, error)

    def _create_old_keyrings(self):
        '''Create old format keyrings'''
        testlib.config_replace(self.old_uncrypted,
'''[qrt_2Dscript]
migrationuser = bWlncmF0aW9ucGFzcw==
	
''')

        # Password is 'ubuntu'
        testlib.config_replace(self.old_crypted,
'''[keyring-setting]
crypted-password = ubR3Twh1k5PQE

[qrt_2Dscript]
migrationuser = QthbZuq+jitTi3eVVA==
	
''')

    def _clean_gnome_keyring(self):
        '''Clean out our test entries from Gnome Keyring'''

        try:
            items = gnomekeyring.find_network_password_sync(self.userA, self.service)
            gnomekeyring.item_delete_sync(None, items[0]['item_id'])
        except:
            pass

        try:
            items = gnomekeyring.find_network_password_sync(self.userB, self.service)
            gnomekeyring.item_delete_sync(None, items[0]['item_id'])
        except:
            pass

    def _check_file_permissions(self, filename):
        '''See if the expected file exists and has appropriate perms'''

        self.assertTrue(os.path.exists(filename), "Couldn't locate database file '%s'!" % filename)
        # Check permissions on directory
        directory = os.path.dirname(filename)
        error = "'%s' has incorrect permissions" % (directory)
        self.assertEquals(S_IMODE(os.stat(directory)[0]), 0700, error)

    def test_uncrypted_keyring(self):
        '''Test UncryptedFileKeyring'''

        keyring.set_keyring(keyring.backend.UncryptedFileKeyring())
        self._password_test()
        self._check_file_permissions(self.uncrypted)

    def test_crypted_keyring(self):
        '''Test CryptedFileKeyring'''

        keyring.set_keyring(StubbedCryptedFileKeyring())
        self._password_test()
        self._check_file_permissions(self.crypted)

    def test_gnome_keyring(self):
        '''Test GnomeKeyring'''

        keyring.set_keyring(keyring.backend.GnomeKeyring())
        self._password_test()

    def test_uncrypted_keyring_migration_add(self):
        '''Test UncryptedFileKeyring Migration by adding'''

        self._create_old_keyrings()
        keyring.set_keyring(keyring.backend.UncryptedFileKeyring())
        self._password_test()
        self._check_file_permissions(self.uncrypted)

    def test_uncrypted_keyring_migration_get(self):
        '''Test UncryptedFileKeyring Migration by getting'''

        self._create_old_keyrings()
        keyring.set_keyring(keyring.backend.UncryptedFileKeyring())
        password = keyring.get_password('qrt-script', 'migrationuser')
        error = "Couldn't locate old data!"
        self.assertEquals(password, 'migrationpass', error)
        self._check_file_permissions(self.uncrypted)

    def test_crypted_keyring_migration_add(self):
        '''Test CryptedFileKeyring Migration by adding'''

        self._create_old_keyrings()
        keyring.set_keyring(StubbedCryptedFileKeyring())
        self._password_test()
        self._check_file_permissions(self.crypted)

    def test_crypted_keyring_migration_get(self):
        '''Test CryptedFileKeyring Migration by getting'''

        # This is LP: #1042754
        self._create_old_keyrings()
        keyring.set_keyring(StubbedCryptedFileKeyring())
        password = keyring.get_password('qrt-script', 'migrationuser')
        error = "Couldn't locate old data!"
        self.assertEquals(password, 'migrationpass', error)
        self._check_file_permissions(self.crypted)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
