#!/usr/bin/python
#
#    test-python-crypto.py quality assurance test script for python-crypto
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
# QRT-Packages: python-crypto
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install python-crypto && sudo ./test-python-crypto.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-python-crypto.py -v'
'''


import unittest, sys, os
import testlib
from Crypto.Hash import MD5
from Crypto.PublicKey import ElGamal
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Util.number import getPrime
from Crypto.Util.number import getRandomNumber
from Crypto.Util.number import GCD

try:
    from private.qrt.PythonCrypto import PrivatePythonCryptoTest
except ImportError:
    class PrivatePythonCryptoTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PythonCryptoTest(testlib.TestlibCase, PrivatePythonCryptoTest):
    '''Test python-crypto.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.plaintext = "Ubuntu rocks!"
        self.hash = MD5.new(self.plaintext).digest()

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_rsa(self):
        '''Test RSA algorithm'''
        # Based on
        # http://stackoverflow.com/questions/4232389/signing-and-verifying-data-using-pycrypto-rsa

        # Generates a fresh public/private key pair
        key=RSA.generate(1024,os.urandom)

        # Sign the hash
        K=''
        signature=key.sign(self.hash,K)

        # Get public key
        pubkey=key.publickey()

        result = 'Could not verify signature'
        self.assertTrue(pubkey.verify(self.hash,signature), result)

        result = 'Succesfully verified bad hash!!'
        self.assertFalse(pubkey.verify(self.hash[:-1],signature), result)

    def test_dsa(self):
        '''Test DSA algorithm'''
        # Based on
        # http://stackoverflow.com/questions/4232389/signing-and-verifying-data-using-pycrypto-rsa

        # Generates a fresh public/private key pair
        key=DSA.generate(1024,os.urandom)

        # Sign the hash
        K=getRandomNumber(128,os.urandom)
        signature=key.sign(self.hash,K)

        # Get public key
        pubkey=key.publickey()

        result = 'Could not verify signature'
        self.assertTrue(pubkey.verify(self.hash,signature), result)

        result = 'Succesfully verified bad hash!!'
        self.assertFalse(pubkey.verify(self.hash[:-1],signature), result)

    def test_elgamal(self):
        '''Test ElGamal algorithm'''
        # Based on
        # http://stackoverflow.com/questions/4232389/signing-and-verifying-data-using-pycrypto-rsa

        # Generates a fresh public/private key pair
        key=ElGamal.generate(1024,os.urandom)

        # Sign the hash
        K=getPrime(128,os.urandom)
        while GCD(K,key.p-1)!=1:
            K=getPrime(128,os.urandom)

        signature=key.sign(self.hash,K)

        # Get public key
        pubkey=key.publickey()

        result = 'Could not verify signature'
        self.assertTrue(pubkey.verify(self.hash,signature), result)

        result = 'Succesfully verified bad hash!!'
        self.assertFalse(pubkey.verify(self.hash[:-1],signature), result)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
