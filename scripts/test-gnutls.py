#!/usr/bin/python
#
#    test-gnutls.py quality assurance test script for gnutls
#    Copyright (C) 2008-2016 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install gnutls-bin python-pexpect ca-certificates ssl-cert iputils-ping libgnutls-dev build-essential && ./test-gnutls.py -v'

    TODO:
      - gnutls-cli -p 5556 test.gnutls.org --ctypes OPENPGP (hardy and lower)
      - gnutls-cli -p 5556 test.gnutls.org --priority NORMAL:+CTYPE-OPENPGP:-CTYPE-X509 (intrepid and higher)
      - incorporate http://www.gnu.org/software/gnutls/server.html and
        http://www.gnu.org/software/gnutls/manual/html_node/Invoking-gnutls_002dserv.html
'''

# QRT-Depends: ssl gnutls private/qrt/gnutls.py
# QRT-Packages: gnutls-bin python-pexpect ca-certificates ssl-cert iputils-ping libgnutls-dev build-essential sudo valgrind
# QRT-Alternates: libtasn1-6-dev:!lucid libtasn1-6-dev:!precise libtasn1-3-dev:lucid libtasn1-3-dev:precise
# QRT-Privilege: root

import unittest, subprocess, sys
import testlib
import re
import os
import time
import pexpect
import shutil
import signal
import tempfile

try:
    from private.qrt.gnutls import PrivateGnutlsTest
except ImportError:
    class PrivateGnutlsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class GnutlsTest(testlib.TestlibCase, PrivateGnutlsTest):
    '''Test gnutls'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.tmpdir = ""

        if self.lsb_release['Release'] == 10.04:
            self.protocols =   ['SSL3.0', 'TLS1.0', 'TLS1.1', 'TLS1.2']
            self.types =       ['X.509', 'OPENPGP']
            self.compression = ['DEFLATE', 'NULL']
        else:
            self.protocols =   ['VERS-SSL3.0', 'VERS-TLS1.0',
                                'VERS-TLS1.1', 'VERS-TLS1.2']
            self.types =       ['CTYPE-X.509', 'CTYPE-OPENPGP']
            self.compression = ['COMP-DEFLATE', 'COMP-NULL']

        if self.lsb_release['Release'] <= 14.04:
            self.suites = [ 'TLS_ANON_DH_ARCFOUR_MD5',
                            'TLS_ANON_DH_3DES_EDE_CBC_SHA1',
                            'TLS_ANON_DH_AES_128_CBC_SHA1',
                            'TLS_ANON_DH_AES_256_CBC_SHA1',
                            'TLS_ANON_DH_CAMELLIA_128_CBC_SHA1',
                            'TLS_ANON_DH_CAMELLIA_256_CBC_SHA1',
                            'TLS_PSK_SHA_ARCFOUR_SHA1',
                            'TLS_PSK_SHA_3DES_EDE_CBC_SHA1',
                            'TLS_PSK_SHA_AES_128_CBC_SHA1',
                            'TLS_PSK_SHA_AES_256_CBC_SHA1',
                            'TLS_DHE_PSK_SHA_ARCFOUR_SHA1',
                            'TLS_DHE_PSK_SHA_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_PSK_SHA_AES_128_CBC_SHA1',
                            'TLS_DHE_PSK_SHA_AES_256_CBC_SHA1',
                            'TLS_SRP_SHA_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_AES_256_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_AES_256_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_AES_256_CBC_SHA1',
                            'TLS_DHE_DSS_ARCFOUR_SHA1',
                            'TLS_DHE_DSS_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_DSS_AES_128_CBC_SHA1',
                            'TLS_DHE_DSS_AES_256_CBC_SHA1',
                            'TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1',
                            'TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1',
                            'TLS_DHE_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_RSA_AES_128_CBC_SHA1',
                            'TLS_DHE_RSA_AES_256_CBC_SHA1',
                            'TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1',
                            'TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1',
                            'TLS_RSA_NULL_MD5',
                            'TLS_RSA_EXPORT_ARCFOUR_40_MD5',
                            'TLS_RSA_ARCFOUR_SHA1',
                            'TLS_RSA_ARCFOUR_MD5',
                            'TLS_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_RSA_AES_128_CBC_SHA1',
                            'TLS_RSA_AES_256_CBC_SHA1',
                            'TLS_RSA_CAMELLIA_128_CBC_SHA1',
                            'TLS_RSA_CAMELLIA_256_CBC_SHA1']

            if self.lsb_release['Release'] >= 12.04:
                self.suites.extend([
                            'TLS_ANON_DH_AES_128_CBC_SHA256',
                            'TLS_ANON_DH_AES_256_CBC_SHA256',
                            'TLS_DHE_DSS_AES_128_CBC_SHA256',
                            'TLS_DHE_DSS_AES_256_CBC_SHA256',
                            'TLS_DHE_RSA_AES_128_CBC_SHA256',
                            'TLS_DHE_RSA_AES_256_CBC_SHA256',
                            'TLS_RSA_NULL_SHA1',
                            'TLS_RSA_NULL_SHA256',
                            'TLS_RSA_AES_128_CBC_SHA256',
                            'TLS_RSA_AES_256_CBC_SHA256',
                            ])

        if self.lsb_release['Release'] >= 14.10:
            self.suites = [ 'TLS_RSA_NULL_MD5',
                            'TLS_RSA_NULL_SHA1',
                            'TLS_RSA_NULL_SHA256',
                            'TLS_RSA_ARCFOUR_128_SHA1',
                            'TLS_RSA_ARCFOUR_128_MD5',
                            'TLS_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_RSA_AES_128_CBC_SHA1',
                            'TLS_RSA_AES_256_CBC_SHA1',
                            'TLS_RSA_CAMELLIA_128_CBC_SHA256',
                            'TLS_RSA_CAMELLIA_256_CBC_SHA256',
                            'TLS_RSA_CAMELLIA_128_CBC_SHA1',
                            'TLS_RSA_CAMELLIA_256_CBC_SHA1',
                            'TLS_RSA_AES_128_CBC_SHA256',
                            'TLS_RSA_AES_256_CBC_SHA256',
                            'TLS_RSA_AES_128_GCM_SHA256',
                            'TLS_RSA_AES_256_GCM_SHA384',
                            'TLS_RSA_CAMELLIA_128_GCM_SHA256',
                            'TLS_RSA_CAMELLIA_256_GCM_SHA384',
                            'TLS_RSA_SALSA20_256_SHA1',
                            'TLS_RSA_ESTREAM_SALSA20_256_SHA1',
                            'TLS_DHE_DSS_ARCFOUR_128_SHA1',
                            'TLS_DHE_DSS_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_DSS_AES_128_CBC_SHA1',
                            'TLS_DHE_DSS_AES_256_CBC_SHA1',
                            'TLS_DHE_DSS_CAMELLIA_128_CBC_SHA256',
                            'TLS_DHE_DSS_CAMELLIA_256_CBC_SHA256',
                            'TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1',
                            'TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1',
                            'TLS_DHE_DSS_AES_128_CBC_SHA256',
                            'TLS_DHE_DSS_AES_256_CBC_SHA256',
                            'TLS_DHE_DSS_AES_128_GCM_SHA256',
                            'TLS_DHE_DSS_AES_256_GCM_SHA384',
                            'TLS_DHE_DSS_CAMELLIA_128_GCM_SHA256',
                            'TLS_DHE_DSS_CAMELLIA_256_GCM_SHA384',
                            'TLS_DHE_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_RSA_AES_128_CBC_SHA1',
                            'TLS_DHE_RSA_AES_256_CBC_SHA1',
                            'TLS_DHE_RSA_CAMELLIA_128_CBC_SHA256',
                            'TLS_DHE_RSA_CAMELLIA_256_CBC_SHA256',
                            'TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1',
                            'TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1',
                            'TLS_DHE_RSA_AES_128_CBC_SHA256',
                            'TLS_DHE_RSA_AES_256_CBC_SHA256',
                            'TLS_DHE_RSA_AES_128_GCM_SHA256',
                            'TLS_DHE_RSA_AES_256_GCM_SHA384',
                            'TLS_DHE_RSA_CAMELLIA_128_GCM_SHA256',
                            'TLS_DHE_RSA_CAMELLIA_256_GCM_SHA384',
                            'TLS_ECDHE_RSA_NULL_SHA1',
                            'TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_ECDHE_RSA_AES_128_CBC_SHA1',
                            'TLS_ECDHE_RSA_AES_256_CBC_SHA1',
                            'TLS_ECDHE_RSA_AES_256_CBC_SHA384',
                            'TLS_ECDHE_RSA_ARCFOUR_128_SHA1',
                            'TLS_ECDHE_RSA_CAMELLIA_128_CBC_SHA256',
                            'TLS_ECDHE_RSA_CAMELLIA_256_CBC_SHA384',
                            'TLS_ECDHE_ECDSA_NULL_SHA1',
                            'TLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA1',
                            'TLS_ECDHE_ECDSA_AES_128_CBC_SHA1',
                            'TLS_ECDHE_ECDSA_AES_256_CBC_SHA1',
                            'TLS_ECDHE_ECDSA_ARCFOUR_128_SHA1',
                            'TLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256',
                            'TLS_ECDHE_ECDSA_CAMELLIA_256_CBC_SHA384',
                            'TLS_ECDHE_ECDSA_AES_128_CBC_SHA256',
                            'TLS_ECDHE_RSA_AES_128_CBC_SHA256',
                            'TLS_ECDHE_ECDSA_CAMELLIA_128_GCM_SHA256',
                            'TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384',
                            'TLS_ECDHE_ECDSA_AES_128_GCM_SHA256',
                            'TLS_ECDHE_ECDSA_AES_256_GCM_SHA384',
                            'TLS_ECDHE_RSA_AES_128_GCM_SHA256',
                            'TLS_ECDHE_RSA_AES_256_GCM_SHA384',
                            'TLS_ECDHE_ECDSA_AES_256_CBC_SHA384',
                            'TLS_ECDHE_RSA_CAMELLIA_128_GCM_SHA256',
                            'TLS_ECDHE_RSA_CAMELLIA_256_GCM_SHA384',
                            'TLS_ECDHE_RSA_SALSA20_256_SHA1',
                            'TLS_ECDHE_ECDSA_SALSA20_256_SHA1',
                            'TLS_ECDHE_RSA_ESTREAM_SALSA20_256_SHA1',
                            'TLS_ECDHE_ECDSA_ESTREAM_SALSA20_256_SHA1',
                            'TLS_ECDHE_PSK_3DES_EDE_CBC_SHA1',
                            'TLS_ECDHE_PSK_AES_128_CBC_SHA1',
                            'TLS_ECDHE_PSK_AES_256_CBC_SHA1',
                            'TLS_ECDHE_PSK_AES_128_CBC_SHA256',
                            'TLS_ECDHE_PSK_AES_256_CBC_SHA384',
                            'TLS_ECDHE_PSK_ARCFOUR_128_SHA1',
                            'TLS_ECDHE_PSK_NULL_SHA256',
                            'TLS_ECDHE_PSK_NULL_SHA384',
                            'TLS_ECDHE_PSK_CAMELLIA_128_CBC_SHA256',
                            'TLS_ECDHE_PSK_CAMELLIA_256_CBC_SHA384',
                            'TLS_ECDHE_PSK_SALSA20_256_SHA1',
                            'TLS_ECDHE_PSK_ESTREAM_SALSA20_256_SHA1',
                            'TLS_PSK_ARCFOUR_128_SHA1',
                            'TLS_PSK_3DES_EDE_CBC_SHA1',
                            'TLS_PSK_AES_128_CBC_SHA1',
                            'TLS_PSK_AES_256_CBC_SHA1',
                            'TLS_PSK_AES_128_CBC_SHA256',
                            'TLS_PSK_AES_256_GCM_SHA384',
                            'TLS_PSK_CAMELLIA_128_GCM_SHA256',
                            'TLS_PSK_CAMELLIA_256_GCM_SHA384',
                            'TLS_PSK_AES_128_GCM_SHA256',
                            'TLS_PSK_NULL_SHA256',
                            'TLS_PSK_CAMELLIA_128_CBC_SHA256',
                            'TLS_PSK_CAMELLIA_256_CBC_SHA384',
                            'TLS_PSK_SALSA20_256_SHA1',
                            'TLS_PSK_ESTREAM_SALSA20_256_SHA1',
                            'TLS_PSK_AES_256_CBC_SHA384',
                            'TLS_PSK_NULL_SHA384',
                            'TLS_RSA_PSK_ARCFOUR_128_SHA1',
                            'TLS_RSA_PSK_3DES_EDE_CBC_SHA1',
                            'TLS_RSA_PSK_AES_128_CBC_SHA1',
                            'TLS_RSA_PSK_AES_256_CBC_SHA1',
                            'TLS_RSA_PSK_CAMELLIA_128_GCM_SHA256',
                            'TLS_RSA_PSK_CAMELLIA_256_GCM_SHA384',
                            'TLS_RSA_PSK_AES_128_GCM_SHA256',
                            'TLS_RSA_PSK_AES_128_CBC_SHA256',
                            'TLS_RSA_PSK_NULL_SHA256',
                            'TLS_RSA_PSK_AES_256_GCM_SHA384',
                            'TLS_RSA_PSK_AES_256_CBC_SHA384',
                            'TLS_RSA_PSK_NULL_SHA384',
                            'TLS_RSA_PSK_CAMELLIA_128_CBC_SHA256',
                            'TLS_RSA_PSK_CAMELLIA_256_CBC_SHA384',
                            'TLS_DHE_PSK_ARCFOUR_128_SHA1',
                            'TLS_DHE_PSK_3DES_EDE_CBC_SHA1',
                            'TLS_DHE_PSK_AES_128_CBC_SHA1',
                            'TLS_DHE_PSK_AES_256_CBC_SHA1',
                            'TLS_DHE_PSK_AES_128_CBC_SHA256',
                            'TLS_DHE_PSK_AES_128_GCM_SHA256',
                            'TLS_DHE_PSK_NULL_SHA256',
                            'TLS_DHE_PSK_NULL_SHA384',
                            'TLS_DHE_PSK_AES_256_CBC_SHA384',
                            'TLS_DHE_PSK_AES_256_GCM_SHA384',
                            'TLS_DHE_PSK_CAMELLIA_128_CBC_SHA256',
                            'TLS_DHE_PSK_CAMELLIA_256_CBC_SHA384',
                            'TLS_DHE_PSK_CAMELLIA_128_GCM_SHA256',
                            'TLS_DHE_PSK_CAMELLIA_256_GCM_SHA384',
                            'TLS_DH_ANON_ARCFOUR_128_MD5',
                            'TLS_DH_ANON_3DES_EDE_CBC_SHA1',
                            'TLS_DH_ANON_AES_128_CBC_SHA1',
                            'TLS_DH_ANON_AES_256_CBC_SHA1',
                            'TLS_DH_ANON_CAMELLIA_128_CBC_SHA256',
                            'TLS_DH_ANON_CAMELLIA_256_CBC_SHA256',
                            'TLS_DH_ANON_CAMELLIA_128_CBC_SHA1',
                            'TLS_DH_ANON_CAMELLIA_256_CBC_SHA1',
                            'TLS_DH_ANON_AES_128_CBC_SHA256',
                            'TLS_DH_ANON_AES_256_CBC_SHA256',
                            'TLS_DH_ANON_AES_128_GCM_SHA256',
                            'TLS_DH_ANON_AES_256_GCM_SHA384',
                            'TLS_DH_ANON_CAMELLIA_128_GCM_SHA256',
                            'TLS_DH_ANON_CAMELLIA_256_GCM_SHA384',
                            'TLS_ECDH_ANON_NULL_SHA1',
                            'TLS_ECDH_ANON_3DES_EDE_CBC_SHA1',
                            'TLS_ECDH_ANON_AES_128_CBC_SHA1',
                            'TLS_ECDH_ANON_AES_256_CBC_SHA1',
                            'TLS_ECDH_ANON_ARCFOUR_128_SHA1',
                            'TLS_SRP_SHA_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_AES_256_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_AES_128_CBC_SHA1',
                            'TLS_SRP_SHA_DSS_AES_256_CBC_SHA1',
                            'TLS_SRP_SHA_RSA_AES_256_CBC_SHA1']


            if self.lsb_release['Release'] == 14.10:
                self.suites.extend(['TLS_RSA_SALSA20_256_UMAC96',
                                    'TLS_RSA_ESTREAM_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_RSA_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_ECDSA_SALSA20_256_UMAC96',
                                    'TLS_PSK_ESTREAM_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_RSA_ESTREAM_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_ECDSA_ESTREAM_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_PSK_ESTREAM_SALSA20_256_UMAC96',
                                    'TLS_PSK_SALSA20_256_UMAC96',
                                    'TLS_ECDHE_PSK_SALSA20_256_UMAC96'])


        if self.lsb_release['Release'] <= 14.04:
            self.ciphers = ['AES-256-CBC',
                            'AES-128-CBC',
                            '3DES-CBC',
                            'DES-CBC',
                            'ARCFOUR-128',
                            'ARCFOUR-40',
                            'RC2-40',
                            'CAMELLIA-256-CBC',
                            'CAMELLIA-128-CBC',
                            'NULL']
        if self.lsb_release['Release'] >= 14.10:
            self.ciphers = ['AES-256-CBC',
                            'AES-192-CBC',
                            'AES-128-CBC',
                            'AES-128-GCM',
                            'AES-256-GCM',
                            'ARCFOUR-128',
                            'ESTREAM-SALSA20-256',
                            'SALSA20-256',
                            'CAMELLIA-256-CBC',
                            'CAMELLIA-192-CBC',
                            'CAMELLIA-128-CBC',
                            'CAMELLIA-128-GCM',
                            'CAMELLIA-256-GCM',
                            '3DES-CBC',
                            'DES-CBC',
                            'ARCFOUR-40',
                            'RC2-40']

        if self.lsb_release['Release'] <= 14.04:
            self.macs =    ['SHA1',
                            'MD5',
                            'SHA256',
                            'SHA384',
                            'SHA512',
                            'MD2',
                            'RIPEMD160']

            if self.lsb_release['Release'] == 10.04:
                self.macs.extend(['NULL'])
            else:
                self.macs.extend(['MAC-NULL'])

        if self.lsb_release['Release'] >= 14.10:
            self.macs =    ['SHA1',
                            'MD5',
                            'SHA256',
                            'SHA384',
                            'SHA512',
                            'SHA224',
                            'UMAC-96',
                            'UMAC-128',
                            'AEAD']


        if self.lsb_release['Release'] <= 14.04:
            self.key_exch = ['ANON-DH',
                             'RSA',
                             'RSA-EXPORT',
                             'DHE-RSA',
                             'DHE-DSS',
                             'SRP-DSS',
                             'SRP-RSA',
                             'SRP',
                             'PSK',
                             'DHE-PSK']

        if self.lsb_release['Release'] >= 14.10:
            self.key_exch = ['ANON-DH',
                             'ANON-ECDH',
                             'RSA',
                             'DHE-RSA',
                             'DHE-DSS',
                             'ECDHE-RSA',
                             'ECDHE-ECDSA',
                             'SRP-DSS',
                             'SRP-RSA',
                             'SRP',
                             'PSK',
                             'RSA-PSK',
                             'DHE-PSK',
                             'ECDHE-PSK']

        self.hosts = "/etc/hosts"
        testlib.config_replace(self.hosts, "", True)
        subprocess.call(['sed', '-i', 's/^\\(127.0.0.1.*\\)/\\1 server client/g', self.hosts])

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore(self.hosts)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        os.chdir(self.fs_dir)

    def test_certtool(self):
        '''Test certtool'''
        rc, report = testlib.cmd(['certtool', '-k', '--infile', './ssl/private.key'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'Public Key Algorithm' not in report\n"
        self.assertTrue('Public Key Algorithm' in report, result + report)

        result = "'BEGIN RSA PRIVATE KEY' not in report\n"
        self.assertTrue('BEGIN RSA PRIVATE KEY' in report, result + report)

        rc, report = testlib.cmd(['certtool', '-i', '--infile', './ssl/thawte.pem'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "'X.509 Certificate Info' not in report\n"
        self.assertTrue('X.509 Certificate Info'.lower() in report.lower(), result + report)

        result = "'BEGIN CERTIFICATE' not in report\n"
        self.assertTrue('BEGIN CERTIFICATE' in report, result + report)

    def _check_in_list(self, start, list):
        '''Check if all elements in list are in the line that starts with
           start
        '''
        rc, report = testlib.cmd(['gnutls-cli', '-l'])
        expected = 0
        assert expected == rc

        pat = re.compile(r'^' + start)
        not_found = ""
        line = ""
        for i in report.splitlines():
            if pat.search(i):
                line = i
                break

        components = line[line.find(':')+1:].replace(',','').split()
        for i in list:
            if i not in components:
                not_found += i + " "
        return not_found

    def test_types(self):
        '''Test certificate types list'''
        not_found = self._check_in_list('Certificate types:', self.types)
        result = "' %s' not found in 'Certificate types' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_protocols(self):
        '''Test protocol list'''
        not_found = self._check_in_list('Protocols:', self.protocols)
        result = "' %s' not found in 'Protocols' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_cipher_suites(self):
        '''Test cipher suite list'''
        rc, report = testlib.cmd(['gnutls-cli', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        not_found = ""
        for i in self.suites:
            if not i in report:
                not_found += i + " "
        result = "'%s' not found in 'Cipher suites'. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_ciphers(self):
        '''Test ciphers list'''
        not_found = self._check_in_list('Ciphers:', self.ciphers)
        result = "' %s' not found in 'Ciphers' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_macs(self):
        '''Test MACs list'''
        not_found = self._check_in_list('MACs:', self.macs)
        result = "' %s' not found in 'MACs' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_key_exchange(self):
        '''Test key exchange list'''
        not_found = self._check_in_list('Key exchange', self.key_exch)
        result = "' %s' not found in 'Key exchange' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_compression(self):
        '''Test compression lists'''
        not_found = self._check_in_list('Compression', self.compression)
        result = "' %s' not found in 'Compression' line. " % (not_found)
        self.assertTrue(not_found == "", result)

    def test_CVE_2008_4989(self):
        '''Test CVE-2008-4989'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4433 --x509keyfile ./ssl/private.key --x509certfile ./ssl/CVE-2008-4989_chain.pem >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['ping', '-c', '1', 'server'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        str = "certificate is trusted"
        report = ""
        try:
            child = pexpect.spawn('gnutls-cli --x509cafile ./ssl/thawte.pem -p 4433 server')
            time.sleep(0.2)
            child.expect('.* ' + str, timeout=5)
            time.sleep(0.2)
            report = child.after
        except:
            pass

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        child.kill(0)

        result = "'%s' found in report\n" % (str)
        self.assertTrue(report == "", result + report)

    def test_debian505279(self):
        '''Test Debian bug #505279'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4433 --x509keyfile /etc/ssl/private/ssl-cert-snakeoil.key --x509certfile /etc/ssl/certs/ssl-cert-snakeoil.pem >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['ping', '-c', '1', 'server'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        exe = '/usr/bin/gnutls-cli'
        args = ['/bin/sh', '-c', 'exec ' + exe + ' -V --x509cafile /etc/ssl/certs/ca-certificates.crt -p 4433 --insecure server >/dev/null 2>&1']
        pid = os.spawnv(os.P_NOWAIT, args[0], args)
        time.sleep(2)

        running = False
        if (testlib.check_pid(exe, pid)):
            running = True
            os.kill(pid, signal.SIGALRM)

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "'%s' died unexpectedly." % (exe)
        self.assertTrue(running, result)

    def test_lp292604(self):
        '''Test Launchpad bug #292604'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4433 --x509keyfile /etc/ssl/private/ssl-cert-snakeoil.key --x509certfile /etc/ssl/certs/ssl-cert-snakeoil.pem --x509cafile ./ssl/lp292604-ca-certificate.crt >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['ping', '-c', '1', 'server'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        exe = '/usr/bin/gnutls-cli'
        args = ['/bin/sh', '-c', 'exec ' + exe + ' -V -p 4433 --insecure server >/dev/null 2>&1']
        pid = os.spawnv(os.P_NOWAIT, args[0], args)
        time.sleep(2)

        running = False
        if (testlib.check_pid(exe, pid)):
            running = True
            os.kill(pid, signal.SIGALRM)

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "'%s' died unexpectedly." % (exe)
        self.assertTrue(running, result)

    def test_lp305264(self):
        '''Test Launchpad bug #305264 - deprecation of rsa/md2 certificates'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4433 --x509keyfile ./ssl/lp305264/lp305264-key.pem --x509certfile ./ssl/lp305264/lp305264-cert.pem >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['ping', '-c', '1', 'server'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        exe = '/usr/bin/gnutls-cli'
        args = ['/bin/sh', '-c', 'exec ' + exe + ' -V -p 4433 --x509cafile ./ssl/lp305264/cacert.pem server >/dev/null 2>&1']
        pid = os.spawnv(os.P_NOWAIT, args[0], args)
        time.sleep(2)

        running = False
        if (testlib.check_pid(exe, pid)):
            running = True
            os.kill(pid, signal.SIGALRM)

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "'%s' accepted an rsa/md2 certificate." % (exe)
        self.assertFalse(running, result)

    def _get_v1_ca_crt_priority_by_release(self):
        ''' Needed to work around https://launchpad.net/bugs/310675 '''
        priority = ""
        # gnutls 2.10.4 switched from rejecting v1 CA certs by default
        # and having the VERIFY_ALLOW_X509_V1_CA_CRT flag, to accepting
        # them by default and being able to disable them with the
        # GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT flag.
        if self.lsb_release['Release'] == 10.04:
            priority = "--priority NORMAL:%VERIFY_ALLOW_X509_V1_CA_CRT "
        return priority

    def test_sites(self):
        '''Test sites'''
        sites = [ 'launchpad.net', 'landscape.canonical.com', 'www.verisign.com', 'staging.landscape.canonical.com' ]

        error = ""
        for site in sites:
            print >>sys.stdout, "\n " + site + " ... ",
            sys.stdout.flush()

            str = "certificate is trusted"
            report = ""
            cmd = "gnutls-cli -V --x509cafile /etc/ssl/certs/ca-certificates.crt -p 443 "
            cmd += self._get_v1_ca_crt_priority_by_release()
            try:
                child = pexpect.spawn(cmd + site)
                time.sleep(0.2)
                child.expect('.* ' + str, timeout=5)
                time.sleep(0.2)
                report = child.after
            except:
                # report is empty when can't connect, so collect these here
                # and check later
                error += site + " "

            child.kill(0)
            child = None

            if report != "":
                result = "'%s' not found in report\n" % (str)
                self.assertTrue(str in report, result + report)

        result = "Error with: " + error + ". For more info, run:\n$ " + cmd + " <site>"
        self.assertTrue(error == "", result)

    def test_alt_cert_chain(self):
        '''Test alternative certificate chains in gnutls'''
        sites = [ "www.ibps.alpes.banquepopulaire.fr" ]

        error = ""
        for site in sites:
            print >>sys.stdout, "\n " + site + " ... ",
            sys.stdout.flush()

            str = "certificate is trusted"
            report = ""
            cmd = "gnutls-cli -V --x509cafile /etc/ssl/certs/ca-certificates.crt -p 443 "
            cmd += self._get_v1_ca_crt_priority_by_release()
            try:
                child = pexpect.spawn(cmd + site)
                time.sleep(0.2)
                child.expect('.* ' + str, timeout=5)
                time.sleep(0.2)
                report = child.after
            except:
                # report is empty when can't connect, so collect these here
                # and check later
                error += site + " "

            child.kill(0)
            child = None

            if report != "":
                result = "'%s' not found in report\n" % (str)
                self.assertTrue(str in report, result + report)

        result = "Error with: " + error + ". For more info, run:\n$ " + cmd + " <site>"
        self.assertTrue(error == "", result)

    def disabled_test_md2_regression(self):

        # This test no longer works, need to investigate

        '''Test 2.6.2 MD2 regression'''
        error = ""
        str = "certificate is trusted"
        cmd = "gnutls-cli -V --x509cafile /etc/ssl/certs/7651b327.0 -p 443 "
        cmd += self._get_v1_ca_crt_priority_by_release()
        site = "www.verisign.com"
        report = ""
        try:
            child = pexpect.spawn(cmd + site)
            time.sleep(0.2)
            child.expect('.* ' + str, timeout=5)
            time.sleep(0.2)
            report = child.after
        except:
            error = site

        child.kill(0)
        child = None

        if report != "":
            result = "'%s' not found in report\n" % (str)
            self.assertTrue(str in report, result + report)

        result = "Error with: %s. For more info, run:\n$ %s" % (error, cmd + site)
        self.assertTrue(error == "", result)

    def test_CVE_2009_2730(self):
        '''Test CVE-2009-2730'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2009-2730_nul-in-x509-names.c")
        binary = os.path.join(self.tmpdir, "CVE-2009-2730_nul-in-x509-names")
        shutil.copy('./gnutls/CVE-2009-2730_nul-in-x509-names.c', source)

        rc, report = testlib.cmd(['gcc', '-o', binary, source, '-lgnutls'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2014_1959(self):
        '''Test CVE-2014-1959'''

        if self.lsb_release['Release'] == 10.04:
            return self._skipped("PoC does't work on 10.04")

        if self.lsb_release['Release'] >= 14.10:
            return self._skipped("PoC does't work on 14.10+")

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2014-1959.c")
        binary = os.path.join(self.tmpdir, "CVE-2014-1959")
        shutil.copy('./gnutls/CVE-2014-1959/CVE-2014-1959.c', source)

        rc, report = testlib.cmd(['gcc', '-o', binary, source, '-lgnutls'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2014_3466(self):
        '''Test CVE-2014-3466'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2014-3466.c")
        binary = os.path.join(self.tmpdir, "CVE-2014-3466")
        shutil.copy('./gnutls/CVE-2014-3466/long-session-id.c', source)

        rc, report = testlib.cmd(['gcc', '-o', binary, source, '-lgnutls'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2012_1569_libtasn(self):
        '''Test CVE-2012-1569 (actually libtasn1)'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "Test_overflow.c")
        binary = os.path.join(self.tmpdir, "Test_overflow")

        # libtasn1 2.12 in quantal+ fixed the security issue in a different
        # way then the minimal patch in precise and earlier. The test
        # script needs to be slightly different.
        if self.lsb_release['Release'] > 12.04:
            shutil.copy('./gnutls/CVE-2012-1569/Test_overflow-212.c', source)
        else:
            shutil.copy('./gnutls/CVE-2012-1569/Test_overflow.c', source)

        rc, report = testlib.cmd(['gcc', '-o', binary, source, '-ltasn1'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2012_1569_gnutls(self):
        '''Test CVE-2012-1569 (gnutls)'''

        rc, report = testlib.cmd(['/usr/bin/certtool', '--certificate-info',
                                  '--inder', '--infile',
                                  './gnutls/CVE-2012-1569/invalid-cert.der'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2015_0294(self):
        '''Test CVE-2015-0294'''

        rc, report = testlib.cmd(['/usr/bin/certtool', '-e', '--infile',
                                  './gnutls/CVE-2015-0294/invalid-sig2.pem'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['/usr/bin/certtool', '-e', '--infile',
                                  './gnutls/CVE-2015-0294/invalid-sig3.pem'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2014_8564(self):
        '''Test CVE-2014-8564'''

        if self.lsb_release['Release'] <= 14.04:
            return self._skipped("Only affects gnutls28")

        rc, report = testlib.cmd(['/usr/bin/certtool', '--inder',
                                  '--crq-info', '--infile',
                                  './gnutls/CVE-2014-8564/csr-invalid.der'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


if __name__ == '__main__':
    # simple
    testlib.require_sudo()
    unittest.main()
