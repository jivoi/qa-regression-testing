#!/usr/bin/python
#
#    test-openssl.py quality assurance test script for openssl
#    Copyright (C) 2009-2016 Canonical Ltd.
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release openssl python-pexpect ca-certificates ssl-cert && ./test-openssl.py -v'

'''

# QRT-Packages: python-pexpect
# QRT-Depends: rng private/qrt/openssl.py

import unittest, subprocess, sys
import testlib
import re
import os
import time
import pexpect
import tempfile
import socket

# expect compression only if 'OPENSSL_DEFAULT_ZLIB' is set in the environment
expect_compression = False

try:
    from private.qrt.openssl import PrivateOpenSSLTest
except ImportError:
    class PrivateOpenSSLTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class OpenSSLTest(testlib.TestlibCase, PrivateOpenSSLTest):
    '''Test openssl'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        self.tmpdir = tempfile.mkdtemp(prefix='testlib-openssl', dir='/tmp')
        os.environ.setdefault('RANDFILE', '')
        os.environ['RANDFILE'] = os.path.join(self.tmpdir, ".rnd")
        self.port = 1000 + int(self.lsb_release['Release'] * 100)
        self.devnull = None

        # Make sure the precise workaround isn't set
        if 'OPENSSL_NO_CLIENT_TLS1_2' in os.environ:
            del(os.environ['OPENSSL_NO_CLIENT_TLS1_2'])

        self.topdir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        if self.devnull:
            self.devnull.close()

        # Make sure all servers and clients are dead
        # pexpect in < 14.04 ignores SIGHUP by default, unfortunately
        testlib.cmd(['killall', '-9', 'openssl'])

    def sslcmd(self, command, stdin=None, stdout=subprocess.PIPE, stderr=None):
        '''Try to execute command'''
        try:
            sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr)
        except OSError, e:
            return [127, str(e)]
        out = sp.communicate()[0]
        return [sp.returncode,out]

    def gen_ssl(self, type="rsa", server_hostname="server", client_hostname="client"):
        '''Generate ssl certificates for server and client'''
        os.chdir(self.tmpdir)

        cakey_pem = os.path.join(self.tmpdir, "cakey.pem")
        cacert_pem = os.path.join(self.tmpdir, "cacert.pem")
        srvkey_pem = os.path.join(self.tmpdir, "srvkey.pem")
        srvcert_pem = os.path.join(self.tmpdir, "srvcert.pem")
        srvreq_pem = os.path.join(self.tmpdir, "srvreq.pem")
        clientkey_pem = os.path.join(self.tmpdir, "clientkey.pem")
        clientcert_pem = os.path.join(self.tmpdir, "clientcert.pem")
        clientreq_pem = os.path.join(self.tmpdir, "clientreq.pem")
        dsaparam_pem = os.path.join(self.tmpdir, "dsaparam.pem")
        crl_pem = os.path.join(self.tmpdir, "crl.pem")
        openssl_conf = os.path.join(self.tmpdir, "openssl.conf")

        open(os.path.join(self.tmpdir, "index.txt"),'w').write("")
        open(os.path.join(self.tmpdir, "index.txt.attr"),'w').write("")
        open(os.path.join(self.tmpdir, "serial"),'w').write("01")
        open(os.path.join(self.tmpdir, "crlnumber"),'w').write("01")

        contents = '''
#
# Please see /usr/lib/ssl/openssl.cnf, 'man x509v3_config', 'man ca' and
# 'man req' for details.
#

HOME                    = .
RANDFILE                = $ENV::HOME/.rnd
oid_section             = new_oids

[ new_oids ]

[ ca ]
default_ca      = CA_default            # The default ca section

[ CA_default ]
dir             = ./                 # Where everything is kept
certs           = ./                 # Where the issued certs are kept
crl_dir         = ./                 # Where the issued crl are kept
database        = ./index.txt        # database index file.
new_certs_dir   = ./newcerts         # default place for new certs.
certificate     = ./cacert.pem       # The CA certificate
serial          = ./serial           # The current serial number
crlnumber       = ./crlnumber        # the current crl number
crl             = ./crl.pem          # The current CRL
private_key     = ./cakey.pem        # The private key
RANDFILE        = ./.rand            # private random number file
x509_extensions = usr_cert              # The extentions to add to the cert
name_opt        = ca_default            # Subject Name options
cert_opt        = ca_default            # Certificate field options
default_days    = 1000                  # how long to certify for (30 years)
default_crl_days= 1000                  # how long before next CRL
default_md      = default               # use public key default MD
preserve        = no                    # keep passed DN ordering
policy          = policy_match

[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits            = 2048
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert
string_mask = utf8only

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = US
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Arizona
localityName                    = Locality Name (eg, city)
localityName_default            = Phoenix
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = Testlib
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Test
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64

[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name

[ usr_cert ]
basicConstraints=critical,CA:FALSE
extendedKeyUsage = codeSigning,1.3.6.1.4.1.311.10.3.6
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]
basicConstraints = critical,CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = digitalSignature, cRLSign, keyCertSign
crlDistributionPoints=URI:http://localhost/ca.crl

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
basicConstraints=critical,CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
'''
        open(openssl_conf,'w').write(contents)

        # see http://dev.mysql.com/doc/refman/5.0/en/secure-create-certs.html
        # and http://bugs.mysql.com/bug.php?id=21287

        # generate the CA
        (rc, out) = self.sslcmd(['openssl', 'genrsa', '-out', cakey_pem, '2048'], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out

        # generate the CA cert
        (rc, out) = self.sslcmd(['openssl', 'req', '-new', '-x509', '-config', openssl_conf, '-nodes', '-sha1', '-days', '1000', '-key', cakey_pem, '-subj', '/C=US/ST=Arizona/O=Testlib/OU=Test/CN=CA', '-out', cacert_pem ], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out


        # generate the CRL
        (rc, out) = self.sslcmd(['openssl', 'ca', '-config', openssl_conf, '-md', 'sha1', '-cert', cacert_pem, '-keyfile', cakey_pem, '-gencrl', '-out', crl_pem], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out

        new_key_type = 'rsa:1024'
        if type == "dsa":
            (rc, out) = self.sslcmd(['openssl', 'dsaparam', '-out', dsaparam_pem, '1024'], None, subprocess.PIPE, subprocess.PIPE)
            assert rc == 0, out
            new_key_type = 'dsa:' + dsaparam_pem

        for i in [ 'server', 'client' ]:
            key = srvkey_pem
            req = srvreq_pem
            crt = srvcert_pem
            hostname = server_hostname
            if i == "client":
                key = clientkey_pem
                req = clientreq_pem
                crt = clientcert_pem
                hostname = client_hostname
            (rc, out) = self.sslcmd(['openssl', 'req', '-newkey', new_key_type, '-sha1', '-days', '1000', '-nodes', '-keyout', key, '-out', req, '-subj', '/C=US/ST=Arizona/O=Testlib/OU=Test/CN=' + hostname], None, subprocess.PIPE, subprocess.PIPE)
            assert rc == 0, out

            (rc, out) = self.sslcmd(['openssl', 'x509', '-req', '-in', req, '-days', '1000', '-sha1', '-CA', cacert_pem, '-CAkey', cakey_pem, '-set_serial', '01', '-out', crt], None, subprocess.PIPE, subprocess.PIPE)
            assert rc == 0, out

        os.chdir(self.topdir)

        return srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem, crl_pem

    def _try_renegotiate(self, server_extra="", client_extra=""):
        '''Attempt to connect and renegotiate'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem,
         self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        client_failure = 0
        str = "Ubuntu has Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Why Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                cmd = ('openssl s_server ' + server_extra +
                       ' -accept %d -key ' % (self.port) + self.srvkey_pem +
                       ' -cert ' + self.srvcert_pem)
                if self.lsb_release['Release'] < 14.04:
                    srv_child = pexpect.spawn(cmd)
                else:
                    srv_child = pexpect.spawn(cmd, ignore_sighup = False)

                time.sleep(0.2)
                srv_child.expect("Secure Renegotiation IS supported", timeout=5)
                srv_child.expect(str, timeout=5)
                time.sleep(0.2)
                srv_child.sendline(str2)
                time.sleep(0.2)
                # Renegotiate a few times to make sure that's working
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline(str2)
                time.sleep(0.2)
                srv_child.expect(str, timeout=5)
            except Exception, e:
                os._exit(1)

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client ' + client_extra +
                ' -no_ssl2 -CAfile ' + self.cacert_pem + ' -cert ' +
                self.clientcert_pem + ' -key ' + self.clientkey_pem +
                ' -verify 2048 -connect localhost:%d' % (self.port))
            time.sleep(0.2)
            child.expect("Secure Renegotiation IS supported", timeout=5)
	    if expect_compression:
		    child.expect("Compression: zlib compression", timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            report = child.after
        except:
            client_failure = 1

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        # This doesn't always work in < 14.04 as pexpect ignores SIGHUP
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "Client exited abnormally with status code %s.\n" % client_failure
        self.assertTrue(client_failure == 0, result)

        child.kill(0)

    def _check_tls(self, client_extra = "", client_expected = "TLSv1.2"):
        '''Test if proper tls version is used'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem,
         self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        client_failure = 0
        str = "Ubuntu Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                cmd = ('openssl s_server -accept %d -key ' % (self.port) +
                       self.srvkey_pem + ' -cert ' + self.srvcert_pem)
                if self.lsb_release['Release'] < 14.04:
                    srv_child = pexpect.spawn(cmd)
                else:
                    srv_child = pexpect.spawn(cmd, ignore_sighup = False)

                time.sleep(0.2)
                srv_child.expect("Secure Renegotiation IS supported", timeout=5)
                srv_child.expect(str, timeout=5)
                time.sleep(0.2)
                srv_child.sendline(str2)
            except Exception, e:
                os._exit(1)

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client ' + client_extra + ' -no_ssl2 -CAfile ' + self.cacert_pem + ' -verify 2048 -connect localhost:%d' % (self.port))
            time.sleep(0.2)
            child.expect("Protocol  : %s" % client_expected, timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            report = child.after
        except:
            client_failure = 1

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        # This doesn't always work in < 14.04 as pexpect ignores SIGHUP
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "Client exited abnormally with status code %s.\n" % client_failure
        self.assertTrue(client_failure == 0, result)

        child.kill(0)

    def _check_fallback(self, client_extra = "", client_expected = "TLSv1.2"):
        '''Test if inappropriate fallback is reported'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem,
         self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        client_failure = 0
        str = "Ubuntu Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                cmd = ('openssl s_server -accept %d -key ' % (self.port) +
                       self.srvkey_pem + ' -cert ' + self.srvcert_pem)
                if self.lsb_release['Release'] < 14.04:
                    srv_child = pexpect.spawn(cmd)
                else:
                    srv_child = pexpect.spawn(cmd, ignore_sighup = False)

                time.sleep(0.2)
                srv_child.expect("SSL routines:SSL_BYTES_TO_CIPHER_LIST:inappropriate fallback", timeout=5)
            except Exception, e:
                os._exit(1)

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client ' + client_extra + ' -fallback_scsv -no_ssl2 -CAfile ' + self.cacert_pem + ' -verify 2048 -connect localhost:%d' % (self.port))
            time.sleep(0.2)
            child.expect("alert inappropriate fallback", timeout=5)
            child.expect("Protocol  : %s" % client_expected, timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            report = child.after
        except:
            client_failure = 1

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        # This doesn't always work in < 14.04 as pexpect ignores SIGHUP
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        result = "Client exited abnormally with status code %s.\n" % client_failure
        self.assertTrue(client_failure == 0, result)

        child.kill(0)

    def test_DSA_Client_Verify(self):
        '''Test DSA Client Verify'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem,
         self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        str = "Ubuntu has Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Why Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                cmd = ('openssl s_server -accept %d -key ' % (self.port) +
                       self.srvkey_pem + ' -cert ' + self.srvcert_pem)
                if self.lsb_release['Release'] < 14.04:
                    srv_child = pexpect.spawn(cmd)
                else:
                    srv_child = pexpect.spawn(cmd, ignore_sighup = False)

                time.sleep(0.2)
                srv_child.expect(str, timeout=5)
                time.sleep(0.2)
                srv_child.sendline(str2)
            except:
                raise

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client -no_ssl2 -CAfile ' + self.cacert_pem + ' -cert ' + self.clientcert_pem + ' -key ' + self.clientkey_pem + ' -verify 2048 -connect localhost:%d' % (self.port))
            time.sleep(0.2)
	    if expect_compression:
		    child.expect("Compression: zlib compression", timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            report = child.after
        except:
            raise

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        # This doesn't always work in < 14.04 as pexpect ignores SIGHUP
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        child.kill(0)

    def test_rfc5746(self):
        '''Test RFC5746 Support - default'''

        self._try_renegotiate()

    def test_rfc5746_tls_v1(self):
        '''Test RFC5746 Support - TLS v1'''

        self._try_renegotiate(server_extra="-tls1", client_extra="-tls1")

    def test_rfc5746_tls_v1_1(self):
        '''Test RFC5746 Support - TLS v1.1'''

        self._try_renegotiate(server_extra="-tls1_1", client_extra="-tls1_1")

    def test_rfc5746_tls_v1_2(self):
        '''Test RFC5746 Support - TLS v1.2'''

        self._try_renegotiate(server_extra="-tls1_2", client_extra="-tls1_2")

    def test_tls_default(self):
        '''Test negotiated TLS protocol - default'''

        expected = "TLSv1.2"

        # 1.0.1-4ubuntu5.26 now enables TLSv1.2 by default
        # TLSv1.2 should be disabled by default in precise
        #if self.lsb_release['Release'] == 12.04:
        #    expected="TLSv1.1"

        self._check_tls(client_expected = expected)

    def test_tls_default_precise(self):
        '''Test negotiated TLS protocol - precise workaround'''

        if self.lsb_release['Release'] != 12.04:
            return self._skipped("workaround only supported on Precise")

        # Disable TLSv1.2 by default
        os.environ['OPENSSL_NO_CLIENT_TLS1_2']="1"

        # Make sure it's using TLSv1.1
        expected = "TLSv1.1"

        self._check_tls(client_expected = expected)

        # Disable workaround
        if 'OPENSSL_NO_CLIENT_TLS1_2' in os.environ:
            del(os.environ['OPENSSL_NO_CLIENT_TLS1_2'])

    def test_tls_v1(self):
        '''Test negotiated TLS protocol - v1'''

        self._check_tls(client_extra="-tls1", client_expected = "TLSv1")

    def test_tls_v1_1(self):
        '''Test negotiated TLS protocol - v1.1'''

        self._check_tls(client_extra="-tls1_1", client_expected = "TLSv1.1")

    def test_tls_v1_2(self):
        '''Test negotiated TLS protocol - v1.2'''

        self._check_tls(client_extra="-tls1_2", client_expected = "TLSv1.2")

    def test_fallback_default(self):
        '''Test fallback SCSV - default'''

        expected = "TLSv1.2"

        # 1.0.1-4ubuntu5.26 now enables TLSv1.2 by default
        # TLSv1.2 is disabled by default in the precise client, but not
        # the precise server, so it is normal that this test would fail
        #if self.lsb_release['Release'] == 12.04:
        #    return self._skipped("TLSv1.2 is disabled in the precise client")

        self._check_tls(client_extra = '-fallback_scsv',
                        client_expected = expected)

    def test_fallback_tls_v1(self):
        '''Test fallback SCSV - v1'''

        # This should fail
        self._check_fallback(client_extra="-tls1", client_expected = "TLSv1")

    def test_fallback_tls_v1_1(self):
        '''Test fallback SCSV - v1.1'''

        # This should fail
        self._check_fallback(client_extra="-tls1_1", client_expected = "TLSv1.1")

    def test_fallback_tls_v1_2(self):
        '''Test fallback SCSV - v1.2'''

        # This should work
        self._check_tls(client_extra="-tls1_2 -fallback_scsv",
                        client_expected = "TLSv1.2")

    def test_fallback_ssl_v3(self):
        '''Test fallback SCSV - SSLv3'''

        if self.lsb_release['Release'] >= 15.10:
            return self._skipped("No SSLv3 in 15.10 and later") 

        # This should fail
        self._check_fallback(client_extra="-ssl3", client_expected = "SSLv3")

    def test_dtls(self):
        '''Test DTLS'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        str = "Ubuntu Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                srv_child = pexpect.spawn('openssl s_server -accept %d -dtls1 -no_ecdhe -timeout -key ' % (self.port) + self.srvkey_pem + ' -cert ' + self.srvcert_pem)
                time.sleep(0.2)
                srv_child.expect(str, timeout=5)
                time.sleep(0.2)
                srv_child.sendline(str2)
            except:
                raise

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client -no_ssl2 -CAfile ' + self.cacert_pem + ' -cert ' + self.clientcert_pem + ' -key ' + self.clientkey_pem + ' -verify 2048 -dtls1 -timeout -connect localhost:%d' % (self.port))
            time.sleep(0.2)
	    if expect_compression:
		    child.expect("Compression: zlib compression", timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            report = child.after
        except:
            raise

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        child.kill(0)

    def test_rfc5746_dtls(self):
        '''Test DTLS RFC5746 support'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        str = "Ubuntu Rocks %0.f %d" % (time.time(), os.getpid())
        str2 = "Yes, it does!"
        self.listener = os.fork()
        if self.listener == 0:
            try:
                srv_child = pexpect.spawn('openssl s_server -accept %d -dtls1 -no_ecdhe -timeout -key ' % (self.port) + self.srvkey_pem + ' -cert ' + self.srvcert_pem)
                time.sleep(0.2)
                srv_child.expect("Secure Renegotiation IS supported", timeout=5)
                srv_child.expect(str, timeout=5)
                time.sleep(0.2)
                srv_child.sendline(str2)
                # DTLS renegotiation is broken on lucid and earlier
                time.sleep(0.2)
                # Renegotiate a few times to make sure that's working
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline('r')
                time.sleep(0.2)
                srv_child.sendline(str2)
                time.sleep(0.2)
                srv_child.expect(str, timeout=5)
            except:
                raise

            srv_child.wait()
            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        report = ""
        try:
            child = pexpect.spawn('openssl s_client -tls1 -no_ssl2 -CAfile ' + self.cacert_pem + ' -cert ' + self.clientcert_pem + ' -key ' + self.clientkey_pem + ' -verify 2048 -dtls1 -timeout -connect localhost:%d' % (self.port))
            time.sleep(0.2)
            child.expect("Secure Renegotiation IS supported", timeout=5)
	    if expect_compression:
		    child.expect("Compression: zlib compression", timeout=5)
            child.expect("Verify return code: 0", timeout=5)
            time.sleep(0.2)
            child.sendline(str)
            time.sleep(0.2)
            child.expect(str2, timeout=5)

            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect('read R BLOCK', timeout=5)
            time.sleep(0.2)
            child.expect(str2, timeout=5)
            time.sleep(0.2)
            child.sendline(str)

            report = child.after
        except:
            raise

        # Check if the server is still running
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        child.kill(0)

    def test_cve_2009_1386(self):
        '''Test CVE-2009-1386'''

        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("dsa")

        self.listener = os.fork()
        if self.listener == 0:
            try:
                srv_child = pexpect.spawn('openssl s_server -accept %d -dtls1 -no_ecdhe -timeout -key ' % (self.port) + self.srvkey_pem + ' -cert ' + self.srvcert_pem)
            except:
                raise
            srv_child.wait()

            # We shouldn't get here unless we crashed
            # Let's wedge the status into the return code
            os._exit(srv_child.signalstatus)

        time.sleep(1)

        # Send a crafted packet.
        # Based on http://www.milw0rm.com/exploits/8873

        request = "\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('localhost', 4433))
        s.send(request)
        s.close()
        time.sleep(1)

        # Check if the server is still running 
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        return_code = status >> 8   # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        result = "Server exited abnormally with status code %s.\n" % return_code
        self.assertTrue(return_code == 0, result)

        # kill server now if it's still running
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

    def test_cve_2009_2409(self):
        '''Test CVE-2009-2409'''

        # This test checks to see if md2 was disabled
        any_file = '/etc/hosts'
        rc, report = testlib.cmd(['openssl', 'dgst', '-md2', any_file])

        # Make sure we got an error code
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure we got the exact error
        expected_error = "unknown option '-md2'"
        result = 'Could not find expected error message: %s\n' % expected_error
        self.assertTrue(expected_error in report, result + report)

    def test_key_generation(self):
        '''Test key generation'''
        tries = 2
        print ""
        for type in ['RSA', 'DSA']:
            print "  %s:" % (type),
            sys.stdout.flush()

            for len in ['512', '1024', '2048', '4096']:
                print "%s" % (len),
                sys.stdout.flush()
                rc, report = testlib.cmd(['./rng/openssl.sh', str(tries), type, len, self.tmpdir])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
            print ""

    def test_x509(self):
        '''Test x509 (CA and client/server certs)'''
        print ""
        for type in ['RSA', 'DSA']:
            print "  %s" % (type)
            (srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem, crl_pem) = self.gen_ssl(type)

            # verify the keys
            for i in [ 'server', 'client' ]:
                key = srvkey_pem
                crt = srvcert_pem
                if i == "client":
                    key = clientkey_pem
                    crt = clientcert_pem

                # verify positive result
                rc, report = testlib.cmd(["openssl", "verify", "-CAfile", cacert_pem, "-purpose", "ssl" + i, crt], None, subprocess.PIPE, subprocess.PIPE)
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                # verify negative result
                rc, report = testlib.cmd(["openssl", "verify", "-CApath", "/etc/ssl/certs", "-purpose", "ssl" + i, crt], None, subprocess.PIPE, subprocess.PIPE)
                self.assertTrue("error" in report, "Could not find 'error' in report:\n%s" % (report))

    def test_ciphers(self):
        '''Test cipher suite list'''

        # 2015-06-01: These export ciphers are now disabled by default:
        # EXP-EDH-RSA-DES-CBC-SHA EXP-EDH-DSS-DES-CBC-SHA EXP-DES-CBC-SHA EXP-RC2-CBC-MD5 EXP-RC4-MD5

        ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-AES-256-CBC-SHA:SRP-3DES-EDE-CBC-SHA:SRP-AES-128-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:PSK-3DES-EDE-CBC-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:PSK-AES128-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:PSK-RC4-SHA"

        # Removed in 1.0.2g
        if self.lsb_release['Release'] < 16.04:
            ciphers += ":EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA"

        if self.lsb_release['Release'] >= 15.10:
            ciphers += ":DH-DSS-AES256-GCM-SHA384:DH-RSA-AES256-SHA256:DH-DSS-AES256-SHA256:DH-DSS-AES256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:DH-DSS-AES128-GCM-SHA256:DH-DSS-AES128-SHA256:DH-DSS-AES128-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA"

        rc, report = testlib.cmd(["openssl", "ciphers"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        cur_ciphers = report.rstrip().split(':')

        # try to find any missing ciphers
        missing = []
        for c in ciphers.split(':'):
            if c not in cur_ciphers:
                missing.append(c)
        self.assertTrue(len(missing) == 0, "Could not find '%s' in report:\n%s" % (" ".join(missing), report))

        new_ciphers = []
        for c in cur_ciphers:
            if c not in ciphers:
                new_ciphers.append(c)
        self.assertTrue(len(new_ciphers) == 0, "Found new '%s' in report:\n%s" % (" ".join(new_ciphers), report))


    def test_passwd(self):
        '''test passwd to ensure results are sane'''

        rc, report = testlib.cmd(["openssl", "passwd", "-salt", "rl", "password"])
        self.assertEquals(0, rc, report)
        self.assertEquals('rl0uE0e2WKB0.', report.splitlines()[0], report)

        rc, report = testlib.cmd(["openssl", "passwd", "-1", "-salt", "salt", "password"])
        self.assertEquals(0, rc, report)
        self.assertEquals('$1$salt$qJH7.N4xYta3aEG/dfqo/0', report.splitlines()[0], report)

        rc, report = testlib.cmd(["openssl", "passwd", "-apr1", "-salt", "LBHigEZx", "password"])
        self.assertEquals(0, rc, report)
        self.assertEquals('$apr1$LBHigEZx$bYOvuU45B.Q9ZWh1MzQeS1', report.splitlines()[0], report)

    def test_sslv2_disabled(self):
        '''Make sure SSLv2 is disabled'''

        expected = True
        ex_result = "unknown option -ssl2"
        rc, report = testlib.cmd(["openssl","s_client","-ssl2","-connect","localhost:1"])
        self.assertEquals(1, rc, report)
        self.assertEquals(expected, ex_result in report, report)

    def test_sha(self):
        '''Test that SHA-* results agree with standard tools'''

        algorithms = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']

        self.devnull = open('/dev/null')
        print ""
        for length in (0, 1, 16, 321, 1024, 65537, 99999):
            print "  %d:" % (length),
            sha_input = testlib.random_string(length)
            for alg in algorithms:
                print "%s" % (alg),
                rc, report = testlib.cmd(["%ssum" % alg], input=sha_input, stdin=subprocess.PIPE, stderr=self.devnull)
                self.assertEqual(0, rc, report)
                expected = re.sub(r'\s*-$', '', report.strip())

                rc, report = testlib.cmd(["openssl", alg], input=sha_input, stdin=subprocess.PIPE, stderr=self.devnull)
                self.assertEqual(0, rc, report)
                observed = re.sub(r'^\(stdin\)=\s*', '', report.strip())
                self.assertEqual(expected, observed)
            print ""

    def test_smime(self):
        '''Test S/MIME'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        msg = os.path.join(self.tmpdir, "msg")
        # Create a message
        msgtxt = "Look ma, no hands!"
        open(msg,'w').write(msgtxt)

        print ""

        sig = msg + ".sig"

        # Sign the message
        print "  sign"
        rc, report = testlib.cmd(['openssl', 'smime', '-sign', '-in', msg, '-out', sig, '-signer', self.clientcert_pem, '-inkey', self.clientkey_pem, '-text'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Verify the signed message contents
        sig_contents = open(sig).read()
        sig_search_terms = ['MIME-Version:', 'Content-Type:', 'protocol="application/', 'pkcs7-signature"', msgtxt]

        for s in sig_search_terms:
            result = "Could not find '%s' in:\n%s" % (s, sig_contents)
            self.assertTrue(s in sig_contents, result)

        # Create a falsified message
        bad_contents = ""
        for line in sig_contents.splitlines():
            if line == msgtxt:
                bad_contents += "%s (gotcha)\n" % (msgtxt)
            else:
                bad_contents += line + "\n"
        open(sig + ".bad",'w').write(bad_contents)

        # Verify the falsified message
        print "  verify (falsified message)"
        rc, report = testlib.cmd(['openssl', 'smime', '-verify', '-text', '-CAfile', self.cacert_pem, '-in', sig + ".bad"])
        unexpected = 0
        result = 'Got exit code %d but should not have\n' % (unexpected)
        self.assertNotEquals(expected, rc, result + report)

        for s in ['Verification fail', msgtxt]:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

        for fmt in ['SMIME', 'PEM', 'DER']:
            print " format %s:" % fmt
            enc = msg + ".enc." + fmt.lower()
            dec = msg + ".dec." + fmt.lower()

            # Encrypt the signed message
            print "  encrypt"
            rc, report = testlib.cmd(['openssl', 'smime', '-encrypt', '-in', sig, '-outform', fmt, '-out', enc, self.srvcert_pem])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Verify the encrypted message contents
            enc_contents = open(enc).read()
            if fmt == "SMIME":
                enc_search_terms = ['MIME-Version:', 'Content-Type:', 'application/', 'pkcs7-mime']
            elif fmt == "PEM":
                enc_search_terms = ['BEGIN PKCS7', 'END PKCS7']
            else:
                enc_search_terms = [] # DER is binary

            for s in enc_search_terms:
                result = "Could not find '%s' in:\n%s" % (s, enc_contents)
                self.assertTrue(s in enc_contents, result)

            # Decrypt the signed message
            print "  decrypt"
            rc, report = testlib.cmd(['openssl', 'smime', '-decrypt', '-inform', fmt, '-in', enc, '-outform', fmt, '-out', dec, '-recip', self.srvcert_pem, '-inkey', self.srvkey_pem])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Verify decrypted message contents
            dec_contents = open(dec).read()
            for s in sig_search_terms:
                result = "Could not find '%s' in:\n%s" % (s, dec_contents)
                self.assertTrue(s in dec_contents, result)

            # Decrypt the signed message with wrong recipient
            print "  decrypt (wrong recipient)"
            rc, report = testlib.cmd(['openssl', 'smime', '-decrypt', '-inform', fmt, '-in', enc, '-outform', fmt, '-recip', self.clientcert_pem, '-inkey', self.clientkey_pem])
            unexpected = 0
            result = 'Got exit code %d but should not have\n' % (unexpected)
            self.assertNotEquals(expected, rc, result + report)

            # Verify the decrypted signed message (sig is SMIME, so we always verify as SMIME)
            print "  verify"
            rc, report = testlib.cmd(['openssl', 'smime', '-verify', '-text', '-CAfile', self.cacert_pem, '-inform', 'SMIME', '-in', dec])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            for s in ['Verification successful', msgtxt]:
                result = "Could not find '%s' in:\n%s" % (s, report)
                self.assertTrue(s in report, result)


            # Verify the decrypted message with wrong CA
            print "  verify (wrong CA)"
            rc, report = testlib.cmd(['openssl', 'smime', '-verify', '-text', '-CAfile', self.srvcert_pem, '-inform', 'SMIME', '-in', dec])
            unexpected = 0
            result = 'Got exit code %d but should not have\n' % (unexpected)
            self.assertNotEquals(expected, rc, result + report)

            # Verify PKCS#7 output is same for signed message and decrypted message
            print "  pkcs7"
            rc, report = testlib.cmd_pipe(['openssl', 'smime', '-pk7out', '-in', sig], ['openssl', 'pkcs7', '-print_certs', '-text'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report2 = testlib.cmd_pipe(['openssl', 'smime', '-pk7out', '-inform', fmt, '-in', dec, '-inform', 'SMIME'], ['openssl', 'pkcs7', '-print_certs', '-text'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report2)

            self.assertTrue(report == report2, "pkcs7 output is different:\n= %s =\n%s\n\n= %s =\n%s" % (os.path.basename(sig), report, os.path.basename(dec), report2))

    def test_ca(self):
        '''Test CA'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        rc, report = testlib.cmd(['openssl', 'x509', '-in', self.cacert_pem, '-text', '-noout'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for s in ['Certificate:', 'Signature Algorithm: sha1WithRSAEncryption', 'Issuer:', 'O=Testlib', 'Public Key Algorithm: rsaEncryption', '(2048 bit)', 'Modulus', 'X509v3 Basic Constraints: critical', 'CA:TRUE', 'Digital Signature, Certificate Sign, CRL Sign', 'URI:http://localhost/ca.crl']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

        pubkey = os.path.join(self.tmpdir, "ca.pubkey")
        rc, report = testlib.cmd(['openssl', 'x509', '-pubkey', '-in', self.cacert_pem, '-noout'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        open(pubkey,'w').write(report)

        rc, report = testlib.cmd(['openssl', 'rsa', '-pubin', '-in', pubkey, '-text', '-noout'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "(2048 bit)"
        result = "Could not find '%s' in:\n%s" % (search, report)
        self.assertTrue(search in report, result)

        for cert in [self.cacert_pem, self.srvcert_pem, self.clientcert_pem]:
            if cert == self.cacert_pem:
                rc, report = testlib.cmd(['openssl', 'verify', cert])
            else:
                rc, report = testlib.cmd(['openssl', 'verify', '-CAfile', self.cacert_pem, cert])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            result = "Could not find 'OK' in:\n%s" % (report)
            self.assertTrue("OK" in report, result)

    def test_crl(self):
        '''Test CRL'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        rc, report = testlib.cmd(['openssl', 'crl', '-in', self.crl_pem, '-text'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['Certificate Revocation List', 'Signature Algorithm: sha1WithRSAEncryption', 'O=Testlib', 'No Revoked Certificates', 'CRL extensions']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

        # Needed for ca commands
        os.chdir(self.tmpdir)

        # Revoke a certificate
        rc, report = testlib.cmd(['openssl', 'ca', '-config', os.path.join(self.tmpdir, "openssl.conf"), '-md', 'sha1', '-cert', self.cacert_pem, '-keyfile', os.path.join(self.tmpdir, "cakey.pem"), '-revoke', self.srvcert_pem, "-crl_reason", "keyCompromise"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['Revoking Certificate 01', 'Data Base Updated']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

        # Update the crl
        updated_crl = self.crl_pem + ".updated"
        rc, report = testlib.cmd(['openssl', 'ca', '-config', os.path.join(self.tmpdir, "openssl.conf"), '-md', 'sha1', '-cert', self.cacert_pem, '-keyfile', os.path.join(self.tmpdir, "cakey.pem"), '-gencrl', '-out', updated_crl])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Verify crl was updated
        rc, report = testlib.cmd(['openssl', 'crl', '-in', updated_crl, '-text'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['Certificate Revocation List', 'Signature Algorithm: sha1WithRSAEncryption', 'O=Testlib', 'Revoked Certificates:', 'Key Compromise', 'CRL extensions']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)


    def test_der(self):
        '''Test DER'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        for i in [self.srvcert_pem, self.clientcert_pem, self.cacert_pem]:
            # Convert pem to der
            der = i + ".der"
            rc, report = testlib.cmd(['openssl', 'x509', '-in', i, '-outform', 'DER', '-out', der])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Examine der file
            rc, report = testlib.cmd(['openssl', 'x509', '-in', der, '-text', '-inform', 'DER'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for s in ['Certificate:', 'Signature Algorithm: sha1WithRSAEncryption', 'Issuer:', 'O=Testlib', 'Public Key Algorithm: rsaEncryption', 'Modulus']:
                result = "Could not find '%s' in:\n%s" % (s, report)
                self.assertTrue(s in report, result)

        # now the crl
        # Convert pem to der
        der = self.crl_pem + ".der"
        rc, report = testlib.cmd(['openssl', 'crl', '-in', self.crl_pem, '-outform', 'DER', '-out', der])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Examine der file
        rc, report = testlib.cmd(['openssl', 'crl', '-in', der, '-text', '-inform', 'DER'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['Certificate Revocation List', 'Signature Algorithm: sha1WithRSAEncryption', 'O=Testlib', 'No Revoked Certificates', 'CRL extensions']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

    def test_asn1parse(self):
        '''Test asn1parse'''
        files = self.gen_ssl("rsa")

        # Create DER files
        for i in files:
            if "key" in i:
                rc, report = testlib.cmd(['openssl', 'rsa', '-outform', 'DER', '-in', i, '-out', i + ".der"])
            elif "crl" in i:
                rc, report = testlib.cmd(['openssl', 'crl', '-outform', 'DER', '-in', i, '-out', i + ".der"])
            else:
                rc, report = testlib.cmd(['openssl', 'x509', '-outform', 'DER', '-in', i, '-out', i + ".der"])

            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        for fmt in ['PEM', 'DER']:
            for i in files:
                fn = i
                if fmt == 'DER':
                    fn += ".der"

                search_terms = [':sha1WithRSAEncryption', ':countryName', ':US']
                if "key" in i:
                    search_terms = ['SEQUENCE', 'INTEGER']
                elif "crl" in i:
                    search_terms.append('CRL Number')
                elif "cacert" in i:
                    search_terms.append('CRL Distribution Points')
                else:
                    search_terms.append(':Testlib')

                rc, report = testlib.cmd(['openssl', 'asn1parse', '-in', fn, '-inform', fmt])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                for s in search_terms:
                    result = "Could not find '%s' in for '%s':\n%s" % (s, i, report)
                    self.assertTrue(s in report, result)

        rc, report = testlib.cmd(['openssl', 'asn1parse', '-genstr', 'UTF8:Hello World'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search_terms = ['UTF8STRING', ':Hello World']
        for s in search_terms:
            result = "Could not find '%s' in for '%s':\n%s" % (s, i, report)
            self.assertTrue(s in report, result)

    def test_pkcs7(self):
        '''Test PKCS#7'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        for fmt in ['PEM', 'DER']:
            for i in [self.srvcert_pem, self.clientcert_pem, self.cacert_pem]:
                # Convert pem to pkcs7
                pkcs7 = i + ".pkcs7." + fmt.lower()
                rc, report = testlib.cmd(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', i, '-outform', fmt, '-out', pkcs7])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                # Examine pkcs7 file
                rc, report = testlib.cmd(['openssl', 'pkcs7', '-in', pkcs7, '-text', '-inform', fmt, '-print_certs', '-noout'])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                for s in ['Certificate:', 'Signature Algorithm: sha1WithRSAEncryption', 'Issuer:', 'O=Testlib', 'Public Key Algorithm: rsaEncryption', 'Modulus']:
                    result = "Could not find '%s' in:\n%s" % (s, report)
                    self.assertTrue(s in report, result)

            # Convert pem to pkcs7 on the crl
            pkcs7 = self.crl_pem + ".pkcs7"
            rc, report = testlib.cmd(['openssl', 'crl2pkcs7', '-in', self.crl_pem, '-certfile', i, '-outform', fmt, '-out', pkcs7])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Examine pkcs7 file
            rc, report = testlib.cmd(['openssl', 'pkcs7', '-in', pkcs7, '-text', '-inform', fmt, '-print_certs', '-noout'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            for s in ['Certificate:', 'Signature Algorithm: sha1WithRSAEncryption', 'Issuer:', 'O=Testlib', 'Public Key Algorithm: rsaEncryption', 'Modulus', 'Certificate Revocation List']:
                result = "Could not find '%s' in:\n%s" % (s, report)
                self.assertTrue(s in report, result)

    def test_pkcs12(self):
        '''Test PKCS#12'''
        (self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem, self.crl_pem) = self.gen_ssl("rsa")

        # Create a pkcs12 file
        pkcs12 = self.clientcert_pem + ".pkcs12"
        rc, report = testlib.cmd(['openssl', 'pkcs12', '-export', '-in', self.clientcert_pem, '-inkey', self.clientkey_pem, '-out', pkcs12, '-passout', 'pass:ubuntu', '-name', 'Cert for %s' % os.path.basename(self.clientcert_pem)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Get info on a pkcs12 file
        rc, report = testlib.cmd(['openssl', 'pkcs12', '-in', pkcs12, '-info', '-noout', '-passin', 'pass:ubuntu'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['MAC Iteration', 'verified OK', 'PKCS7 Encrypted data', 'PKCS7 Data']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

        # Parse a pkcs12 file
        rc, report = testlib.cmd(['openssl', 'pkcs12', '-in', pkcs12, '-passin', 'pass:ubuntu', '-nodes'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for s in ['verified OK', 'BEGIN CERTIFICATE', 'BEGIN', 'PRIVATE KEY', 'subject=', 'issuer=']:
            result = "Could not find '%s' in:\n%s" % (s, report)
            self.assertTrue(s in report, result)

    def test_incorrectly_truncated_cipher_lists(self):

        if self.lsb_release['Release'] >= 16.04:
            return self._skipped("Test no longer works in 16.04")

        # Test that suggested cipher lists sent from TLS 1.1 and lower clients
        # are not affected by TLS 1.2 workarounds. These workarounds have been
        # known to incorrectly truncate suggested cipher lists despite TLS 1.2
        # not being in use.
        # https://launchpad.net/bugs/986147
        # https://launchpad.net/bugs/1051892
        proto_mode = [('ssl3', 'ssl3'), ('tls1', 'tls1'), ('tls1_1', 'tls1')]

        # No ssl3 in wily+
        if self.lsb_release['Release'] >= 15.10:
            proto_mode = [('tls1', 'tls1'), ('tls1_1', 'tls1')]

        (srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem, crl_pem) = self.gen_ssl("rsa")

        for (proto, mode) in proto_mode:
            expected = 0
            rc, out = testlib.cmd(['openssl', 'ciphers', '-' + mode])
            result = 'Got ciphers exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(rc, expected, result)

            # Find the least-preferred cipher (most likely to be truncated)
            cipher = out.split(':').pop().rstrip()

            try:
                srv_child = pexpect.spawn('openssl s_server' +
                                          ' -accept %d' % self.port +
                                          ' -key ' + srvkey_pem +
                                          ' -cert ' + srvcert_pem +
                                          ' -www -' + proto +
                                          ' -cipher ' + cipher)

            except:
                raise

            time.sleep(1)
            result = 'Server died unexpectedly when using %s cipher and %s protocol\n' % (cipher, proto)
            self.assertTrue(srv_child.isalive(), result)

            rc, out = testlib.cmd_pipe(['echo', 'QUIT'],
                                       ['openssl', 's_client',
                                       '-connect', 'localhost:%d' % self.port,
                                       '-CAfile', cacert_pem])

            # Make sure server exited before doing any asserts
            srv_child.close(True)

            result = 'Client exit code was %d (expected %d) when using %s cipher and %s protocol\n' % (rc, expected, cipher, proto)
            self.assertEquals(rc, expected, result + out)
            self.assertTrue(('Cipher is ' + cipher) in out, cipher + ' not found in output:\n' + out)

if __name__ == '__main__':
    print >>sys.stderr, "Please also consider running test-ca-certificates.py"

    release = testlib.manager.lsb_release["Release"]

    # 10.04 LTS's test suite doesn't allow running twice in one process
    # so let's only run the with-compression tests on 'lucid'.
    if release == 10.04:
        print >>sys.stderr, "Skipping no compression test"
        os.environ['OPENSSL_DEFAULT_ZLIB']="1"
        expect_compression = True
        unittest.main()
    # Trusty's OpenSSL is built without compression at all, so only run
    # the no compression tests
    elif release >= 14.04:
        print >>sys.stderr, "Skipping compression test"
        unittest.main()

    # Ok, for other releases, run tests twice
    else:
        print >>sys.stderr, "Look for two test-suite runs"
        print >>sys.stderr, "First, no compression"
        unittest.main(exit=False)

        print >>sys.stderr, "Second, with compression"
        os.environ['OPENSSL_DEFAULT_ZLIB']="1"
        expect_compression = True
        unittest.main()

