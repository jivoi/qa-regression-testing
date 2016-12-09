#!/usr/bin/python
#
#    fetchmail.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
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

'''
    How to run against a clean schroot named 'edgy':
        schroot -c edgy -u root -- sh -c 'apt-get -y install fetchmail netbase dovecot-imapd dovecot-pop3d python-openssl ssl-cert && ./test-fetchmail.py -v'
        # Dapper uses python-pyopenssl instead...
'''

# QRT-Depends: testlib_dovecot.py fetchmail
# QRT-Packages: fetchmail netbase dovecot-imapd dovecot-pop3d ssl-cert
# QRT-Alternates: python-openssl python-pyopenssl
# QRT-Privilege: root

import unittest, subprocess, tempfile, os, re, shutil
import SocketServer

import testlib
import testlib_dovecot

class ReuseTCPServer(SocketServer.TCPServer):
    def __init__(self,*args):
        self.allow_reuse_address = True

        self.imap_capabilities = ''
        self.test_result = 'Failure: never connected'

        SocketServer.TCPServer.__init__(self,*args)

    def set_capabilities(self,capa):
        self.imap_capabilities = capa

    def get_capabilities(self):
        return self.imap_capabilities

    def set_test_result(self, result):
        self.test_result = result

    def get_test_result(self):
        return self.test_result

class ImapHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        self.wfile.write("* OK TestRig ready.\r\n")

        self.default_result()

        self.imap_running = 1
        while self.imap_running:
            prefix = cmd = ''
            parts = self.rfile.readline(512).strip().split(' ')
            try:
                prefix = parts.pop(0)
                cmd    = parts.pop(0)
            except:
                pass

            if cmd == 'NOOP' or cmd == '*':
                self.wfile.write('%s OK That was hard work!\r\n' % prefix)
            elif cmd == 'CAPABILITY':
                self.wfile.write('* CAPABILITY IMAP4rev1 %s\r\n' % self.server.get_capabilities())
                self.wfile.write('%s OK Capability completed.\r\n' % prefix)
            elif cmd == 'AUTHENTICATE':
                self.wfile.write('%s BAD Not supported.\r\n' % prefix)
            elif cmd == '' or cmd == 'LOGOUT':
                # Empty cmd seems to be the "EOF" mode
                self.imap_running = 0
            else:
                self.imap_cmd(prefix,cmd,parts)

# When running without --sslproto TLS1:
#  * OK Dovecot ready.
# A0001 CAPABILITY
#  * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN
#  $1 OK Capability completed.
# A0002 STARTTLS
#  $1 FAIL I tricked you
# A0003 NOOP
#  $1 OK
# A0004 LOGIN "..." "..."
class ImapAllowAuthFallback(ImapHandler):
    def default_result(self):
        # Our last command should be "LOGIN", so everything else is a fail
        self.server.set_test_result('Failure: LOGIN not the last command')
        
    def imap_cmd(self,prefix,cmd,args):
        if cmd == 'STARTTLS':
            self.wfile.write('%s BAD I lied about the TLS.\r\n' % prefix)
        elif cmd == 'LOGIN':
            self.server.set_test_result('Success: LOGIN seen after STARTTLS failure')
            self.wfile.write('%s BAD Test finished.\r\n' % prefix)
            self.imap_running = 0
        else:
            self.wfile.write('%s BAD Go away.\r\n' % prefix)
            self.imap_running = 0

# When running with and without --sslproto TLS1:
#  * OK Dovecot ready.
# A0001 CAPABILITY
#  * CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED
#  $1 OK Capability completed.
# A0002 STARTTLS
#  $1 FAIL I tricked you
# ->CLOSE
#
# When running with --sslproto TLS1:
#  * OK Dovecot ready.
# A0001 CAPABILITY
#  * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN
#  $1 OK Capability completed.
# A0002 STARTTLS
#  $1 FAIL I tricked you
# ->CLOSE
class ImapDisallowAuthFallback(ImapHandler):
    def default_result(self):
        # Our last command should not be "LOGIN", so everything else is okay
        self.server.set_test_result('Success: did not LOGIN')

    def imap_cmd(self,prefix,cmd,args):
        if cmd == 'STARTTLS':
            self.wfile.write('%s BAD I lied about the TLS.\r\n' % prefix)
        elif cmd == 'LOGIN':
            self.server.set_test_result('Failure: LOGIN seen after STARTTLS failure')
            self.wfile.write('%s BAD Test finished.\r\n' % prefix)
            self.imap_running = 0
        else:
            self.server.set_test_result('Failure: unexpected cmd "%s"' % cmd)
            self.wfile.write('%s BAD Go away.\r\n' % prefix)
            self.imap_running = 0

class FetchmailAuth(unittest.TestCase):
    '''Test fetchmail authentication behavior (CVE-2006-5867).'''

    def setUp(self):
        tmpfd, self.tmppath = tempfile.mkstemp(prefix='fetchmail-test')

    def replace_tmpfile(self,cfg):
        self.tmpfile = file(self.tmppath,"w")
        self.tmpfile.write(cfg)
        self.tmpfile.close()

        check = file(self.tmppath,"r").read()
        self.assertEquals(check,cfg)

    def tearDown(self):
        os.unlink(self.tmppath)

    def _run_test(self,handler,capabilities,fetchmailrc,default_result='Failure: never ran'):
        server = ReuseTCPServer( ('', 1143), handler)
        server.set_capabilities(capabilities)
        server.set_test_result(default_result)

        self.replace_tmpfile(fetchmailrc);
        sp = subprocess.Popen(['fetchmail','-vk','-f',self.tmppath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)

        try:
            testlib.timeout(2,server.handle_request)
        finally:
            # get state of test
            report = server.get_test_result()
            # report state of fetchmail too
            out = sp.communicate(None)[0]
            # release server
            server = None
            # add fetchmail report on failure
            if report.find("Success") != 0:
                report +='\n%s' % out
            self.assertEquals(report.find("Success"),0,report)

    def test_auth_no_fallback_plain(self):
        '''Test [server: broken STARTTLS, LOGINDISABLED] [client: allow plaintext]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS LOGINDISABLED', 
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
''')

    def test_auth_no_fallback_tls_required(self):
        '''Test [server: broken STARTTLS, LOGINDISABLED] [client: require TLS]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS LOGINDISABLED', 
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
    sslproto TLS1
''')

    def test_auth_plain_fallback_allowed(self):
        '''Test [server: broken STARTTLS, AUTH=PLAIN] [client: allow plaintext]'''
        self._run_test(ImapAllowAuthFallback,
                       'STARTTLS AUTH=PLAIN',
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
''')

    # CVE-2006-5867, Issue 2
    def test_auth_plain_fallback_disallowed(self):
        '''Test [server: broken STARTTLS, AUTH=PLAIN] [client: need TLS]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS AUTH=PLAIN', 
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
    sslproto TLS1
''')

    # CVE-2006-5867, Issue 1
    def test_auth_plain_fallback_disallowed_sslcertck(self):
        '''Test [server: broken STARTTLS, AUTH=PLAIN] [client: need Cert]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS AUTH=PLAIN', 
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
    sslcertck
''')

    # CVE-2006-5867, Issue 1
    def test_auth_plain_fallback_disallowed_sslfingerprint(self):
        '''Test [server: broken STARTTLS, AUTH=PLAIN] [client: need fingerprint]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS AUTH=PLAIN', 
                       '''
poll localhost protocol IMAP port 1143:
    user nobody password nothing
    sslfingerprint "DE:AD:BE:EF:00:00:00:00:00:00:00:00:00:00:00:00"
''')

    # CVE-2006-5867, Issue 4 (broken behavior not reproduced)
    def test_auth_plain_fallback_disallowed_gssapi(self):
        '''Test [server: broken STARTTLS, AUTH=PLAIN] [client: require MD5]'''
        self._run_test(ImapDisallowAuthFallback,
                       'STARTTLS AUTH=PLAIN', 
                       '''
poll localhost protocol IMAP port 1143 auth cram-md5:
    user nobody password nothing
''')


class FetchmailDovecot(testlib.TestlibCase):
    '''Helper functions for fetchmail/dovecot testing'''

    def setUp(self):
        tmpfd, self.tmppath = tempfile.mkstemp(prefix='fetchmail-test')
        self.user = testlib.TestUser()
        self.dovecot = testlib_dovecot.Dovecot(self, self.user)
        self.hostname = self.yank_commonname_from_cert(self.dovecot.get_cert())

    def replace_tmpfile(self,contents):
        self.tmpfile = file(self.tmppath,"w")
        self.tmpfile.write(contents)
        self.tmpfile.close()

        check = file(self.tmppath,"r").read()
        self.assertEquals(check,contents)

    def tearDown(self):
        self.dovecot = None
        self.user = None
        os.unlink(self.tmppath)

    def _run_fetchmail(self):
        sp = subprocess.Popen(['fetchmail','-vf',self.tmppath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)

        out = sp.communicate(None)[0]

        # If we didn't connect, the server didn't start up, try to figure
        # out why...
        if out.find('Connection refused')>0:
            out += file("/etc/dovecot/dovecot.conf","r").read()

        return out

    def _fetch_proto(self,protocol,user_opts='',server_opts='',badlogin_test=True):
        '''Test a specific protocol with options'''

        cfg = 'poll %s protocol %s ' + server_opts + '''
    user %s password %s ''' + user_opts + '''
    mda "cat > %s"
'''
        # This is slow due to the PAM delays, so make it configurable
        if badlogin_test:
            # Bad username
            self.replace_tmpfile(cfg % (self.hostname, protocol, 'nosuchuser', self.user.password, self.tmppath))
            out = self._run_fetchmail()
            self.assertTrue(out.find('fetchmail: Authorization failure')>=0 or
                                     'fetchmail: Query status=3 (AUTHFAIL)'>=0,out)

            # Bad password
            self.replace_tmpfile(cfg % (self.hostname, protocol, self.user.login, 'badpassword', self.tmppath))
            out = self._run_fetchmail()
            self.assertTrue(out.find('fetchmail: Authorization failure')>=0 or
                                     'fetchmail: Query status=3 (AUTHFAIL)'>=0,out)

            # Empty password
            self.replace_tmpfile(cfg % (self.hostname, protocol, self.user.login, '""', self.tmppath))
            out = self._run_fetchmail()
            self.assertTrue(out.find('fetchmail: Authorization failure')>=0 or
                                     'fetchmail: Query status=3 (AUTHFAIL)'>=0,out)

        # Good password
        self.replace_tmpfile(cfg % (self.hostname, protocol, self.user.login, self.user.password, self.tmppath))
        self.run_output = self._run_fetchmail()
        self.run_email = file(self.tmppath,"r").read()

    def _check_common(self):
        '''Check the run output for things specific to all behaviors'''
        self.assertTrue(self.run_output.find('2 messages')>=0,self.run_output)
        self.assertTrue(self.run_output.find('reading message')>=0,self.run_output)
        self.assertTrue(self.run_output.find('flushed')>=0,self.run_output)

        self.assertTrue(self.run_email.find('Received: from %s' % (self.hostname))==0,self.run_email)

    def _check_pop(self):
        '''Check the run output for things specific to POP behavior'''
        self._check_common()
        self.assertTrue(self.run_email.find('Date: Tue, 28 Nov 2006 11:29:34 +0100\nFrom: Test User 2 <test2@test2.com>\nTo: Dovecot tester <dovecot@test.com>\nSubject: Test 2\n')>0 and self.run_email.find('\n\nMore news.\n\nGet cracking!\n')>0,self.run_email)

    def _check_imap(self):
        '''Check the run output for things specific to IMAP behavior'''
        self._check_common()
        self.assertTrue(self.run_output.find('skipping message')>=0,self.run_output)
        self.assertTrue(self.run_email.find('Date: Thu, 16 Nov 2006 17:12:23 -0800\nFrom: Test User 1 <test1@test1.com>\nTo: Dovecot tester <dovecot@test.com>\nSubject: Test 1\n')>0 and self.run_email.find('\n\nSome really important news.\n')>0,self.run_email)

    def _check_cert_cn(self, expected=True):
        state = re.search(r'fetchmail: (Server|Issuer) CommonName: %s' % (self.hostname), self.run_output) != None
        self.assertEquals(state, expected, self.run_output)


class FetchmailDovecot00(FetchmailDovecot):
    '''Test basic fetchmail behavior with dovecot.'''

    def test_00_hashes(self):
        '''Rebuild PEM hashes'''
        # regenerate PEM hashes
        self.assertShellExitEquals(0, ["c_rehash"])

    def test_fetch_imap(self):
        '''Test IMAP fetching'''
        self._fetch_proto('IMAP','sslproto ""')
        self._check_imap()
        self._check_cert_cn(False)

    def test_fetch_imap_tls(self):
        '''Test IMAP TLS fetching'''
        self._fetch_proto('IMAP', 'sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_imap()
        self._check_cert_cn()
        self._fetch_proto('IMAP', 'sslcertck sslcertpath "/dev/null"')
        self.assertTrue(self.run_output.find('fetchmail: Server certificate verification error: self signed certificate')>=0,self.run_output)

    def test_fetch_imaps(self):
        '''Test IMAP SSL fetching'''
        self._fetch_proto('IMAP','ssl sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_imap()
        self._check_cert_cn()
        self._fetch_proto('IMAP', 'ssl sslcertck sslcertpath "/dev/null"')
        self.assertTrue(self.run_output.find('fetchmail: Server certificate verification error: self signed certificate')>=0,self.run_output)

    def test_ssl_fingerprint_good(self):
        '''Test IMAP TLS fetching with good SSL fingerprint'''
        self._fetch_proto('IMAP',user_opts='sslfingerprint "%s"' % self.dovecot.get_ssl_fingerprint())
        self._check_imap()
        self._check_cert_cn()

    def test_ssl_fingerprint_bad(self):
        '''Test IMAP TLS fetching with bad SSL fingerprint'''
        self._fetch_proto('IMAP',server_opts='auth password',user_opts='sslfingerprint "DE:AD:BE:EF:00:00:00:00:00:00:00:00:00:00:00:00"')
        self._check_cert_cn()
        self.assertTrue(self.run_output.find('fetchmail: %s fingerprints do not match' % (self.hostname))>=0,self.run_output)
        self.assertTrue(self.run_output.find('2 messages')<0,self.run_output)

# Not even dovecot wants to do POP2
#    # CVE-2006-5867, Issue 5
#    def test_fetch_pop2(self):
#        '''Test POP2 fetching'''
#        self._fetch_proto('POP2','sslproto ""')
#        self._check_pop()
#        self.assertTrue(self.run_output.find('fetchmail: Server CommonName')<0,self.run_output)

    def test_fetch_pop3(self):
        '''Test POP3 fetching'''
        self._fetch_proto('POP3','sslproto ""')
        self._check_pop()
        self._check_cert_cn(False)

    # CVE-2006-5867, Issue 3
    def test_fetch_pop3_nocapa(self):
        '''Test POP3 fetching TLS upgrade without Capabilities (CVE-2006-5867)'''
        self._fetch_proto('POP3',server_opts='auth cram-md5', user_opts='sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_pop()
        self._check_cert_cn()

    # CVE-2006-5867, Issue 3
    def test_fetch_pop3_nocapa_tls(self):
        '''Test POP3 fetching TLS required without Capabilities (CVE-2006-5867)'''
        self._fetch_proto('POP3',server_opts='auth cram-md5', user_opts='sslproto tls1 sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_pop()
        self._check_cert_cn()

    def test_fetch_pop3s_tls(self):
        '''Test POP3 TLS fetching'''
        self._fetch_proto('POP3', 'sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_pop()
        self._check_cert_cn()
        self._fetch_proto('POP3', 'sslcertck sslcertpath "/dev/null"')
        self.assertTrue(self.run_output.find('fetchmail: Server certificate verification error: self signed certificate')>=0,self.run_output)

    def test_fetch_pop3s(self):
        '''Test POP3 SSL fetching'''
        self._fetch_proto('POP3','ssl sslcertck sslcertpath "/etc/ssl/certs"')
        self._check_pop()
        self._check_cert_cn()
        self._fetch_proto('POP3', 'ssl sslcertck sslcertpath "/dev/null"')
        self.assertTrue(self.run_output.find('fetchmail: Server certificate verification error: self signed certificate')>=0,self.run_output)

class FetchmailDovecot01(FetchmailDovecot):
    '''Test goofy SSL certs with fetchmail/dovecot'''

    def setUp(self):
        tmpfd, self.tmppath = tempfile.mkstemp(prefix='fetchmail-test')
        self.user = testlib.TestUser()

        # use NULL-byte certs
        self.certs = tempfile.mkdtemp(prefix='dovecot-certs-')
        self.cert_pub = self.certs + '/public.pem'
        self.cert_key = self.certs + '/private.pem'
        self.assertShellExitEquals(0, ['fetchmail/null-snakeoil.py',self.cert_pub,self.cert_key])
        self.dovecot = testlib_dovecot.Dovecot(self, self.user, cert_pub=self.cert_pub, cert_key=self.cert_key)
        self.hostname = self.yank_commonname_from_cert(self.dovecot.get_cert()).split('\x00')[0]

    def tearDown(self):
        self.dovecot = None
        self.user = None
        os.unlink(self.tmppath)
        shutil.rmtree(self.certs)

    def test_fetch_imap_tls(self):
        '''Test IMAP SSL fetching rejects NULL-byte CN (CVE-2009-2666)'''
        # cert check
        self._fetch_proto('IMAP', 'sslproto tls1')
        self._check_cert_cn()
        self.assertTrue(self.run_output.find('fetchmail: Bad certificate: Subject CommonName contains NUL, aborting')>=0,self.run_output)

if __name__ == '__main__':
    testlib.require_root()
    unittest.main()
