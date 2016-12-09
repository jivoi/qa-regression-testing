#!/usr/bin/python
#
#    test-postfix.py quality assurance test script for postfix
#    Copyright (C) 2008-2012 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: postfix sasl2-bin procmail python-pexpect
# QRT-Privilege: root
# QRT-Conflicts: exim4

'''
    Note: When installing postfix, select "Internet Site". This script will
    not work if "Local Only" was selected.

    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install procmail postfix sasl2-bin python-pexpect lsb-release && ./test-postfix.py -v'

    Tests:
      00: setup
      10: basic plain auth setup
      11: above, but with CVE reproducers
      20: sasl non-PLAIN setup
      21: 20, but with CVE reproducers
      99: restore configs
'''

import unittest, subprocess, pexpect, smtplib, socket, os, time
import testlib

class PostfixTest(testlib.TestlibCase):
    '''Test Postfix MTA.'''

    def _setUp(self):
        '''Create server configs.'''

        # Move listener to localhost:2525
        conf_file = '/etc/postfix/master.cf'
        lines = open(conf_file)
        contents = ''
        for cfline in lines:
            if cfline.startswith('smtp') and 'smtpd' in cfline and 'inet' in cfline:
                contents += '127.0.0.1:2525      inet  n       -       -       -       -       smtpd\n'
            else:
                contents += "%s\n" % cfline
        testlib.config_replace(conf_file, contents, append=False)

        conf_file = '/etc/postfix/main.cf'
        # Use mbox only
        testlib.config_comment(conf_file,'home_mailbox')
        testlib.config_set(conf_file,'mailbox_command','procmail -a "$EXTENSION"')

        # Turn on sasl
        self._setup_sasl("PLAIN")
        reply = self._check_auth("PLAIN")


    def setUp(self):
        '''Set up prior to each test_* function'''
        # list of files that we update
        self.conf_files = [ '/etc/postfix/master.cf', '/etc/postfix/main.cf', '/etc/default/saslauthd', '/etc/postfix/sasl/smtpd.conf', '/etc/sasldb2']

        self.user = testlib.TestUser(lower=True)
        self.s = None
        # Silently allow for this connection to fail, to handle the
        # initial setup of the postfix server.
        try:
            self.s = smtplib.SMTP('localhost', port=2525)
        except:
            pass

    def _tearDown(self):
        '''Restore server configs'''
        for f in self.conf_files:
            testlib.config_restore(f)

        # put saslauthd back
        for f in ['/var/spool/postfix/var/run/saslauthd', '/var/run/saslauthd']:
            if os.path.isfile(f) or os.path.islink(f):
                os.unlink(f)
            elif os.path.exists(f):
                testlib.recursive_rm(f)
        subprocess.call(['mkdir','-p','/var/run/saslauthd'])
        subprocess.call(['/etc/init.d/saslauthd', 'stop'], stdout=subprocess.PIPE)
        subprocess.call(['/etc/init.d/saslauthd', 'start'], stdout=subprocess.PIPE)

    def tearDown(self):
        '''Clean up after each test_* function'''

        try:
            self.s.quit()
        except:
            pass
        self.user = None

    def _restart_server(self):
        '''Restart server'''
        subprocess.call(['/etc/init.d/postfix', 'stop'], stdout=subprocess.PIPE)
        assert subprocess.call(['/etc/init.d/postfix', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        # Postfix exits its init script before the master listener has started
        time.sleep(2)

    def _setup_sasl(self, mech, other_mech="", force_sasldb=False):
        '''Setup sasl for mech'''
        conf_file = '/etc/postfix/main.cf'
        for field in ['smtpd_sasl_type','smtpd_sasl_local_domain','smtpd_tls_auth_only']:
            testlib.config_comment(conf_file,field)
        testlib.config_set(conf_file,'smtpd_sasl_path','smtpd')
        testlib.config_set(conf_file,'smtpd_sasl_auth_enable','yes')
        #testlib.config_set(conf_file,'broken_sasl_auth_clients','yes')
        testlib.config_set(conf_file,'smtpd_sasl_authenticated_header','yes')
        testlib.config_set(conf_file,'smtpd_tls_loglevel','2')

        # setup smtpd.conf and the sasl users
        contents = ''

        self.assertTrue(mech in ['LOGIN', 'PLAIN', 'CRAM-MD5', 'DIGEST-MD5'], "Invalid mech: %s" % mech)

        if not force_sasldb and (mech == "PLAIN" or mech == "LOGIN"):
            conf_file = '/etc/default/saslauthd'
            testlib.config_set(conf_file, 'START', 'yes', spaces=False)

            contents = '''
pwcheck_method: saslauthd
allowanonymouslogin: 0
allowplaintext: 1
mech_list: %s %s
''' % (mech, other_mech)

            # attach SASL to postfix chroot
            subprocess.call(['mkdir','-p','/var/spool/postfix/var/run/saslauthd'])
            subprocess.call(['rm','-rf','/var/run/saslauthd'])
            subprocess.call(['ln','-s','/var/spool/postfix/var/run/saslauthd','/var/run/saslauthd'])
            subprocess.call(['/etc/init.d/saslauthd', 'stop'], stdout=subprocess.PIPE)
            assert subprocess.call(['/etc/init.d/saslauthd', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0

            # Force crackful perms so chroot'd postfix can talk to saslauthd
            subprocess.call(['chmod','o+x','/var/spool/postfix/var/run/saslauthd'])
        else:
            plaintext = "1"
            if mech == "LOGIN" or mech == "PLAIN":
                plaintext = "0"
            contents = '''
pwcheck_method: auxprop
allowanonymouslogin: 0
allowplaintext: %s
mech_list: %s %s
''' % (plaintext, mech, other_mech)

            # Add user to sasldb2
            testlib.config_replace("/etc/sasldb2", '', append=False)

            rc, report = testlib.cmd(['postconf', '-h', 'myhostname'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            child = pexpect.spawn('saslpasswd2 -c -u %s %s' % (report.strip(), self.user.login))
            time.sleep(0.2)
            child.expect(r'.*[pP]assword', timeout=5)
            time.sleep(0.2)
            child.sendline(self.user.password)
            time.sleep(0.2)
            child.expect(r'.*(for verification)', timeout=5)
            time.sleep(0.2)
            child.sendline(self.user.password)
            time.sleep(0.2)
            rc = child.expect('\n', timeout=5)
            time.sleep(0.2)
            self.assertEquals(rc, expected, "passwd returned %d" %(rc))

            child.kill(0)

            os.chmod("/etc/sasldb2", 0640)
            rc, report = testlib.cmd(['chgrp', 'postfix', '/etc/sasldb2'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Force crackful perms so chroot'd postfix can talk to saslauthd
            subprocess.call(['mv', '-f', '/etc/sasldb2', '/var/spool/postfix/etc'])
            subprocess.call(['ln', '-s', '/var/spool/postfix/etc/sasldb2', '/etc/sasldb2'])

        conf_file = '/etc/postfix/sasl/smtpd.conf'
        testlib.config_replace(conf_file, contents, append=False)

        # Restart server
        self._restart_server()

    def _is_listening(self):
        '''Is the server listening'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('localhost',2525))
        greeting = s.recv(1024)
        # 220 gorgon.outflux.net ESMTP Postfix (Ubuntu)
        self.assertTrue(greeting.startswith('220 '),greeting)
        self.assertTrue('ESMTP' in greeting,greeting)
        self.assertTrue('Postfix' in greeting,greeting)
        self.assertFalse('MTA' in greeting,greeting)
        s.close()

    def test_00_listening(self):
        '''Postfix is listening'''
        # Get the main instance running
        self._setUp()

        self._is_listening()

    def _vrfy(self, address, valid = True):
        self.s.putcmd("vrfy",address)
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        if valid:
            self.assertEquals(code, 252, reply)
            self.assertTrue(address in msg, reply)
        else:
            self.assertEquals(code, 550, reply)
            self.assertTrue('Recipient address rejected' in msg, reply)
            self.assertTrue('<%s>' % (address) in msg, reply)

    def test_10_commands(self):
        '''Basic SMTP commands'''

        #s = smtplib.SMTP('localhost', port=2525)
        # EHLO
        code, msg = self.s.ehlo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertEquals(self.s.does_esmtp, 1, reply)
        self.assertTrue('8BITMIME' in self.s.ehlo_resp, reply)
        # No help available
        self.s.putcmd("help")
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 502, reply)
        self.assertTrue('Error' in msg, reply)
        # VRFY addresses
        self._vrfy('address@example.com', valid=True)
        self._vrfy('does-not-exist', valid=False)
        self._vrfy(self.user.login, valid=True)

    def _test_deliver_mail(self, user_sent_to, auth_user=None, auth_pass=None, use_tls=False):
        '''Perform mail delivery'''

        if auth_user and auth_pass:
            self.s.login(auth_user, auth_pass)
        if use_tls:
            self.s.starttls()
        failed = self.s.sendmail('root',[user_sent_to.login,'does-not-exist'],'''From: Rooty <root>
To: "%s" <%s>
Subject: This is test 1

Hello, nice to meet you.
''' % (user_sent_to.gecos, user_sent_to.login))
        #for addr in failed.keys():
        #    print '%s %d %s' % (addr, failed[addr][0], failed[addr][1])
        self.assertEquals(len(failed),1,failed)
        self.assertTrue(failed.has_key('does-not-exist'),failed)
        self.assertEquals(failed['does-not-exist'][0],550,failed)

        # Frighteningly, postfix seems to accept email before confirming
        # a successful write to disk for the recipient!
        time.sleep(2)

    def _test_mail_in_spool(self, user_directed_to, target_spool_user=None, spool_file=None, auth_user=None, use_tls=False):
        '''Check that mail arrived in the spool'''

        # Handle the case of forwarded emails
        if target_spool_user == None:
            target_spool_user = user_directed_to
        # Read delivered email
        if spool_file == None:
            spool_file = '/var/mail/%s' % (target_spool_user.login)
        time.sleep(1)
        contents = open(spool_file).read()
        #print contents
        # Server-side added headers...
        self.assertTrue('\nReceived: ' in contents, contents)
        if use_tls and self.lsb_release['Release'] > 6.06:
            expected = ' (Postfix) with ESMTPS id '
        else:
            expected = ' (Postfix) with ESMTP id '
        if auth_user:
            if self.lsb_release['Release'] < 8.04:
                self._skipped("Received header portion")
            else:
                expected = ' (Postfix) with ESMTPA id '
                self.assertTrue('(Authenticated sender: %s)' % (auth_user))
        self.assertTrue(expected in contents, 'Looking for "%s" in email:\n%s' % (expected, contents))
        self.assertTrue('\nMessage-Id: ' in contents, contents)
        self.assertTrue('\nDate: ' in contents, contents)
        # client-side headers/body...
        self.assertTrue('\nSubject: This is test 1' in contents, contents)
        self.assertTrue('\nFrom: Rooty' in contents, contents)
        self.assertTrue('\nTo: "Buddy %s" <%s@' % (user_directed_to.login, user_directed_to.login) in contents, contents)
        self.assertTrue('\nHello, nice to meet you.' in contents, contents)

    def _test_roundtrip_mail(self, user_sent_to, user_to_check=None, spool_file=None, auth_user=None, auth_pass=None, use_tls=False):
        '''Send and check email delivery'''
        self._test_deliver_mail(user_sent_to, auth_user, auth_pass, use_tls=use_tls)
        self._test_mail_in_spool(user_sent_to, user_to_check, spool_file, auth_user=auth_user, use_tls=use_tls)

    def test_10_sending_mail_direct(self):
        '''Mail delivered normally'''
        self._test_roundtrip_mail(self.user)

    def test_10_sending_mail_direct_with_tls(self):
        '''Mail delivered normally with TLS'''
        self._test_roundtrip_mail(self.user, use_tls=True)

    def test_10_sending_mail_direct_auth(self):
        '''Mail authentication'''
        # Verify rejected bad password and user
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')
        self.s.login(self.user.login, self.user.password)

    def test_10_sending_mail_direct_auth_full(self):
        '''Mail delivered with authentication'''
        # Perform end-to-end authentication test
        self._test_roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def _write_forward(self, user, contents):
        forward_filename = '/home/%s/.forward' % (user.login)
        open(forward_filename,'w').write(contents)
        os.chown(forward_filename, user.uid, user.gid)

    def test_10_sending_mail_forward_normal(self):
        '''Mail delivered via .forward'''

        forward_user = testlib.TestUser(lower=True)
        self._write_forward(forward_user, self.user.login+'\n')
        self._test_roundtrip_mail(forward_user, self.user)

    def test_10_sending_mail_forward_xternal(self):
        '''Mail processed by commands in .forward'''

        # Create user-writable redirected mbox destination
        mbox, mbox_name = testlib.mkstemp_fill('',prefix='test-postfix.mbox-')
        mbox.close()
        os.chown(mbox_name, self.user.uid, self.user.gid)

        # Create a script to run in the .forward
        redir, redir_name = testlib.mkstemp_fill('''#!/bin/bash
/bin/cat > "%s"
''' % (mbox_name),prefix='test-postfix.redir-')
        redir.close()
        os.chmod(redir_name,0755)

        self._write_forward(self.user,'|%s\n' % (redir_name))
        self._test_roundtrip_mail(self.user, spool_file=mbox_name)

        os.unlink(redir_name)
        os.unlink(mbox_name)

    def test_11_security_CVE_2008_2936(self):
        '''CVE-2008-2936 fixed'''

        # First, create our "target" file
        secret = '/root/secret.txt'
        open(secret,'w').write('Secret information\n')
        os.chmod(secret, 0700)

        # Now, create a symlink to the target (we're going to use /var/tmp
        # since we're assuming it, /root, /var/mail are on the same filesystem.
        # For most chroot testing, /tmp is mounted from the real machine.
        if os.path.exists('/var/tmp/secret.link'):
            os.unlink('/var/tmp/secret.link')
        self.assertEquals(subprocess.call(['su','-c','ln -s /root/secret.txt /var/tmp/secret.link',self.user.login]),0,"Symlink creation")

        # Now, the hardlink, which in ubuntu's case needs to be done by root.
        os.link('/var/tmp/secret.link','/var/mail/%s' % (self.user.login))

        # Email delivered to this user will be written to the root-owned
        # file now if the CVE is unfixed.
        failed = self.s.sendmail('root',[self.user.login],'''From: Evil <root>
To: "%s" <%s>
Subject: This is an overwrite test

Hello, nice to pwn you.
''' % (self.user.gecos, self.user.login))
        self.assertEquals(len(failed),0,failed)

        # Pause for delivery
        time.sleep(2)

        contents = open(secret).read()
        # Clean up before possible failures
        os.unlink('/var/mail/%s' % (self.user.login))
        os.unlink('/var/tmp/secret.link')
        os.unlink(secret)
        # Check results
        self.assertTrue('Secret information' in contents, contents)
        self.assertFalse('nice to pwn you' in contents, contents)

    def _check_auth(self, mech):
        '''Check AUTH: side effect-- self.s is set'''
        try:
            self.s.quit()
        except:
            pass
        self.s = smtplib.SMTP('localhost', port=2525)

        self._is_listening()

        # has mech
        code, msg = self.s.ehlo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertEquals(self.s.does_esmtp, 1, reply)
        self.assertTrue('%s' % mech in self.s.ehlo_resp, reply)
        return reply

    def test_20_sasldb_cram_md5(self):
        '''Test sasldb CRAM-MD5'''
        # Quit the setUp() connection, restart the server and reconnect
        self.s.quit()
        self._setup_sasl("CRAM-MD5")

        reply = self._check_auth("CRAM-MD5")
        self.assertTrue('PLAIN' not in reply, reply)

        # Verify rejected bad password and user
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')

        # Perform end-to-end authentication test
        self._test_roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def test_20_sasldb_digest_md5(self):
        '''Test sasldb DIGEST-MD5 is supported'''
        # Quit the setUp() connection, restart the server and reconnect
        self.s.quit()
        self._setup_sasl("DIGEST-MD5")

        reply = self._check_auth("DIGEST-MD5")
        self.assertTrue('PLAIN' not in reply, reply)

        # TODO: Perform end-to-end authentication test (need alternative to smtplib)
        #self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        #self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')
        #self._test_roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def test_20_sasldb_login(self):
        '''Test sasldb LOGIN is supported'''
        # Quit the setUp() connection, restart the server and reconnect
        self.s.quit()
        self._setup_sasl("LOGIN", force_sasldb=True)

        reply = self._check_auth("LOGIN")
        self.assertTrue('PLAIN' not in reply, reply)

        # TODO: Perform end-to-end authentication test (need alternative to smtplib)
        #self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        #self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')
        #self._test_roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def test_20_sasldb_plain(self):
        '''Test sasldb PLAIN'''
        # Quit the setUp() connection, restart the server and reconnect
        self.s.quit()
        self._setup_sasl("PLAIN", force_sasldb=True)

        reply = self._check_auth("PLAIN")

        # Verify rejected bad password and user
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')
        # TODO: Perform end-to-end authentication test (need alternative to smtplib)
        self._test_roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def test_21_security_CVE_2011_1720(self):
        '''CVE-2011-1720 fixed'''
        # http://www.postfix.org/CVE-2011-1720.html

        # setup sasl and connect
        self.s.quit()
        self._setup_sasl("CRAM-MD5", "DIGEST-MD5")

        # verify sasl support
        rc, report = testlib.cmd(['postconf', 'smtpd_sasl_auth_enable'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue('yes' in report, "Could not find 'yes' in report:\n%s" % report)

        if self.lsb_release['Release'] > 6.06:
            rc, report = testlib.cmd(['postconf', 'smtpd_sasl_type'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue('cyrus' in report, "Could not find 'cyrus' in report:\n%s" % report)

        # ehlo
        reply = self._check_auth("CRAM-MD5")
        self.assertTrue('DIGEST-MD5' in reply, reply)

        code, msg = self.s.docmd("AUTH", "CRAM-MD5")
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 334, reply)

        code, msg = self.s.docmd("*")
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 501, reply)

        error = False
        try:
            code, msg = self.s.docmd("AUTH", "DIGEST-MD5")
        except:
            error = True
        self.assertFalse(error, "server disconnected")
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 334, reply)

    def test_99_restore(self):
        '''Restore configuration'''
        self._tearDown()

if __name__ == '__main__':
    unittest.main()
