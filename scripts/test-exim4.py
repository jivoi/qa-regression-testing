#!/usr/bin/python
#
#    test-exim4.py quality assurance test script for exim4
#    Copyright (C) 2010-2016 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
#    Based on test-postfix.py by Kees Cook <kees@ubuntu.com>
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
# QRT-Packages: exim4 exim4-daemon-heavy apache2-utils
# QRT-Privilege: root
# QRT-Depends: exim4

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install exim4 exim4-daemon-heavy sasl2-bin apache2-utils && ./test-exim4.py -v'

    On package install on Dapper, configure as:
    - internet site
    - set the root and postmaster recipient to 'root' (delivered to
      /var/mail/mail)

    IMPORTANT:
    - Do *NOT* use the split configuration from debconf. When that is in effect
      the files in /etc/exim4/conf.d and update-exim4.conf.conf are merged and
      shoved into /var/lib/exim4/config.autogenerated when calling
      update-exim4.conf.
      Instead, in this script we depend on the single configuration file,
      /etc/exim4/exim4.conf.template (and /etc/exim4/update-exim4.conf.conf
      to configure the template), which is used by update-exim4.conf to
      generate /var/lib/exim4/config.autogenerated when not using the split
      configuration

    TODO:
    - SASL
    - TLS
    - server auth via /etc/exim4/passwd.client
    - lots more (see http://wiki.debian.org/PkgExim4UserFAQ for ideas)
'''

import unittest, subprocess, smtplib, socket, os, time
import testlib

class Exim4Test(testlib.TestlibCase):
    '''Test Exim4 MTA.'''

    def _setUp(self):
        '''Create server configs.'''

        contents = ''
        for cfline in open(self.update_exim4_conf):
            if cfline.startswith('dc_eximconfig_configtype='):
                contents += "dc_eximconfig_configtype='internet'\n"
            elif cfline.startswith('dc_other_hostnames='):
                contents += "dc_other_hostnames='%s'\n" % (self.domain)
            elif cfline.startswith('dc_minimaldns='):
                contents += "dc_minimaldns='false'\n"
            elif cfline.startswith('CFILEMODE='):
                contents += "CFILEMODE='644'\n"
            elif cfline.startswith('dc_use_split_config='):
                contents += "dc_use_split_config='false'\n"
            elif cfline.startswith('dc_mailname_in_oh='):
                contents += "dc_mailname_in_oh='true'\n"
            elif cfline.startswith('dc_localdelivery='):
                contents += "dc_localdelivery='mail_spool'\n"
            else:
                found = False
                for i in ['dc_local_interfaces', 'dc_relay_domains', 'dc_relay_domains', 'dc_relay_nets', 'dc_smarthost', 'dc_hide_mailname']:
                    # These should just be emptied out
                    if cfline.startswith('%s=' % i):
                        contents += "%s=''\n" % (i)
                        found = True
                        break
                if not found:
                    contents += cfline

        testlib.config_replace(self.update_exim4_conf, contents, False)
        self._apply_exim4_configuration()

        # Now do the same for the aliases file
        contents = ''
        for line in open("/etc/aliases"):
            if line.startswith("postmaster:"):
                contents += "postmaster: root\n"
            else:
                contents += line

        testlib.config_replace("/etc/aliases", contents, False)
        rc, report = testlib.cmd(['newaliases'])
        expected = 0
        result = "Got '%d', expected '%d':\n %s" % (rc, expected, report)
        self.assertTrue(rc == expected, result)

        if os.path.exists(self.exim4_passwd):
            self.had_system_exim4_passwd = True

    def _tearDown(self):
        '''Restore the server configs'''
        testlib.config_restore(self.update_exim4_conf)
        testlib.config_restore(self.exim4_conf_template)
        self._apply_exim4_configuration()

        testlib.config_restore("/etc/aliases")
        rc, report = testlib.cmd(['newaliases'])
        expected = 0
        result = "Got '%d', expected '%d':\n %s" % (rc, expected, report)
        self.assertTrue(rc == expected, result)

        testlib.config_restore(self.exim4_passwd)
        if not self.had_system_exim4_passwd and os.path.exists(self.exim4_passwd):
            os.unlink(self.exim4_passwd)

    def _apply_exim4_configuration(self):
        '''run update-exim4.conf and restart'''
        # Generate the configuration
        rc, report = testlib.cmd(['update-exim4.conf'])
        expected = 0
        result = "Got '%d', expected '%d':\n %s" % (rc, expected, report)
        self.assertTrue(rc == expected, result)

        # Verify the configuration
        rc, report = testlib.cmd(['exim4', '-bV'])
        expected = 0
        result = "Got '%d', expected '%d':\n %s" % (rc, expected, report)
        self.assertTrue(rc == expected, result)

        self._restart_daemon()

    def _start_daemon(self):
        '''Start Exim4'''
        assert subprocess.call(['/etc/init.d/exim4', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        time.sleep(2)

    def _stop_daemon(self):
        '''Stop Exim4'''
        subprocess.call(['/etc/init.d/exim4', 'stop'], stdout=subprocess.PIPE)

    def _restart_daemon(self):
        '''Restart Exim4'''
        self._stop_daemon()
        self._start_daemon()

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.update_exim4_conf = "/etc/exim4/update-exim4.conf.conf"
        self.exim4_conf_template = "/etc/exim4/exim4.conf.template"
        self.exim4_passwd = "/etc/exim4/passwd"
        self.exim4_trusted = "/etc/exim4/trusted_configs"
        self.exim4_spool = "/var/spool/exim4"
        self.exim4_hack_conf = "/var/spool/exim4/e.conf"
        self.exim4_hack_setuid = "/var/spool/exim4/setuid"
        self.exim4_panic_log = "/var/log/exim4/paniclog"
        self.had_system_exim4_passwd = False

        self.port = 25 # TODO: different port (2525?)
        self.domain = "example.com"

        testlib.config_replace(self.exim4_trusted,"",append=True)

        self.user = testlib.TestUser(lower=True)
        self.s = None
        # Silently allow for this connection to fail, to handle the
        # initial setup of the exim4 server.
        try:
            self.s = smtplib.SMTP('localhost', port=self.port)
        except:
            pass

    def tearDown(self):
        '''Clean up after each test_* function'''

        try:
            self.s.quit()
        except:
            pass
        self.user = None

        # Clean up CVE-2010-4345 cruft
        if os.path.exists(self.exim4_hack_conf):
            os.unlink(self.exim4_hack_conf)
        if os.path.exists(self.exim4_hack_setuid):
            os.unlink(self.exim4_hack_setuid)

        # If there's no backup, there was no file originally
        if os.path.exists("%s.autotest" % self.exim4_trusted):
            testlib.config_restore(self.exim4_trusted)
        else:
            os.unlink(self.exim4_trusted)

        # Some tests may modify the configuration template, so restore it
        # if the backup file is found
        if os.path.exists("%s.autotest" % self.exim4_conf_template):
            testlib.config_restore(self.exim4_conf_template)
            self._apply_exim4_configuration()

    def _reconnect(self):
        self.s.putcmd("QUIT")
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertTrue(code == 221)
        self.assertTrue('closing connection' in msg, reply)
        connected = True
        try:
            code, msg = self.s.helo()
        except:
            connected = False
        self.assertFalse(connected, "Still connected after QUIT")

        # Reconnect after QUIT
        self.s = smtplib.SMTP('localhost', port=self.port)
        code, msg = self.s.helo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertTrue('Hello' in reply, reply)

    def _vrfy(self, address, valid = True):
        self.s.putcmd("vrfy",address)
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        if valid:
            self.assertEquals(code, 250, reply)
            self.assertTrue(address in msg, reply)
        else:
            self.assertTrue(code == 252 or code == 550, reply)
            if code == 550:
                self.assertTrue('<%s> Unrouteable address' % address in msg, reply)
            else:
                self.assertTrue('Administrative prohibition' in msg, reply)

    def _setup_smtpauth_plain(self):
        auth_str = '''plain_server:
  driver = plaintext
  public_name = PLAIN
  server_condition = "${if crypteq{$auth3}{${extract{1}{:}{${lookup{$auth2}lsearch{CONFDIR/passwd}{$value}{*:*}}}}}{1}{0}}"
  server_set_id = $auth2
  server_prompts = :
'''
        if self.lsb_release['Release'] < 8.04:
            auth_str = '''
plain_server:
  driver = plaintext
  public_name = PLAIN
  server_condition = "${if crypteq{$3}{${extract{1}{:}{${lookup{$2}lsearch{CONFDIR/passwd}{$value}{*:*}}}}}{1}{0}}"
  server_set_id = $2
  server_prompts = :
'''

        contents = ''
        wrote_smtp_vrfy = False
        for cfline in open(self.exim4_conf_template):
            if cfline.startswith('# plain_server:\n'):
                contents += auth_str
                contents += cfline
            else:
                contents += cfline

        testlib.config_replace(self.exim4_conf_template, contents, False)
        self._apply_exim4_configuration()
        self._reconnect()

        code, msg = self.s.ehlo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertEquals(self.s.does_esmtp, 1, reply)
        self.assertTrue('AUTH PLAIN' in self.s.ehlo_resp, reply)

    def _add_smtpauth_user(self, user):
        '''Allows PLAIN authentication with:
           AUTH PLAIN amFtaWUuY29t
           cGFzcw==

           Where you find these values with:
           $ perl -MMIME::Base64 -e 'print encode_base64("user@domain")'
           $ perl -MMIME::Base64 -e 'print encode_base64("pass")'
        '''
        rc, report = testlib.cmd(['htpasswd', '-nb', '-d', user.login, user.password])
        expected = 0
        result = "Got '%d', expected '%d':\n %s" % (rc, expected, report)
        self.assertTrue(rc == expected, result)
        testlib.config_replace(self.exim4_passwd, report, True)

    def _deliver_mail(self, user_sent_to, auth_user=None, auth_pass=None, domain=None):
        '''Perform mail delivery'''
        if auth_user and auth_pass:
            self.s.login(auth_user, auth_pass)

        if domain == None:
            domain = "@%s" % self.domain

	# Send a mail from 'root@domain' to 'user_sent_to@domain' and
        # 'missing-domain'. The mail to 'user_sent_to@domain' should succeed
        # and the one to 'missing-domain' should fail.
        failed = self.s.sendmail('root%s' % domain,["%s%s" % (user_sent_to.login, domain),'missing-domain'],'''From: Rooty <root%s>
To: "%s" <%s%s>
Subject: This is test 1

Hello, nice to meet you.
''' % (domain, user_sent_to.gecos, user_sent_to.login, domain))
        #for addr in failed.keys():
        #    print '%s %d %s' % (addr, failed[addr][0], failed[addr][1])
        self.assertEquals(len(failed),1,failed)
        self.assertTrue(failed.has_key('missing-domain'),failed)
        self.assertEquals(failed['missing-domain'][0],501,failed)

        time.sleep(2)

    def _mail_in_spool(self, user_directed_to, target_spool_user=None, spool_file=None, auth_user=None):
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
        expected = ' esmtp (Exim 4'
        if auth_user:
            expected = ' esmtpa (Exim 4'
            self.assertTrue('(Authenticated sender: %s)' % (auth_user))
        self.assertTrue(expected in contents, 'Looking for "%s" in email:\n%s' % (expected, contents))
        self.assertTrue('\nMessage-Id: ' in contents, contents)
        self.assertTrue('\nDate: ' in contents, contents)
        # client-side headers/body...
        self.assertTrue('\nSubject: This is test 1' in contents, contents)
        self.assertTrue('\nFrom: Rooty' in contents, contents)
        self.assertTrue('\nTo: "Buddy %s" <%s@' % (user_directed_to.login, user_directed_to.login) in contents, contents)
        self.assertTrue('\nHello, nice to meet you.' in contents, contents)

    def _roundtrip_mail(self, user_sent_to, user_to_check=None, spool_file=None, auth_user=None, auth_pass=None):
        '''Send and check email delivery'''
        self._deliver_mail(user_sent_to, auth_user, auth_pass)
        self._mail_in_spool(user_sent_to, user_to_check, spool_file, auth_user=auth_user)

    def _write_forward(self, user, contents):
        forward_filename = '/home/%s/.forward' % (user.login)
        open(forward_filename,'w').write(contents)
        os.chown(forward_filename, user.uid, user.gid)

    def test_00_initial_setup(self):
        '''Setup exim4 configuration'''
        # Get the main instance running
        self._setUp()

    def test_01_listening(self):
        '''Test listening'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('localhost',self.port))
        greeting = s.recv(1024)
        # 220 sec-hardy-amd64.strandboge.com ESMTP Exim 4.69 Fri, 10 Dec 2010 16:50:16 +0000
        self.assertTrue(greeting.startswith('220 '),greeting)
        self.assertTrue('ESMTP' in greeting,greeting)
        self.assertTrue('Exim' in greeting,greeting)
        self.assertFalse('MTA' in greeting,greeting)
        s.close()

    def test_commands(self):
        '''Test basic non-delivery SMTP commands'''
        #s = smtplib.SMTP('localhost', port=self.port)
        print "\n EHLO"
        code, msg = self.s.ehlo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertEquals(self.s.does_esmtp, 1, reply)
        self.assertTrue('SIZE' in self.s.ehlo_resp, reply)
        self.assertTrue('PIPELINING' in self.s.ehlo_resp, reply)

        print " HELO"
        code, msg = self.s.helo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        self.assertTrue('Hello' in reply, reply)

        print " NOOP"
        self.s.putcmd("NOOP")
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertTrue(code == 250)
        self.assertTrue('OK' in msg, reply)

        print " HELP"
        self.s.putcmd("help")
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 214, reply)
        for i in ['AUTH', 'HELO', 'EHLO', 'MAIL', 'RCPT', 'DATA', 'NOOP', 'QUIT', 'RSET', 'HELP']:
            result = "Could not find '%s' in reply:\n%s" % (i, reply)
            self.assertTrue('%s' % i in msg, result)

        print " VRFY disabled"
        self._vrfy('%s@%s' % (self.user.login, self.domain), valid=False)
        self._vrfy('does-not-exist', valid=False)

        print " EXPN disabled"
        self.s.putcmd("expn", "%s@%s" % (self.user.login, self.domain))
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertTrue(code == 252 or code == 550, reply)
        self.assertTrue('Administrative prohibition' in msg, reply)

        # These must be last
        print " QUIT"
        self._reconnect()

        print " RSET"
        self.s.putcmd("RSET")
        try:
            self.s.getreply()
        except:
            pass

    def test_vrfy_acl(self):
        '''Test acls'''
        print "\n Adding acl_smtp_vrfy"
        contents = ''
        wrote_smtp_vrfy = False
        for cfline in open(self.exim4_conf_template):
            if cfline.startswith('### main/02_exim4-config_options') and not wrote_smtp_vrfy:
                contents += cfline
                contents += "\nacl_smtp_vrfy = check_vrfy\n\n"
                wrote_smtp_vrfy = True
            elif cfline.startswith('begin acl\n'):
                contents += cfline
                contents += "\ncheck_vrfy:\n  accept  hosts         = *\n  deny    message       = vrfy not allowed from this host, sorry\n          delay         = TEERGRUBE\n\n"
            else:
                contents += cfline

        testlib.config_replace(self.exim4_conf_template, contents, False)
        self._apply_exim4_configuration()
        self._reconnect()

        print " VRFY in HELP"
        code, msg = self.s.ehlo()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 250, reply)
        time.sleep(2)

        self.s.putcmd("help")
        code, msg = self.s.getreply()
        reply = '%d %s' % (code, msg)
        self.assertEquals(code, 214, reply)
        result = "Could not find 'VRFY' in reply:\n%s" % (reply)
        self.assertTrue('VRFY' in msg, result)

        print " VRFY addresses"
        self._vrfy('%s@%s' % (self.user.login, self.domain), valid=True)
        self._vrfy('does-not-exist@%s' % self.domain, valid=False)

    def test_sending_mail_direct(self):
        '''Test mail delivered normally'''
        self._roundtrip_mail(self.user)

    def test_sending_mail_direct_invalid_recipient(self):
        '''Test mail to non-existent user is ignored'''
        spool_file = "/var/mail/mail"

        # First unlink the /var/mail/mail file
        if os.path.exists(spool_file):
            self._stop_daemon()
            time.sleep(2)
            os.unlink(spool_file)
            self._start_daemon()

	# Send a mail from 'root@domain' to 'not-here@domain'. It should not
	# fail from the sender's perspective, but should end up in
        # /var/mail/mail
        not_here = "not-here"
        try:
            failed = self.s.sendmail('root@%s' % self.domain,["%s@%s" % (not_here, self.domain),'%s@%s' % (not_here, self.domain)],'''From: Rooty <root@%s>
To: "Not Here" <%s@%s>
Subject: This is test 1

Hello, nice to meet you.
''' % (self.domain, not_here, self.domain))
        except smtplib.SMTPDataError, e:
            # Dapper errors out with 'valid RCPT command must precede DATA'
            if self.lsb_release['Release'] < 8.04 and e[0] == 503:
                return
            raise
        #for addr in failed.keys():
        #    print '%s %d %s' % (addr, failed[addr][0], failed[addr][1])
        self.assertEquals(len(failed),0,failed)

        time.sleep(2)

        # Verify it is not in the spool
        time.sleep(1)
        contents = open(spool_file).read()
        #print contents
        # Server-side added headers...
        self.assertTrue('\nReceived: from Debian-exim by ' in contents, contents)
        self.assertTrue('\nDate: ' in contents, contents)
        self.assertTrue('\nX-Failed-Recipients: %s@%s' % (not_here, self.domain) in contents, contents)
        self.assertTrue('Unrouteable address' in contents, contents)

    def test_sending_mail_direct_auth(self):
        '''Test mail PLAIN authentication'''
        self._setup_smtpauth_plain()
        self._add_smtpauth_user(self.user)

        # Verify rejected bad password and user
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, 'root', 'crapcrapcrap')
        self.assertRaises(smtplib.SMTPAuthenticationError, self.s.login, self.user.login, 'crapcrapcrap')
        self.s.login(self.user.login, self.user.password)

    def test_sending_mail_direct_auth_full(self):
        '''Test mail delivered with PLAIN authentication'''
        self._setup_smtpauth_plain()
        self._add_smtpauth_user(self.user)

        # Perform end-to-end authentication test
        self._roundtrip_mail(self.user, auth_user=self.user.login, auth_pass=self.user.password)

    def test_sending_mail_forward_normal(self):
        '''Test mail delivered via .forward'''
        forward_user = testlib.TestUser(lower=True)
        self._write_forward(forward_user, self.user.login+'\n')
        self._roundtrip_mail(forward_user, self.user)

    def test_sending_mail_forward_xternal(self):
        '''Test mail processed by commands in .forward'''

        # Create user-writable redirected mbox destination
        mbox, mbox_name = testlib.mkstemp_fill('',prefix='test-exim4.mbox-')
        mbox.close()
        os.chown(mbox_name, self.user.uid, self.user.gid)

        # Create a script to run in the .forward
        redir, redir_name = testlib.mkstemp_fill('''#!/bin/bash
/bin/cat > "%s"
''' % (mbox_name),prefix='test-exim4.redir-')
        redir.close()
        os.chmod(redir_name,0755)

        self._write_forward(self.user,'|%s\n' % (redir_name))
        self._roundtrip_mail(self.user, spool_file=mbox_name)

        os.unlink(redir_name)
        os.unlink(mbox_name)

    def test_string_expansion_vulnerability(self):
        '''Verify that string expansion is safe (CVE-2010-4344)'''
        self.assertShellExitEquals(0, ['./exim4/CVE-2010-4344.py','localhost'])

    def test_cve_2010_4345(self):
        '''Verify that Debian-exim can't escalate to root (CVE-2010-4345)'''

        #
        # Based on http://www.exim.org/lurker/message/20101207.215955.bb32d4f2.en.html
        #

        open(self.exim4_hack_conf,'w').write('''spool_directory = ${run{/bin/chown root:root /var/spool/exim4/setuid}}${run{/bin/chmod 4755 /var/spool/exim4/setuid}}
''')
        open(self.exim4_hack_setuid,'w').write('''This is a dummy file
''')
        for f in (self.exim4_hack_conf, self.exim4_hack_setuid):
            os.chmod(f,0644)
            subprocess.call(['chown', 'Debian-exim:Debian-exim', f])

        rc, report = testlib.cmd(['sudo', '-u', 'Debian-exim', 'exim',
                                  '-C' + self.exim4_hack_conf, '-q'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Remove panic log to get rid of warnings
        if os.path.exists(self.exim4_panic_log):
            os.unlink(self.exim4_panic_log)

        sb = os.lstat(self.exim4_hack_setuid)
        self.assertFalse(sb.st_uid == 0, "setuid file is owned by root!")
        self.assertFalse(sb.st_gid == 0, "setuid file is group-owned by root!")

    def test_trusted_configs_file(self):
        '''Verify that the new trusted_configs file works'''

        open(self.exim4_hack_conf,'w').write('''spool_directory = ${run{/bin/chown root:root /var/spool/exim4/setuid}}
''')
        open(self.exim4_hack_setuid,'w').write('''This is a dummy file
''')
        open(self.exim4_trusted,'w').write('''%s
''' % self.exim4_hack_conf)

        for f in (self.exim4_hack_conf, self.exim4_hack_setuid):
            os.chmod(f,0644)
            subprocess.call(['chown', 'Debian-exim:Debian-exim', f])

        # Make sure it doesn't work if conf file isn't owned by root
        rc, report = testlib.cmd(['sudo', '-u', 'Debian-exim', 'exim',
                                  '-C' + self.exim4_hack_conf, '-q'])

        # Remove panic log to get rid of warnings
        if os.path.exists(self.exim4_panic_log):
            os.unlink(self.exim4_panic_log)

        sb = os.lstat(self.exim4_hack_setuid)
        self.assertFalse(sb.st_uid == 0, "setuid file is owned by root!")
        self.assertFalse(sb.st_gid == 0, "setuid file is group-owned by root!")

        # Make sure it does work if it's owned by root
        subprocess.call(['chown', 'root:root', self.exim4_hack_conf])
        rc, report = testlib.cmd(['sudo', '-u', 'Debian-exim', 'exim',
                                  '-C' + self.exim4_hack_conf, '-q'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        sb = os.lstat(self.exim4_hack_setuid)
        self.assertTrue(sb.st_uid == 0, "setuid file wasn't owned by root!")
        self.assertTrue(sb.st_gid == 0, "setuid file was not group-owned by root!")

    def test_user_filter_regression(self):
        '''Test CVE-2010-4345 user filter regression'''
        # See http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=611572
        forward_user = testlib.TestUser(lower=True)
        self._write_forward(forward_user, '''# Exim filter
if $header_subject: contains "Ubuntu" or
$header_subject: contains "Rocks"
then
save $home/mail/ubunturocks
endif
''')

        rc, report = testlib.cmd(['sudo', '-u', forward_user.login, '/bin/bash',
                                  '-c', 'echo "" | /usr/sbin/exim4 -bf /home/' + forward_user.login + '/.forward'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("Normal delivery will occur" in report, "Didn't find 'Normal deliver will occur'")
        self.assertFalse("Operation not permitted" in report, "Found 'Operation not permitted'")

    def test_zz_zz_tearDown(self):
        '''Restore exim4 restore configuration'''
        self._tearDown()

if __name__ == '__main__':
    unittest.main()
