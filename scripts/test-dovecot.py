#!/usr/bin/python
#
#    dovecot.py quality assurance test script
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Modified by: Marc Deslauriers <marc.deslauriers@canonical.com>
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
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''

# QRT-Depends: testlib_dovecot.py
# QRT-Packages: dovecot-imapd dovecot-pop3d procmail
# QRT-Alternates: dovecot-sieve:!lucid
# QRT-Privilege: root

import unittest, subprocess, os, os.path, sys, glob
import imaplib, poplib

import testlib
import testlib_dovecot

class DovecotBasics(testlib.TestlibCase):
    '''Base operational tests for Dovecot server.'''

    def _setUp(self,config_mmap_disable=False):
        '''Create test scenario.

        dovecot is configured for all protocols (imap[s] and pop3[s]), a test
        user is set up, and /var/mail/$user contains an unread and a read mail.
        '''

        # Dovecot in quantal+ doesn't like mixed-case usernames
        self.user = testlib.TestUser(lower=True)
        self.evil_user = testlib.TestUser(lower=True)

        if self.lsb_release['Release'] == 10.04:
            config = '''
log_timestamp = "%Y-%m-%d %H:%M:%S "
#mail_extra_groups = mail
mail_privileged_group = mail
protocols = imap imaps pop3 pop3s
mail_location = mbox:~/mail:INBOX=/var/mail/%u
protocol imap {
  mail_plugins = acl imap_acl
}
protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
}
auth default {
  mechanisms = plain
  passdb pam {
  }
  userdb passwd {
  }
  socket listen {
    master {
      path = /var/run/dovecot/auth-master
      mode = 0600
    }
  }
  user = root
}
protocol lda {
  postmaster_address = root
  mail_plugins = sieve
  mail_plugin_dir = /usr/lib/dovecot/modules/lda
  auth_socket_path = /var/run/dovecot/auth-master
}
plugin {
  acl = vfile
}
'''
        else:
            # Yuck, the mail_access_groups makes dovecot vulnerable to
            # CVE-2008-1199 but if not enabled, it fails due to
            # http://wiki2.dovecot.org/Errors/ChgrpNoPerm when
            # when using postfix/procmail for an MDA
            config = '''
log_timestamp = "%Y-%m-%d %H:%M:%S "
#mail_extra_groups = mail
mail_privileged_group = mail
protocols = imap pop3
mail_access_groups = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u
protocol imap {
  mail_plugins = acl imap_acl
}
passdb {
  driver = pam
}
userdb {
  driver = passwd
}
service auth {
  unix_listener auth-master {
    mode = 0600
  }
  user = root
}
lda_mailbox_autocreate = yes
protocol lda {
  postmaster_address = root
  mail_plugins = sieve
  auth_socket_path = /var/run/dovecot/auth-master
}
plugin {
  acl = vfile
}
'''

            #ssl_cert = </etc/ssl/certs/dovecot.pem
            #ssl_key = </etc/ssl/private/dovecot.pem

        if config_mmap_disable:
            config += '''
mmap_disable = yes
'''
        self.dovecot = testlib_dovecot.Dovecot(self,self.user,config)

    def _tearDown(self):
        self.dovecot = None
        self.user = None
        self.evil_user = None

    def _test_pop3_proto(self, pop):
        '''Internal factorization of POP3 protocol checks with an established
        connection.'''

        # check empty password
        self.assertEqual(pop.user(self.user.login), '+OK')
        self.assertRaises(poplib.error_proto, pop.pass_, '')

        # check wrong password
        self.assertEqual(pop.user(self.user.login), '+OK')
        self.assertRaises(poplib.error_proto, pop.pass_, '123')

        # check correct password
        self.assertEqual(pop.user(self.user.login), '+OK')
        self.assertEqual(pop.pass_(self.user.password), '+OK Logged in.')

        # check messages
        self.assertEqual(pop.stat()[0], 2, '2 available messages')
        self.assertEqual(pop.list()[1], ['1 163', '2 161'])
        self.assertEqual('\n'.join(pop.retr(1)[1]), '''Date: Thu, 16 Nov 2006 17:12:23 -0800
From: Test User 1 <test1@test1.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 1

Some really important news.''')
        self.assertEqual('\n'.join(pop.retr(2)[1]), '''Date: Tue, 28 Nov 2006 11:29:34 +0100
From: Test User 2 <test2@test2.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 2

More news.

Get cracking!''')

        self.assertEqual(pop.quit(), '+OK Logging out.')

        # check new status
        status = ''
        for l in open(self.dovecot.get_mailbox()):
            if l.startswith('Status:'):
                status += l
        self.assertEqual(status, 'Status: NRO\nStatus: RO\n')

    def test_pop3(self):
        '''Test POP3 protocol'''

        if self.lsb_release['Release'] >= 13.10:
            message = '+OK Dovecot (Ubuntu) ready.'
        else:
            message = '+OK Dovecot ready.'

        pop = poplib.POP3('localhost')
        self.assertEqual(pop.getwelcome(), message)

        self._test_pop3_proto(pop)

    def test_pop3s(self):
        '''Test POP3S protocol'''

        if self.lsb_release['Release'] >= 13.10:
            message = '+OK Dovecot (Ubuntu) ready.'
        else:
            message = '+OK Dovecot ready.'

        pop = poplib.POP3_SSL('localhost')
        self.assertEqual(pop.getwelcome(), message)

        self._test_pop3_proto(pop)

    def test_tls(self):
        '''Test TLS support'''

        rc, report = testlib.cmd_pipe(["echo", "-n"],
                                      ["openssl", "s_client", "-tls1",
                                       "-connect", "localhost:995"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue("Protocol  : TLSv1" in report,
                        "Couldn't find TLSv1 in report!")

    def test_sslv3(self):
        '''Test SSLv3 support'''

        rc, report = testlib.cmd_pipe(["echo", "-n"],
                                      ["openssl", "s_client", "-ssl3",
                                       "-connect", "localhost:995"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue("Protocol  : SSLv3" in report,
                        "Couldn't find SSLv3 in report!")

    def test_sslv3_disabled(self):
        '''Test disabled SSLv3 support'''

        cfgfile = open('/etc/dovecot/dovecot.conf', 'a')
        cfgfile.write("ssl_protocols = !SSLv3")
        cfgfile.close()

        self.dovecot.reload_conf(self)

        # Make sure SSLv3 is disabled
        rc, report = testlib.cmd_pipe(["echo", "-n"],
                                      ["openssl", "s_client", "-ssl3",
                                       "-connect", "localhost:995"])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue("ssl handshake failure" in report,
                        "Could not find handshake failure in report!")

        # Now make sure TLSv1 still works
        rc, report = testlib.cmd_pipe(["echo", "-n"],
                                      ["openssl", "s_client", "-tls1",
                                       "-connect", "localhost:995"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.assertTrue("Protocol  : TLSv1" in report,
                        "Couldn't find TLSv1 in report!")

    def _test_imap_proto(self, imap, second_flags='\\Seen \\Recent'):
        '''Internal factorization of IMAP4 protocol checks with an established
        connection.'''

        # invalid passwords
        self.assertRaises(imaplib.IMAP4.error, imap.login, self.user.login, '')
        self.assertRaises(imaplib.IMAP4.error, imap.login, self.user.login, '123')
        # CVE-2008-1218
        self.assertRaises(imaplib.IMAP4.error, imap.login, self.user.login, '"\tmaster_user=root\tskip_password_check=1"')

        # correct password
        imap.login(self.user.login, self.user.password)

        # list mailboxes
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        found_inbox = False

        if self.lsb_release['Release'] >= 14.04:
            inbox_name = 'INBOX'
        else:
            inbox_name = '"INBOX"'

        for entry in list:
            if entry.endswith(inbox_name):
                found_inbox = True
        self.assertTrue(found_inbox)

        # check mails
        self.assertEqual(imap.select('INBOX')[0], 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1 2']))
        self.assertEqual(imap.fetch('1', '(FLAGS)'), 
            ('OK', ['1 (FLAGS (\\Recent))']))

        report = imap.fetch('2', '(FLAGS)')
        self.assertTrue(len(report)>1,report)
        self.assertTrue(len(report[1])>0,report)
        checkflags = second_flags
        if 'Recent' in report[1][0] and not 'Recent' in checkflags:
            if len(checkflags):
                checkflags += ' '
            checkflags += '\\Recent'
        self.assertEqual(report,
            ('OK', ['2 (FLAGS (%s))'%(checkflags)]))

        self.assertEqual(imap.fetch('1', '(BODY[TEXT])')[1][0][1].rstrip(), 
            'Some really important news.')
        self.assertEqual(imap.fetch('2', '(BODY[TEXT])')[1][0][1].rstrip(), 
            'More news.\r\n\r\nGet cracking!')

        email1='''Date: Thu, 16 Nov 2006 17:12:23 -0800\r
From: Test User 1 <test1@test1.com>\r
To: Dovecot tester <dovecot@test.com>\r
Subject: Test 1\r
\r
Some really important news.\r
'''

        # HACK to deal with procmail redelivery into Maildir
        if os.path.exists(self.user.home+"/Maildir"):
            email1 = email1.replace('\r\n\r\n','\r\nStatus: N\r\n\r\n',1)+'\r\n'

        size1 = len(email1)
        self.assertEqual(imap.fetch('1', '(RFC822)')[1],
            [('1 (RFC822 {%d}' % (size1), email1), ')'])

        # save email to local mail store
        self.assertEqual(imap.create('NewStorage')[0],'OK')
        self.assertEqual(imap.copy('1', 'NewStorage')[0], 'OK')

        # delete mail 1
        self.assertEqual(imap.store('1', '+FLAGS', '\\Deleted')[0], 'OK')
        self.assertEqual(imap.expunge()[0], 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))

        # old mail 2 is mail 1 now
        email2='''Date: Tue, 28 Nov 2006 11:29:34 +0100\r
From: Test User 2 <test2@test2.com>\r
To: Dovecot tester <dovecot@test.com>\r
Subject: Test 2\r
\r
More news.\r
\r
Get cracking!'''

        # HACK to deal with procmail redelivery into Maildir
        if os.path.exists(self.user.home+"/Maildir"):
            email2 = email2.replace('\r\n\r\n','\r\nStatus: R\r\n\r\n',1)+'\r\n\r\n'

        size2 = len(email2)
        self.assertEqual(imap.fetch('1', '(RFC822)')[1],
            [('1 (RFC822 {%d}' % (size2), email2), ')'])

        # pull messages back out of local mail store
        self.assertEqual(imap.select('NewStorage')[0],'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        report = imap.fetch('1', '(FLAGS)')
        self.assertTrue(len(report)>1,report)
        self.assertTrue(len(report[1])>0,report)
        if 'Recent' in report[1][0]:
            self.assertEqual(report,
                ('OK', ['1 (FLAGS (\\Seen \\Recent))']))
        else:
            self.assertEqual(report,
                ('OK', ['1 (FLAGS (\\Seen))']))
        self.assertEqual(imap.fetch('1', '(RFC822)')[1],
            [('1 (RFC822 {%d}' % (size1), email1), ')'])

        imap.close()
        imap.logout()

    def _setup_maildir(self, mailpath):
        '''Setup for Maildir'''

        os.mkdir(mailpath)
        os.chmod(mailpath,0700)
        os.chown(mailpath, self.user.uid, self.user.gid)
        # Aim procmail into Maildir location
        rcpath = self.user.home+'/.procmailrc'
        rc = file(rcpath,'w')
        rc.write('MAILDIR=$HOME/Maildir/\nDEFAULT=$HOME/Maildir/\n')
        rc.close()
        os.chmod(rcpath,0644)
        os.chown(rcpath, self.user.uid, self.user.gid)

        # redeliver to Maildir inbox
        self.assertTrue(subprocess.call(['formail','-s','procmail','-d',self.user.login],stdin=file('/var/mail/%s'%(self.user.login))) == 0)
        # move 2nd one into "cur" so it is not "new"
        second = sorted(glob.glob(mailpath+'/new/*'))[1]
        os.rename(second,mailpath+'/cur/'+os.path.basename(second))

        # Reconfigure dovecot for maildir location
        subprocess.call(['sed', '-i', 's#^mail_location = mbox:~/mail:INBOX=/var/mail/%u#mail_location = maildir:~/Maildir#', '/etc/dovecot/dovecot.conf'])
        self.dovecot.reload_conf(self)

    def test_imap(self):
        '''Test IMAP4 protocol (mbox)'''

        imap = imaplib.IMAP4('localhost')
        self._test_imap_proto(imap)

        mailpath = self.user.home+"/mail"
        self.assertTrue(os.path.exists(mailpath+"/NewStorage"))

    def test_imaps(self):
        '''Test IMAP4S protocol (mbox)'''

        # Timing is strange here -- sometimes we get EOFs on SSL connect
        try:
            imap = imaplib.IMAP4_SSL('localhost')
        except:
            imap = imaplib.IMAP4_SSL('localhost')

        self._test_imap_proto(imap)

        mailpath = self.user.home+"/mail"
        self.assertTrue(os.path.exists(mailpath+"/NewStorage"))

    def test_imap_folders_maildir(self):
        '''Test IMAP4 with Maildir folders'''

        # Built Maildir storage location
        mailpath = self.user.home+"/Maildir"
        self._setup_maildir(mailpath)

        imap = imaplib.IMAP4('localhost')
        self._test_imap_proto(imap,second_flags='')

        self.assertTrue(os.path.exists(mailpath+"/new/"))
        self.assertTrue(os.path.exists(mailpath+"/.NewStorage/cur/"))

    def test_acl_plugin_readonly(self):
        '''Test ACL plugin read-only'''

        mailpath = self.user.home + "/Maildir"
        mailpath_acl = os.path.join(mailpath, "dovecot-acl")
        mailpath_acl_list = os.path.join(mailpath, "dovecot-acl-list")
        self._setup_maildir(mailpath)

        open(mailpath_acl,'w').write('''user=%s r
''' % self.user.login)
        if os.path.exists(mailpath_acl_list):
            os.unlink(mailpath_acl_list)

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)

        # See if we can open INBOX for writing
        can_write = True
        try:
            imap.select('INBOX')
        except:
            can_write = False

        self.assertFalse(can_write)

        imap.close
        imap.logout

    def test_acl_plugin_permissive(self):
        '''Test ACL plugin permissive'''

        mailpath = self.user.home + "/Maildir"
        mailpath_acl = os.path.join(mailpath, "dovecot-acl")
        mailpath_acl_list = os.path.join(mailpath, "dovecot-acl-list")
        self._setup_maildir(mailpath)
        if self.lsb_release['Release'] >= 10.04:
            acl_list = "lrwstipekxa"
        else:
            acl_list = "lrwstiekxa"

        open(mailpath_acl,'w').write('''user=%s %s
''' % (self.user.login, acl_list))
        if os.path.exists(mailpath_acl_list):
            os.unlink(mailpath_acl_list)

        imap = imaplib.IMAP4('localhost')
        self._test_imap_proto(imap,second_flags='')

        self.assertTrue(os.path.exists(mailpath+"/new/"))
        self.assertTrue(os.path.exists(mailpath+"/.NewStorage/cur/"))

    def test_cve_2010_3304(self):
        '''Test CVE-2010-3304'''

        mailpath = self.user.home + "/Maildir"
        mailpath_acl = os.path.join(mailpath, "dovecot-acl")
        mailpath_acl_list = os.path.join(mailpath, "dovecot-acl-list")
        self._setup_maildir(mailpath)
        if self.lsb_release['Release'] >= 10.04:
            acl_list = "lrwstipekxa"
        else:
            acl_list = "lrwstiekxa"

        open(mailpath_acl,'w').write('''user=%s %s
user=joe %s
''' % (self.user.login, acl_list, acl_list))
        if os.path.exists(mailpath_acl_list):
            os.unlink(mailpath_acl_list)

        imap = imaplib.IMAP4('localhost')
        self._test_imap_proto(imap,second_flags='')

        self.assertTrue(os.path.exists(mailpath+"/new/"))
        self.assertTrue(os.path.exists(mailpath+"/.NewStorage/cur/"))

        # Make sure we didn't inherit INBOX's acl
        self.assertFalse(os.path.exists(mailpath + '/.NewStorage/dovecot-acl'))

    def test_deliver(self):
        '''Test dovecot's deliver LDA'''

        test_mail = '''From test4@test4.com Fri Dec 28 11:29:34 2007
Date: Fri, 28 Dec 2007 11:29:34 +0100
From: ( Test User 4 <test4@test4.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 4

Ubuntu Rocks!
'''

        handle, name = testlib.mkstemp_fill(test_mail, dir=self.user.home)

        (rc, report) = testlib.cmd(['/usr/lib/dovecot/deliver','-d',self.user.login, '-m', 'TestMB'],stdin=handle)
        expected = 0

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        mail_file = self.user.home+'/mail/TestMB'

        # Is the file there?
        self.assertTrue(os.path.exists(mail_file))

        # Does it contain our email?
        self.assertEquals(subprocess.call(['/bin/grep', '-q', 'Ubuntu Rocks!', mail_file], stdout=subprocess.PIPE), 0)

    def test_deliver_sieve(self):
        '''Test dovecot's deliver LDA with sieve plugin'''

        open(self.user.home+'/.dovecot.sieve','w').write('''require "fileinto";
if header :comparator "i;ascii-casemap" :contains "Subject" "**SPAM**"  {
        fileinto "Trash";
        stop;
}
''')

        test_mail = '''From test4@test4.com Fri Dec 28 11:29:34 2007
Date: Fri, 28 Dec 2007 11:29:34 +0100
From: ( Test User 4 <test4@test4.com>
To: Dovecot tester <dovecot@test.com>
Subject: **SPAM** Buy stuff

Hey! Guess what? I've got a great opportunity for ya!
'''

        handle, name = testlib.mkstemp_fill(test_mail, dir=self.user.home)

        (rc, report) = testlib.cmd(['/usr/lib/dovecot/deliver','-d',self.user.login, '-m', 'TestMB'],stdin=handle)
        expected = 0

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        mail_file = self.user.home+'/mail/Trash'

        # Is the file there?
        self.assertTrue(os.path.exists(mail_file))

        # Does it contain our email?
        self.assertEquals(subprocess.call(['/bin/grep', '-q', 'Buy stuff', mail_file], stdout=subprocess.PIPE), 0)

    def test_security_001_mail_group(self):
        '''Handles malicious symlinks (CVE-2008-1199)'''

        if self.lsb_release['Release'] >= 12.04:
            return self._skipped("Can't properly test CVE-2008-1199 in Oneiric+ (see comments in script)")

        # Prepare an "evil" user
        mailpath = self.evil_user.home+"/mail"
        os.mkdir(mailpath)
        os.chmod(mailpath,0700)
        os.chown(mailpath, self.evil_user.uid, self.evil_user.gid)
        mailbox = "other_inbox" 
        mailpath += "/" + mailbox
        os.symlink("/var/mail/"+self.user.login,mailpath)

        imap = imaplib.IMAP4('localhost')
        imap.login(self.evil_user.login, self.evil_user.password)
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        status, data = imap.select(mailbox)
        self.assertEqual(status, 'NO', "Reading via symlinks: %s %s" % (status, data))

    def test_security_002_corrupt_header(self):
        '''Handles corrupt headers (CVE-2008-4907)'''

        open('/var/mail/'+self.user.login,'w').write('''From test3@test1.com Tue Nov 28 11:29:34 2007
Date: Tue, 28 Nov 2007 11:29:34 +0100
From: ( Test User 3 <test3@test2.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 2
Status: R

Stop cracking!
''')

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" "Test 2" NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])

    def test_security_003_corrupt_header(self):
        '''Handles corrupt headers (CVE-2011-1929)'''

        open('/var/mail/'+self.user.login,'w').write('''From test4@test3.com Tue Nov 28 11:29:34 2007
Date\0: Tue, 28 Nov 2007 11:29:34 +0100
\0From: ( Test User 4 <test4@test3.com>
To: Dovecot tester <dovecot@test.com>
Sub\0ject: Test 3
Statu\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0s: R

Stop cracking!
''')

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" NIL NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])
        self.assertEqual(imap.store(1, '-FLAGS', '\\SEEN')[0], 'OK')
        self.assertEqual(imap.logout(), ('BYE', ['Logging out']))

    def disabled_test_security_004_corrupt_header(self):
        '''Handles corrupt headers (incomplete CVE-2011-1929?)'''

        open('/var/mail/'+self.user.login,'w').write('''From test4@test3.com Tue Nov 28 11:29:34 2007
Date\0: Tue, 28 Nov 2007 11:29:34 +0100
\0From: ( Test User 4 <test4@test3.com>
To: Dovecot tester <dovecot@test.com>
Sub\0ject: Test 3
Statu\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0s: R

Stop cracking!
''')

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" NIL NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])
        self.assertEqual(imap.store(1, '-FLAGS', '\\SEEN')[0], 'OK')
        self.assertEqual(imap.logout(), ('BYE', ['Logging out']))
        imap = None

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        print imap.fetch('1', '(ENVELOPE)')[1]
        print imap.fetch('1', '(BODY[HEADER.FIELDS (SUB)])')[1]
        self.assertEqual(imap.fetch('1', '(BODY[HEADER.FIELDS (SUB)])')[1],
            [('1 (FLAGS (\\Seen) BODY[HEADER.FIELDS (SUB)] {15}', 'Sub: Test 3\r\n\r\n'), ')'])
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" NIL NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])

    def disabled_test_security_005_corrupt_header(self):
        '''Handles corrupt headers (incomplete CVE-2011-1929?)'''

        open('/var/mail/'+self.user.login,'w').write('''From test4@test3.com Tue Nov 28 11:29:34 2007
Date\0: Tue, 28 Nov 2007 11:29:34 +0100
\0From: ( Test User 4 <test4@test3.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 3
Subject\0ive: Not Test 3's Subject
Status: R

Stop cracking!
''')

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        status, list = imap.list()
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" "Test 3" NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])
        self.assertEqual(imap.store(1, '-FLAGS', '\\SEEN')[0], 'OK')
        self.assertEqual(imap.logout(), ('BYE', ['Logging out']))
        imap = None

        imap = imaplib.IMAP4('localhost')
        imap.login(self.user.login, self.user.password)
        self.assertEqual(status, 'OK')
        status, data = imap.select('INBOX')
        self.assertEqual(status, 'OK')
        self.assertEqual(imap.search(None, 'ALL'), ('OK', ['1']))
        print imap.fetch('1', '(ENVELOPE)')[1]
        print imap.fetch('1', '(BODY[HEADER.FIELDS (SUB)])')[1]
        self.assertEqual(imap.fetch('1', '(BODY[HEADER.FIELDS (SUB)])')[1],
            [('1 (FLAGS (\\Seen) BODY[HEADER.FIELDS (SUB)] {15}', 'Sub: Test 3\r\n\r\n'), ')'])
        self.assertEqual(imap.fetch('1', '(ENVELOPE)')[1],
            ['1 (ENVELOPE ("Tue, 28 Nov 2007 11:29:34 +0100" NIL NIL NIL NIL (("Dovecot tester" NIL "dovecot" "test.com")) NIL NIL NIL NIL))'])

class DovecotMmapTest(DovecotBasics):
    '''Test dovecot with mmap support'''

    def setUp(self):
        self._setUp()

    def tearDown(self):
        self._tearDown()

    def test_configuration(self):
        '''Test dovecot configuration with mmap enabled'''
        self.assertEquals(subprocess.call(['/bin/grep', '-q', '^mmap_disable = yes','/etc/dovecot/dovecot.conf'], stdout=subprocess.PIPE), 1)

class DovecotDirectTest(DovecotBasics):
    '''Test dovecot without mmap support'''

    def setUp(self):
        self._setUp(config_mmap_disable=True)

    def tearDown(self):
        self._tearDown()

    def test_configuration(self):
        '''Test dovecot configuration with mmap disabled'''
        self.assertEquals(subprocess.call(['/bin/grep', '-q', '^mmap_disable = yes','/etc/dovecot/dovecot.conf'], stdout=subprocess.PIPE), 0)


if __name__ == '__main__':
    testlib.require_sudo()
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DovecotMmapTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DovecotDirectTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
