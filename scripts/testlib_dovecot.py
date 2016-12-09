#!/usr/bin/python
#
#    testlib_dovecot.py quality assurance test library
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Modified by: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Library General Public
#    License as published by the Free Software Foundation; either
#    version 2 of the License.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Library General Public License for more details.
#
#    You should have received a copy of the GNU Library General Public
#    License #    along with this program.  If not, see
#    <http://www.gnu.org/licenses/>.
#

# QRT-Packages: dovecot-imapd dovecot-pop3d
# Only needed on 11.10 and above
# QRT-Alternates: dovecot-sieve

'''
    Packages required: dovecot-imapd dovecot-pop3d
'''

import subprocess, shutil, grp, os, os.path, time
import testlib

class Dovecot:
    def get_mailbox(self):
        return self.mailbox

    def _check_pid(self):
        return os.path.exists(self.pidfile) and testlib.check_pidfile("dovecot", self.pidfile)

    def __init__(self,unittester,user,config=None,prepopulate_inbox=True,cert_pub=None,cert_key=None):
        '''Create test scenario.

        dovecot is configured for all protocols (imap[s] and pop3[s]), a test
        user is set up, and /var/mail/$user contains an unread and a read mail.
        '''

        self.new_version = False
        if file("/etc/dovecot/dovecot.conf","r").read().find('!include_try /usr/share/dovecot/protocols.d/*.protocol')>0:
            self.new_version = True

        # Stop dovecot before we make any changes to the config file
        self.pidfile = "/var/run/dovecot/master.pid"
        if self.new_version:
            self.auth_sockets = ["/var/run/dovecot/auth-master","/var/run/dovecot/auth-worker",
                                 "/var/run/dovecot/login/login", "/var/run/dovecot/anvil",
                                 "/var/run/dovecot/anvil-auth-penalty"]
        else:
            self.auth_sockets = ["/var/run/dovecot/auth-master","/var/run/dovecot/login/default"]

        if self._check_pid():
            # Prefer upstart
            if os.path.exists('/etc/init/dovecot.conf'):
                subprocess.call(['stop', 'dovecot'], stdout=subprocess.PIPE)
            else:
                subprocess.call(['/etc/init.d/dovecot', 'stop'], stdout=subprocess.PIPE)

        # wait for daemon to stop
        for count in range(0,10):
            if self._check_pid():
                time.sleep(0.5)

        if config == None:
            if file("/etc/dovecot/dovecot.conf","r").read().find('auth_mechanisms = plain')>0:
                # Old dovecot
                config='''
protocols = imap imaps pop3 pop3s
login = imap
login = pop3
#mail_extra_groups = mail
mail_privileged_group = mail

auth = auth-cram
auth_mechanisms = cram-md5
auth_passdb = passwd-file /etc/dovecot/test.passwd
auth_user = root

auth = auth-plain
auth_mechanisms = plain
auth_passdb = pam
auth_user = root

'''
            elif self.new_version:
                # dovecot 2.0.x
                config='''
auth_mechanisms = plain cram-md5
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_location = mbox:~/mail:INBOX=/var/mail/%u
mail_privileged_group = mail
# Yuck, the following makes dovecot vulnerable to
# CVE-2008-1199 but if not enabled, it fails due to
# http://wiki2.dovecot.org/Errors/ChgrpNoPerm when
# when using postfix/procmail for an MDA
mail_access_groups = mail
passdb {
  args = /etc/dovecot/test.passwd
  driver = passwd-file
}
passdb {
  driver = pam
}
protocols = imap pop3
service auth {
  user = root
}
userdb {
  driver = passwd
}
'''
            else:
                # dovecot 1.1/1.2 era
                config='''
protocols = imap imaps pop3 pop3s
log_timestamp = "%Y-%m-%d %H:%M:%S "
#mail_extra_groups = mail
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u
protocol imap {
}
protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
}
auth default {
  mechanisms = plain cram-md5
  passdb passwd-file {
    args = /etc/dovecot/test.passwd
  }
  passdb pam {
  }
  userdb passwd {
  }
  user = root
}
'''
        if self.new_version:
            key_config_str = 'ssl_key = <%s\n'
            cert_config_str = 'ssl_cert = <%s\n'
            # ssl_key and ssl_cert need to be defined in dovecot 2.0.x
            # Raring+ uses snakeoil by default
            if cert_key == None:
                if os.path.exists('/etc/ssl/private/dovecot.pem'):
                    cert_key = '/etc/ssl/private/dovecot.pem'
                else:
                    cert_key = '/etc/ssl/private/ssl-cert-snakeoil.key'
            if cert_pub == None:
                if os.path.exists('/etc/ssl/certs/dovecot.pem'):
                    cert_pub = '/etc/ssl/certs/dovecot.pem'
                else:
                    cert_pub = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
        else:
            key_config_str = 'ssl_key_file = %s\n'
            cert_config_str = 'ssl_cert_file = %s\n'

        self.cert_key = cert_key
        if self.cert_key:
            config = key_config_str % (self.cert_key) + config
        self.cert_pub = cert_pub
        if self.cert_pub:
            config = cert_config_str % (self.cert_pub) + config

        # make sure that /etc/inetd.conf exists to avoid init script errors
        self.created_inetdconf = False
        if not os.path.exists('/etc/inetd.conf'):
            open('/etc/inetd.conf', 'a')
            self.created_inetdconf = True

        # Move dovecot-postfix.conf out of the way
        if os.path.exists('/etc/dovecot/dovecot-postfix.conf'):
            os.rename('/etc/dovecot/dovecot-postfix.conf', '/etc/dovecot/dovecot-postfix.conf.autotest')
        # configure and restart dovecot
        if not os.path.exists('/etc/dovecot/dovecot.conf.autotest'):
            shutil.copyfile('/etc/dovecot/dovecot.conf', '/etc/dovecot/dovecot.conf.autotest')
        cfgfile = open('/etc/dovecot/dovecot.conf', 'w')
        cfgfile.write(config)
        cfgfile.close()

        file('/etc/dovecot/test.passwd','w').write('%s:{plain}%s\n' % (user.login, user.password) )

        if prepopulate_inbox:
            # create test mailbox with one new and one old mail
            self.mailbox = '/var/mail/' + user.login
            self.orig_mbox = \
'''From test1@test1.com Fri Nov 17 02:21:08 2006
Date: Thu, 16 Nov 2006 17:12:23 -0800
From: Test User 1 <test1@test1.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 1
Status: N

Some really important news.

From test2@test1.com Tue Nov 28 11:29:34 2006
Date: Tue, 28 Nov 2006 11:29:34 +0100
From: Test User 2 <test2@test2.com>
To: Dovecot tester <dovecot@test.com>
Subject: Test 2
Status: R

More news.

Get cracking!
'''
            open(self.mailbox, 'w').write(self.orig_mbox)
            os.chown(self.mailbox, user.uid, grp.getgrnam('mail')[2])
            os.chmod(self.mailbox, 0660)

        # For some reason, this gets left over sometimes
        for socket in self.auth_sockets:
            if os.path.exists(socket):
                os.unlink(socket)

        # Start the daemon
        if os.path.exists('/etc/init/dovecot.conf'):
            unittester.assertEquals( subprocess.call(['start', 'dovecot'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT), 0, "Failed to start dovecot")
        else:
            unittester.assertEquals( subprocess.call(['/etc/init.d/dovecot', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT), 0, "Failed to start dovecot")

        # Check if daemons are running
        self._check_daemons(unittester)

    def _check_daemons(self, unittester):
        # make sure daemon is running
        for count in range(0,10):
            if not self._check_pid():
                time.sleep(0.5)
        unittester.assertTrue (self._check_pid(), "No dovecot PID file found")

        # auth daemon takes a while to start up sometimes
        found = False
        for count in range(0,20):
            for socket in self.auth_sockets:
                if os.path.exists(socket):
                    found = True
                else:
                    found = False
                    time.sleep(0.5)
            if found == True:
                break
        unittester.assertTrue(found, 'Not dovecot sockets found (tried "' + '", "'.join(self.auth_sockets)+'")')

    def __del__(self):
        # Stop the daemon
        if os.path.exists('/etc/init/dovecot.conf'):
            subprocess.call(['stop', 'dovecot'], stdout=subprocess.PIPE)
        else:
            subprocess.call(['/etc/init.d/dovecot', 'stop'], stdout=subprocess.PIPE)

        # wait for daemon to stop
        for count in range(0,10):
            if self._check_pid():
                time.sleep(0.5)

        # For some reason, this gets left over sometimes
        for socket in self.auth_sockets:
            if os.path.exists(socket):
                os.unlink(socket)

        # restore original configuration
        os.rename('/etc/dovecot/dovecot.conf.autotest', '/etc/dovecot/dovecot.conf')
        if os.path.exists('/etc/dovecot/dovecot-postfix.conf.autotest'):
            os.rename('/etc/dovecot/dovecot-postfix.conf.autotest', '/etc/dovecot/dovecot-postfix.conf')

        if self.created_inetdconf:
            os.unlink('/etc/inetd.conf')
        if os.path.exists(self.mailbox):
            os.unlink(self.mailbox)

    def reload_conf(self, unittester):
        # reload the daemon
        if os.path.exists('/etc/init/dovecot.conf'):
            subprocess.call(['reload', 'dovecot'], stdout=subprocess.PIPE)
        else:
            subprocess.call(['/etc/init.d/dovecot', 'reload'], stdout=subprocess.PIPE)

        # Check if daemons are running
        self._check_daemons(unittester)

    def get_cert(self):
        # Known?
        if self.cert_pub:
            return self.cert_pub
        # Guess
        pem = '/etc/ssl/certs/dovecot.pem'
        if not os.path.exists(pem):
            pem = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
        return pem

    def get_ssl_fingerprint(self):
        pem = self.get_cert()

        sp = subprocess.Popen(['openssl','x509','-in',pem,'-noout','-md5','-fingerprint'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        return sp.communicate(None)[0].split('=',1)[1].strip()
