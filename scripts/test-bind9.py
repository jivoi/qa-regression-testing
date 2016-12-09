#!/usr/bin/python
#
#    test-bind9.py quality assurance test script
#    Copyright (C) 2008-2015 Canonical Ltd.
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
# QRT-Packages: python-adns bind9 dnsutils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_dns.py
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release python-adns bind9 dnsutils apparmor-utils && ./test-bind9.py -v'

    TODO:
        - views (requires totally new config, not a default-bolt-on
        - recursion (requires functional external network)
        - serial updates & notifications
        - more DNSSEC (DLV, invalid signature, etc.)
'''

import unittest, subprocess, os, sys, shutil, re
import adns
import testlib_dns
import testlib

class Bind9Test(testlib_dns.DnsCommon):
    '''Test bind9 DNS server functionality.'''

    def setUp(self):
        '''Setup mechanisms'''

        self.options_file = "/etc/bind/named.conf.options"
        if self.lsb_release['Release'] < 6.10:
            options = '''
options {
        directory "/var/cache/bind";
        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { any; };
};
'''
            testlib.config_replace(self.options_file, options)

        # configure and restart bind9
        cfgfile = open('/etc/bind/db.autotest-zone.private', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     private. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       172.20.0.1

mongoose    IN  A       172.20.0.10
serenity    IN  A       172.20.0.20
moya        IN  A       172.20.0.30

$GENERATE 100-200 guest-$   A  172.20.0.$
''')
        cfgfile.close()

        cfgfile = open('/var/cache/bind/db.autotest-zone.nsupdate', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     nsupdate. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       172.30.0.1

foo     IN  A       172.30.0.10
bar     IN  A       172.30.0.20

$GENERATE 100-200 guest-$   A  172.30.0.$
''')
        cfgfile.close()

        cfgfile = open('/etc/bind/db.autotest-zone.public', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     public. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       172.20.0.1

www    IN  A       172.20.0.10
smtp    IN  A       172.20.0.20
imap        IN  A       172.20.0.30

$GENERATE 100-200 vpn-$   A  172.20.0.$
''')
        cfgfile.close()

        cfgfile = open('/etc/bind/db.autotest-zone.172.20.0', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.

; example network
0       IN      PTR     network.private.
10      IN      PTR     mongoose.private.
20      IN      PTR     serenity.private.
30      IN      PTR     moya.private.
$GENERATE 100-200 $ PTR guest-$.private.
255     IN      PTR     broadcast.private.
''')
        cfgfile.close()

        cfgfile = open('/var/cache/bind/db.autotest-zone.172.30.0', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.

; example network
0       IN      PTR     network.nsupdate.
10      IN      PTR     foo.nsupdate.
20      IN      PTR     bar.nsupdate.
$GENERATE 100-200 $ PTR guest-$.nsupdate.
255     IN      PTR     broadcast.nsupdate.
''')
        cfgfile.close()

        cfgfile = open('/etc/bind/db.autotest-zone.10.20.0', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.

; example network
0       IN      PTR     network.public.
10      IN      PTR     www.public.
20      IN      PTR     smtp.public.
30      IN      PTR     imap.public.
$GENERATE 100-200 $ PTR vpn-$.public.
255     IN      PTR     broadcast.public.
''')

        cfgfile.close()
        cfgfile = open('/etc/bind/autotest-conf.public', 'w')
        cfgfile.write('''
''')
        cfgfile.close()

        olddir = os.getcwd()
        os.chdir("/etc/bind")
        assert subprocess.call(['dnssec-keygen', '-r', '/dev/urandom', '-a', 'hmac-md5', '-b', '128', '-n', 'USER', 'dnsupdate'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        os.chdir(olddir)

        self.nsupdatekey = ""
        for name in os.listdir("/etc/bind"):
            if re.match(r'Kdnsupdate.*.key', name):
                keyfile = open(os.path.join("/etc/bind", name))
                for line in keyfile:
                    self.nsupdatekey = line.split()[6]
                    break
                keyfile.close()
                break

        cfgfile = open('/etc/bind/autotest-conf.private', 'w')
        cfgfile.write('''
zone "private" IN {
    type master;
    file "/etc/bind/db.autotest-zone.private";
    allow-transfer { 127.0.0.1; };
};

zone "0.20.172.in-addr.arpa" IN {
    type master;
    file "/etc/bind/db.autotest-zone.172.20.0";
    allow-transfer { 127.0.0.1; };
};
''')
        cfgfile.close()

        self.nsupdatefile = '/etc/bind/autotest.nsupdate'
        cfgfile = open(self.nsupdatefile, 'w')
        cfgfile.write('''server 127.0.0.1
key dnsupdate ''' + self.nsupdatekey + '''
zone 0.30.172.in-addr.arpa
update delete 50.0.30.172.in-addr.arpa
send
zone nsupdate
update delete dyndns.nsupdate.
send
zone 0.30.172.in-addr.arpa
update add 50.0.30.172.in-addr.arpa 600 IN PTR dyndns.nsupdate.
send
zone nsupdate
update add dyndns.nsupdate. 600 IN A 172.30.0.50
send
quit
''')
        cfgfile.close()

        cfgfile = open('/etc/bind/autotest-conf.nsupdate', 'w')
        cfgfile.write('''
key dnsupdate {
  algorithm hmac-md5;
  secret "''' + self.nsupdatekey + '''";
};
zone "nsupdate" IN {
    type master;
    file "/var/cache/bind/db.autotest-zone.nsupdate";
    allow-transfer { 127.0.0.1; };
    allow-update { key dnsupdate; };
};

zone "0.30.172.in-addr.arpa" IN {
    type master;
    file "/var/cache/bind/db.autotest-zone.172.30.0";
    allow-transfer { 127.0.0.1; };
    allow-update { key dnsupdate; };
};
''')
        cfgfile.close()

        if not os.path.exists('/etc/bind/named.conf.local.autotest'):
            shutil.copyfile('/etc/bind/named.conf.local', '/etc/bind/named.conf.local.autotest')
        cfgfile = open('/etc/bind/named.conf.local', 'w')
        cfgfile.write('''
/*
view "local" {
    match-clients { localhost; };
*/

    include "/etc/bind/autotest-conf.public";
    include "/etc/bind/autotest-conf.private";
    include "/etc/bind/autotest-conf.nsupdate";
/*
};

view "public" {
    match-clients { any; };

    // notify our secondaries of any zone changes
    notify yes;
    allow-transfer { localhost; };

    include "/etc/bind/autotest-conf.public";
};
*/
''')
        cfgfile.close()

        self._set_initscript("/etc/init.d/bind9")
        self.daemon.stop()
        self.daemon.start()

        self.dns = adns.init(adns.iflags.noautosys,sys.stderr,'nameserver 127.0.0.1')

    def tearDown(self):
        '''Shutdown methods'''
        testlib_dns.DnsCommon._tearDown(self)

        os.rename('/etc/bind/named.conf.local.autotest', '/etc/bind/named.conf.local')
        os.unlink('/etc/bind/db.autotest-zone.private')
        os.unlink('/etc/bind/db.autotest-zone.172.20.0')
        os.unlink('/etc/bind/db.autotest-zone.public')
        os.unlink('/etc/bind/db.autotest-zone.10.20.0')
        os.unlink('/var/cache/bind/db.autotest-zone.nsupdate')
        os.unlink('/var/cache/bind/db.autotest-zone.172.30.0')
        os.unlink('/etc/bind/autotest-conf.public')
        os.unlink('/etc/bind/autotest-conf.private')
        os.unlink('/etc/bind/autotest-conf.nsupdate')

        for name in os.listdir("/etc/bind"):
            if re.match(r'Kdnsupdate.*.key', name):
                os.unlink(os.path.join("/etc/bind", name))
            if re.match(r'Kdnsupdate.*.private', name):
                os.unlink(os.path.join("/etc/bind", name))
        for name in os.listdir("/var/cache/bind"):
            if re.match(r'db.autotest-zone.*.jnl', name):
                os.unlink(os.path.join("/var/cache/bind", name))
        os.unlink(self.nsupdatefile)

        testlib.config_restore(self.options_file)

    def test_record_A(self):
        '''Test lookups on A records'''
        self.query('localhost.', 'A', '127.0.0.1')
        self.query('invalid.localhost.', 'A', '', 'nxdomain')
        self.query('mongoose.private.', 'A', '172.20.0.10')
        self.query('serenity.private.', 'A', '172.20.0.20')
        self.query('moya.private.', 'A', '172.20.0.30')
        self.query('impavid.private.', 'A', '', 'nxdomain')
        self.query('guest-142.private.', 'A', '172.20.0.142')
        self.query('guest-42.private.', 'A', '', 'nxdomain')

    def test_record_PTR(self):
        '''Test lookups on PTR records'''
        self.query('1.0.0.127.in-addr.arpa.', 'PTR', 'localhost')
        self.query('2.0.0.127.in-addr.arpa.', 'PTR', '', 'nxdomain')
        self.query('10.0.20.172.in-addr.arpa.', 'PTR', 'mongoose.private')
        self.query('20.0.20.172.in-addr.arpa.', 'PTR', 'serenity.private')
        self.query('30.0.20.172.in-addr.arpa.', 'PTR', 'moya.private')
        self.query('40.0.20.172.in-addr.arpa.', 'PTR', '', 'nxdomain')
        self.query('142.0.20.172.in-addr.arpa.', 'PTR', 'guest-142.private')

    def test_xternal_lookups(self):
	'''Test external lookups via the server'''

        res = self.dns.synchronous('www.twitter.com.',adns.rr.A)
        self.assertTrue(res[0] == adns.status.ok,res)

        res = self.dns.synchronous('mongoose-does-not-exist.twitter.com.',adns.rr.A)
        self.assertFalse(res[0] == adns.status.ok,res)

        self._test_external_lookups()

    def test_dynamic_updates(self):
        '''Test dynamic updates'''
        assert subprocess.call(['nsupdate', self.nsupdatefile], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0

        self.query('dyndns.nsupdate.', 'A', '172.30.0.50')
        self.query('50.0.30.172.in-addr.arpa.', 'PTR', 'dyndns.nsupdate')

    def test_daemons(self):
        '''Test daemon is running'''
        if self.lsb_release['Release'] <= 9.04:
            pidfile = "/var/run/bind/run/named.pid"
        else:
            pidfile = "/var/run/named/named.pid"
        warning = "Could not find pidfile '" + pidfile + "'"
        self.assertTrue(os.path.exists(pidfile), warning)
        self.assertTrue(testlib.check_pidfile("named", pidfile))

    def test_ipv4(self):
        '''Test ipv4 listening'''
        str = ":53 "
        rc, report = testlib.cmd(['netstat', '-tnl4'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

        rc, report = testlib.cmd(['netstat', '-unl4'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

    def test_ipv6(self):
        '''Test ipv6 listening'''
        str = ":::53 "
        rc, report = testlib.cmd(['netstat', '-tnl6'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

        rc, report = testlib.cmd(['netstat', '-unl6'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/named', 8.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class Bind9DNSSECTest(testlib_dns.DnsCommon):
    '''Test bind9 DNSSEC functionality.'''

    def setUp(self):
        '''Setup mechanisms'''

        self.options_file = "/etc/bind/named.conf.options"
        options = '''
options {
        directory "/var/cache/bind";
        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { any; };
        dnssec-enable yes;
'''
        if self.lsb_release['Release'] > 6.06:
            options += '''
        dnssec-validation yes;
'''
        options += '''
};
'''
        testlib.config_replace(self.options_file, options)

        #
        # Create the DNSSEC keys for our zone
        #

        # Clean up old leftover keys
        for name in os.listdir("/etc/bind"):
            if re.match(r'Kprivate.*.key', name):
                os.unlink(os.path.join("/etc/bind", name))
            if re.match(r'Kprivate.*.private', name):
                os.unlink(os.path.join("/etc/bind", name))

        olddir = os.getcwd()
        os.chdir("/etc/bind")
        # ZSK
        assert subprocess.call(['dnssec-keygen', '-r', '/dev/urandom', '-a', 'rsasha1', '-b', '1024', '-n', 'ZONE', 'private'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        # KSK
        assert subprocess.call(['dnssec-keygen', '-r', '/dev/urandom', '-a', 'rsasha1', '-b', '4096', '-n', 'ZONE', '-f', 'KSK', 'private'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        os.chdir(olddir)

        # Create our zone file
        cfgfile = open('/etc/bind/db.autotest-zone.private', 'w')
        contents = '''
$TTL    604800
@       IN      SOA     private. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.
@       IN      A       172.20.0.1

mongoose    IN  A       172.20.0.10
serenity    IN  A       172.20.0.20
moya        IN  A       172.20.0.30

$GENERATE 100-200 guest-$   A  172.20.0.$
'''

        # Include the key files in our zone file
        for name in os.listdir("/etc/bind"):
            if re.match(r'Kprivate.*.key', name):
                contents += '''
$INCLUDE %s
''' % name

        cfgfile.write(contents)
        cfgfile.close()

        #
        # Sign the zone file
        #
        olddir = os.getcwd()
        os.chdir("/etc/bind")
        assert subprocess.call(['dnssec-signzone', '-r', '/dev/urandom', '-o', 'private', 'db.autotest-zone.private'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0
        os.chdir(olddir)

        # Create our reverse zone file
        cfgfile = open('/etc/bind/db.autotest-zone.172.20.0', 'w')
        cfgfile.write('''
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      localhost.

; example network
0       IN      PTR     network.private.
10      IN      PTR     mongoose.private.
20      IN      PTR     serenity.private.
30      IN      PTR     moya.private.
$GENERATE 100-200 $ PTR guest-$.private.
255     IN      PTR     broadcast.private.
''')
        cfgfile.close()

        # Create our conf file (and use the signed zone file)
        if not os.path.exists('/etc/bind/named.conf.local.autotest'):
            shutil.copyfile('/etc/bind/named.conf.local', '/etc/bind/named.conf.local.autotest')
        cfgfile = open('/etc/bind/named.conf.local', 'w')
        contents = '''
zone "private" IN {
    type master;
    file "/etc/bind/db.autotest-zone.private.signed";
    allow-transfer { 127.0.0.1; };
};

zone "0.20.172.in-addr.arpa" IN {
    type master;
    file "/etc/bind/db.autotest-zone.172.20.0";
    allow-transfer { 127.0.0.1; };
};

'''

        #
        # The following configures some TLD trusted anchors
        #
        # TODO: These trusted anchors may change, so they would need to get
        # updated in this test script, or ideally, the test script should
        # download them.
        #
        # See: https://itar.iana.org/ and
        #      https://trustanchor.dotgov.gov/itaranchors.aspx
        #
        # 

        contents += '''
trusted-keys {
'''

        #
        # ZOMG! DNS root is signed now!
        # Unfortunately, it needs bind 9.6.2 or higher :(
        # http://www.isc.org/community/blog/201007/using-root-dnssec-key-bind-9-resolvers
        #

        if self.lsb_release['Release'] >= 10.04:
            contents += '''
 "." 257 3 8 "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=";
'''

        contents += '''
};
'''

        cfgfile.write(contents)
        cfgfile.close()

        self._set_initscript("/etc/init.d/bind9")
        self.daemon.stop()
        self.daemon.start()

    def tearDown(self):
        '''Shutdown methods'''
        testlib_dns.DnsCommon._tearDown(self)

        os.rename('/etc/bind/named.conf.local.autotest', '/etc/bind/named.conf.local')

        files = [ '/etc/bind/db.autotest-zone.private',
                  '/etc/bind/db.autotest-zone.private.signed',
                  '/etc/bind/db.autotest-zone.172.20.0',
                  '/etc/bind/dsset-private.',
                  '/etc/bind/keyset-private.' ]

        for f in files:
            if os.path.exists(f):
                os.unlink(f)

        for name in os.listdir("/etc/bind"):
            if re.match(r'Kprivate.*.key', name):
                os.unlink(os.path.join("/etc/bind", name))
            if re.match(r'Kprivate.*.private', name):
                os.unlink(os.path.join("/etc/bind", name))

        testlib.config_restore(self.options_file)

    def test_daemons(self):
        '''Test daemon is running'''
        if self.lsb_release['Release'] <= 9.04:
            pidfile = "/var/run/bind/run/named.pid"
        else:
            pidfile = "/var/run/named/named.pid"
        warning = "Could not find pidfile '" + pidfile + "'"
        self.assertTrue(os.path.exists(pidfile), warning)
        self.assertTrue(testlib.check_pidfile("named", pidfile))

    def test_ipv4(self):
        '''Test ipv4 listening'''

        str = ":53 "
        rc, report = testlib.cmd(['netstat', '-tnl4'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

        rc, report = testlib.cmd(['netstat', '-unl4'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

    def test_ipv6(self):
        '''Test ipv6 listening'''
        str = ":::53 "
        rc, report = testlib.cmd(['netstat', '-tnl6'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

        rc, report = testlib.cmd(['netstat', '-unl6'])
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in report, warning + report)

    def test_dnssec_gov_lookup(self):
        '''Test gov. NSEC3 DNSSEC signed lookups'''

        if self.lsb_release['Release'] < 10.04:
            return self._skipped("root key not supported (needs bind9 >= 9.6.2")

        # (ad = Authenticated Data)
        self.query_dig('gov.', 'ns', 'flags: qr rd ra ad')
        self.query_dig('gov.', 'a', 'flags: qr rd ra ad')
        self.query_dig('thisdoesntexist.gov.', 'a', 'flags: qr rd ra ad', expected='NXDOMAIN')

    def test_dnssec_cz_lookup(self):
        '''Test cz. DNSSEC signed lookups'''

        if self.lsb_release['Release'] < 10.04:
            return self._skipped("root key not supported (needs bind9 >= 9.6.2")

        self.query_dig('cz.', 'ns', 'flags: qr rd ra ad')
        self.query_dig('cz.', 'a', 'flags: qr rd ra ad')
        self.query_dig('thisdoesntexist.cz.', 'a', 'flags: qr rd ra ad', expected='NXDOMAIN')

    def test_dnssec_se_lookup(self):
        '''Test se. DNSSEC signed lookups'''

        if self.lsb_release['Release'] < 10.04:
            return self._skipped("root key not supported (needs bind9 >= 9.6.2")

        self.query_dig('se.', 'ns', 'flags: qr rd ra ad')
        self.query_dig('se.', 'a', 'flags: qr rd ra ad')
        self.query_dig('thisdoesntexist.se.', 'a', 'flags: qr rd ra ad', expected='NXDOMAIN')

    def test_dnssec_ubuntu_lookup(self):
        '''Test ubuntu.com. DNSSEC unsigned lookups'''

        # Make sure the ubuntu.com domain isn't signed (we don't have a Trust Anchor)
        self.query_dig('ubuntu.com.', 'ns', 'flags: qr rd ra ad', invert=True)
        self.query_dig('thisdoesntexist.ubuntu.com.', 'ns', 'flags: qr rd ra ad', invert=True, expected='NXDOMAIN')

    def test_dnssec_private_lookup(self):
        '''Test private. DNSSEC signed lookups'''
        #
        # An authoritative server will not set the AD flag
        # See RFC 4035 Section 3.1.6
        #
        # Also, http://blog.techscrawl.com/2009/01/13/enabling-dnssec-on-bind/
        # says "..BIND will not validate zone data for a zone for which it
        # is authoritative."
        #
        self.query_dig('private.', 'ns', 'flags: qr aa rd ra')
        self.query_dig('private.', 'a', 'flags: qr aa rd ra')
        self.query_dig('private.', 'ns', 'IN RRSIG')
        self.query_dig('thisdoesntexist.private.', 'a', 'flags: qr aa rd ra', expected='NXDOMAIN')

if __name__ == '__main__':

    # Test if dnsmasq is running
    rc, report = testlib.cmd(['ps', 'ax'])
    if '/usr/sbin/dnsmasq' in report:
        print >>sys.stderr, ("\n\nMust not be running dnsmasq! Please comment out dnsmasq integration in")
        print >>sys.stderr, ("/etc/NetworkManager/NetworkManager.conf and reboot!\n\n")
        sys.exit(1)

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Bind9Test))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Bind9DNSSECTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
