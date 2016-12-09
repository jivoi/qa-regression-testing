#!/usr/bin/python
#
#    test-libnet-dns-perl.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd
#    Author: Kees Cook <kees@canonical.com>
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
    How to run against a clean schroot named 'gutsy':
        schroot -c gutsy -u root -- sh -c 'apt-get -y install libnet-dns-perl bind9-host netbase && ./test-libnet-dns-perl.py -v'

    This system expects a functional resolver.
'''
# QRT-Packages: libnet-dns-perl bind9-host netbase

import unittest, subprocess
import testlib

class LibNetDnsPerlTest(unittest.TestCase):
    '''Test Net::DNS Perl module.'''

    def setUp(self):
        '''Setup'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _compare_A(self,name,rrtype='A',min_count=1):
        rc, out = testlib.cmd(['host','-t',rrtype.lower(),name])
        self.assertEqual(rc,0,out)
        hostaddrs = sorted([x.split(' ').pop() for x in out.split('\n') if 'has address' in x])

        self.assertTrue(len(hostaddrs)>=min_count,"result should have %d items: %s"%(min_count,out))

        rc, out = testlib.cmd(['perl','-e','''
use strict;
use warnings;
use Net::DNS;
my $res   = Net::DNS::Resolver->new;
my $query = $res->search("%s");

if ($query) {
    foreach my $rr ($query->answer) {
        next unless $rr->type eq "%s";
        print $rr->address, "\n";
    }
} else {
    die "query failed: ", $res->errorstring, "\n";
}
'''%(name,rrtype.upper())])
        self.assertEqual(rc,0,out)
        perladdrs = sorted(out.splitlines())

        self.assertEqual(hostaddrs,perladdrs)

    def _compare_MX(self,name,rrtype='MX',min_count=1):
        rc, out = testlib.cmd(['host','-t',rrtype.lower(),name])
        self.assertEqual(rc,0,out)
        hostaddrs = sorted([" ".join(x.split(' ')[-2:]) for x in out.split('\n') if 'is handled by' in x])

        self.assertTrue(len(hostaddrs)>=min_count,"result should have %d items: %s"%(min_count,out))

        rc, out = testlib.cmd(['perl','-e','''
use strict;
use warnings;
use Net::DNS;
my $res   = Net::DNS::Resolver->new;
my @mx    = mx($res, "%s");

if (@mx) {
    foreach my $rr (@mx) {
        print $rr->preference, " ", $rr->exchange, "\n";
    }
} else {
    die "MX failed: ", $res->errorstring, "\n";
}
'''%(name)])
        self.assertEqual(rc,0,out)
        perladdrs = sorted(out.splitlines())

    def test_compare_cnn(self):
        '''Test looking up CNN'''
        self._compare_A('www.cnn.com',min_count=4)
        self._compare_MX('cnn.com',min_count=2)

    def test_compare_yahoo(self):
        '''Test looking up Yahoo'''
        self._compare_A('www.yahoo.com',min_count=1)
        self._compare_MX('yahoo.com',min_count=1)

    def test_compare_ubuntu(self):
        '''Test looking up Ubuntu'''
        self._compare_A('www.ubuntu.com',min_count=1)
        self._compare_MX('ubuntu.com',min_count=1)

    def test_small_sized_reply(self):
        '''Test for CVE-2007-6341 fix'''
        badserver = subprocess.Popen(['perl','-e',r'''
# Beyond Security(c)
# Vulnerability found by beSTORM - DNS Server module

use strict;
use IO::Socket;
my($sock, $oldmsg, $newmsg, $hisaddr, $hishost, $MAXLEN, $PORTNO);
$MAXLEN = 1024;
$PORTNO = 5351;
$sock = IO::Socket::INET->new(LocalPort => $PORTNO, Proto => 'udp') or die "socket: $@";

my $oldmsg = "\x5a\x40\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\x07\x63\x72\x61".
"\x63\x6b\x6d\x65\x0a\x6d\x61\x73\x74\x65\x72\x63\x61\x72\x64\x03".
"\x63\x6f\x6d\x00\x00\x01\x00\x01\x03\x77\x77\x77\x0e\x62\x65\x79".
"\x6f\x6e\x64\x73\x65\x63\x75\x72\x69\x74\x79\x03\x63\x6f\x6d\x00".
"\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\xc0\xa8\x01\x02\x0e\x62".
"\x65\x79\x6f\x6e\x64\x73\x65\x63\x75\x72\x69\x74\x79\x03\x63\x6f".
"\x6d\x00\x00\x02\x00\x01\x00\x00\x00\x01\x00\x1b\x02\x6e\x73\x03".
"\x77\x77\x77\x0e\x62\x65\x79\x6f\x6e\x64\x73\x65\x63\x75\x72\x69".
"\x74\x79\x03\x63\x6f\x6d\x00\x02\x6e\x73\x0e\x62\x65\x79\x6f\x6e".
"\x64\x73\x65\x63\x75\x72\x69\x74\x79\x03\x63\x6f\x6d\x00\x00\x01".
"\x00\x01\x00\x00\x00\x01\x00\x01\x41";
$sock->recv($newmsg, $MAXLEN);
my($port, $ipaddr) = sockaddr_in($sock->peername);
$hishost = gethostbyaddr($ipaddr, AF_INET);
$sock->send($oldmsg);
print "Sent reply to $hishost\n";
'''],stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        rc, out = testlib.cmd(['perl','-e','''
use strict;
use warnings;
use Net::DNS;
my $res   = Net::DNS::Resolver->new;
$res->nameservers('127.0.0.1');
$res->port(5351);
$res->udp_timeout(2);
my $query = $res->search("%s");

if ($query) {
    foreach my $rr ($query->answer) {
        next unless $rr->type eq "%s";
        print $rr->address, "\n";
    }
} else {
    die "query failed: ", $res->errorstring, "\n";
}
'''])
        self.assertNotEqual(rc,0,out);
        self.assertTrue('timed out' in out, out);

        out, err = badserver.communicate()
        self.assertTrue("Sent reply to " in out, out)


if __name__ == '__main__':
    unittest.main()
	
