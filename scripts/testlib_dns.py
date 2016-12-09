#!/usr/bin/python
#
#    testlib_dns.py quality assurance test script
#    Copyright (C) 2008-2012 Canonical Ltd.
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
#    along with this program.  If not, see <httpd://www.gnu.org/licenses/>.
#

import adns
import sys
import testlib
import testlib_dns
import time

class DnsCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self, nameserver="127.0.0.1"):
        '''Setup'''
        self.daemon.stop()
        self.release = testlib.ubuntu_release()
        self.dns = adns.init(adns.iflags.noautosys,sys.stderr,'nameserver ' + nameserver)
        self.daemon.start()

    def _set_initscript(self, initscript):
        self.daemon = testlib.TestDaemon(initscript)

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self.dns = None
        self.daemon.stop()
        time.sleep(2)

    def query(self, name, type, resolved="", expected="success", ignored=False):
        '''Test the given name for type'''
        if type == 'A':
            t = adns.rr.A
        elif type == 'PTR':
            t = adns.rr.PTRraw
        elif type == 'MX':
            t = adns.rr.MX
        elif type == 'NS':
            t = adns.rr.NS
        elif type == 'SOA':
            t = adns.rr.SOA
        elif type == 'TXT':
            t = adns.rr.TXT
        elif type == 'CNAME':
            t = adns.rr.CNAME
        elif type == 'SRV':
            t = adns.rr.SRV
        elif type == 'HINFO':
            t = adns.rr.HINFO
        elif type == 'RP':
            t = adns.rr.RP
        else:
            self.assertTrue(False, "Invalid type '%s'" % (type))

        ret_code = None
        if expected == "success":
            ret_code = adns.status.ok
        elif expected == "nxdomain":
            ret_code = adns.status.nxdomain

        res = self.dns.synchronous(name, t)

        if ignored == False:
            if ret_code != None:
                self.assertTrue(res[0] == ret_code, res)
                if expected == "success" and resolved:
                    self.assertTrue(res[3][0] == resolved, res)
            else:
                self.assertFalse(res[0] == adns.status.ok, res)

    def query_dig(self, name, type, search="", expected="NOERROR", invert=False):
        '''Test the given name for type using dig'''

        (rc, report) = testlib.cmd(["/usr/bin/dig", "+dnssec", "+multiline", "-t", type, name, "@localhost"])
        expected_rc = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        status = 'status: %s' % expected
        result = "Incorrect status '%s' in report: '%s'\n" % (expected, report)
        self.assertTrue(status in report, result)

        if search:
            if invert == False:
                result = "Couldn't find '%s' in report: '%s'\n" % (search, report)
                self.assertTrue(search in report, result)
            else:
                result = "Found '%s' in report: '%s'\n" % (search, report)
                self.assertFalse(search in report, result)

    def _test_external_lookups(self):
        '''Test external lookups via the server'''
        self.query('www.ubuntu.com', 'A')
        self.query('bogus.ubuntu.com', 'A', "", "fail")

        # This will fail if the IP address changes...
        self.query('avocado.canonical.com', 'A', '91.189.90.40')

        # First query sometimes fails for some reason
        self.query('40.90.189.91.in-addr.arpa', 'PTR', ignored = True)
        self.query('40.90.189.91.in-addr.arpa', 'PTR')

        self.query('ubuntu.com', 'MX')
        self.query('ubuntu.com', 'NS')
        self.query('ubuntu.com', 'SOA')
        self.query('google.com', 'TXT')
        self.query('mail.google.com', 'CNAME')


