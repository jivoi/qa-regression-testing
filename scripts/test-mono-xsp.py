#!/usr/bin/python
#
#    mono-xsp.py quality assurance test script
#    Copyright (C) 2008,2009,2012 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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

'''
    How to run against a clean schroot named 'hardy' or 'intrepid':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release asp.net2-examples mono-xsp2 && ./test-mono-xsp.py -v'

    How to run against a clean schroot named 'jaunty' or newer:
        schroot -c jaunty -u root -- sh -c 'apt-get -y install lsb-release asp.net2-examples mono-xsp2 mono-devel && ./test-mono-xsp.py -v'
'''

# QRT-Packages: asp.net-examples mono-xsp2
# QRT-Alternates: mono-devel
# QRT-Alternates: asp.net2-examples
# QRT-Privilege: root

import unittest, os, urllib, time, socket
import testlib

class MonoXSPTest(testlib.TestlibCase):
    '''Test Mono XSP functionality.'''

    def setUp(self):
        '''Setup mechanisms'''

        # Try to figure out (or guess) what port the XSP2 server is on
        self.port = 8082
        try:
                for line in file('/etc/default/mono-xsp2').read().splitlines():
                        if line.find('port=')>=0:
                                self.port = line.split('=',2)[1]
        except IOError:
                # Ignore failures
                return

        if os.path.exists("/usr/share/asp.net2-demos/"):
            self.test_page = "/usr/share/asp.net2-demos/test.aspx"
        else:
            self.test_page = "/usr/share/asp.net-demos/test.aspx"
        self.test_url = "/samples/test.aspx"

        self.daemon = testlib.TestDaemon("/etc/init.d/mono-xsp2")
        self.xsp2_pid = "/var/run/mono-xsp2.pid"
        self.daemon.start()


#    def tearDown(self):

    def _geturl(self,url):
        return urllib.urlopen('http://localhost:'+self.port+url).read()

    def _test_raw(self, request="", content="", host="localhost", invert = False, limit=1024):
        '''Test the given url with a raw socket to include headers'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(self.port)))
        s.send(request)
        data = s.recv(limit)
        s.close()

        if content != "":
            if invert:
                warning = 'Found "%s"\n' % content
                self.assertTrue(content not in data, warning + data)
            else:
                warning = 'Could not find "%s"\n' % content
                self.assertTrue(content in data, warning + data)

    def test_aa_start_daemon(self):
        '''Start up the daemon'''

        self.daemon.stop()
        time.sleep(1)
        rc, result = self.daemon.start()
        self.assertTrue(rc, result)
        self.assertTrue(testlib.check_pidfile('mono', self.xsp2_pid), 'mono-xsp2 is not running')


    def test_example_okay(self):
        '''Test example server availability'''

        source = self._geturl('/samples/')
        self.assertTrue(source.find('<title>Welcome to Mono XSP')>=0)

    def test_example_missing(self):
        '''Test bad example server URL'''

        source = self._geturl('/samples/does-not-exist')
        self.assertTrue(source.find('<title>Error 404</title>')>=0)

    def test_simple_page(self):
        '''Test simple page availability'''

        source = self._geturl('/samples/2.0/masterpages/simple.aspx')
        self.assertTrue(source.find('Simple Master Page')>=0)

    def test_simple_page_source(self):
        '''Test simple page source not shown (CVE-2006-6104)'''

        source = self._geturl('/samples/2.0/masterpages/simple.aspx%20')
        self.assertTrue(source.find('<%@ Page Language="C#" MasterPageFile="simple.master" %>')<0)
        self.assertTrue(source.find('<title>Error 404</title>')>=0)

    def test_cve_2008_3906(self):
        '''Test CVE-2008-3906 vulnerability'''

        testlib.create_fill(self.test_page, '''
<script runat="server">
void Page_Load(object o, EventArgs e) {
    // Query parameter text is not checked before saving in user cookie
    NameValueCollection request = Request.QueryString;

    // Adding cookies to the response
    Response.Cookies["userName"].Value = request["text"]; 
}
</script>
''')

        request = "GET " + self.test_url + \
                  "?text=esiu%0D%0ASet-Cookie%3A%20HackedCookie=Hacked" + \
                  " HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        if self.lsb_release['Release'] < 11.10:
            self._test_raw(request, 'esiu%0d%0aSet-Cookie')
        else:
            self._test_raw(request, 'Set-Cookie: %0d%0a')

    def test_cve_2008_3422(self):
        '''Test CVE-2008-3422 vulnerability'''

        source = self._geturl('/samples/1.1/html/htmlinputtext.aspx?&quot;onmouseover=&quot;window.alert%28%27xss%27%29;&quot;')
        self.assertTrue(source.find('htmlinputtext.aspx?&amp;quot;onmouseover=&amp;quot')>=0)
        self.assertTrue(source.find('htmlinputtext.aspx?&quot;onmouseover=&quot')<0)

    def test_zz_stop_daemon(self):
        '''Stop the daemon'''

        self.daemon.stop()

if __name__ == '__main__':
    unittest.main()
