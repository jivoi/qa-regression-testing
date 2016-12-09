#!/usr/bin/python
#
#    testlib_http-test-server.py quality assurance test script
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# NOTE: This is certainly full of bugs, is not safe and should only be used
#       for testing and not production. You have been warned.

# $ testlib_http-test-server.py -h
# Usage: testlib_http-test-server.py [options]
#
# Options:
#   -h, --help            show this help message and exit
#   -d DIR, --directory=DIR
#                        directory
#   -p PORT, --port=PORT  port
#   -H HOSTNAME, --hostname=HOSTNAME
#                         hostname
#
# After starting:
# $ elinks -dump http://127.0.0.1:8000/200
# $ elinks -dump http://127.0.0.1:8000/401
# $ elinks -dump http://127.0.0.1:8000/403
# $ elinks -dump http://127.0.0.1:8000/404
# $ elinks -dump http://127.0.0.1:8000/500
# $ elinks -dump http://127.0.0.1:8000/200?auth (user: test, password: pass)
# $ elinks -dump http://127.0.0.1:8000/500?auth
# $ elinks -dump http://test:pass@127.0.0.1:8000/200?auth
# $ elinks -dump http://127.0.0.1:8000/?reset (reset password auth)
# webdav is also supported
# webdav://127.0.0.1:8000/file
# webdav://127.0.0.1:8000/file?auth (user: test, password: pass)
# webdav://test:pass@127.0.0.1:8000/file?auth
# webdav://127.0.0.1:8000/file?reset (user: test, password: pass)

import BaseHTTPServer
import time
import optparse
import os
import re
import xml.etree.ElementTree
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import ElementTree
from xml.etree.ElementTree import QName
from xml.etree.ElementTree import SubElement


server_auth = "Basic dGVzdDpwYXNz" # test:pass
myauth = server_auth

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    def send401(s):
        s.send_response(401)
        s.send_header('WWW-Authenticate', 'Basic realm=\"testlib\"')
        s.end_headers()

    def checkAuth(s):
        global myauth
        global server_auth

        if not s.path.endswith("?auth") and not s.path.endswith("?reset"):
            return True

        auth = s.headers.get('Authorization')
        print "DEBUG: authorization = %s" % auth

        if auth != myauth:
            s.send401()
            if myauth == "reset":
                myauth = server_auth
            return False
        return True

    def do_PROPFIND(self):
        """Respond to a PROPFIND request."""
        print 'PROPFIND ' + self.path
        abs_path = re.sub("\\?auth", "", os.path.join(os.getcwd(), self.path[1:]))
        rc = self.get_rc(abs_path)
        #for key in self.headers.keys():
        #    print key + '\t' + self.headers[key]
        req = self.parseinputxml()
        req = ElementTree(req)
        res = ElementTree(Element(QName("DAV:", 'multistatus')))
        if rc == 200:
            self.addresponse('/', res.getroot(), 0)
        self.writeresponse(res, rc)

    def do_OPTIONS(self):
        #self.parseinputxml()
        #req = self.parseinputxml()
        #print req
        self.send_response(200)
        self.send_header("DAV", "1");
        self.end_headers()
        self.wfile.close()

    def parseinputxml(self):
        try:
            contentlength = int(self.headers['content-length'])
        except:
            return None
        data = self.rfile.read(contentlength)
        #print data
        return xml.etree.ElementTree.fromstring(data)

    def writeresponse(self, response, rc=200):
        self.send_response(rc)
        self.send_header("Content-Type", 'text/xml; charset="utf-8"')
        self.end_headers()
        if rc == 200:
            response.write(self.wfile, 'utf-8')
        #d = xml.etree.ElementTree.tostring(response.getroot(), 'utf-8')
        #print d
        self.wfile.close()

    def addresponse(self, path, root, depth):
        e = SubElement(root, QName("DAV:", 'response'))
        href = SubElement(e, QName("DAV:", 'href'))
        href.text = path
        propstat = SubElement(e, QName("DAV:", 'propstat'))
        prop = SubElement(propstat, QName("DAV:", 'resourcetype'))
        if os.path.isdir(path):
            SubElement(prop, QName("DAV:", 'collection'))

    def get_rc(s, abs_path):
        rc = 200
        topdir = os.getcwd()
        if not abs_path.startswith(topdir):
            rc = 403
        elif s.path == "/200":
            rc = 200
        elif s.path == "/401":
            rc = 401
        elif s.path == "/403":
            rc = 403
        elif s.path == "/500":
            rc = 500
        elif s.path == "/404" or not os.path.exists(abs_path):
            # This should be last after all the above special URLs
            rc = 404

        return rc

    def do_GET(s):
        """Respond to a GET request."""
        global myauth
        topdir = os.getcwd()
        abs_path = os.path.join(topdir, s.path[1:])
        rc = 200
        title = "testlib server"
        err_msg = "<html><head><title>%s - Error</title></head>\n" % title
        err_msg += "<body><p>Error: "

        auth = ""

        if s.path.endswith("?reset") and myauth != "reset":
            myauth = "reset"
            s.send401()
            return
        if not s.checkAuth():
            return

        # DAV
        # handle headers like Range: bytes=0-1023
        if 'Range' in s.headers:
            m = re.match('\s*bytes\s*=\s*(\d+)\s*-\s*(\d+)\s*', s.headers['Range'])
            if m:
                start = int(m.group(1))
                end = int(m.group(2))
                f = s.send_range_head(start, end)
                if f:
                    s.copyfilerange(f, s.wfile, start, end)
                    f.close()
                    return

        s.path = re.sub("\\?auth", "", s.path)
        abs_path = re.sub("\\?auth", "", abs_path)

        msg = ""
        serve_file = False
        rc = s.get_rc(abs_path)

        if rc == 200:
            if s.path == "/200":
                msg = '''<html><head><title>%s - %s</title></head>
<p>Success: %d</p>%s</body></html>
''' % (title, os.path.basename(abs_path), rc, auth)
            elif os.path.exists(abs_path) and os.path.isfile(abs_path):
                try:
                    msg = open(abs_path).read()
                    serve_file = True
                except:
                    rc = 500
            else:
                # may get here with '/'
                msg = '''<html><head><title>%s (default response)</title></head>
<body><p>Default page</p>
<p>You accessed relative path: %s</p>
<p>You accessed absolute path: %s</p>
%s</body></html>
''' % (title, s.path, abs_path, auth)

        if rc >= 400:
            err_msg += "%d</p></body></html>" % (rc)
            msg = err_msg

        s.send_response(rc)
        if serve_file:
            if abs_path.endswith(".html") or abs_path.endswith(".htm"):
                s.send_header("Content-type", "text/html")
            else:
                s.send_header("Content-type", "text/plain")
        else:
            s.send_header("Content-type", "text/html")

        s.end_headers()
        s.wfile.write(msg)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-d", "--directory", dest="topdir", help="directory", metavar="DIR")
    parser.add_option("-p", "--port", dest="port", help="port", metavar="PORT")
    parser.add_option("-H", "--hostname", dest="hostname", help="hostname", metavar="HOSTNAME")

    (opt, args) = parser.parse_args()

    port = 8000
    if opt.port:
        port = int(opt.port)

    hostname = ""
    if opt.hostname:
        hostname = opt.hostname

    if opt.topdir and os.path.isdir(opt.topdir):
        os.chdir(opt.topdir)

    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((hostname, port), MyHandler)
    print time.asctime(), "Server Starts - %s:%s" % (hostname, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (hostname, port)
