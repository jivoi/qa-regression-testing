#!/usr/bin/python
#
#    test-unix-domain-connect.py quality assurance test script for apparmor
#    Copyright (C) 2013 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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

# Return values:
# 0 - test success
# 1 - test failed
# 2 - wrong args
# 3 - other error

import optparse
import socket
import sys

def test_connect(sock_type, sock_path):
    sock = socket.socket(socket.AF_UNIX, sock_type)
    sock.settimeout(5)
    sock.connect(sock_path);
    sock.close()


sock_types=dict(stream=socket.SOCK_STREAM, dgram=socket.SOCK_DGRAM, seqpacket=socket.SOCK_SEQPACKET)
parser = optparse.OptionParser()
parser.add_option("-p", "--path", dest="sock_path", help="Path to socket", metavar="PATH")
parser.add_option("-t", "--type", dest="sock_type", help="Socket type: %s" % sock_types.keys(), metavar="TYPE")
(opt, args) = parser.parse_args()

if not opt.sock_type or opt.sock_type not in sock_types:
    parser.error("Must specify a valid socket type")
    sys.exit(2)
elif not opt.sock_path:
    parser.error("Must specify a socket path")
    sys.exit(2)

test_connect(sock_types[opt.sock_type], opt.sock_path)
sys.exit(0)
