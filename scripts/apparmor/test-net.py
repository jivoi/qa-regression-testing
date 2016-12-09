#!/usr/bin/python
#
#    test-net.py quality assurance test script for apparmor
#    Copyright (C) 2011 Canonical Ltd.
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

# Return values:
# 0 - test success
# 1 - test failed
# 2 - wrong args
# 3 - other error

import optparse
import socket
import sys

def create_socket(af, socktype, proto):
    rc = 0

    p = 0
    if proto != None:
        p = socket.getprotobyname(proto)

    try:
        s = socket.socket(af, socktype, p)
        s.close()
    except:
        rc = 1
        raise

    return rc

def test_proto(proto, v6=False):
    rc = 0

    af = socket.AF_INET
    if v6:
        af = socket.AF_INET6

    if proto == "icmp":
        rc = create_socket(af, socket.SOCK_RAW, proto)
    elif proto == "tcp":
        rc = create_socket(af, socket.SOCK_STREAM, proto)
    elif proto == "udp":
        rc = create_socket(af, socket.SOCK_DGRAM, proto)
    else:
        print >> sys.stderr, "Bad protocol '%s'" % (proto)
        rc = 2

    return rc


def test_domain(domain):
    rc = 1
    if domain == "inet":
        rc = test_proto("tcp")
        rc += test_proto("udp")
        rc += test_proto("icmp")
        if rc != 0:
            rc = 1
    elif domain == "inet6":
        rc = test_proto("tcp", v6=True)
        rc += test_proto("udp", v6=True)
        rc += test_proto("icmp", v6=True)
        if rc != 0:
            rc = 1
    elif domain == "ax25":
        # modprobe ax25
        rc = create_socket(socket.AF_AX25, socket.SOCK_DGRAM, None)
    elif domain == "x25":
        # modprobe x25
        rc = create_socket(socket.AF_X25, socket.SOCK_SEQPACKET, None)
    elif domain == "ipx":
        # modprobe ipx
        rc = create_socket(socket.AF_IPX, socket.SOCK_DGRAM, None)
    elif domain == "appletalk":
        # modprobe appletalk
        rc = create_socket(socket.AF_APPLETALK, socket.SOCK_DGRAM, None)
    elif domain == "netrom":
        # modprobe netrom
        rc = create_socket(socket.AF_NETROM, socket.SOCK_SEQPACKET, None)
    elif domain == "bridge":
        print >> sys.stderr, "'%s' not available in python" % (domain)
        rc = 3
        # modprobe bridge
        #rc = create_socket(socket.AF_BRIDGE, socket.SOCK_RAW, None)
    elif domain == "netbeui":
        print >> sys.stderr, "'%s' not available in python" % (domain)
        rc = 3
        # modprobe netbeui??
        #rc = create_socket(socket.AF_NETBEUI, socket.SOCK_DGRAM, None)
    elif domain == "atmpvc":
        rc = create_socket(socket.AF_ATMPVC, socket.SOCK_DGRAM, None)
    elif domain == "atmsvc":
        rc = create_socket(socket.AF_ATMSVC, socket.SOCK_DGRAM, None)
    elif domain == "rose":
        # modprobe rose
        rc = create_socket(socket.AF_ROSE, socket.SOCK_SEQPACKET, None)
    elif domain == "packet":
        rc = create_socket(socket.AF_PACKET, socket.SOCK_RAW, None)
    elif domain == "ash":
        print >> sys.stderr, "'%s' not available in python" % (domain)
        rc = 3
        # modprobe ash??
        #rc = create_socket(socket.AF_ASH, socket.SOCK_???, None)
    elif domain == "econet":
        # modprobe econet
        rc = create_socket(socket.AF_ECONET, socket.SOCK_DGRAM, None)
    elif domain == "sna":
        print >> sys.stderr, "'%s' not available in python" % (domain)
        rc = 3
        # modprobe sna??
        #rc = create_socket(socket.AF_SNA, socket.SOCK_???, None)
    elif domain == "irda":
        rc = create_socket(socket.AF_IRDA, socket.SOCK_DGRAM, None)
    elif domain == "pppox":
        rc = create_socket(socket.AF_PPPOX, socket.SOCK_DGRAM, None)
    elif domain == "wanpipe":
        print >> sys.stderr, "'%s' not available in python" % (domain)
        rc = 3
        # modprobe wanpipe??
        #rc = create_socket(socket.AF_WANPIPE, socket.SOCK_RAW, None)
    elif domain == "bluetooth":
        # NOTE: linux-grouper needs to have brcm-patchram-plus-nexus7 installed
        # to initialize, otherwise this fails:
        #  socket.socket(socket.AF_BLUETOOTH, socket.SOCK_DGRAM, 0)
        rc = create_socket(socket.AF_BLUETOOTH, socket.SOCK_DGRAM, None)
    else:
        print >> sys.stderr, "Bad domain '%s'" % (domain)
        rc = 2

    return rc


def test_type(nettype):
    rc = 1
    if nettype == "stream":
        rc = test_proto("tcp")
    elif nettype == "dgram":
        rc = test_proto("udp")
    elif nettype == "raw":
        rc = test_proto("icmp")
    elif nettype == "seqpacket":
        # may need 'modprobe tipc'
        rc = create_socket(socket.AF_TIPC, socket.SOCK_SEQPACKET, None)
    elif nettype == "rdm":
        # may need 'modprobe tipc'
        rc = create_socket(socket.AF_TIPC, socket.SOCK_RDM, None)
    elif nettype == 'packet':
        rc = create_socket(socket.AF_PACKET, socket.SOCK_RAW, None)
    else:
        print >> sys.stderr, "Bad protocol '%s'" % (nettype)
        rc = 2

    return rc


rc = 2
parser = optparse.OptionParser()
parser.add_option("-p", "--proto", dest="proto", help="protocol", metavar="PROTOCOL")
parser.add_option("-d", "--domain", dest="domain", help="domain", metavar="DOMAIN")
parser.add_option("-t", "--type", dest="nettype", help="type", metavar="TYPE")
(opt, args) = parser.parse_args()

if opt.proto:
    rc = test_proto(opt.proto)
elif opt.domain:
    rc = test_domain(opt.domain)
elif opt.nettype:
    rc = test_type(opt.nettype)
else:
    print >> sys.stderr, "Must specify protocol, domain or type"

if rc == 2:
    print ""
    parser.print_help()


sys.exit(rc)
