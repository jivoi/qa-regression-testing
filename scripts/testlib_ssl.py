#!/usr/bin/python
#
#    testlib_ssl.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
  gen_ssl() will generate a CA certificate, server certificate and key and
  client certificate and key. Eg:

    (dir, srv_crt, srv_key, clnt_crt, clnt_key, ca_crt) = testlib_ssl.gen_ssl()

  gen_pem() is a wrapper for gen_ssl(), and will create a combined key/crt
  pem file. It is the equivalent of 'cat srv_key srv_key > srv.pem'. Eg:
    (dir, srv_pem) = testlib_ssl.gen_pem()

  For both functions, 'dir' is a temproary directory and the caller is
  responsible for cleaning it up.
'''

import subprocess, os
from tempfile import mkdtemp

def sslcmd(command, stdin=None, stdout=subprocess.PIPE, stderr=None):
    '''Try to execute command'''
    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr)
    except OSError, e:
        return [127, str(e)]
    out = sp.communicate()[0]
    return [sp.returncode,out]

def gen_ssl(type="rsa", server_hostname="server", client_hostname="client"):
    '''Generate ssl certificates for server and client'''
    tmpdir = mkdtemp()
    cakey_pem = os.path.join(tmpdir, "cakey.pem")
    cacert_pem = os.path.join(tmpdir, "cacert.pem")
    srvkey_pem = os.path.join(tmpdir, "srvkey.pem")
    srvcert_pem = os.path.join(tmpdir, "srvcert.pem")
    srvreq_pem = os.path.join(tmpdir, "srvreq.pem")
    clientkey_pem = os.path.join(tmpdir, "clientkey.pem")
    clientcert_pem = os.path.join(tmpdir, "clientcert.pem")
    clientreq_pem = os.path.join(tmpdir, "clientreq.pem")
    dsaparam_pem = os.path.join(tmpdir, "dsaparam.pem")

    # see http://dev.mysql.com/doc/refman/5.0/en/secure-create-certs.html
    # and http://bugs.mysql.com/bug.php?id=21287

    # generate the CA
    (rc, out) = sslcmd(['openssl', 'genrsa', '-out', cakey_pem, '2048'], None, subprocess.PIPE, subprocess.PIPE)
    assert rc == 0, out

    # generate the CA cert
    (rc, out) = sslcmd(['openssl', 'req', '-new', '-x509', '-extensions', 'v3_ca', '-nodes', '-sha1', '-days', '1000', '-key', cakey_pem, '-subj', '/C=US/ST=Arizona/O=Testlib/OU=Test/CN=CA', '-out', cacert_pem ], None, subprocess.PIPE, subprocess.PIPE)
    assert rc == 0, out

    new_key_type = 'rsa:1024'
    if type == "dsa":
        (rc, out) = sslcmd(['openssl', 'dsaparam', '-out', dsaparam_pem, '1024'], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out
        new_key_type = 'dsa:' + dsaparam_pem

    for i in [ 'server', 'client' ]:
        key = srvkey_pem
        req = srvreq_pem
        crt = srvcert_pem
        hostname = server_hostname
        if i == "client":
            key = clientkey_pem
            req = clientreq_pem
            crt = clientcert_pem
            hostname = client_hostname
        (rc, out) = sslcmd(['openssl', 'req', '-newkey', new_key_type, '-sha1', '-days', '1000', '-nodes', '-keyout', key, '-out', req, '-subj', '/C=US/ST=Arizona/O=Testlib/OU=Test/CN=' + hostname], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out

        (rc, out) = sslcmd(['openssl', 'x509', '-req', '-in', req, '-days', '1000', '-sha1', '-CA', cacert_pem, '-CAkey', cakey_pem, '-set_serial', '01', '-out', crt], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out

        (rc, out) = sslcmd(["openssl", "verify", "-CAfile", cacert_pem, "-purpose", "ssl" + i, crt], None, subprocess.PIPE, subprocess.PIPE)
        assert rc == 0, out

    return tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem

def gen_pem(server_hostname="server", client_hostname="client"):
    '''Creates a single pem file by generating ssl certs and combining the
       key and cert files.
    '''
    (tmpdir, scert, skey, ccert, ckey, capem) = gen_ssl(server_hostname=server_hostname, client_hostname=client_hostname)
    pem_file = os.path.join(tmpdir, "server_combined.pem")
    contents = file(skey).read() + file(scert).read()
    open(pem_file, 'w').write(contents)

    return tmpdir, pem_file

