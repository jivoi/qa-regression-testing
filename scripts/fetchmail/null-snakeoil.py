#!/usr/bin/python
# Generate a NULL-byte injected cert, using local hostname
# Copyright 2009, Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
import sys, os, tempfile, shutil, subprocess
from OpenSSL import crypto

out_pub = sys.argv[1]
out_key = sys.argv[2]

hostname=os.uname()[1]

dir=tempfile.mkdtemp(prefix='null-cert-XXXXXX')
cnf=dir + '/ssleay.cnf'
pubpem=dir + '/public.pem'
prepub = pubpem + '.pre'
keypem=dir + '/private.pem'

pubder=dir + '/public.der'
preder=pubder + '.pre'

# Dapper contains more than just @HostName@, so we must toss out those lines
cnf_fd = open(cnf,'w')
for line in file('/usr/share/ssl-cert/ssleay.cnf'):
    if '@HostName@' in line:
        line = line.replace('@HostName@','%s0.example.com' % (hostname))
    if '@' in line:
        continue
    cnf_fd.write(line)
cnf_fd.close()

# create basic cert
subprocess.call(['openssl','req','-config',cnf,'-new','-x509','-days','3650','-nodes','-out',prepub,'-keyout',keypem],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

# into raw
subprocess.call(['openssl','x509','-outform','der','-in',prepub,'-out',preder])
# inject NULL
open(pubder,'w').write(open(preder).read().replace('0.example.com','\x00.example.com'))
# back to PEM
subprocess.call(['openssl','x509','-inform','der','-in',pubder,'-out',pubpem])

# reload
cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(pubpem).read())
key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(keypem).read())
# re-sign
cert.sign(key, 'sha1')
# export
open(pubpem,'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))

shutil.move(pubpem,out_pub)
shutil.move(keypem,out_key)
shutil.rmtree(dir)

subprocess.call(['openssl','x509','-noout','-text','-in',out_pub])
