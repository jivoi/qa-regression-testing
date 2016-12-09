#!/bin/sh
#
# test-ca
# Copyright (C) 2010 Canonical Ltd.
# Author: Jamie Strandboge <jamie@canonical.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
set -e

destdir="/tmp/test-ca"
if [ -e "$destdir" ]; then
    echo "'$destdir' exists. Aborting" >&2
    exit 1
fi

if [ -z "$1" ]; then
    echo "USAGE: $0 <server hostname> [<client1 hostname> <client2 hostname>]"
    exit 1
fi
hname="$1"
shift

client_hnames=""
if [ -n "$1" ]; then
    client_hnames="$*"
    shift
fi

tmpdir=`mktemp -d`
trap "rm -rf $tmpdir" EXIT HUP INT QUIT TERM

cd "$tmpdir"
count=1000

echo "Creating templates..."
cat > ./ca.cfg << EOM
organization = "QRT"
unit = "Test CA"
ca
cn = $hname
cert_signing_key
expiration_days = 10000
serial = $count
EOM

echo "Creating CA key..."
certtool -p --outfile test-ca-key.pem

echo "Creating CA certificate..."
certtool --generate-self-signed --load-privkey ./test-ca-key.pem --outfile test-ca.pem --template ./ca.cfg

for h in $hname $client_hnames ; do
    for type in "" -tls ; do
        count=$(( $count + 1 ))
        cat > ./$h.cfg << EOM
cn = $h
organization = "QRT"
unit = "Test Certificate"
expiration_days = 10000
country = US
state = Texas
serial = $count
EOM
        if [ "$type" = "-tls" ]; then
            if [ "$h" = "$hname" ]; then
                echo "tls_www_server" >> ./$h.cfg
            else
                echo "tls_www_client" >> ./$h.cfg
            fi
            echo "signing_key" >> ./$h.cfg
            echo "encryption_key" >> ./$h.cfg
        fi

        echo "Creating key for '$h'..."
        certtool -p --outfile $h$type-key.pem

        echo "Creating server certificate for '$h'..."
        certtool --generate-certificate --load-privkey ./$h$type-key.pem --load-ca-privkey ./test-ca-key.pem --load-ca-certificate ./test-ca.pem --outfile $h$type.pem --template ./$h.cfg
    done
done

cd - >/dev/null
echo ""
echo ""
echo "SUCCESS"
mv "$tmpdir" "$destdir"
echo "$ ls -1 '$destdir'/*.pem"
ls -1 "$destdir"/*.pem

