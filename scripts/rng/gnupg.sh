#!/bin/sh
#
#    gnupg.sh
#    Copyright (C) 2009 Canonical Ltd.
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
set -e

TRIES="$1"
KEYTYPE=$(echo "$2" | tr a-z A-Z)
KEYSIZE="$3"
WORKDIR="$4"
if [ -z "$TRIES" ] || [ -z "$KEYTYPE" ] || [ -z "$KEYSIZE" ] || [ ! -d  "$WORKDIR" ]; then
    echo "Usage: $0 TRIES KEYTYPE KEYSIZE DIRECTORY" >&2
    exit 1
fi


cd "$WORKDIR"
hashes="./hashes"
status="$WORKDIR/status"
gpg_batch_file="./gpg.batch"

# based on doc/DETAILS
cat >$gpg_batch_file <<EOF
%echo Generating a standard key
Key-Type: $KEYTYPE
Key-Length: $KEYSIZE
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe@foo.bar
Expire-Date: 0
Passphrase: abc
%pubring foo.pub
%secring foo.sec
%commit
%echo done
EOF

rm -f "$hashes"
for i in $(seq 1 $TRIES) ; do
    echo "$KEYTYPE: $i" > "$status"
    gpg --batch --gen-key "$gpg_batch_file" 2>/dev/null
    gpg --fingerprint --homedir ./ --keyring ./foo.pub --secret-keyring ./foo.sec 2>/dev/null | grep 'fingerprint' | cut -d '=' -f 2 |sed 's/ //g' >> $hashes
    rm -f ./*.pub ./*.sec

    # every 10000 keys, lets see if we have a duplicate
    if echo $i | egrep -q '0000$' ; then
        total=`wc -l $hashes | cut -d ' ' -f1`
        unique=`cat $hashes | sort -u | wc -l | cut -d ' ' -f1`
        if [ "$unique" != "$total" ]; then
            echo "FAIL: only '$unique' unique hashes out of '$total'" >&2
            exit 1
        fi
    fi
done

total=`wc -l $hashes | cut -d ' ' -f1`
unique=`cat $hashes | sort -u | wc -l | cut -d ' ' -f1`
if [ "$unique" != "$total" ]; then
    echo "FAIL: only '$unique' unique hashes out of '$total'" >&2
    exit 1
fi
echo "SUCCESS: '$unique' unique hashes out of '$total'" >&2

exit 0
