#!/bin/sh
#
#    dnssec-keygen.sh
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
KEYTYPE="$2"
KEYSIZE="$3"
WORKDIR="$4"
if [ -z "$TRIES" ] || [ -z "$KEYTYPE" ] || [ -z "$KEYSIZE" ] || [ ! -d  "$WORKDIR" ]; then
    echo "Usage: $0 TRIES KEYTYPE KEYSIZE DIRECTORY" >&2
    exit 1
fi

cd "$WORKDIR"
hashes="./hashes"
prefix="foo"
status="$WORKDIR/status"
rm -f "$hashes"
for i in $(seq 1 $TRIES) ; do
    echo "$KEYTYPE: $i" > "$status"
    dnssec-keygen -a "$KEYTYPE" -b "$KEYSIZE" -n ZONE -r /dev/urandom "$prefix" >/dev/null
    cat ./K${prefix}*.private | grep Modulus | cut -d ' ' -f 2 | sha1sum | cut -d ' ' -f 1 >> "$hashes"
    rm -f ./*.key ./*.private

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
