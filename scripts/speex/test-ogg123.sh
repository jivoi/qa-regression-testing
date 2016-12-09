#!/bin/sh -e

#    test-ogg123.sh quality assurance test script
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

# apt-get install speex vorbis-tools
#
# NOTE: dapper know to fail with unmatched hertz in wav file and specified
#       band. Eg, speexenc -w <file> works with a 16000 Hz audio, but segfaults
#       with 8000 Hz
#

if [ -z "$1" ]; then
    echo "$0 <wavfile>"
    exit 1
fi

tmpdir=`mktemp -d`
trap "rm -rf ${tmpdir}" EXIT

spx="$tmpdir/foo.spx"

failed=""

for orig in "$@"
do
    for arg in n w u
    do
        echo "Converting $orig to speex"
        speexenc -${arg} $orig $spx 2>/dev/null || true
        if [ ! -e "$spx" ]; then
            echo "Skipped"
            echo ""
            continue
        fi
        echo -n "ogg123 playing speex file with '$arg': "
        if ogg123 -d null $spx ; then
            echo PASS
        else
            echo FAIL
            failed="yes"
        fi
        rm -f $spx
        echo ""
    done
done

if [ "$failed" = "yes" ]; then
    echo ""
    echo "*** FAILED ***"
    exit 1
fi
echo "*** PASSED ***"
exit 0
