#!/bin/sh -e

#    test-speex.sh quality assurance test script
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

#
# use gst-inspect-0.10 to see available plugins
# and gst-inspect-0.10 <plugin> to see plugin options
#
# NOTE: dapper know to fail with hertx < 32000

if [ -z "$1" ]; then
    echo "$0 <wavfile>"
    exit 1
fi

tmpdir=`mktemp -d`
trap "rm -rf ${tmpdir}" EXIT

spx="$tmpdir/foo.spx"
wav="$tmpdir/foo.wav"

failed=""
for orig in "$@"
do
    echo "Converting $orig"
    gst-launch-0.10 filesrc location=$orig ! wavparse ! audioconvert ! speexenc ! oggmux ! filesink location=$spx 2>/dev/null || true
    if [ -e "$spx" ]; then
        gst-launch-0.10 filesrc location=$spx ! oggdemux ! speexdec ! audioconvert ! wavenc ! filesink location=$wav 2>/dev/null || true
    fi

    if [ -s "$spx" ] && [ -s "$wav" ]; then
        echo PASS
    else
        echo FAIL
        failed="yes"
    fi
    rm -f $spx $wav
    echo ""
done

if [ "$failed" = "yes" ]; then
    echo ""
    echo "*** FAILED ***"
    exit 1
fi
echo "*** PASSED ***"
exit 0
