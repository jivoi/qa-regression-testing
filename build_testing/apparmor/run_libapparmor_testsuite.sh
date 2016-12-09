#!/bin/sh -e

#
#    run_libapparmor_testsuite.sh
#    Copyright (C) 2008 Canonical Ltd.
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

#
# Run with:
# $ cd <toplevel source>
# $ fakeroot debian/rules build
# $ cd libraries/libapparmor/testsuite
# $ make 
# $ run_libapparmor_testsuite.sh
#

tmp=`mktemp`
err=""
for i in test_multi/*.in
do
    echo "Running: $i:"
    ./test_multi.multi $i > $tmp
    out=`echo "$i" | sed 's/\.in\$/.out/'`
    if diff $out $tmp ; then
        echo PASS
    else
        echo FAIL
        err="yes"
    fi
    echo ""
done

if [ "$err" = "yes" ]; then
    echo "FAILED TESTS"
fi

rm -f $tmp
