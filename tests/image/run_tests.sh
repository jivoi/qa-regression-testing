#!/bin/bash
################################################################################
# Copyright 2013 Canonical Ltd.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; version 2.1.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Jamie Strandboge <jamie@canonical.com>
################################################################################

set -e

# Failure counter
F_I=0

# Success counter
S_I=0

# Total counter
T_I=0

uid=`id -u`

user=
if getent passwd phablet >/dev/null ; then
    user="phablet"
else
    user=`getent passwd 1000 | cut -d ':' -f 1`
fi
if [ -z "$user" ]; then
    echo "ERROR: could not find suitable sudo user for unprivileged tests" >&2
    exit -1
fi

script=`readlink -e "$0"`
topdir=`dirname "$script"`

echo "= Unprivileged tests ="
for i in `find "$topdir"/unprivileged -type f -executable | sort` ; do
    echo "== $i =="
    cmd="$i"
    if [ "$uid" = "0" ]; then
        cmd="sudo -i -H -u $user $i"
    fi
    if ! $cmd ; then
        F_I=$(($F_I + 1))
    else
        S_I=$(($S_I + 1))
    fi
    T_I=$(($T_I + 1))
done
echo

echo "= Privileged tests ="
if [ "$uid" = "0" ]; then
    for i in `find "$topdir"/privileged -type f -executable | sort` ; do
        echo "== $i =="
        if ! "$i" ; then
            F_I=$(($F_I + 1))
        else
            S_I=$(($S_I + 1))
        fi
        T_I=$(($T_I + 1))
    done
else
    echo "SKIPPED (uid=$uid)"
fi

#######################################
# Print summary
echo
echo "= Summary for all tests run by `basename $0` ="
echo " Passed: ${S_I}/${T_I}"
echo " Failed: ${F_I}/${T_I}"
echo -n " Result for all tests: "
if [ ${F_I} -gt 0 ]; then
    echo FAIL
else
    echo pass
fi
exit ${F_I}
