#!/bin/sh -e

#
#    test-lp784473.sh quality assurance test script for apt
#    Copyright (C) 2009-2011 Canonical Ltd.
#    Author: Micael Vogt <michael.vogt@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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

DEBUG=false
error=""

run_apt_update() {
    apt-get update -qq \
                   -o Debug::Acquire::gpgv=$DEBUG \
                   -o Dir::etc::sourcelist=$PWD/apt/sources.list \
	           -o Dir::State::lists="./lists" \
                   -o APT::GPGV::TrustedKeyring="$PWD/keyring/pubring.gpg"
}

assert_valid_signature() {
    MSG="$1"
    if ! ls ./lists/*InRelease >/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}

assert_no_signature() {
    MSG="$1"
    if ls ./lists/*InRelease 2>/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}

assert_bad_signature() {
    MSG="$1"
    if ls ./lists/*InRelease >/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}


# test repo with good in-line signature
echo "test good InRelease"
echo "deb file:$PWD/repo-good-lp784473 /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, not accepting valid in-line signature"

# test repo with bad in-line signature
echo "test bad InRelease"
echo "deb file:$PWD/repo-bad-lp784473 /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting bad in-line signature"

# test repo with appended in-line signature
echo "test appended InRelease"
echo "deb file:$PWD/repo-appended-lp784473 /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting appended in-line signature"

if [ "$error" = "yes" ]; then
    echo "FAIL"
    exit 1
fi

exit 0
