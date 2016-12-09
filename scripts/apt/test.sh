#!/bin/sh

#
#    test.sh quality assurance test script for apt
#    Copyright (C) 2009-2014 Canonical Ltd.
#    Author: Micael Vogt <michael.vogt@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
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
    rm -f ./lists/*.gpg
    apt-get update -qq \
                   -o Debug::Acquire::gpgv=$DEBUG \
                   -o Dir::etc::sourcelist=$PWD/apt/sources.list \
	           -o Dir::State::lists="./lists" \
                   -o APT::GPGV::TrustedKeyring="$PWD/keyring/pubring.gpg"
}

assert_valid_signature() {
    MSG="$1"
    if ! ls ./lists/*.gpg >/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}

assert_no_signature() {
    MSG="$1"
    if ls ./lists/*.gpg 2>/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}

assert_bad_signature() {
    MSG="$1"
    if ls ./lists/*.gpg >/dev/null; then
	echo "ERROR: $MSG"
        error="yes"
    else
	echo "PASS"
    fi
    echo
}

# test good key
echo "test good"
echo "deb file:$PWD/repo-good /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, not accepting valid key"

# test expired keys
echo "test expire "
echo "deb file:$PWD/repo-expired /" > apt/sources.list
run_apt_update
assert_no_signature "ERROR, accepting a expired key"

# test revoked key
echo "test revoked"
echo "deb file:$PWD/repo-revoked /" > apt/sources.list
run_apt_update
assert_no_signature "ERROR, accepting a revoked key"

# test repo signed by expired and good key
echo "test expired+good"
echo "deb file:$PWD/repo-expired-and-valid /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, expired+good is still good"

echo "test good+expired"
echo "deb file:$PWD/repo-valid-and-expired /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, good+expired is still good"

# test repo signed by revoked and good key
echo "test revoked+good"
echo "deb file:$PWD/repo-revoked-and-valid /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, revoked+good is still good"

echo "test good+revoked"
echo "deb file:$PWD/repo-valid-and-revoked /" > apt/sources.list
run_apt_update
assert_valid_signature "ERROR, good+revoked is still good"


# test bad signature
echo "test bad"
echo "deb file:$PWD/repo-bad /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting bad signature"

# test bad expired signature
echo "test bad expired"
echo "deb file:$PWD/repo-bad-expired /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting bad expired signature"

# test bad revoked signature
echo "test bad revoked"
echo "deb file:$PWD/repo-bad-revoked /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting bad revoked signature"

# test repo signed by expired and good, with good signature wrong
echo "test expired+bad"
echo "deb file:$PWD/repo-bad-expired-and-good /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting expired+bad signature"

# test repo signed by revokedand good, with good signature wrong
echo "test revoked+bad"
echo "deb file:$PWD/repo-bad-revoked-and-good /" > apt/sources.list
run_apt_update
assert_bad_signature "ERROR, accepting revoked+bad signature"


if [ "$error" = "yes" ]; then
    echo "FAIL"
    exit 1
fi

exit 0
