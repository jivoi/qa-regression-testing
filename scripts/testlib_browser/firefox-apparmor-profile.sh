#!/bin/sh -e
#
#    firefox-apparmor-profile.sh quality assurance test script for Firefox, etc
#    Copyright (C) 2010 Canonical Ltd.
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

preinst="/var/lib/dpkg/info/firefox.preinst"
postinst="/var/lib/dpkg/info/firefox.postinst"
aad="/etc/apparmor.d"

old_version="$1"
if [ -z "$old_version" ]; then
    echo "Need to specify old version" >&2
    exit 1
fi

ff35_disabled=""
ff_disabled=""
tmpdir=
err=

backup_profiles() {
    echo "Backing up profiles"
    cp "$aad"/usr.bin.firefox* "$tmpdir"

    if [ -e "$aad/disable/usr.bin.firefox-3.5" ]; then
        ff35_disabled="yes"
    fi
    if [ -e "$aad/disable/usr.bin.firefox" ]; then
        ff_disabled="yes"
    fi
}

restore_profiles() {
    echo "Restoring profiles"
    fresh_start
    mv -f "$tmpdir"/usr.bin.firefox* "$aad"
    if [ "$ff35_disabled" = "yes" ]; then
        ln -sf "$aad/usr.bin.firefox-3.5" "$aad/disable"
    fi
    if [ "$ff_disabled" = "yes" ]; then
        ln -sf "$aad/usr.bin.firefox" "$aad/disable"
    fi
}

fresh_start() {
    for f in "$aad"/usr.bin.firefox* ; do
        if echo "$f" | grep -q "dpkg" ; then
            continue
        fi
        apparmor_parser -R "$f" 2>/dev/null || true
    done
    rm -f "$aad"/usr.bin.firefox* "$aad/disable"/usr.bin.firefox*

    # Now be really sure for when we might have had the profile enabled
    # before upgrade
    for i in `aa-status | grep '/usr/lib/firefox-' | grep -v '//'`; do
        echo "$i {}" | apparmor_parser -R
    done
}

tmpdir=`mktemp -d`
trap "restore_profiles ; rmdir $tmpdir" EXIT HUP INT QUIT TERM

backup_profiles

echo ""

# TESTS
echo -n "Test new install: "
fresh_start
$preinst install || true
cp -f "$tmpdir/usr.bin.firefox" "$aad"
$postinst configure | grep -v "Please restart" || true
if [ -e "$aad/disable/usr.bin.firefox" ] && ! aa-status | grep -q "firefox" ; then
    echo "PASS"
else
    echo "FAIL"
    err="yes"
fi

if [ -e "$tmpdir/usr.bin.firefox-3.5" ] || [ -e "$tmpdir/usr.bin.firefox-3.5.dpkg-old" ]; then
    # this machine one had the old firefox-3.5 profile. Let's do some upgrade
    # tests to make sure the upgrade is sane
    echo -n "Test 3.5 to 3.6 upgrade with disabled profile: "
    fresh_start
    cp -f "$tmpdir/usr.bin.firefox-3.5" "$aad"
    touch -t 200911010000 "$aad/usr.bin.firefox-3.5"
    ln -sf "$aad/usr.bin.firefox-3.5" "$aad/disable"
    $preinst upgrade "$old_version"
    cp -f "$tmpdir/usr.bin.firefox" "$aad"
    $postinst configure "$old_version" 2>&1 | egrep -v "(Please restart|apparmor_parser: Unable to remove)" || true
    if [ -e "$aad/disable/usr.bin.firefox" ] && [ -e "$aad/usr.bin.firefox-3.5.dpkg-old" ] && [ ! -e "$aad/usr.bin.firefox-3.5" ] && ! aa-status | grep -q "firefox" ; then
        echo "PASS"
    else
        echo "FAIL"
        err="yes"
    fi

    echo -n "Test 3.5 to 3.6 upgrade with enabled profile: "
    fresh_start
    cp -f "$tmpdir/usr.bin.firefox-3.5" "$aad"
    touch -t 200911010000 "$aad/usr.bin.firefox-3.5"
    apparmor_parser -r "$aad/usr.bin.firefox-3.5"
    $preinst upgrade "$old_version"
    cp -f "$tmpdir/usr.bin.firefox" "$aad"
    $postinst configure "$old_version" | grep -v "Please restart" || true
    if [ ! -e "$aad/disable/usr.bin.firefox" ] && [ -e "$aad/usr.bin.firefox-3.5.dpkg-old" ] && [ ! -e "$aad/usr.bin.firefox-3.5" ] && aa-status | grep -q "firefox" ; then
        echo "PASS"
    else
        echo "FAIL"
        err="yes"
    fi
fi

echo -n "Test 3.6 upgrade with disabled profile: "
fresh_start
cp -f "$tmpdir/usr.bin.firefox" "$aad"
touch -t 201005010000 "$aad/usr.bin.firefox"
ln -sf "$aad/usr.bin.firefox" "$aad/disable"
$preinst upgrade "$old_version"
$postinst configure "$old_version" 2>&1 | egrep -v "(Please restart|apparmor_parser: Unable to remove)" || true
if [ -e "$aad/disable/usr.bin.firefox" ] && ! aa-status | grep -q "firefox" ; then
    echo "PASS"
else
    echo "FAIL"
    err="yes"
fi

echo -n "Test 3.6 upgrade with enabled profile: "
fresh_start
cp -f "$tmpdir/usr.bin.firefox" "$aad"
touch -t 201005010000 "$aad/usr.bin.firefox"
apparmor_parser -r "$aad/usr.bin.firefox"
$preinst upgrade "$old_version"
$postinst configure "$old_version" | grep -v "Please restart" || true
if [ ! -e "$aad/disable/usr.bin.firefox" ] && aa-status | grep -q "firefox" ; then
    echo "PASS"
else
    echo "FAIL"
    err="yes"
fi

# END TESTS

rc="0"
if [ "$err" = "yes" ]; then
    rc="1"
fi
echo ""
exit $rc
