#!/bin/sh

#    test_apparmor_profile_migration.sh quality assurance test script
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
# apparmor_test.sh package profile previous_version[,previous_version] [test script]
#
# Assumes most recent version is version being tested and previous_version...
# are all in a directory named 'previous_version'.  Typical usage might be:
#
# ./apparmor_test.sh bind9 usr.sbin.named 9.3.2-2ubuntu1.4,9.4.1-P1-3ubuntu1
# 9.3.2-2ubuntu1.4/	contains dapper debs
# 9.4.1-P1-3ubuntu1/	contains gutsy debs
#
# TODO: integrate apparmor-profiles testing

old_apparmor="2.1+993-0ubuntu3"

prompts="0"
success="0"

help() {
    echo "apparmor_test.sh package profile previous_version [test_script]"
}

# install pkgname
# install pkgname=previous_version
# install pkgname=previous_version test_script
install() {
    prev=`echo $1 | cut -d '=' -f 2`
    if [ -d "$prev" ]; then
        sudo dpkg -i $prev/*.deb
    else
        sudo aptitude -y install $1
    fi
    
    if [ ! -z "$2" ]; then
        sudo $2 -v
    fi
}

# remove pkgname
# remove --purge pkgname
# remove --purge pkgname=previous_version
remove() {
    purge=""
    if [ "$1" = "--purge" ]; then
        purge="$1"
        shift
    fi
    pkgs=""
    prev=`echo $1 | cut -d '=' -f 2`
    if [ -d "$prev" ]; then
        for p in `ls $prev` ; do
            tmp=`echo $p | cut -d '_' -f 1`
            pkgs="$pkgs $tmp"
        done
    else
        pkgs="$1"
    fi
    sudo apt-get -y remove $purge $pkgs
}

upgrade() {
    sudo apt-get upgrade
    if [ ! -z "$1" ]; then
        sudo $1 -v
    fi
}

header() {
    echo ""
    echo "**********"
    echo "  $1"
    echo "**********"
    echo ""
}

prompt() {
    prompts=$(($prompts+1))
    echo ""
    echo -n "Did it work correctly? "
    read ans
    if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        success=$(($success+1))
    fi
}

is_complain() {
    local profile="$1"
    sudo aa-status | while read line; do 
        in_complain=""
        if echo "$line" | egrep -q "profiles are in complain mode" ; then
            in_complain="yes"
        elif echo "$line" | egrep -q "enforce mode" ; then
            in_complain="false"
        fi
        if [ "$in_complain" = "yes" ] && echo "$line" | egrep -q "$profile" ; then
            echo "** $profile in complain mode"
            return 0
        fi
    done
    echo "** $profile in enforce mode"
    return 1
}

if [ -z "$1" ]; then
    help
    exit 1
fi
package="$1"
shift

if [ -z "$1" ]; then
    help
    exit 1
fi
profile="$1"
shift

if [ -z "$1" ]; then
    help
    exit 1
fi
previous_versions="$1"
shift

script=
if [ ! -z "$1" ]; then
    script="$1"
    shift
fi


# start script

header "Start"
echo "Package: $package"
echo "Profile: $profile"
echo "Previous: $previous_versions"
echo "Script: $script"
echo ""
echo "** WARNING **"
echo "Do NOT run this on a production system.  You have been warned."
echo ""
echo "Press enter to continue"
read ans

header "new install"
remove --purge $package
install $package $script
prompt

# copy the profile and change it
changed=`mktemp`
cat /etc/apparmor.d/$profile > $changed
echo "# changed" >> $changed

header "new install with existing modified profile (should prompt)"
remove --purge $package
sudo cp -f $changed /etc/apparmor.d/$profile
install $package
prompt


header "new install after remove with existing modified profile (should not prompt)"
remove $package
sudo cp -f $changed /etc/apparmor.d/$profile
install $package
prompt

last="$package"
for v in `echo $previous_versions | sed 's/,/ /g'`
do
    header "upgrade from $v"
    remove --purge $last
    if [ "$package" = "slapd" ]; then
        sudo rm -rf /var/backups/*ldapdb
    fi
    install ${package}=${v}
    upgrade
    prompt

    header "upgrade from $v with existing modified profile (may prompt)"
    remove --purge $package=${v}
    if [ "$package" = "slapd" ]; then
        sudo rm -rf /var/backups/*ldapdb
    fi
    install ${package}=${v}
    sudo cp -f $changed /etc/apparmor.d/$profile
    upgrade
    prompt

    last="$v"
done
remove --purge $last


# report
echo ""
echo "RESULTS: $success/$prompts"
echo ""

# cleanup
echo "Cleanup"
for v in `echo $previous_versions | sed 's/,/ /g'`
do
    remove --purge $package=${v}
done
remove --purge $package
rm -f /etc/apparmor.d/$profile
rm -f /etc/apparmor.d/force-complain/$profile
rm -f $changed

