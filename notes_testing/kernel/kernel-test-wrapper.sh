#!/bin/sh
#
#    kernel-test-wrapper.sh: wrapper around the test-kernel*.py scripts
#
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@ubuntu.com>
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

arch=`uname -m`
uid=`id -u`
if [ "$uid" = '0' ]; then
    echo "This script must run as a non-root user with sudo privileges"
    exit 1
fi

release=`lsb_release -c | awk '{print $2}'`

if [ "$release" = "dapper" ]; then
    kernel_version=`cat /proc/version | awk '{print $3}'`
else
    kernel_version=`cat /proc/version_signature | awk '{print $2}'`
fi

install_packages() {
    echo "Installing script dependencies ..."
    cd /tmp
    for dir in `ls -1d qrt-*kernel*/` ; do
        cd "$dir"
        sudo ./install-packages ./test-*kernel*py
        cd ..
    done
    echo Done
    echo ""
}

check_version() {
    uname -a
    if [ "$release" != "dapper" ]; then
        cat /proc/version_signature
    fi
}

check_linux_meta() {
    # This is based on vm-new...
    meta="linux-image-generic"
    if [ "$release" = "dapper" ]; then
        if [ "$arch" = "x86_64" ]; then
            meta="linux-image-amd64-generic"
        else
            meta="linux-image-386"
        fi
    elif [ "$release" = "hardy" ]; then
        if [ "$arch" = "i686" ]; then
            meta="linux-image-386"
        fi
    elif [ "$release" = "precise" ]; then
        if [ "$arch" = "i686" ]; then
            meta="linux-image-generic-pae"
        fi
    fi

    echo "Checking if '$meta' is installed... "
    dpkg -l $meta >/dev/null || {
        error="yes"
        echo "FAIL"
        echo ""
        return
    }
    echo OK
    echo ""
}

echo "Unpacking scripts ..."
cd /tmp
for i in qrt*kernel*gz ; do tar -zxf $i ; done
echo Done
echo ""

install_packages

error=""

check_linux_meta

# do qrt-test-kernel-aslr-collisions towards the end
for dir in `ls -1d qrt-*kernel* | grep -v 'qrt\-test\-kernel\-aslr\-collisions'` qrt-test-kernel-aslr-collisions ; do
    cd /tmp
    if [ ! -d "$dir" ]; then
        #echo "Skipping '$dir' (not a directory)" >&2
        continue
    fi
    cd "$dir"

    sudo=""
    case "$dir" in
        qrt-test-kernel-security|qrt-test-kernel-root-ops)
            sudo="sudo"
            ;;
        *)
            sudo=""
            ;;
    esac
    echo "$dir:"
    $sudo ./test-*kernel*py -v || {
        error="yes"
    }
    echo ""
done

# do this last so we see it at the bottom
check_version

if [ -n "$error" ]; then
    echo "FAIL"
    exit 1
fi

echo "SUCCESS"
