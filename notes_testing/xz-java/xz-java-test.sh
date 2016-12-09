#!/bin/sh
#
# xz-java-test.sh QA test script
# Copyright (C) 2012 Canonical Ltd.
# Author: Jamie Strandboge <jamie@canonical.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     /usr/share/common-licenses/Apache-2.0 (on Debian systems)
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
set -e

testdir="/bin"
if [ -d "$1" ]; then
    testdir="$1"
fi

topdir=`pwd`
if [ ! -e "$topdir"/build/jar/XZEncDemo.jar ] || [ ! -e "$topdir"/build/jar/XZDecDemo.jar ]; then
    echo "Could not find required XZEncDemo.jar and XZDecDemo.jar in build/jar." >&2
    echo "Please run this from the toplevel source directory after building." >&2
    exit 1
fi

tmpdir=`mktemp -d`
trap "rm -rf $tmpdir" 0 1 2 3 4 5 6 7 8 10 11 12 13 14 15
cd "$tmpdir"

err=
find "$testdir" -type f | sort | while read file ; do
    echo -n "$file: "
    tmp=`basename "$file"`
    java -jar "$topdir"/build/jar/XZEncDemo.jar < "$file" > "./$tmp.xz" 2>/dev/null
    java -jar "$topdir"/build/jar/XZDecDemo.jar "./$tmp.xz" > "./$tmp" 2>/dev/null
    orig=`md5sum "$file" | cut -d ' ' -f 1`
    new=`md5sum "./$tmp" | cut -d ' ' -f 1`
    if [ "$new" != "$orig" ]; then
        echo "FAIL (md5sum does not match)"
        err="yes"
    else
        echo "pass"
    fi
    rm -f "./$tmp"
done
cd "$topdir"

if [ "$err" = "yes" ]; then
    exit 1
fi
exit 0
