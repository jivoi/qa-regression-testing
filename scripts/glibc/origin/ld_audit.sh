#!/bin/bash
# CVE-2010-3856
set -e
dir=$(mktemp -t -d)
trap "rm -rf $dir" EXIT
ls -l /bin/ping
base=$(dirname $(ldd /bin/ping | grep 'libc.so' | head -n1 | awk '{print $3}'))
ls -l "$base"/libpcprofile.so
LD_AUDIT="libpcprofile.so" PCPROFILE_OUTPUT="$dir/evilness" ping || true
ls -l "$dir"/evilness && exit 1
exit 0
