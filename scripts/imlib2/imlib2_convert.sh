#!/bin/bash
#
# Wrapper script to call the right binary
#
#
arch=`/bin/uname -m`
current_dir=`dirname $0`

if [ "$arch" = "unknown" ]; then
    return 1;
elif [ "$arch" = "x86_64" ]; then
    binary="imlib2_convert-amd64"
else
    binary="imlib2_convert-i386"
fi

$current_dir/$binary "$@"

