#!/bin/bash
#
# Copyright (c) halfdog <me@halfdog.net>
#
# This software is provided by the copyright owner "as is" to
# study it but without any expressed or implied warranties, that
# this software is fit for any other purpose. If you try to compile
# or run it, you do it solely on your own risk and the copyright
# owner shall not be liable for any direct or indirect damage
# caused by this software.

mkdir -p tmp/proc
(cd tmp/proc; sleep 1; ../../FuseMinimal .) &
(./DirModifyInotify --Watch tmp/proc --Watch /etc/mtab --WatchCount 8 --MovePath tmp --LinkTarget /) &
sleep 3
fusermount -u -z /proc/
# Check that proc was unmounted by running ps
ps aux
