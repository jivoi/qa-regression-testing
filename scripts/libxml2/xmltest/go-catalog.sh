#!/bin/bash
# Catch libc aborts on stderr
# Jamie Strandboge <jamie@ubuntu.com>
# Based on go.sh by Kees Cook <kees@ubuntu.com>
export LIBC_FATAL_STDERR_=1
find . -type f -name '*.xml' | sort | grep -v '/out/' | while read xml
do
	echo "Checking $xml ..."
	xmlcatalog --create "$xml" 2>&1
done
