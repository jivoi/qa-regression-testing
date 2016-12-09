#!/bin/bash
# Catch libc aborts on stderr
# Kees Cook <kees@ubuntu.com>
export LIBC_FATAL_STDERR_=1
find . -type f -name '*.xml' | sort | grep -v '/out/' | while read xml
do
	echo "Checking $xml ..."
	xmllint "$xml" 2>&1
done
