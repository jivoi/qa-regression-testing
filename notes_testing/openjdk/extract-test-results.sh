#!/bin/sh

releases="$*"
if [ -z "$releases" ]; then
    echo "$0 <space separated list of releases>"
    exit 1
fi

err=
for i in $releases ; do
    echo "$i..."
    for k in previous current ; do
        if [ ! -d "./$k" ]; then
            echo "Could not find './$k'. Skipping"
	    err="yes"
            continue
        fi
        for j in openjdk-6 openjdk-7 openjdk-8; do
            egrep -H -B10 'tee test/check-.*\.log' ./$k/*$i*$j*.txt 2>/dev/null | sed -e 's/openjdk-\([678]\)_[0-9].*_.*\.txt/openjdk-\1-VERSION_BUILDING/' -e 's#/openjdk-\([67]\).*/#/openjdk-\1-VERSION/#g' -e 's#.*buildlog_ubuntu-##g' > /tmp/$i-$j.$k-testruns
            egrep -H 'Test results' ./$k/*$i*$j*.txt 2>/dev/null |sed -e 's/openjdk-\([678]\)_[0-9].*._.*\.txt/openjdk-\1-VERSION_BUILDING/' -e 's#.*buildlog_ubuntu-##g' > /tmp/$i-$j.$k-results
            egrep -H '(FAILED: |Passed: )' ./$k/*$i*$j*.txt 2>/dev/null | sed -e 's/openjdk-\([678]\)_[0-9].*_.*\.txt/openjdk-\1-VERSION_BUILDING/' -e 's#.*buildlog_ubuntu-##g' > /tmp/$i-$j.$k-testcases
        done
    done
done

if [ -n "$err" ]; then
    exit 1
fi

echo ""
echo "Now run:"
echo "$ for i in $releases ; do meld /tmp/\$i-openjdk-6.previous-testruns /tmp/\$i-openjdk-6.current-testruns ; meld /tmp/\$i-openjdk-6.previous-results /tmp/\$i-openjdk-6.current-results ; meld /tmp/\$i-openjdk-6.previous-testcases /tmp/\$i-openjdk-6.current-testcases ; done"
echo "$ for i in $releases ; do meld /tmp/\$i-openjdk-7.previous-testruns /tmp/\$i-openjdk-7.current-testruns ; meld /tmp/\$i-openjdk-7.previous-results /tmp/\$i-openjdk-7.current-results ; meld /tmp/\$i-openjdk-7.previous-testcases /tmp/\$i-openjdk-7.current-testcases ; done"
echo "$ for i in $releases ; do meld /tmp/\$i-openjdk-8.previous-testruns /tmp/\$i-openjdk-8.current-testruns ; meld /tmp/\$i-openjdk-8.previous-results /tmp/\$i-openjdk-8.current-results ; meld /tmp/\$i-openjdk-8.previous-testcases /tmp/\$i-openjdk-8.current-testcases ; done"
