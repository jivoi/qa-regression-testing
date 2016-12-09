#!/bin/sh
set -e

tmpdir=`mktemp -d`
trap "rm -rf $tmpdir" EXIT HUP INT QUIT TERM

tmp="$tmpdir/file.tar.gz"

help() {
    cat <<EOM
Usage:
`basename $0` <evolution backup file>

Eg:
`basename $0` $HOME/evolution.tar.gz
EOM
}

if [ ! -s "$1" ]; then
    help  
    exit 1
fi
orig="$1"

cd $tmpdir || exit 1
tar -zxf "$orig"
rm -f ./.evolution/*.db
sed -i "s#jamie#$USER#g" ./.evolution/backup-restore-gconf.xml
tar chf - .evolution .camel_certs | gzip > $HOME/evolution-backup-$USER.tar.gz

echo ""
echo "Please use evolution to import $HOME/evolution-backup-$USER.tar.gz"
