#!/bin/bash
echo "Content-type: text/plain"
echo ""
DIR=/var/www/output
LOG=$(basename $0 .cgi | cut -d- -f1).log
rm -f "$DIR"/"$LOG"
