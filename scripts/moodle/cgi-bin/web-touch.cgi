#!/bin/bash
echo "Content-type: text/plain"
echo ""
DIR=/var/www/output
LOG=$(basename $0 .cgi | cut -d- -f1).log
touch "$DIR"/"$LOG"
