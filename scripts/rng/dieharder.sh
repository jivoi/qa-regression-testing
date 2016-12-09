#!/bin/sh
set -e
# Just a single quick test:
#./$1-rand | dieharder -g 200 -d 1
./$1-rand | dieharder -g 200 -a
