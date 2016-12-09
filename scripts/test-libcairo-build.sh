#!/bin/sh
#
#    test-libcairo-build.sh quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#
# quick script just to let know how to test libcairo builds
#

cat << EOF
Cairo TESTING
------------
This is not an automatic test, but rather instructions and notes on how to test
Cairo.  It is best to run the tests before patching so you know what is
expected to fail and compare it to what fails after patching.

First build libcairo with:
$ sudo apt-get update ; apt-get source libcairo ; sudo apt-get build-dep libcairo
$ cd libcairo-*
$ fakeroot debian/rules build

The tests need "gs" to be installed, and for $DISPLAY to be reachable:

$ sudo apt-get install gs
$ export DISPLAY=:0.0

Run the tests:

$ (cd debian/build-main/test; make check) 2>&1 | tee check.log

Trim "check.log" to just the tests and summary, and stored it in
test-output/libcairo, which can be used for comparisons.  Each release of
libcairo should have its test output recorded for future security update
regression tests.

To rebuild:

$ fakeroot debian/rules clean
$ fakeroot debian/rules build

EOF
