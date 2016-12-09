PHP5 TESTING
------------
php5 on Hardy and newer run the test suite when built, so compare build
logs to the previous release to make sure no new failures were introduced.

For Dapper, here are instructions and notes on how to test PHP5.  It is
best to run the tests before patching so you know what is expected to fail
and compare it to what fails after patching.  The currently saved test runs
are done on amd64 (there are some arch differences in the test runs).

First build php5 with:
$ sudo apt-get update ; apt-get source php5 ; sudo apt-get build-dep php5
$ cd php5-*
$ fakeroot debian/rules build-cgi-stamp

Running the tests requires root privs on Feisty and prior.  It wants to
write to /var, so do it in a chroot:

$ sudo mkdir /var/lib/php5
$ (cd cgi-build; sudo make test)

Save the TEST RESULT SUMMARY and FAILED TEST SUMMARY sections
with the other test output, (in later versions the log is stored in
test-output/php5, otherwise it goes into /tmp on request), which can be
used for comparisons.  Each release of php5 should have its test output
recorded for future security update regression tests.

Please note that some of the tests fail intermittently:
 - Bug #20539 failed (all releases)
 - oo_002.php (date/timezone dependent (seen in feisty))
 - server009.php failed (feisty)

To rebuild:

$ fakeroot debian/rules clean
$ fakeroot debian/rules binary


Copyright (C) 2008,2009 Canonical Ltd.
