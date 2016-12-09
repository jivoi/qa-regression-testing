Update-manager contains a test suite that can be run in the following way:

In a VM:
- apt-get build-dep update-manager
- apt-get install python-mock
- get the source:
  - original: apt-get source update-manager
  - patched: copy over source tree to VM (must tar before copying over so
    symlinks aren't converted to actual files)
- enter source tree
- cd tests
- make > /tmp/results.txt 2>&1

WARNING: a single test failure aborts the whole make script, so you must
either fix failures, or disable broken tests.

Also, the makefile will only run tests that have the executable bit set,
and for some reason, it's not set on most tests.

----------------


Using update-manager to upgrade to a newer distro will download a tarball
containing code from the next distro version's update-manager and execute
it.

There a two ways to test this part of an update-manager update:

1) You can run (locally) sudo ./dist-upgrade.py to test in the DistUpgrade
   directory
2) Use the tarball that is generated during the build (dist-upgrader*)

To test the KDE frontend:
dist-upgrade.py --frontend DistUpgradeViewKDE
