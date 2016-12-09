As of vivid, apport no longer ships the test suite in the binary packages.

To run test suite manually in a VM:

- Make sure VM has src-deb in sources.list
- Need to run in X session
- Need to install apport binaries for version to be tested

$ sudo apt-get build-dep apport
$ sudo apt-get install python3-pykde4 python3-pyqt5 valgrind
$ apt-get source apport
$ cd apport*
$ ./setup.py build
$ test/run



Certain tests require special conditions for completeness:

For the record, the tests should be run in four modes: as root and user,
and with suid_dumpable enabled and disabled:

sudo rm /var/crash/*
echo 0 | sudo tee /proc/sys/fs/suid_dumpable
sudo test/run signal_crashes && test/run signal_crashes
echo 2 | sudo tee /proc/sys/fs/suid_dumpable
sudo rm /var/crash/*
sudo test/run signal_crashes && test/run signal_crashes

The above only works on vivid+. Utopic and older require suid_dumpable=2.
