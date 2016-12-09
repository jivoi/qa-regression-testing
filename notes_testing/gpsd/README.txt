gpsd includes a test suite that is run during build. Unfortunately, it
would appear that the proper dependencies required for it to run properly
are not necessarily installed during build, such as having access to the
system dbus.

Here are instructions for running the test suite in a VM:

$ sudo apt-get build-dep gpsd
$ sudo apt-get install devscripts

enter source tree

$ debuild
$ scons testregress

On precise, 10 out of the 75 tests fail

Testing with gps hardware:

I wasn't able to get a portable Garmin unit working via USB, but a usb GPS
unit from an old copy of MS Streets and Trips worked without a hitch:

$ sudo apt-get install gpsd gpsd-clients

Modify /etc/default/gpsd to change START_DAEMON to true. Start service.

Plug in GPS device, look for pl2303 converter message in dmesg.

Start up xgps and see if location is found.


