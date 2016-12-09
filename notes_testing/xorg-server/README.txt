Some random notes for testing xorg-server updates:

--------------------

For hardware enablement backports, you need to install from the following
ISOs:

12.04.2 has the lts-quantal backport
12.04.3 has the lts-raring backport

--------------------

To test non-root X servers:

In first terminal: 
$ sudo apt-get install xserver-xephyr
$ Xephyr -verbosity 255 -screen 800x600 -br -reset -terminate :1

In second terminal:
$ export DISPLAY=:1
$ xcalc

Precise's Xephyr doesn't like 24bpp color, so testing in a VM with the
cirrus driver will result in a segfault. Switch to vmvga to test it.

--------------------



