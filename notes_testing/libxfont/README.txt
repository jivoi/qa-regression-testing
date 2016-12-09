A few commands to test libxfont:

xlsfonts - lists currently available fonts
xset q - shows current directories
xfontsel -fn micro - tries to display font called "micro"
xset fp rehash - rescans directories
update-fonts-dir /usr/share/fonts/testing - regens fonts.dir
fslsfonts -server unix/:7100 - lists fonts installed in server
xset fp+ unix/:7100 - adds the font server to the path
xset fp+ tcp/sec-lucid-i386:7100 - adds the remote font server to the path

To test using a remote font server (saucy and earlier only, remote font
servers are disabled in trusty+):

apt-get install xfs
modify directories in /etc/X11/fs/config
enable remote connections in /etc/X11/fs/config

strategy is to remove the default font called "micro" from the default
install, configure it to be available via the font server:

on font server:
mkdir /usr/share/fonts/testing
mv /usr/share/fonts/X11/misc/micro* /usr/share/fonts/testing
rm /usr/share/fonts/X11/misc/fonts*
update-fonts-dir /usr/share/fonts/X11/misc/
update-fonts-dir /usr/share/fonts/testing/

Add /usr/share/fonts/testing to /etc/X11/fs/config
Enable remote connections in /etc/X11/fs/config
Restart xfs

Check if font is now available via font server:
fslsfonts -server unix/:7100 | grep micro

on machine to test:
rm /usr/share/fonts/X11/misc/micro*
rm /usr/share/fonts/X11/misc/fonts*
update-fonts-dir /usr/share/fonts/X11/misc/

make sure it's not available by checking with xlsfonts:
xlsfonts | grep micro

add a remote font server:
xset fp+ tcp/sec-lucid-i386:7100
xset fp rehash

see if it's now available
xlsfonts | grep micro

try and use it:
xfontsel -fn micro


