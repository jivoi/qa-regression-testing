To test sssd:

1- Setup Windows 2012 server in a VM (must disable graphics tablet device
   or it will be cpu intensive). Using remote desktop is best.

2- Set static IPs to Windows 2012 server, and test Ubuntu VM

3- Point Ubuntu VM to Windows 2012 server VM as DNS

4- Install a few packages in Ubuntu VM:
   - apt-get install realmd
   - apt-get install sssd libpam-sss libnss-sss
   - apt-get install samba-common-bin
   - apt-get install adcli sssd-tools

5- Follow instructions here:
   https://fedorahosted.org/sssd/wiki/Configuring_sssd_with_ad_server

   - Do the "Joining the Linux client using realmd" part and not
     "Joining the Linux client to the AD domain manually" or
     "Creating Service Keytab on AD"

6- Will likely hit bug LP: #1333694
   - comment out "samba-common-bin = /usr/bin/net" from
     /usr/lib/realmd/realmd-distro.conf

7- After install, see if can access remotely:
   - ssh -l "administrator@ad.example.com" 192.168.122.6


Some example commands:

ping server.ad.example.com
dig -t SRV  _ldap._tcp.ad.example.com @server.ad.example.com

realm discover --verbose AD.EXAMPLE.COM
realm join --verbose ad.example.com

getent passwd administrator@ad.example.com

