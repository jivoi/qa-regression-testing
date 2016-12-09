To test dhcp, you need to set up some virtual machines with isolated
networks. In virt-manager/libvirt, set up an "isolated networks" in
addition to the default "NAT" network that is already configured. We will
be setting up the two virtual machines in the following fashion:


            ------------------------------------------   192.168.122.0/24
                |                                |       (default NAT net)
                |                                |
              +---+                            +---+
              |   |.1     192.168.131.0/24     |   |
              +   +----------------------------+   +
              |   |           isonet1          |   |
              +---+                            +---+
               vm1                              vm2

Add an additional network interface to each vm, on the isolated network.
Boot up the VMs. Add static networking configuration to vm1 which will
act as the dhcp server, and add dhcp networking configuration to vm2:

/etc/network/interfaces files:

VM1:
auto eth1
iface eth1 inet static
address 192.168.131.1
netmask 255.255.255.0

VM2:
auto eth1
iface eth1 inet dhcp

Modify /etc/dhcp/dhcpd.conf on VM1 to contain the following:

ddns-update-style none;
default-lease-time 60;
max-lease-time 720;
allow bootp;
authoritative;
log-facility local7;
subnet 192.168.131.0 netmask 255.255.255.0 {
    range 192.168.131.50 192.168.131.60;
}


Reboot them, and see if vm2 is able to obtain a dhcp address from vm1.

-------------------------------------


Testing IPv6:

/etc/network/interfaces files:

VM1:
auto eth1
iface eth1 inet static
address 192.168.131.1
netmask 255.255.255.0

iface eth1 inet6 static
address fd00:0:0::1:1
netmask 48

VM2:
auto eth1
iface eth1 inet6 dhcp

Modify /etc/dhcp/dhcpd.conf on VM1 to contain the following:

ddns-update-style none;
default-lease-time 60;
max-lease-time 720;
allow bootp;
authoritative;
log-facility local7;
subnet6 fd00:0:0::/48 {
	range6 fd00:0:0::1 fd00:0:0::ffff;
}


You must start the dhcp daemon manually:

# touch /var/lib/dhcp/dhcpd6.leases
# chown dhcpd:dhcpd /var/lib/dhcp/dhcpd6.leases 

# /usr/sbin/dhcpd -6 -f -cf /etc/dhcp/dhcpd.conf eth1


