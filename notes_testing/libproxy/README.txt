Testing libproxy:

Proxy server:

1- In a precise VM (in this example, sec-precise-i386), install the following:

$sudo apt-get install apache2 squid3

2- Create a PAC file with the following contents in /var/www/proxy.pac

function FindProxyForURL(url, host)
{
return "PROXY sec-precise-i386:3128";
}


3- Add the following line to /etc/apache2/httpd.conf:

AddType application/x-ns-proxy-autoconfig .pac 

4- Restart apache:

$sudo /etc/init.d/apache2 restart

5- Uncomment the following lines in /etc/squid3/squid.conf:

acl localnet src 192.168.0.0/16        # RFC1918 possible internal network
http_access allow localnet

6- Restart squid:

$sudo /etc/init.d/squid restart

7- Monitor squid access log:

$sudo tail -f /var/log/squid3/access.log


------------------

In the virtual machine to test:

- Configure gnome to use the PAC file (network applet in system settings)
- Open time and date applet. Should see access in both squid and apache logs
- Perform youtube search in totem.
- Test firefox web connectivity (this doesn't actually use libproxy)

Notes:

If testing a precise client, must install the missing libproxy1-plugin-webkit
package (LP: #981900)

