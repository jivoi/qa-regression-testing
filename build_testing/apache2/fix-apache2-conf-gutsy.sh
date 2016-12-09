#!/bin/sh

mv /etc/apache2/httpd.conf /etc/apache2/httpd.conf.old
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.old
ln -s /etc/apache2/apache2.conf /etc/apache2/httpd.conf
sed -i 's,^Include /etc/apache2/httpd.conf,,' /etc/apache2/apache2.conf

/etc/init.d/apache2 force-reload

for i in access actions alias asis auth_digest authn_anon autoindex cache cgi disk_cache dav dav_lock dav_fs deflate ext_filter filter auth_digest dir env expires headers imagemap include info negotiation proxy proxy_balancer proxy_connect proxy_ftp proxy_http rewrite setenvif ssl status vhost_alias php5
do
        a2enmod $i
done

/etc/init.d/apache2 force-reload

