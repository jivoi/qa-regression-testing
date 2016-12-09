#!/bin/sh

mv /etc/apache2/httpd.conf /etc/apache2/httpd.conf.old
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.old
ln -s /etc/apache2/apache2.conf /etc/apache2/httpd.conf
sed -i 's,^Include /etc/apache2/httpd.conf,,' /etc/apache2/apache2.conf

/etc/init.d/apache2 force-reload

for i in asis auth_digest auth_anon cache cgi disk_cache dav dav_fs deflate expires ext_filter file_cache headers imap include info proxy proxy_connect proxy_ftp proxy_http rewrite ssl vhost_alias php5
do
        a2enmod $i
done

/etc/init.d/apache2 force-reload

