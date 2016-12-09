#!/bin/bash

if [ `id -u` -ne 0 ]; then
	echo "Must be root"
	exit 1
fi

topdir="$(dirname $0)"
cd ${topdir}

rootfs="${topdir}/lxc-rootfs"
if [ -d $rootfs ]; then
	echo "$rootfs exists.  Please remove it if you want to re-extract"
	exit 1
fi

mkdir -p $rootfs

arch=amd64
url1=`ubuntu-cloudimg-query precise daily $arch --format "%{url}\n"`
url2=`echo $url1 | sed -e 's/.tar.gz/-root\0/'`
filename=`basename $url2`

if [ ! -f $filename ]; then
    wget $url2
fi

echo "Extracting rootfs"
cd lxc-rootfs
tar -zxf ../$filename

cd ..

seed_d=$rootfs/var/lib/cloud/seed/nocloud-net
hostid=$(uuidgen | cut -c -8)
mkdir -p $seed_d

cat > "$seed_d/meta-data" <<EOF
instance_id: lxc-$host_id
EOF

echo "#cloud-config" > $seed_d/user-data
if [ -z "$MIRROR" ]; then
    MIRROR="http://archive.ubuntu.com/ubuntu"
fi
echo "apt-mirror: $MIRROR" >> $seed_d/user-data

chroot $rootfs /usr/sbin/usermod -U ubuntu
