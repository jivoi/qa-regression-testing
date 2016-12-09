#!/bin/sh
#
#    Copyright (C) 2012 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# This script was developed on Ubuntu 12.04 and is used to configure
# the 'local:' juju environment (ie, juju with LXC). There are several
# limitations to this enviornment:
# https://juju.ubuntu.com/docs/provider-configuration-local.html
#
# Troubleshooting:
# Look in $HOME/juju-local/$USER-local/units/master-customize.log for LXC
# set and $HOME/juju-local/$USER-local/units/*/unit.log or container.log.
#
# To start from scratch again:
# $ sudo juju destroy-environment
# $ sudo rm -rf ./juju-local # not documented
# $ juju bootstrap
#
# For most up to date documentaion, see:
# https://juju.ubuntu.com/docs/

set -e

VMNET="192.168.123"

echo "Installing packages"
sudo apt-get install juju charm-tools apt-cacher-ng zookeeper libvirt-bin lxc || true

echo "Adding $USER to libvirtd group"
sudo adduser $USER libvirtd || true

echo "Adjusting libvirt default network to $VMNET"
if sg libvirtd -c "virsh net-dumpxml default" | grep -q "192.168.122" ; then
    tmp=`mktemp`
    sg libvirtd -c "virsh net-dumpxml default | sed 's/192.168.122/$VMNET/g' > $tmp"
    sg libvirtd -c "virsh net-define $tmp"
    #sg libvirtd -c "virsh net-start default"
    rm -f "$tmp"
else
    echo "(not needed)"
fi

echo "Adjusting juju-create to use $VMNET"
if grep -q "192.168.122" /usr/share/pyshared/juju/lib/lxc/data/juju-create ; then
    sudo sed -i "s/192.168.122/$VMNET/g" /usr/share/pyshared/juju/lib/lxc/data/juju-create
else
    echo "(not needed)"
fi

if [ ! -d "$HOME/.juju" ]; then
    echo "Creating $HOME/.juju/environments.yaml to use 'juju-local'"
    mkdir "$HOME/.juju"
    cat > "$HOME/.juju/environments.yaml" <<EOF
environments:
  local:
    type: local
    data-dir: $HOME/juju-local
    admin-secret: abcdefghijklmnopqrstuvwxyz1234567890
    control-bucket: foo-bucket
    default-series: oneiric
EOF
    chmod 600 "$HOME/.juju/environments.yaml"
fi

if [ ! -e "$HOME/.ssh/id_rsa" ]; then
    echo "Creating ssh key"
    ssh-keygen -t rsa -b 2048 -f "$HOME/.ssh/id_rsa"
fi

if [ ! -d "$HOME/juju-local" ]; then
    echo "Calling juju bootstrap"
    sg libvirtd -c "juju bootstrap"

    sleep 3
    sg libvirtd -c "juju status"
fi

cat <<EOM
At this point, you should:
$ sg libvirtd

Setup ssh-agent:
$ ssh-agent > $HOME/.ssh/environment
$ chmod 600 $HOME/.ssh/environment
$ . $HOME/.ssh/environment
$ ssh-add

Now start using juju! Eg:
$ juju deploy --repository=/usr/share/doc/juju/examples local:oneiric/wordpress
$ juju deploy --repository=/usr/share/doc/juju/examples local:oneiric/mysql
$ juju add-relation wordpress mysql
$ juju expose wordpress
$ juju status

NOTE: it will take a while for the machines to debootstrap, so be patient.

You can start from scratch with:
$ sudo juju destroy-environment
$ sudo rm -rf $HOME/juju-local
$ `basename $0`
EOM
