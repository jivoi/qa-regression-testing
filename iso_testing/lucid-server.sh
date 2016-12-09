#!/bin/sh

#    lucid-server.sh quality assurance test script for ISO testing
#    Copyright (C) 2009-2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# based on:
# http://testcases.qa.ubuntu.com/Install/ServerWhole

set -e

tmpdir=`mktemp -d`
trap "rm -rf $tmpdir" EXIT HUP INT QUIT TERM

ip_address=`ifconfig | grep -A1 eth0 | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1`

# Tests
test_mysql() {
    mysqlpass="pass"
    echo -n "Testing MySQL (with '$mysqlpass' as mysql root password): "
    cat > "$tmpdir/mysql.sql" << EOF
show databases;
connect mysql;
show tables;
select * from user;
EOF
    if ! mysql --no-defaults -u root -h localhost -p${mysqlpass} < "$tmpdir/mysql.sql" >/dev/null ; then
	echo "FAIL"
else
	echo "PASS"
    fi
    rm -f ./mysql.sql
}

test_bind9() {
    error=
    echo -n "Testing bind9: "
    if ! pgrep named ; then
	error="yes"
    fi

    for i in tcp tcp6 udp udp6; do
        if ! sudo netstat -atuvpn | egrep '(127.0.0.1|::):53 .*' | egrep -v ESTABLISHED | grep $i ; then
            error="yes"
        fi
    done

    if ! host www.ubuntu.com localhost | grep "has address" ; then
        error="yes"
    fi
    if ! host -T www.ubuntu.com localhost | grep "has address" ; then
        error="yes"
    fi
    if ! host -6 www.ubuntu.com localhost | grep "has address" ; then
        error="yes"
    fi
    if ! host -T -6 www.ubuntu.com localhost | grep "has address" ; then
        error="yes"
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_apache() {
    echo -n "Testing Apache: "
    error=
    if ! w3m -dump http://127.0.0.1/ >/dev/null ; then
        error="yes"
    fi
    if ! wget http://127.0.0.1/index.html >/dev/null 2>/dev/null ; then
	error="yes"
    else
	if ! diff index.html /var/www/index.html ; then
            error="yes"
	fi
	rm -f index.html
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_cupsys() {
    echo -n "Testing CUPS: "
    if sudo /etc/init.d/cups status | grep "is running" ; then
	echo "PASS"
    else
	echo "FAIL"
    fi
}

test_ssh() {
    echo "Testing ssh: "
    error=
    if ! pgrep sshd  >/dev/null; then
	error="yes"
    fi

    if [ -z "$1" ]; then
        echo "Skipping login tests. Use '`basename $0` ssh <user@host>'"
        echo "Eg:"
        echo "$ `basename $0` ssh foo@192.168.122.1"
    else
        if ! ssh -tt $1 ssh -oStrictHostKeyChecking=no ${USER}@$ip_address /bin/true ; then
            error="yes"
        fi
    fi

    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_samba() {
    echo "Testing Samba: "
    echo -n "  smbd: "
    if pgrep smbd  >/dev/null; then
	echo PASS
    else
	echo "FAIL"
    fi

    echo -n "  nmbd: "
    if pgrep nmbd  >/dev/null; then
	echo PASS
    else
	echo "FAIL"
    fi

    echo -n "  winbindd: "
    if pgrep winbindd  >/dev/null; then
	echo PASS
    else
	echo "FAIL"
    fi

    echo -n "  SID checks: "
    error=
    if ! sudo net getlocalsid | egrep -qi 'SID for domain UBUNTU is: S\-1\-5' ; then
        error="yes"
    fi
    if ! net usersidlist | egrep -qi 'UBUNTU\\' ; then
        error="yes"
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_postgresql() {
    echo -n "Testing Postgresql: "
    error=""
    if ! sudo -u postgres psql -l >/dev/null; then
        error="yes"
    fi
    if ! sudo -u postgres createuser -DRS ${USER} >/dev/null; then
        error="yes"
    fi
    if ! sudo -u postgres createdb -O ${USER} ${USER}_db >/dev/null; then
        error="yes"
    fi
    if ! echo "\l" | psql ${USER}_db >/dev/null; then
        error="yes"
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_postfix() {
    if echo 'quit' | nc -q1 localhost 25 | grep 'Postfix' ; then
        echo PASS
    else
        echo FAIL
    fi
}

test_dovecot() {
    error=
    for i in 110 143 993 995; do
        if ! sudo netstat -ltnp | grep $i | grep 'dovecot' ; then
            error="yes"
        fi
    done
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_send() {
    error=
    sudo rm -f /var/mail/${USER}
    if ! echo foo | mail -s 'test' ${USER} ; then
        error="yes"
    fi
    sleep 5
    if ! grep foo /var/mail/${USER} ; then
        error="yes"
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_tomcat() {
    echo -n "Testing Tomcat: "
    error=
    if ! sudo netstat -ltnp | grep 'java' ; then
        error="yes"
    fi
    if ! w3m -dump http://127.0.0.1:8080/ | grep 'It works' ; then
        error="yes"
    fi
    if ! w3m -dump http://localhost:8080/examples/servlets/servlet/HelloWorldExample | grep 'Hello World' ; then
        error="yes"
    fi
    if ! w3m -dump http://localhost:8080/examples/jsp/jsp2/el/basic-arithmetic.jsp | grep 'Basic Arithmetic' ; then
        error="yes"
    fi
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

test_lvm() {
    echo -n "Mount: "
    if mount | grep -q '/dev/mapper/ubuntu-root on /' ; then
        echo PASS
    else
        echo FAIL
    fi

    echo -n "vgs: "
    if sudo vgs | grep -q ubuntu ; then
        echo PASS
    else
        echo FAIL
    fi

    echo "lvs: "
    for i in root swap ; do
        echo -n "  $i: "
        if sudo lvs | grep ubuntu | grep -q $i ; then
            echo PASS
        else
            echo FAIL
        fi
    done
}

test_securityfs() {
    if mount | grep '/sys/kernel/security type securityfs' ; then
        echo PASS
    else
        echo FAIL
    fi
}

test_raid1() {
    if ! which strings >/dev/null ; then
        echo "Installing binutils"
        sudo apt-get install -y binutils
    fi

    error=
    if ! mount | grep '/dev/md.* on /' ; then
        error="yes"
    fi
    if ! cat /proc/mdstat | grep 'md1 : active raid1' ; then
        error="yes"
    fi
    if ! cat /proc/swaps | grep '/dev/md1' ; then
        error="yes"
    fi
    if ! cat /proc/mdstat | grep 'md0 : active raid1' ; then
        error="yes"
    fi
    if ! sudo mdadm --detail /dev/md0 | grep 'Working Devices : 2' ; then
        error="yes"
    fi
    if ! sudo mdadm --detail /dev/md0 | grep 'Active Devices : 2' ; then
        error="yes"
    fi

    for i in $(sudo mdadm -Q --detail $(df -P /boot | grep ^/dev/ | cut -d" " -f1) | grep " /dev/" | awk '{print $NF}' | sed -e 's/[0-9]$//'); do
        if sudo dd if=$i bs=512 count=1 2>/dev/null | strings -a | grep -q GRUB ; then
             echo $i: found grub
        else
             echo $i: FAIL
             error="yes"
        fi
    done

    if ! cat /etc/initramfs-tools/conf.d/mdadm | grep 'BOOT_DEGRADED=true' ; then
        error="yes"
    fi

    if [ -z "$error" ]; then
        echo "PASS (please also test with disks removed - http://testcases.qa.ubuntu.com/Install/ServerRAID1)"
    else
        echo "FAIL"
    fi
}

test_php() {
    echo -n "Testing PHP (cli): "
    if ! which php >/dev/null ; then
        echo ""
        echo "Installing php5-cli"
        sudo apt-get install -y php5-cli
    fi

    error=
    if ! php -r 'phpinfo();' | grep -qi 'php version' ; then
        error="yes"
    fi

    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi

    echo -n "Testing PHP (mod_php): "
    error=
    cat > "$tmpdir/phptest.php" << EOF
<? phpinfo(); ?>
EOF
    sudo mv -f "$tmpdir/phptest.php" /var/www

    if ! w3m -dump http://127.0.0.1/phptest.php | grep -qi 'php version' ; then
        error="yes"
    fi

    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

case "$1" in
    apache)
        test_apache
        ;;
    bind9)
        test_bind9
        ;;
    cups)
        test_cupsys
        ;;
    dovecot)
        test_dovecot
        ;;
    elvm)
        test_lvm
        test_securityfs
        ;;
    lamp)
        test_apache
        test_mysql
        test_php
        ;;
    lvm)
        test_lvm
        ;;
    mail)
        test_postfix
        test_dovecot
        test_send
        ;;
    mysql)
        test_mysql
        ;;
    postfix)
        test_postfix
        ;;
    postgresql)
        test_postgresql
        ;;
    raid1)
        test_raid1
        ;;
    samba)
        test_samba
        ;;
    ssh)
        test_ssh $2
        ;;
    tomcat)
        test_tomcat
        ;;
    *)
        echo "`basename $0` apache|bind9|cupsys|dovecot|lamp|lvm|elvm|mail|mysql|postfix|postgresql|raid1|samba|ssh <user@host>|tomcat"
        exit 1
esac

