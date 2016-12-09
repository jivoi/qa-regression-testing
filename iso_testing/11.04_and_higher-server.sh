#!/bin/sh
#
#    natty-server.sh quality assurance test script for ISO testing
#    Copyright (C) 2009-2011 Canonical Ltd.
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
    if sudo service cups status | grep "/running" ; then
	echo "PASS"
    else
	echo "FAIL"
    fi
}

test_ssh() {
    login="$1"
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
        user="${USER}"
        if ! ssh -tt "$login" ssh -oStrictHostKeyChecking=no "$user"@$ip_address /bin/true ; then
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
    if ! sudo net getlocalsid | egrep -qi 'SID for domain .* is: S\-1\-5' ; then
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
    # to make this repeatable
    if ! sudo -u postgres dropdb ${USER}_db >/dev/null; then
        error="yes"
    fi
    if ! sudo -u postgres dropuser ${USER} >/dev/null; then
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
    echo "Mount:"
    if mount | grep '/dev/mapper/.*-root on / ' ; then
        echo PASS
    else
        echo FAIL
    fi

    echo "vgs:"
    if sudo vgs | grep '[0-9]\.[0-9][0-9]g ' ; then
        echo PASS
    else
        echo FAIL
    fi

    echo "lvs (root):"
    if sudo lvs | grep '  root' ; then
        echo PASS
    else
        echo FAIL
    fi

    echo "lvs (swap):"
    if sudo lvs | grep '  swap' ; then
        echo PASS
    else
        echo FAIL
    fi
}

test_securityfs() {
    if mount | grep '/sys/kernel/security type securityfs' ; then
        echo PASS
    else
        echo FAIL
    fi
}

test_raid1() {
    echo "Tests '/', '/home' and swap on RAID1. Assumes:"
    echo " - /dev/md0 is /"
    echo " - /dev/md1 is swap"
    echo " - /dev/md2 is /home"
    echo "See http://testcases.qa.ubuntu.com/Install/ServerRAID1 for details"
    echo ""

    pass="$1"
    if [ -z "$pass" ]; then
        pass="1"
    fi

    case "$pass" in
        1) test_raid1_pass1;;
        2) test_raid1_pass2;;
        3) test_raid1_pass3;;
        4) test_raid1_pass4;;
        5) test_raid1_pass5;;
        *) echo "`basename $0` raid1 <pass #>"
           exit 1
           ;;
    esac
}

raid_all_active() {
    error=
    echo "Test root on md:"
    if ! mount | grep '/dev/md0 on / ' ; then
        error="yes"
        echo "FAIL"
    fi
    echo "Test md for root is active:"
    if ! cat /proc/mdstat | grep 'md0 : active raid1' ; then
        error="yes"
        echo "FAIL"
    fi
    echo "Test /home on md:"
    if ! mount | grep '/dev/md2 on /home ' ; then
        error="yes"
        echo "FAIL"
    fi
    echo "Test md for /home is active:"
    if ! cat /proc/mdstat | grep 'md2 : active raid1' ; then
        error="yes"
        echo "FAIL"
    fi
    echo "Test swaps:"
    # encrypted swap can be on /dev/dm-
    if ! cat /proc/swaps | egrep '/dev/md1|/dev/dm\-' ; then
        error="yes"
        echo "FAIL"
    fi
    echo "Test md for swap is active:"
    if ! cat /proc/mdstat | grep 'md1 : active raid1' ; then
        error="yes"
        echo "FAIL"
    fi

    for i in `seq 0 2` ; do
        echo "Working devices for /dev/md$i:"
        if ! sudo mdadm --detail /dev/md$i | grep 'Working Devices : 2' ; then
            error="yes"
            echo "FAIL"
        fi
        echo "Active devices for /dev/md$i:"
        if ! sudo mdadm --detail /dev/md$i | grep 'Active Devices : 2' ; then
            error="yes"
            echo "FAIL"
        fi
    done

    if [ ! -z "$error" ]; then
        return 1
    fi
}

raid_all_degraded() {
    error=
    echo "Test md for root is degraded:"
    if ! sudo mdadm --detail /dev/md0 | grep 'degraded' ; then
        error="yes"
        echo "FAIL"
    fi

    # Swap doesn't fail immediately, so do it twice
    sudo mdadm --detail /dev/md1 2>&1 >/dev/null || true
    echo "Test md for swap is degraded:"
    if ! sudo mdadm --detail /dev/md1 | grep 'degraded' ; then
        error="yes"
        echo "FAIL"
    fi

    echo "Test md for /home is degraded:"
    if ! sudo mdadm --detail /dev/md2 | grep 'degraded' ; then
        error="yes"
        echo "FAIL"
    fi

    if [ ! -z "$error" ]; then
        return 1
    fi
}

test_raid1_pass1() {
    if ! which strings >/dev/null ; then
        echo "Installing binutils"
        sudo apt-get install -y binutils
    fi

    error=
    if ! raid_all_active ; then
        error="yes"
    fi

    for i in $(sudo mdadm -Q --detail $(df -P /boot | grep ^/dev/ | cut -d" " -f1) | grep " /dev/" | awk '{print $NF}' | sed -e 's/[0-9]$//'); do
        if sudo dd if=$i bs=512 count=1 2>/dev/null | strings -a | grep -q GRUB ; then
             echo $i: found grub
        else
    2        echo $i: FAIL
             error="yes"
        fi
    done

    if ! cat /etc/initramfs-tools/conf.d/mdadm | grep 'BOOT_DEGRADED=true' ; then
        error="yes"
    fi

    echo -n "Phase 1 (clean raid setup): "
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
        return
    fi

    cat <<EOM

Please move to phase 2 by doing the following:
1. shutdown the machine
2. disconnect disk 2 (or mark as <readonly/> in libvirt), leaving disk 1
   connected
3. start the machine
4. Run:
   `basename $0` raid1 2
EOM
}

test_raid1_pass2() {
    error=
    if ! raid_all_degraded ; then
        error="yes"
    fi

    sudo touch /testraid-root
    touch ~/testraid-home

    echo -n "Phase 2 (boot degraded with faulty disk 2): "
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
        return
    fi

    cat <<EOM

Please move to phase 3 by doing the following:
1. shutdown the machine
2. reconnect disk 2 (if using libvirt, remove <readonly/>) such that both disks
   are connected
3. start the machine
4. At this point the machine may boot into the initramfs (tested in 11.04) (if
   the resync isn't fast enough), all the way in or have errors with /home. If
   errors with /home, reboot. Once in initramfs or login, re-add the disk with
   (either in initramfs or after login):
   # mdadm /dev/md0 -a /dev/vdb1
   # mdadm /dev/md2 -a /dev/vdb6
   # mdadm /dev/md1 -a /dev/vdb5 # add swap last
   # reboot
5. Run:
   `basename $0` raid1 3
EOM
}

test_raid1_pass3() {
    error=
    if ! raid_all_active ; then
        error="yes"
    fi

    for i in /testraid-root ~/testraid-home ; do
        echo -n "Has '$i': "
        if [ ! -f "$i" ]; then
            error="yes"
            echo "FAIL"
        else
            echo "yes"
        fi
    done

    echo -n "Phase 3 (boot clean after degraded): "
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
        echo ""
        echo "Note: disks may be resyncing. See 'mdadm --detail /dev/md#' or"
        echo "'cat /proc/mdstat' and try again after sync is complete"
        return
    fi

    cat <<EOM

Please move to phase 4 by doing the following:
1. shutdown the machine
2. disconnect disk 1 (or mark as <readonly/> in libvirt), leaving disk 2
   connected
3. start the machine
4. Run:
   `basename $0` raid1 4
EOM
}

test_raid1_pass4() {
    error=
    if ! raid_all_degraded ; then
        error="yes"
    fi

    # Do this here to make sure that the files created in Phase 2 actually
    # made is (ie, the sync in Phase 3 worked)
    for i in /testraid-root ~/testraid-home ; do
        echo -n "Has '$i': "
        if [ ! -f "$i" ]; then
            error="yes"
            echo "FAIL"
        else
            echo "yes"
        fi
    done

    sudo rm -f /testraid-root
    rm -f ~/testraid-home

    echo -n "Phase 4 (boot degraded with faulty disk 1): "
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
        return
    fi

    echo "SUCCESS"
    return

    # this could be used, but the removing and adding of the same disks in the
    # way we did confusing mdadm. Ideally would add a new disks that has been
    # zeroed out, then repartition it, since that simulates life more.
    cat <<EOM

Please move to phase 5 by doing the following:
1. shutdown the machine
2. reconnect disk 1 (if using libvirt, remove <readonly/>) such that both disks
   are connected
3. start the machine
4. At this point the machine should boot into the initramfs (tested in 11.04) or
   boot without the first disk added. Re-add the disk with:
   # mdadm /dev/md0 -a /dev/vda1
   # mdadm /dev/md2 -a /dev/vda6
   # mdadm /dev/md1 -a /dev/vda5 # add swap last
   # reboot
5. Run:
   `basename $0` raid1 5
EOM
}

test_raid1_pass5() {
    echo "TODO: see comments at end of test_raid1_pass4() for details"
    return 0
    error=
    if ! raid_all_active ; then
        error="yes"
    fi

    for i in /testraid-root ~/testraid-home ; do
        echo -n "Does not have '$i': "
        if [ -f "$i" ]; then
            error="yes"
            echo "FAIL"
        else
            echo "yes"
        fi
    done

    echo -n "Phase 5 (boot clean after degraded #2): "
    if [ -z "$error" ]; then
        echo "PASS"
    else
        echo "FAIL"
        echo ""
        echo "Note: disks may be resyncing. See 'mdadm --detail /dev/md#' or"
        echo "'cat /proc/mdstat' and try again after sync is complete"
        return
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

if [ "$USER" = "root" ]; then
    echo "Please do not run this as root. The script will use sudo as needed."
    exit 1
fi

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
        test_raid1 $2
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
        ;;
esac

