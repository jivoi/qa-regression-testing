#!/bin/bash
#
#    libvirt-apparmor.sh quality assurance test script for libvirt with
#    the apparmor security driver integration
#
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
set -e

help() {
    cat << EOM
USAGE:  *** DEPRECATED ***
  libvirt-apparmor.sh [skip_apparmor] <vmname> [usb:<bus>,<device>] [remote:<ip address>]
  libvirt-apparmor.sh [skip_apparmor] example-xml

  Eg:
  $ libvirt-apparmor.sh foo
  $ libvirt-apparmor.sh foo usb:2,3
  $ libvirt-apparmor.sh foo usb:2,3 remote:192.168.122.203

<vmname> must exist in both qemu:///system and qemu:///session and
must be startable via 'virsh -c qemu:///(system|session) start <vmname>'.
If specifying a remote address, the <vmname> must be startable with
qemu+ssh://<ip address>/system.

Specifying example-xml will dump to stdout a machine definition that you
can modify for use with this script.

Specifying 'skip_apparmor' disables AppArmor specific tests for the security
driver.

** WARNING **
You should not use this script on a virtual machine you care about as
this script could inadvertantly change the domain xml. You have been
warned.
EOM
}

example_xml() {
    cat <<EOM
<domain type='qemu'>
  <name>###NAME (eg: foo)###</name>
  <uuid>###UUID (eg: a22e3930-d87a-584e-22b2-1d8950212bac)###</uuid>
  <memory>262144</memory>
  <currentMemory>65536</currentMemory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>restart</on_crash>
  <devices>
    <emulator>/usr/bin/qemu</emulator>
    <disk type='file' device='disk'>
      <source file='/home/<rest of path here>/foo.img'/>
      <target dev='hda' bus='ide'/>
    </disk>
    <disk type='file' device='cdrom'>
      <target dev='hdc' bus='ide'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <mac address='###MAC (eg: 54:52:00:29:7b:37)###'/>
      <source network='default'/>
    </interface>
    <input type='mouse' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' keymap='en-us'/>
    <video>
      <model type='cirrus' vram='9216' heads='1'/>
    </video>
  </devices>
</domain>
EOM
}

timeout="3"
vm=""
olduser="$USER"

skip_apparmor=
if [ "$1" = "skip_apparmor" ]; then
    echo "Skipping apparmor specific tests and using adjust_perms()"
    skip_apparmor="yes"
    shift
fi

if [ -z "$1" ]; then
    help
    exit 1
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    help
    exit 0
elif [ "$1" = "example-xml" ]; then
    example_xml
    exit 0
else
    vm="$1"
    shift
fi

if [ "$UID" = "0" ]; then
    echo "must not be root to run the script"
    exit 1
fi

if ! id | grep -q libvirtd ; then
    echo "Must be in group 'libvirtd' to run this script"
    exit 1
fi

usb=""
remote="none"
for i in "$@"
do
    if echo "$i" | egrep -q '^usb:' ; then
        usb="$i"
    fi
    if echo "$i" | egrep -q '^remote:' ; then
        remote=`echo $i | sed 's/^remote://g'`
    fi
done

if [ "$skip_apparmor" = "yes" ]; then
    if [ -d "/sys/kernel/security/apparmor" ]; then
        # we seem to have apparmor running, so let's fail if libvirtd is confined
        if sudo aa-status | grep -q '/usr/sbin/libvirtd (' ; then
            echo "ERROR: libvirtd is confined and specified skip_apparmor"
            exit 1
        fi
    fi
else
    if ! sudo aa-status >/dev/null; then
        echo "'sudo aa-status' failed"
        exit 1
    fi
fi

logfile="/var/log/kern.log"
if sudo ls /var/log/audit/audit.log >/dev/null 2>&1 ; then
    logfile="/var/log/audit/audit.log"
fi

#
# HELPERS
#
cleanup() {
    sudo chown $olduser "$tmpdir"

    virsh destroy "$1" >/dev/null 2>&1 || true
    virsh define "$2" >/dev/null 2>&1 || true
    sudo chown $olduser `get_first_disk qemu:///system $vm` || true

    virsh -c qemu:///session destroy "$1" >/dev/null 2>&1 || true
    virsh -c qemu:///session define "$2" >/dev/null 2>&1 || true
    sudo chown $olduser `get_first_disk qemu:///session $vm` || true

    if [ "$remote" != "none" ]; then
        virsh -c qemu+ssh://$remote/system destroy "$1" >/dev/null 2>&1 || true
        virsh -c qemu+ssh://$remote/system define "$2" >/dev/null 2>&1 || true
    fi
    if [ -f "$aa_files" ]; then
        sudo sh -c "cat /dev/null > \"$aa_files\""
    fi
}

uuid_profile_is_loaded() {
    u="$1"
    if ! sudo aa-status | egrep -q "$u \(" ; then
        return 1
    fi
}

uuid_is_confined() {
    u="$1"
    if [ "$skip_apparmor" = "yes" ]; then
        return
    fi

    if ! sudo aa-status | egrep -q "$u \(" ; then
        return 1
    fi
}

vm_is_confined() {
    c="$1"
    v="$2"
    u="$3"
    if ! virsh -c "$c" dominfo "$v" 2>/dev/null | egrep -q "$u \(" ; then
        return 1
    fi
}

get_first_disk() {
    c="$1"
    if [ -z "$2" ]; then
        exit 1
    fi
    vm="$2"

    in_disk="no"
    virsh -c "$c" dumpxml "$vm" 2>/dev/null | while read line ; do
        if echo "$line" | egrep -q '^<disk '; then
            in_disk="yes"
            continue
        elif [ "$in_disk" = "yes" ]; then
            if echo "$line" | egrep -q '^<source file=' ; then
                echo "$line" | cut -d "'" -f 2
                break
            fi
        fi
    done
}

get_first_disk_device() {
    c="$1"
    if [ -z "$2" ]; then
        exit 1
    fi
    vm="$2"

    in_disk="no"
    virsh -c "$c" dumpxml "$vm" 2>/dev/null | while read line ; do
        if echo "$line" | egrep -q '^<disk '; then
            in_disk="yes"
            continue
        elif [ "$in_disk" = "yes" ]; then
            if echo "$line" | egrep -q '^<target dev=' ; then
                echo "$line" | cut -d "'" -f 2
                break
            fi
        fi
    done
}

get_first_net_device() {
    c="$1"
    if [ -z "$2" ]; then
        exit 1
    fi
    vm="$2"

    in_interface="no"
    virsh -c "$c" dumpxml "$vm" 2>/dev/null | while read line ; do
        if echo "$line" | egrep -q '^<interface '; then
            in_interface="yes"
            continue
        elif [ "$in_interface" = "yes" ]; then
            if echo "$line" | egrep -q '^<target dev=' ; then
                echo "$line" | cut -d "'" -f 2
                break
            fi
        fi
    done
}

get_first_aoe() {
    if [ ! -d "/dev/etherd" ]; then
        return
    fi
    ls -1 /dev/etherd/e[0-9]* | head -1
}

runtest() {
    c="$1"
    cmd_args="$2"
    search="$3"
    m=""
    if [ "$4" = "no" ]; then
        m="no"
    fi
    if virsh -c "$c" $cmd_args 2>/dev/null | egrep -q "$search" ; then
        if [ "$m" = "no" ]; then
            echo FAIL
            return 1
        else
            echo pass
            return 0
        fi
    else
        if [ "$m" = "no" ]; then
            echo pass
            return 0
        else
            echo FAIL
            return 1
        fi
    fi
}

adjust_perms() {
    # adjust_perms <user> [<file>]
    if [ "$skip_apparmor" = "yes" ]; then
        change_to="$1"
        file="$2"
        if [ "$change_to" = "root" ]; then
            change_to="root:root"
        fi

        if [ ! -e "$file" ] && [ -d "$tmpdir" ]; then
            file="$tmpdir"
        fi
        #echo "AppArmor disabled, chown'ing '$file' to '$change_to'"
        if [ -d "$file" ]; then
            sudo chown -R "$change_to" "$file"
        else
            sudo chown "$change_to" "$file"
        fi
    fi
}

virsh_cmd_and_check() {
    # Helper for code reuse in the guest checks
    # virsh_cmd_and_check check_aa_files{_tail}[:file] <virsh args>

    check=""
    check_file=""
    invert_flag=""
    if [ "$skip_apparmor" = "yes" ]; then
        check="no_apparmor"
    elif echo "$1" | egrep -q '^check_aa_files:' ; then
        check=`echo "$1" | cut -d ':' -f 1`
        check_file=`echo "$1" | cut -d ':' -f 2`
        if echo "$1" | cut -d ':' -f 3 | grep -q 'invert' ; then
            invert_flag="-v"
        fi
    elif [ "$1" = "check_aa_files" ]; then
        check="$1"
    fi

    if [ -z "$1" ]; then
        echo "Need to specifiy arguments to virsh"
        return 2
    fi

    # bashism, shift didn't work in dash, so use this in bash
    if virsh ${*:2} >/dev/null 2>&1 && sleep "$timeout"; then
        if [ "$check" = "no_apparmor" ]; then
            return
        elif ! uuid_is_confined "$uuid"; then
            echo "FAIL ('$uuid' is not confined)"
            return 1
        fi
    else
        echo "FAIL ('virsh ${*:2}' exited with error)"
        return 1
    fi

    if [ "$check" = "check_aa_files" ] || [ "$check" = "check_aa_files_tail" ]; then
        if [ -n "$check_file" ]; then
            if [ -s "$aa_files" ] && grep $invert_flag -q "$check_file" "$aa_files"; then
                if [ "$check" = "check_aa_files_tail" ]; then
                    if sudo tail -1 $logfile | grep -q "$check_file" ; then
                        return
                    else
                        echo "FAIL (found denied message)"
                        return 1
                    fi
                fi
                return
            else
                if [ -z "$invert_flag" ]; then
                    echo "FAIL (couldn't find '$check_file' in '$aa_files')"
                else
                    echo "FAIL (found '$check_file' in '$aa_files')"
                fi
                return 1
            fi
        elif [ ! -s "$aa_files" ]; then
            echo "FAIL (couldn't find $aa_files)"
            return 1
        fi
    fi
}

#
# MAIN
#
echo "*** THIS SCRIPT IS DEPRECATED. THESE TESTS HAVE BEEN MOVED TO test-libvirt.py ***"
errors=
tmpdir=`mktemp -d`	# Needs to be in a root owned directory, for later
                        # versions of libvirt when not using apparmor
save_tmpdir=`TMPDIR="$HOME" mktemp -d`	# LP: #457716

# why do this? Because when running libvirt as non-root the directory needs
# write access by the non-root kvm user
kvm_user=`egrep '^user *=' /etc/libvirt/qemu.conf | sed 's/.*= *"\(.*\)"/\1/g'`
kvm_group=`egrep '^group *=' /etc/libvirt/qemu.conf | sed 's/.*= *"\(.*\)"/\1/g'`
if [ "$kvm_group" != "root" ]; then
    sudo chgrp "$kvm_group" "$save_tmpdir"
    chmod 770 "$save_tmpdir"
fi

chmod 755 "$tmpdir"

xml="$tmpdir/xml"
orig="$tmpdir/orig"
trap "cleanup "$vm" "$orig" ; rm -rf $tmpdir $save_tmpdir" EXIT HUP INT QUIT TERM

virsh dumpxml "$vm" 2>/dev/null | sed 's/pc-[0-9.]*/pc/g' > "$orig" || {
    echo "'virsh dumpxml \"$vm\" failed'"
    exit 1
}
set +e
error_output=`virsh define "$orig" 2>&1`
if [ "$?" != "0" ]; then
    echo "'virsh define "$orig"' failed:"
    echo "$error_output"
    exit 1
fi
set -e

virsh_version=`virsh --version`

echo "Name: $vm"
echo "Version (virsh): $virsh_version"
echo ""


#
# qemu:///system and qemu:///session shared tests
#
for i in system session remote ; do
    if [ "$i" = "remote" ] && [ "$remote" = "none" ]; then
        continue
    fi
    match=
    cp "$orig" "$xml"

    conn="qemu:///system"
    if [ "$i" = "session" ]; then
        conn="qemu:///session"
        match="no"
        cat "$orig" | tr -d '\n\r' | sed "s#<interface type='network'>.*</interface>##g" > "$xml"
        # Change back the ownership of the disk file (needed in later libvirt
        # versions due to the DAC security driver)
        sudo chown $olduser `get_first_disk $conn $vm`
    elif [ "$i" = "remote" ]; then
        # only 'system' is supported with remote connections
        conn="qemu+ssh://$remote/system"
    fi

    if [ "$skip_apparmor" = "yes" ]; then
        match="no"
    fi

    echo "== libvirtd ($conn) =="
    echo -n "domuuid: "
    uuid=`virsh -c $conn domuuid "$vm" 2>/dev/null | head -1`
    if [ -z "$uuid" ]; then
        echo "FAIL (couldn't find UUID for '$vm')"
        exit 1
    else
        echo "pass ($uuid)"
    fi

    echo -n "domname: "
    runtest $conn "domname $uuid" "$vm" || errors="yes"

    echo -n "dominfo: "
    runtest $conn "dominfo $vm" apparmor $match || errors="yes"

    echo -n "nodeinfo: "
    runtest $conn nodeinfo 'CPU model' || errors="yes"

    echo -n "hostname: "
    runtest $conn hostname '^[a-zA-Z0-9]' || errors="yes"

    echo -n "uri: "
    if [ "$i" = "remote" ]; then
        runtest $conn "uri" "qemu\+ssh://$remote/system" || errors="yes"
    else
        runtest $conn "uri" "$i" || errors="yes"
    fi

    echo -n "version: "
    runtest $conn "version" "libvir" || errors="yes"

    echo -n "list: "
    runtest $conn list 'Id Name' || errors="yes"

    echo -n "list --all: "
    runtest $conn "list --all" "$vm" || errors="yes"

    echo -n "capabilities: "
    runtest $conn capabilities secmodel $match || errors="yes"

    echo -n "define: "
    runtest $conn "define $xml" 'defined from' || errors="yes"

    echo -n "autostart: "
    runtest $conn "autostart $vm" "$vm marked as autostarted" || errors="yes"

    echo -n "autostart (disable): "
    runtest $conn "autostart --disable $vm" "$vm unmarked as autostarted" || errors="yes"

    echo -n "domstate (shut off): "
    runtest $conn "domstate $vm" "shut off" || errors="yes"

    current_maxmem=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'Max memory' | awk '{print $3}'`
    new_mem="131072"
    current_mem=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'Used memory' | awk '{print $3}'`
    if dpkg --compare-versions "$virsh_version" lt "0.7.7" && [ "$current_mem" = "65536" ] && [ "$current_maxmem" = "262144" ]; then
	# 0.7.7 dropped support for setmaxmem and doesn't properly support
	# setvcpus. Also, start the domain here since the domain wasn't started
        # yet
        if dpkg --compare-versions "$virsh_version" lt "0.7.7" ; then
            echo -n "setmem: "
            if virsh -c "$conn" setmem "$vm" $new_mem >/dev/null 2>&1 ; then
                current_mem=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'Used memory' | awk '{print $3}'`
                if [ "$current_mem" = "$new_mem" ]; then
                    echo pass
                else
                    echo FAIL
                    errors="yes"
                fi
            else
                echo FAIL
                errors="yes"
            fi

            echo -n "setmaxmem: "
            if virsh -c "$conn" setmaxmem "$vm" $new_mem >/dev/null 2>&1 ; then
                current_mem=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'Max memory' | awk '{print $3}'`
                if [ "$current_mem" = "$new_mem" ]; then
                    echo pass
                else
                    echo FAIL
                    errors="yes"
                fi
            else
                echo FAIL
                errors="yes"
            fi

            current_vcpus=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'CPU(s)' | awk '{print $2}'`
            new_vcpus="2"
            if [ "$current_vcpus" = "$new_vcpus" ]; then
                new_vcpus="1"
            fi
            echo -n "setvcpus: "
            if virsh -c "$conn" setvcpus "$vm" $new_vcpus >/dev/null 2>&1 ; then
                current_vcpus=`virsh -c "$conn" dominfo "$vm" 2>/dev/null | grep 'CPU(s)' | awk '{print $2}'`
                if [ "$current_vcpus" = "$new_vcpus" ]; then
                    echo pass
                else
                    echo FAIL
                    errors="yes"
                fi
            else
                echo FAIL
                errors="yes"
            fi
        fi
    else
        echo -n "set*: "
        echo "skipped (virsh must be < 0.7.7, memory must be 262144 and currentMemory must be 65536)"
    fi

    echo -n "start: "
    runtest $conn "start $vm" started || {
        errors="yes"
        echo FAIL
        echo "Aborting to avoid VM corruption"
        cleanup "$create_name" "$orig"
        exit 1
    }

    if [ "$skip_apparmor" != "yes" ]; then
        echo -n "confined after start: "
        sleep "$timeout"
        if vm_is_confined $conn "$vm" "$uuid" ; then
            if [ "$i" = "system" ] || [ "$i" = "remote" ]; then
                echo pass
            else
                echo FAIL
                errors="yes"
            fi
        else
            if [ "$i" = "session" ]; then
                echo pass
            else
                echo FAIL
                errors="yes"
            fi
        fi
    fi

    # must be tested after the VM is started
    echo -n "dumpxml: "
    runtest $conn "dumpxml $vm" 'apparmor' $match || errors="yes"

    echo -n "domid: "
    runtest $conn "domid $uuid" "^[0-9]" || errors="yes"

    echo -n "domblkstat: "
    first_disk_device=`get_first_disk_device $conn $vm`
    runtest $conn "domblkstat $vm $first_disk_device" "$first_disk_device rd_req" || errors="yes"

    echo -n "domifstat: "
    first_net_device=`get_first_net_device $conn $vm`
    if [ -z "$first_net_device" ]; then
        echo "skipped (no net device found)"
    else
        runtest $conn "domifstat $vm $first_net_device" "$first_net_device rx_bytes" || errors="yes"
    fi

    echo -n "vcpuinfo: "
    runtest $conn "vcpuinfo $vm" "VCPU:" || errors="yes"

    echo -n "vcpupin: "
    if virsh -c "$conn" vcpupin "$vm" 0 0 >/dev/null 2>&1 ; then
        echo pass
    else
        echo FAIL
        errors="yes"
    fi

    echo -n "suspend: "
    runtest $conn "suspend $vm" suspended || errors="yes"

    sleep 1
    echo -n "domstate (paused): "
    runtest $conn "domstate $vm" "paused" || errors="yes"

    echo -n "resume: "
    runtest $conn "resume $vm" resumed || errors="yes"

    echo -n "domstate (running): "
    runtest $conn "domstate $vm" "running" || errors="yes"

    # while save/restore does work with a remote url, it uses whatever
    # directory the state file is in, and that doesn't exist on the remote
    # system since we used mktemp
    if [ "$i" != "remote" ]; then
      if dpkg --compare-versions "$virsh_version" ge "0.8.5"; then
        # FIXME: 0.8.5 and higher don't work well with this and nested virtualization
        echo "save/restore: skipping, 0.8.5 known not to work"
      else
        state_file="$save_tmpdir/state"
        # 0.8.3 has the AppArmor implementation for save/restore
        if [ "$i" != "session" ] || dpkg --compare-versions "$virsh_version" ge "0.8.3" ; then
            adjust_perms "$kvm_user" "$save_tmpdir"
        fi

        echo -n "save: "
        runtest $conn "save $vm $state_file" "saved to" || errors="yes"

        echo -n "domstate (shut off after save): "
        runtest $conn "domstate $vm" "shut off" || errors="yes"

        echo -n "restore: "
        runtest $conn "restore $state_file" "restored from" || errors="yes"

        echo -n "domstate (running after restore): "
        runtest $conn "domstate $vm" "running" || errors="yes"

        if [ "$i" != "session" ] || dpkg --compare-versions "$virsh_version" ge "0.8.3" ; then
            adjust_perms "$olduser" "$save_tmpdir"
        fi
        rm -f "$state_file"
      fi
    fi

    echo -n "destroy: "
    runtest $conn "destroy $vm" destroyed || {
        errors="yes"
        echo FAIL
        echo "Aborting to avoid VM corruption"
        cleanup "$vm" "$orig"
        exit 1
    }
    if [ "$skip_apparmor" != "yes" ]; then
        echo -n "confined after destroy: "
        sleep "$timeout"
        if ! vm_is_confined $conn "$vm" "$uuid" && ! uuid_profile_is_loaded "$uuid" ; then
            echo pass
        else
            echo FAIL
            errors="yes"
        fi
    fi
    cleanup "$vm" "$orig"

    create_name="test-libvirt-create"
    create_uuid=""
    echo -n "create ($create_name): "
    cat "$orig" | tr -d '\n\r' | sed "s#<interface type='network'>.*</interface>##g" > "$xml"
    sed -i "s,<name>.*</name>,<name>$create_name</name>,g" "$xml"
    sed -i "s,<uuid>.*</uuid>,,g" "$xml"
    runtest $conn "create $xml" created || errors="yes"
    sleep "$timeout"
    create_uuid=`virsh -c $conn domuuid "$create_name" 2>/dev/null | head -1`

    if [ "$skip_apparmor" != "yes" ]; then
    echo -n "confined after create: "
        if vm_is_confined $conn "$create_name" "$create_uuid" ; then
            if [ "$i" = "system" ] || [ "$i" = "remote" ]; then
                echo pass
            else
                echo FAIL
                errors="yes"
            fi
        else
            if [ "$i" = "session" ]; then
                echo pass
            else
                echo FAIL
                errors="yes"
            fi
        fi
    fi

    echo -n "destroy ($create_name): "
    runtest $conn "destroy $create_name" destroyed || {
        errors="yes"
        echo FAIL
        echo "Aborting to avoid VM corruption"
        cleanup "$create_name" "$orig"
        exit 1
    }

    if [ "$skip_apparmor" != "yes" ]; then
        echo -n "confined after destroy ($create_name): "
        sleep "$timeout"
        if ! vm_is_confined $conn "$create_name" "$create_uuid" ; then
            echo pass
        else
            echo FAIL
            errors="yes"
        fi
    fi
    cleanup "$create_name" "$orig"

    echo ""
done

#
# The rest of the tests assume qemu:///system
#
conn="qemu:///system"
uuid=`virsh -c $conn domuuid "$vm" 2>/dev/null | head -1`
aa_files="/etc/apparmor.d/libvirt/libvirt-${uuid}.files"


#
# TEST EMULATORS
#
echo "== emulators =="
echo -n "kvm: "
if [ ! -e "/dev/kvm" ]; then
    echo "skipping, /dev/kvm does not exist"
else
    cat "$orig" | sed "s#<domain type=.*#<domain type='kvm'>#" > "$tmpdir/tmp.xml"
    cat "$tmpdir/tmp.xml" | sed "s#<emulator>.*#<emulator>/usr/bin/kvm</emulator>#" > "$xml"
    virsh -c $conn define "$xml" >/dev/null 2>&1
    if virsh -c $conn start "$vm" >/dev/null 2>&1 && sleep "$timeout" && uuid_is_confined "$uuid" ; then
        echo pass
    else
        errors="yes"
        echo FAIL
    fi
    cleanup "$vm" "$orig"
fi

echo -n "kqemu: "
if [ ! -e "/dev/kqemu" ]; then
    echo "skipping, /dev/kqemu does not exist"
else
    cat "$orig" | sed "s#<domain type=.*#<domain type='kqemu'>#" > "$tmpdir/tmp.xml"
    cat "$tmpdir/tmp.xml" | sed "s#<emulator>.*#<emulator>/usr/bin/qemu</emulator>#" > "$xml"
    virsh -c $conn define "$xml" >/dev/null 2>&1
    if virsh -c $conn start "$vm" >/dev/null 2>&1 && sleep "$timeout" && uuid_is_confined "$uuid" ; then
        echo pass
    else
        errors="yes"
        echo FAIL
    fi
    cleanup "$vm" "$orig"
fi

echo -n "qemu: "
cat "$orig" | sed "s#<domain type=.*#<domain type='qemu'>#" > "$tmpdir/tmp.xml"
cat "$tmpdir/tmp.xml" | sed "s#<emulator>.*#<emulator>/usr/bin/qemu</emulator>#" > "$xml"
virsh -c $conn define "$xml" >/dev/null 2>&1
if virsh -c $conn start "$vm" >/dev/null 2>&1 && sleep "$timeout" && uuid_is_confined "$uuid" ; then
    echo pass
else
    errors="yes"
    echo FAIL
fi
cleanup "$vm" "$orig"


#
# NETWORK TESTS
#
echo ""
echo "== network =="
net_xml="$tmpdir/net.xml"
net_xml2="$tmpdir/net2.xml"
net_name="libvirt-apparmor-test-network"
net_br="virbr100"
net_prefix="169.254.254"
cat > $net_xml << EOM
<network>
  <name>$net_name</name>
  <forward mode='nat'/>
  <bridge name='$net_br' stp='on' forwardDelay='0' />
  <ip address='$net_prefix.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='$net_prefix.2' end='$net_prefix.254' />
    </dhcp>
  </ip>
</network>
EOM
echo -n "net-define: "
runtest $conn "net-define $net_xml" defined || errors="yes"

echo -n "net-list --all: "
runtest $conn "net-list --all" "$net_name" || errors="yes"

echo -n "net-start: "
runtest $conn "net-start $net_name" started || errors="yes"

echo -n "net-list: "
runtest $conn net-list "$net_name" || errors="yes"

echo -n "net-dumpxml: "
runtest $conn "net-dumpxml $net_name" "$net_prefix" || errors="yes"

echo -n "net-autostart: "
runtest $conn "net-autostart $net_name" " marked as autostarted" || errors="yes"

echo -n "net-autostart (disable): "
runtest $conn "net-autostart $net_name --disable" "unmarked as autostarted" || errors="yes"

echo -n "net-uuid: "
net_uuid=`virsh -c $conn net-uuid "$net_name" 2>/dev/null | head -1`
if [ -z "$net_uuid" ]; then
    echo FAIL
else
    echo pass
fi

echo -n "net-name: "
if [ -z "$net_uuid" ]; then
    echo "skipped (no network uuid)"
else
    runtest $conn "net-name $net_uuid" "" || errors="yes"
fi

echo -n "net-destroy: "
runtest $conn "net-destroy $net_name" destroyed || errors="yes"

echo -n "net-undefine: "
runtest $conn "net-undefine $net_name" undefined || errors="yes"

echo -n "net-list --all (after undefine): "
runtest $conn "net-list --all" "$net_name" no || errors="yes"

echo -n "net-create: "
runtest $conn "net-create $net_xml" created || errors="yes"

echo -n "net-list (after create): "
runtest $conn net-list "$net_name" || errors="yes"

echo -n "net-destroy (after create): "
runtest $conn "net-destroy $net_name" destroyed || errors="yes"

echo -n "net-list --all (after create/destroy): "
runtest $conn "net-list --all" "$net_name" no || errors="yes"


#
# GUEST TESTS
# These tests need to use adjust_perms() when not using apparmor, since at that
# point the DAC security driver kicks in and requires the disks being added be
# owned by the user in /etc/libvirt/qemu.conf (on Ubuntu, root).
#
echo ""
echo "== guests =="
device_xml="$tmpdir/device.xml"
device_disk="$tmpdir/device_disk.img"
dd if=/dev/zero of=$device_disk bs=1M count=64 >/dev/null 2>&1
cat > "$device_xml" << EOM
<disk type='block'>
  <driver name='phy'/>
  <source dev='$device_disk'/>
  <target dev='sdb'/>
</disk>
EOM
adjust_perms "$kvm_user"

echo "attach/detach: "
# start the vm
echo -n "  start VM: "
attach_err=""
if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
    # give the guest a chance to come up to avoid:
    # https://bugs.launchpad.net/ubuntu/+source/libvirt/+bug/435527/comments/3
    echo "pass (sleeping 30 seconds to avoid LP: #435527)"
    sleep 30
else
    errors="yes"
    attach_err="yes"
fi

new_mac="52:00:00:00:00:00"
if dpkg --compare-versions "$virsh_version" ge "0.8.3" && dpkg --compare-versions "$virsh_version" lt "0.8.4"; then
    echo "SKIP: attach-interface (LP: #618916)"
else
    if [ -z "$attach_err" ]; then
        echo -n "  attach-interface: "
        if virsh -c $conn attach-interface "$vm" network default --mac "$new_mac" >/dev/null 2>&1 ; then
            echo pass
        else
            echo FAIL
            errors="yes"
            attach_err="yes"
        fi
    fi
    if [ -z "$attach_err" ]; then
    echo -n "  detach-interface: "
        if virsh -c $conn detach-interface "$vm" network --mac "$new_mac" >/dev/null 2>&1; then
            echo pass
        else
            echo FAIL
            errors="yes"
            attach_err="yes"
        fi
    fi
fi

if [ -z "$attach_err" ]; then
    echo -n "  attach-device: "
    if virsh_cmd_and_check check_aa_files_tail:"$device_disk" -c $conn attach-device "$vm" "$device_xml"; then
        echo pass
    else
        errors="yes"
        attach_err="yes"
    fi
fi
if [ -z "$attach_err" ]; then
    echo -n "  detach-device: "
    if dpkg --compare-versions "$virsh_version" ge "0.7.7"; then
        echo "skipped (cannot hot unplug physical block device with qemu in 0.7.7 and higher)"
    else
        if virsh_cmd_and_check check_aa_files:"$device_disk":invert -c $conn detach-device "$vm" "$device_xml" ; then
            echo pass
        else
            errors="yes"
            attach_err="yes"
        fi
    fi
fi

if [ -z "$attach_err" ]; then
    echo -n "  attach-disk: "
    if virsh_cmd_and_check check_aa_files_tail:"$device_disk" -c $conn attach-disk "$vm" "$device_disk" sdc --driver file ; then
        echo pass
    else
        errors="yes"
        attach_err="yes"
    fi
fi
if [ -z "$attach_err" ]; then
    echo -n "  detach-disk: "
    if dpkg --compare-versions "$virsh_version" ge "0.7.7"; then
        echo "skipped (cannot hot unplug scsi device with qemu in 0.7.7 and higher)"
    else
        if virsh_cmd_and_check check_aa_files:"$device_disk":invert -c $conn detach-disk "$vm" sdc ; then
            echo pass
        else
            errors="yes"
            attach_err="yes"
        fi
    fi
fi

# Since 0.7.7 and higher don't detach scsi devices
cleanup "$vm" "$orig"
virsh -c $conn start "$vm" >/dev/null 2>&1 || {
    errors="yes"
    echo FAIL
}

if [ -z "$attach_err" ] && [ -n "$usb" ]; then
    echo -n "  attach-device (USB): "
    usbbus=`echo "$usb" | cut -d ':' -f 2 | cut -d ',' -f 1`
    usbdev=`echo "$usb" | cut -d ':' -f 2 | cut -d ',' -f 2`
    if [ -z "$usbbus" ] || [ -z "$usbdev" ]; then
        echo "ERROR (could not find bus or device)"
    else
        adjust_perms "$olduser"
        cat > "$device_xml" << EOM
<hostdev mode='subsystem' type='usb'>
  <source>
    <address bus='$usbbus' device='$usbdev'/>
  </source>
</hostdev>
EOM
        adjust_perms "$kvm_user"

        if virsh_cmd_and_check check_aa_files:"/bus/" -c $conn attach-device "$vm" "$device_xml" ; then
            if sudo tail -1 $logfile | grep -q "$device_disk" ; then
                echo "FAIL: found denied message for '$device_disk'"
            else
                echo pass
            fi
        else
            errors="yes"
            attach_err="yes"
        fi
        if [ -z "$attach_err" ]; then
            echo -n "  detach-device (USB): "
            if virsh_cmd_and_check check_aa_files:"/bus/":invert -c $conn detach-device "$vm" "$device_xml" ; then
                echo pass
            else
                errors="yes"
                attach_err="yes"
            fi
        fi
    fi
fi

# TODO: also hot attach a scsi disk when libvirt supports it (https://bugs.launchpad.net/ubuntu/+source/eucalyptus/+bug/432154/comments/26)
adjust_perms "$olduser"
cat > "$device_xml" << EOM
<disk type='file' device='disk'>
  <source file='$device_disk'/>
  <target dev='vdb' bus='virtio'/>
</disk>
EOM
adjust_perms "$kvm_user"
for i in `seq 1 4`; do
    if [ -z "$attach_err" ]; then
        echo -n "  attach-device (virtio #$i): "
        if virsh_cmd_and_check check_aa_files_tail:"$device_disk" -c $conn attach-device "$vm" "$device_xml" ; then
            echo pass
        else
            errors="yes"
            attach_err="yes"
        fi
    fi
    if [ -z "$attach_err" ]; then
        echo -n "  detach-device (virtio #$i): "
        if virsh_cmd_and_check check_aa_files:"$device_disk":invert -c $conn detach-device "$vm" "$device_xml" ; then
            echo pass
        else
            errors="yes"
            attach_err="yes"
        fi
    fi
    # 0.8.5 and higher needs a restart of the vm otherwise get:
    # error: operation failed: adding
    # virtio-blk-pci,bus=pci.0,addr=0x5,drive=drive-virtio-disk1,id=virtio-disk1 device failed: Duplicate ID 'virtio-disk1' for device
    if [ -z "$attach_err" ] && dpkg --compare-versions "$virsh_version" ge "0.8.5"; then
        echo -n "  restarting vm and sleeping for 30 seconds (0.8.5 and higher): "
        virsh -c $conn destroy "$vm" >/dev/null 2>&1 || true
        if runtest $conn "start $vm" started ; then
            # give the guest a chance to come up to avoid:
            # https://bugs.launchpad.net/ubuntu/+source/libvirt/+bug/435527/comments/3
            sleep 30
        else
            errors="yes"
            attach_err="yes"
        fi
    fi
done

if [ -z "$attach_err" ]; then
    device_aoe=`get_first_aoe`
    echo -n "  attach-device (aoe): "
    if [ -z "$device_aoe" ]; then
        echo "skipped (could not find AoE device)"
    else
        adjust_perms "$olduser"
        cat > "$device_xml" << EOM
<disk type='block'>
  <driver name='virtio'/>
  <source dev='$device_aoe'/>
  <target dev='vdb' bus='virtio'/>
</disk>
EOM
        adjust_perms "$kvm_user"

        if check_aa_files_tail:"$device_aoe" -c $conn attach-device "$vm" "$device_xml" ; then
            echo pass
        else
            echo "  (might have hit https://launchpad.net/bugs/455832)"
            errors="yes"
            attach_err="yes"
        fi
        if [ -z "$attach_err" ]; then
            echo -n "  detach-device (aoe): "
            if virsh_cmd_and_check check_aa_files:"$device_aoe":invert -c $conn detach-device "$vm" "$device_xml" ; then
                echo pass
            else
                errors="yes"
                attach_err="yes"
            fi
        fi
    fi
fi
cleanup "$vm" "$orig"

echo -n "alternate kernel and initrd: "
kernel="/vmlinuz"
initrd="/initrd.img"
if [ ! -e "$kernel" ] || [ ! -e "$initrd" ]; then
    echo "skipped (couldn't find $kernel or $initrd"
else
    adjust_perms "$olduser"
    cat "$orig" | sed "s#</os>#<kernel>$kernel</kernel><initrd>$initrd</initrd></os>#g" > "$xml"
    adjust_perms "$kvm_user"
    virsh -c $conn define "$xml" >/dev/null 2>&1
    if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
        if [ "$skip_apparmor" = "yes" ]; then
            echo pass
        elif [ -s "$aa_files" ] && grep -q "$kernel" "$aa_files" && grep -q "$initrd" "$aa_files"; then
            echo pass
        else
            echo "FAIL"
            errors="yes"
        fi
    else
        errors="yes"
        echo FAIL
    fi
fi
cleanup "$vm" "$orig"

echo -n "alternate serial: "
serial="$tmpdir/serial.log"
adjust_perms "$olduser"
cat "$orig" | sed "s#</devices>#<serial type='file'><source path='$serial'/><target port='0'/></serial></devices>#g" > "$xml"
adjust_perms "$kvm_user"
virsh -c $conn define "$xml" >/dev/null 2>&1
if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
    if [ "$skip_apparmor" = "yes" ]; then
        echo pass
    elif [ -s "$aa_files" ] && grep -q "$serial" "$aa_files" && [ -e "$serial" ]; then
        echo pass
    else
        echo "FAIL"
        errors="yes"
    fi
else
    errors="yes"
fi
cleanup "$vm" "$orig"

echo -n "alternate console: "
console="$tmpdir/console.log"
adjust_perms "$olduser"
cat "$orig" | sed "s#</devices>#<console type='file'><source path='$console'/><target port='0'/></console></devices>#g" > "$xml"
adjust_perms "$kvm_user"
virsh -c $conn define "$xml" >/dev/null 2>&1
if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
    if [ "$skip_apparmor" = "yes" ]; then
        echo pass
    elif [ -s "$aa_files" ] && grep -q "$console" "$aa_files" && [ -e "$console" ]; then
        echo pass
    else
        echo "FAIL"
        errors="yes"
    fi
else
    errors="yes"
fi
cleanup "$vm" "$orig"

echo -n "relative path: "
adjust_perms "$olduser"
cat "$orig" | sed "s#file='/#file='/./#" > "$xml"
adjust_perms "$kvm_user"
virsh -c $conn define "$xml" >/dev/null 2>&1
if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
    echo pass
else
    errors="yes"
    echo FAIL
fi
cleanup "$vm" "$orig"

echo -n "space in path: "
fn="$tmpdir/disk with space.img"
touch "$fn"
adjust_perms "$olduser"
cat "$orig" | sed "s#file=.*'/>#file='$fn'/>#" > "$xml"
adjust_perms "$kvm_user"
virsh -c $conn define "$xml" >/dev/null 2>&1
if virsh_cmd_and_check check_aa_files -c $conn start "$vm" ; then
    if [ "$skip_apparmor" = "yes" ]; then
        echo pass
    elif [ -s "$aa_files" ] && grep -q "$fn" "$aa_files"; then
        echo pass
    else
        echo "FAIL"
        errors="yes"
    fi
else
    errors="yes"
fi
cleanup "$vm" "$orig"

echo -n "symlink in path: "
disk=`get_first_disk $conn $vm`
if [ -f "$disk" ]; then
    ln -s "$disk" "$tmpdir/ln-s"
    adjust_perms "$olduser"
    cat "$orig" | sed "s#file=.*'/>#file='$tmpdir/ln-s'/>#" > "$xml"
    adjust_perms "$kvm_user"
    virsh -c $conn define "$xml" >/dev/null 2>&1
    if virsh_cmd_and_check check_aa_files:"$disk" -c $conn start "$vm"; then
        echo pass
    else
        errors="yes"
    fi
else
    errors="yes"
    echo "ERROR: couldn't find '$disk'"
fi
cleanup "$vm" "$orig"


echo "*** THIS SCRIPT IS DEPRECATED. THESE TESTS HAVE BEEN MOVED TO test-libvirt.py ***"
echo ""
if [ -n "$errors" ]; then
    echo FAIL
    exit 1
fi
echo PASS
