#!/bin/sh
# Copyright (C) 2012 Canonical Ltd.
# Author: Jamie Strandboge <jamie@canonical.com>
#
# License: GPLv3
# Based on http://jk.ozlabs.org/docs/sbkeysync-maintaing-uefi-key-databases/

set -e

sb_topdir="/etc/secureboot"
keystore="$sb_topdir/keys"
keystore_material="$sb_topdir/key-material"
efi_ubuntu="/boot/efi/EFI/ubuntu"
signed_grub="/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"
scriptdir="`dirname $0`"

create_keystore() {
    echo "Creating keystore... "
    echo "  mkdir '$keystore'"
    sudo mkdir -p "$keystore"
    for d in PK KEK db dbx ; do
        echo "  mkdir '$keystore/$d'"
        sudo mkdir "$keystore"/$d
    done
    echo "done"
    echo ""
}

generate_keys() {
    tmpdir=`mktemp -d`

    echo -n "Creating keys... "
    openssl genrsa -out "$tmpdir"/test-key.rsa 2048 2>/dev/null
    openssl req -new \
                -x509 \
                -sha256 \
                -subj '/CN=test-key' \
                -key "$tmpdir"/test-key.rsa \
                -out "$tmpdir"/test-cert.pem
    openssl x509 -in "$tmpdir"/test-cert.pem \
                 -inform PEM \
                 -out "$tmpdir"/test-cert.der \
                 -outform DER

    chmod 600 "$tmpdir"/*.rsa
    chmod 644 "$tmpdir"/*.pem
    chmod 644 "$tmpdir"/*.der
    chmod 755 "$tmpdir" # for directory listing later on
    sudo mv "$tmpdir" "$keystore_material"
    echo "done"
    echo ""
}

_create_key_update() {
    local guid="$1"
    local keydb="$2"
    local enroll_type="$3"
    local key_type="$4"

    echo "Generating key updates for $keydb... "

    echo "  using GUID=$guid"

    siglist_cert="$keystore_material"/test-cert.der
    if [ "$enroll_type" = "canonical" ]; then
        siglist_cert="$scriptdir"/keys/canonical-master-public.der
    elif [ "$enroll_type" = "microsoft" ]; then
        if [ "$keydb" = "KEK" ]; then
            siglist_cert="$scriptdir"/keys/microsoft-kekca-public.der
        elif [ "$keydb" = "db" ] && [ "$key_type" = "uefica" ]; then
            siglist_cert="$scriptdir"/keys/microsoft-uefica-public.der
        else
            siglist_cert="$scriptdir"/keys/microsoft-pca-public.der
        fi
    fi

    siglist="$keystore_material/`basename $siglist_cert`".siglist
    if [ ! -s "$siglist_cert" ]; then
        echo "ERROR: Could not find '$siglist_cert'. Aborting"
        exit 1
    fi
    echo "  creating EFI_SIGNATURE_LIST (`basename $siglist`)..."

    sbsiglist --owner $guid \
              --type x509 \
              --output "$siglist" \
              "$siglist_cert"

    echo "  creating signed update (`basename $siglist`.$keydb.signed)... "
    sbvarsign --key "$keystore_material"/test-key.rsa \
              --cert "$keystore_material"/test-cert.pem \
              --output "$siglist".$keydb.signed \
              $i \
              "$siglist"
    echo "done"
}

generate_key_updates() {
    local enroll_type="$1"

    # Each key gets its own guid, so it is easier to verify in the EFI
    # firmware configuration.
    # - User key: 1 GUID - user key (shared for PK, KEK and DB)
    # - Canonical: 1 GUID - Master CA (shared for KEK and DB)
    # - Microsoft: 3 GUIDs - KEK CA, PCA and UEFICA
    user_guid=$(uuidgen)
    vendor_guid=$(uuidgen)

    # Always add user key to PK and KEK (ie, user is platform owner)
    for i in PK KEK ; do
        _create_key_update "$user_guid" $i
    done

    # Add OS vendor key to KEK, if specified
    if [ -n "$enroll_type" ]; then
        _create_key_update "$vendor_guid" KEK "$enroll_type"
    fi

    # Add key(s) to db
    if [ "$enroll_type" = "microsoft" ]; then
        vendor_guid=$(uuidgen)
        _create_key_update "$vendor_guid" db "$enroll_type" "pca"
        vendor_guid=$(uuidgen)
        _create_key_update "$vendor_guid" db "$enroll_type" "uefica"
    elif [ "$enroll_type" = "canonical" ]; then
        _create_key_update "$vendor_guid" db "$enroll_type"
    else
        _create_key_update "$user_guid" db "$enroll_type"
    fi
}

add_keys_to_keystore() {
    echo "Initializing keystore..."
    for d in PK KEK db ; do
        echo "  adding to $keystore/$d/"
        sudo cp "$keystore_material"/*.$d.signed "$keystore/$d/"
    done
    echo "done"
    echo ""
}

enroll() {
    sbkeysync --verbose --pk --dry-run
    echo -n "Commit to keystore? (y|N) "
    read ans
    if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        sudo sbkeysync --verbose --pk
    else
        return 1
    fi
}

do_setup() {
    local enroll_type="$1"
    if [ ! -e "$keystore" ]; then
        create_keystore
    fi

    if [ ! -e "$keystore_material" ]; then
        generate_keys
    else
        echo "Using existing key material in '$keystore_material'"
    fi

    if ! `ls "$keystore_material"/$enroll_type*siglist >/dev/null 2>&1` ; then
        generate_key_updates "$enroll_type"
    else
        echo "Using existing signed updates in '$keystore_material/*.siglist'"
    fi

    if ! `ls "$keystore"/*/$enroll_type*signed >/dev/null 2>&1` ; then
        add_keys_to_keystore
    else
        echo "Using existing keystore files in '$keystore/*'"
    fi

    if ! `ls /sys/firmware/efi/efivars/PK-* >/dev/null 2>&1` ; then
        enroll || exit
    else
        echo "PK already enrolled. Skipping sbkeysync."
    fi
}

sign_bootloader() {
    local bootloader_type="$1"
    bootimg=`ls -1 "$efi_ubuntu"/$bootloader_type*.efi | head -1`
    if sbverify --cert "$keystore_material"/test-cert.pem "$bootimg" >/dev/null 2>&1 ; then
        echo "$bootimg already signed."
	return
    fi
    tmpdir=`mktemp -d`
    echo "Signing '$bootimg'"
    sbsign --key "$keystore_material"/test-key.rsa \
           --cert "$keystore_material"/test-cert.pem \
           --output "$tmpdir"/grubx64.efi \
           "$bootimg"
    if [ ! -e "$bootimg.bak" ]; then
        sudo cp "$bootimg" "$bootimg.bak"
    fi
    sudo cp -f "$tmpdir"/grubx64.efi "$bootimg"
    rm -rf "$tmpdir"
}

unenroll_pk() {
    if ! `ls /sys/firmware/efi/efivars/PK-* >/dev/null 2>&1` ; then
        echo "PK not enrolled in /sys/firmware/efi/efivars/PK-*"
        return
    fi
    echo "WARNING: this will deactivate secure boot by unenrolling PK."
    echo -n "Continue? (y|N) "
    read ans
    if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
        echo "Aborting"
	exit 0
    fi
    tmpdir=`mktemp -d`
    touch "$tmpdir"/empty
    sbvarsign --key "$keystore_material"/test-key.rsa \
              --cert "$keystore_material"/test-cert.pem \
              --attrs NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS \
              --include-attrs --output "$tmpdir"/empty.PK.signed \
	      PK \
	      "$tmpdir"/empty
    pk=`ls -1 /sys/firmware/efi/efivars/PK-* | head -1`
    sudo dd bs=4k if="$tmpdir"/empty.PK.signed of="$pk"
    rm -rf "$tmpdir"
}

reset() {
    echo "WARNING: this will reset your secure boot configuration."
    echo -n "Continue anyway? (y|N) "
    read ans
    if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
        echo "Aborting"
	exit 0
    fi
    unenroll_pk
    if [ -d "$sb_topdir" ]; then
        echo "Removing '$sb_topdir'"
        sudo rm -rf "$sb_topdir"
    fi

    bootimg=`ls -1 "$efi_ubuntu"/grub*.efi | head -1`
    echo "Restoring '$bootimg' (preserving '$bootimg.bak')"
    if [ -f "$bootimg.bak" ]; then
        sudo cp -f "$bootimg.bak" "$bootimg"
    fi
}

usage() {
    echo "`basename $0` enroll [canonical|microsoft]"
    echo "`basename $0` unenroll|reset"
}

#
# MAIN
#

for b in sbkeysync openssl ; do
    if ! which $b >/dev/null ; then
        echo "Please perform: sudo apt-get install sbsigntool openssl" >&2
        exit 1
    fi
done

if [ ! -f "$signed_grub" ]; then
    echo "Could not find '$signed_grub'. Please perform:"
    echo "$ sudo sh -c 'apt-get install grub-efi-amd64-signed && grub-install --uefi-secure-boot'"
    echo "After performing the above, please reboot."
    exit 1
fi

if [ -z "$1" ]; then
    usage
    exit 1
fi

enroll_type="" # user key
if [ "$2" = "canonical" ]; then
    enroll_type="canonical"
elif [ "$2" = "microsoft" ]; then
    enroll_type="microsoft"
fi

if [ "$1" = "unenroll" ]; then
    echo "TODO - please use EFI configuration on boot"
    unenroll_pk
elif [ "$1" = "reset" ]; then
    reset
elif [ "$1" = "enroll" ]; then
    do_setup "$enroll_type"
    if [ -z "$enroll_type" ]; then
        sign_bootloader grub
    else
        echo "Skipping bootloader signing for '$enroll_type'"
    fi
else
    echo "ERROR: unknown command '$1'"
    exit 1
fi
