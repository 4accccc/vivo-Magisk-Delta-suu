#MAGISK
############################################
# Magisk Uninstaller (updater-script)
############################################

##############
# Preparation
##############

# Default permissions
umask 022

OUTFD=$2
APK="$3"
COMMONDIR=$INSTALLER/assets
CHROMEDIR=$INSTALLER/assets/chromeos

if [ ! -f $COMMONDIR/util_functions.sh ]; then
  echo "! Unable to extract zip file!"
  exit 1
fi

# Load utility functions
. $COMMONDIR/util_functions.sh

setup_flashable

############
# Detection
############

if echo $MAGISK_VER | grep -q '\.'; then
  PRETTY_VER=$MAGISK_VER
else
  PRETTY_VER="$MAGISK_VER($MAGISK_VER_CODE)"
fi

[ -z "$BOOTMODE" ] && BOOTMODE=false

$BOOTMODE && MAGISKTMP="$(magisk --path)"

print_title "Magisk $PRETTY_VER Uninstaller"

is_mounted /data || mount /data || abort "! Unable to mount /data, please uninstall with the Magisk app"
mount_partitions
check_data
if ! $DATA_DE; then
    abort "! Cannot access /data, please uninstall with the Magisk app"
fi

get_flags
find_boot_image

backup_restore(){
test -f "${1}.gz" || { test -f "$1" && gzip -k "$1"; }
test -f "${1}.gz" && { rm -rf "$1" && gzip -kdf "${1}.gz"; } || return 1
}

if ! $BOOTMODE; then
    ui_print "********************************************"
    ui_print " Due to the complex of recovery environment"
    ui_print " Uninstall Magisk in Recovery is not guaranteed"
    ui_print "********************************************"
fi

# Detect version and architecture
api_level_arch_detect

ui_print "- Device platform: $ABI"

if ( [ -z "$(grep_prop SHA1 "$MAGISKTMP/.magisk/config")" ] && $BOOTMODE ) || [ "$(grep_prop SYSTEMMODE /system/etc/init/magisk/config)" == "true" ]; then

MIRRORDIR="/dev/sysmount_mirror"
ROOTDIR="$MIRRORDIR/system_root"
SYSTEMDIR="$MIRRORDIR/system"
VENDORDIR="$MIRRORDIR/vendor"

abort_install(){
  umount -l "$MIRRORDIR"
  rm -rf "$MIRRORDIR"
  abort "! Installaion faled"
}
	
if $BOOTMODE; then
    # setup mirrors to get the original content
    umount -l "$MIRRORDIR" 2>/dev/null
    rm -rf "$MIRRORDIR"
    mkdir -p "$MIRRORDIR" || return 1
    mount -t tmpfs -o 'mode=0755' tmpfs "$MIRRORDIR" || return 1
    if is_rootfs; then
        ROOTDIR=/
        mkdir "$SYSTEMDIR"
        force_bind_mount "/system" "$SYSTEMDIR" || return 1
    else
        mkdir "$ROOTDIR"
        force_bind_mount "/" "$ROOTDIR" || return 1
        if mountpoint -q /system; then
            mkdir "$SYSTEMDIR"
            force_bind_mount "/system" "$SYSTEMDIR" || return 1
        else
            ln -fs ./system_root/system "$SYSTEMDIR"
        fi
    fi

    # check if /vendor is seperated fs
    if mountpoint -q /vendor; then
        mkdir "$VENDORDIR"
        force_bind_mount "/vendor" "$VENDORDIR" || return 1
    else
        ln -fs ./system/vendor "$VENDORDIR"
    fi
else
    local MIRRORDIR="/" ROOTDIR SYSTEMDIR VENDORDIR
    ROOTDIR="$MIRRORDIR/system_root"
    SYSTEMDIR="$MIRRORDIR/system"
    VENDORDIR="$MIRRORDIR/vendor"
fi

ui_print "--- Uninstall Magisk in system partition"

blockdev --setrw /dev/block/mapper/system$SLOT 2>/dev/null
mount -o rw,remount /system || mount -o rw,remount /
mount -o rw,remount /system_root
mount -o rw,remount /vendor

for file in /vendor/etc/selinux/precompiled_sepolicy /odm/etc/selinux/precompiled_sepolicy /system/etc/selinux/precompiled_sepolicy /system_root/sepolicy /system_root/sepolicy_debug /system_root/sepolicy.unlocked; do
    if [ -f "$MIRRORDIR$file" ]; then
        sepol="$file"
        break
    fi
done

if [ ! -z "$sepol" ]; then
    ui_print "- Restore sepolicy patch"
    backup_restore "$MIRRORDIR$sepol" && rm -rf "$MIRRORDIR$sepol".gz
fi

if [ -f "$MIRRORDIR/system/bin/app_process.orig" ]; then
    rm -rf "$MIRRORDIR/system/bin/app_process"
    mv -f "$MIRRORDIR/system/bin/app_process.orig" "$MIRRORDIR/system/bin/app_process"
fi


ui_print "- Removing Magisk binaries"
rm -rf $MIRRORDIR/system/etc/init/*magisk* $MIRRORDIR/system/system/etc/init/*magisk* $MIRRORDIR/system_root/system/etc/init/*magisk* \
$MIRRORDIR/system/xbin/magisk $MIRRORDIR/system/xbin/.magisk || abort "! Cannot uninstall"

backup_restore "$MIRRORDIR/system/etc/init/bootanim.rc" && rm -rf "$MIRRORDIR/system/etc/init/bootanim.rc.gz"

else

ui_print "--- Uninstall Magisk in boot image"

[ -z $BOOTIMAGE ] && abort "! Unable to detect target image"
ui_print "- Target image: $BOOTIMAGE"

BINDIR=$INSTALLER/lib/$ABI
cd $BINDIR
for file in lib*.so; do mv "$file" "${file:3:${#file}-6}"; done
cd /
cp -af $CHROMEDIR/. $BINDIR/chromeos
chmod -R 755 $BINDIR

############
# Uninstall
############

cd $BINDIR

CHROMEOS=false

ui_print "- Unpacking boot image"
# Dump image for MTD/NAND character device boot partitions
if [ -c $BOOTIMAGE ]; then
  nanddump -f boot.img $BOOTIMAGE
  BOOTNAND=$BOOTIMAGE
  BOOTIMAGE=boot.img
fi
./magiskboot unpack "$BOOTIMAGE"

case $? in
  1 )
    abort "! Unsupported/Unknown image format"
    ;;
  2 )
    ui_print "- ChromeOS boot image detected"
    CHROMEOS=true
    ;;
esac

# Restore the original boot partition path
[ "$BOOTNAND" ] && BOOTIMAGE=$BOOTNAND

# Detect boot image state
ui_print "- Checking ramdisk status"
if [ -e ramdisk.cpio ]; then
  ./magiskboot cpio ramdisk.cpio test
  STATUS=$?
else
  # Stock A only system-as-root
  STATUS=0
fi
case $((STATUS & 3)) in
  0 )  # Stock boot
    ui_print "- Stock boot image detected"
    ;;
  1 )  # Magisk patched
    ui_print "- Magisk patched image detected"
    # Find SHA1 of stock boot image
    SHA1=$(./magiskboot cpio ramdisk.cpio sha1 2>/dev/null)
    BACKUPDIR=/data/magisk_backup_$SHA1
    if [ -d $BACKUPDIR ]; then
      ui_print "- Restoring stock boot image"
      flash_image $BACKUPDIR/boot.img.gz $BOOTIMAGE
      for name in dtb dtbo dtbs; do
        [ -f $BACKUPDIR/${name}.img.gz ] || continue
        IMAGE=$(find_block $name$SLOT)
        [ -z $IMAGE ] && continue
        ui_print "- Restoring stock $name image"
        flash_image $BACKUPDIR/${name}.img.gz $IMAGE
      done
    else
      ui_print "! Boot image backup unavailable"
      ui_print "- Restoring ramdisk with internal backup"
      ./magiskboot cpio ramdisk.cpio restore
      if ! ./magiskboot cpio ramdisk.cpio "exists init"; then
        # A only system-as-root
        rm -f ramdisk.cpio
      fi
      ./magiskboot repack $BOOTIMAGE
      # Sign chromeos boot
      $CHROMEOS && sign_chromeos
      ui_print "- Flashing restored boot image"
      flash_image new-boot.img $BOOTIMAGE || abort "! Insufficient partition size"
    fi
    ;;
  2 )  # Unsupported
    ui_print "! Boot image patched by unsupported programs"
    abort "! Cannot uninstall"
    ;;
esac

fi

if $BOOTMODE; then
  ui_print "- Removing modules"
  magisk --remove-modules -n
fi

ui_print "- Removing Magisk files"
rm -rf \
/cache/*magisk* /cache/unblock /data/*magisk* /data/cache/*magisk* /data/property/*magisk* \
/data/Magisk.apk /data/busybox /data/custom_ramdisk_patch.sh /data/adb/*magisk* \
/data/adb/post-fs-data.d /data/adb/service.d /data/adb/modules* \
/data/unencrypted/magisk /metadata/magisk /persist/magisk /mnt/vendor/persist/magisk \
/data/unencrypted/MAGISKBIN /data/unencrypted/magisk* /cache/early-mount.d \
/data/unencrypted/early-mount.d /metadata/early-mount.d /persist/early-mount.d \
/mnt/vendor/persist/early-mount.d /data/adb/early-mount.d

ADDOND=/system/addon.d/99-magisk.sh
if [ -f $ADDOND ]; then
  blockdev --setrw /dev/block/mapper/system$SLOT 2>/dev/null
  mount -o rw,remount /system || mount -o rw,remount /
  rm -f $ADDOND
fi

cd /

if $BOOTMODE; then
  ui_print "********************************************"
  ui_print " The Magisk app will uninstall itself, and"
  ui_print " the device will reboot after a few seconds"
  ui_print "********************************************"
  (sleep 8; /system/bin/reboot)&
else
  ui_print "********************************************"
  ui_print " The Magisk app will not be uninstalled"
  ui_print " Please uninstall it manually after reboot"
  ui_print "********************************************"
  recovery_cleanup
  ui_print "- Done"
fi

rm -rf $TMPDIR
exit 0
