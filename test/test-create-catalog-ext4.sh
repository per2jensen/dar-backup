#! /bin/bash

# test creation of catalog
#   - create ext4 file system in a file, all operations are done there
#     - this to compare against Per's btrfs file system on /
#   - make 5 backup definitions   
#   - do a backup
#   - create the catalog
#   - populate the catalog with archive data
#   - list catalog
#   - check catalog
#   - restore files using dar_manager and catalog

# take a look at https://sourceforge.net/p/dar/mailman/message/36981216/ for info
# on the file ownership issue


TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/bin/dar-util.sh"
source "$TESTDIR/conf/dar-backup.conf"

# setup a ext4 filesystem
EXT4_FILE="/tmp/ext4-file"
EXT4_MOUNT_POINT="/tmp/mnt/ext4"
dd if=/dev/zero of="$EXT4_FILE" bs=1024 count=150000
mkfs.ext4 "$EXT4_FILE"
umount "$EXT4_MOUNT_POINT" > /dev/null 2<&1
rm -fr "$EXT4_MOUNT_POINT"
mkdir -p "$EXT4_MOUNT_POINT"
mount "$EXT4_FILE" "$EXT4_MOUNT_POINT"
chmod 777 "$EXT4_MOUNT_POINT"
cp -R "$TESTDIR" "$EXT4_MOUNT_POINT"
"$EXT4_MOUNT_POINT"/dar-backup-test/bin/install.sh

# set new TESTDIR location
TESTDIR="$EXT4_MOUNT_POINT"/dar-backup-test
MOUNT_POINT="$TESTDIR/archives"
LOG_LOCATION="$MOUNT_POINT"

# generate 5 different backups
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST2 
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST3
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST4 
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST5 

# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi


# do backups
"$TESTDIR/bin/dar-backup.sh" --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi


# populate catalogs with archive data
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi

# list the catalog
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
    echo "List catalog \"$CATALOG\" for backup definition \"$CURRENT_BACKUPDEF\""
    dar_manager  -l --base "$(realpath "$TESTDIR"/archives/"$CATALOG")"
    if [[ $? != "0" ]]; then
      echo ERROR catalog --list for failed "\"$CATALOG\""
      TESTRESULT=1
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)


# check catalogs
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
    echo check catalog "\"$CATALOG\""
    if [[ -e "$TESTDIR"/archives/"$CATALOG" ]]; then 
      dar_manager -c --base "$(realpath "$TESTDIR"/archives/"${CATALOG}")"
      if [[ $? != "0" ]]; then
        echo ERROR catalog DB "\"$CATALOG\"" is not OK
        TESTRESULT=1
      fi
    else
        echo "ERROR  \"${TESTDIR}/archives/${CATALOG}\" does not exist"
        TESTRESULT=1
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)


# restore files to temp dirs from catalogs
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}

    TEMPDIR="${EXT4_MOUNT_POINT}/${CURRENT_BACKUPDEF}"
    mkdir -p "$TEMPDIR"
    echo restoring "\"$CURRENT_BACKUPDEF\""  to "\"$TEMPDIR\"" from catalog "\"$CATALOG\""
    dar_manager  --base "$(realpath "$TESTDIR"/archives/"$CATALOG")" -e "-R $TEMPDIR  -Oignore-owner
 " -r "dirs"
    if [[ $? != "0" ]]; then
      echo ERROR dar_manager restore failed
      TESTRESULT=1
    fi
    find "$TEMPDIR" -type f 
    rm -fr "$TEMPDIR"
done  <  <(find "${TESTDIR}"/backups.d -type f -print0)

if [[ "$TESTRESULT" == "0" ]]; then
  log_success "Test case succeeded"
else
  log_fail "Test case failed"
fi

exit "$TESTRESULT"
