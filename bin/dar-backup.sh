#! /bin/bash 
# Run script as a non-root user 
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"

MODE=""

# which mode: FULL or DIFF
SCRIPTNAME=`basename $0`
echo $SCRIPTNAME

if [[ $SCRIPTNAME == "dar-backup.sh"  ]]; then
  MODE=FULL
else
  if [[ $SCRIPTNAME == "dar-diff-backup.sh" ]]; then
    MODE=DIFF
  else
    logger -s "script called with wrong name: $0, exiting"
    exit 1
  fi
fi


DATE=`date -I`
SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo $SCRIPTDIRPATH

source ${SCRIPTDIRPATH}/../conf/dar-backup.conf
source ${SCRIPTDIRPATH}/dar-util.sh

# make sure mounts are in order
mountPrereqs


# ======================================
#  test backup
# ======================================
BACKUP_NAME=TEST
# what to backup
FS_ROOT=/home/pj/tmp/dba
# where to restore the testfile
TESTRESTORE_PATH=/tmp

DAR_ARCHIVE=${BACKUP_NAME}_${MODE}_${DATE}
ARCHIVEPATH=${MOUNT_POINT}/${DAR_ARCHIVE}
TESTRESTORE_FILE=.dar-testrestore-${BACKUP_NAME}-${DATE}

if [[ $MODE == "FULL"  ]]; then 
  # backup
  backupTestRestore "$ARCHIVEPATH" "$FS_ROOT" \
    "$TESTRESTORE_PATH" "$TESTRESTORE_FILE"
else
  PREV=`ls "${MOUNT_POINT}"|grep -P ${BACKUP_NAME}_FULL|grep dar$|tail -n 1`
  NEWEST_ARCHIVE=${PREV%%.*}
  echo NEWEST archive: $NEWEST_ARCHIVE
  # backup
  diffBackupTestRestore "$ARCHIVEPATH" "$FS_ROOT" "${MOUNT_POINT}/$NEWEST_ARCHIVE" \
    "$TESTRESTORE_PATH" "$TESTRESTORE_FILE"
fi

