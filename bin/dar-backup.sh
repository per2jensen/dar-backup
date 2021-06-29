#! /bin/bash -x
# Run script as a non-root user 
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"

MODE=""

# which mode: FULL or DIFF
SCRIPTNAME=`basename $0`

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


export DATE=`date -I`
export SCRIPTPATH=`realpath $0`
export SCRIPTDIRPATH=`dirname $SCRIPTPATH`

source ${SCRIPTDIRPATH}/../conf/dar-backup.conf
source ${SCRIPTDIRPATH}/dar-util.sh

# make sure mounts are in order
mountPrereqs


for file in $(ls ${SCRIPTDIRPATH}/../backups.d/); do
    source "${SCRIPTDIRPATH}/../backups.d/${file}"

    DAR_ARCHIVE=${BACKUP_NAME}_${MODE}_${DATE}
    ARCHIVEPATH=${MOUNT_POINT}/${DAR_ARCHIVE}

    # if includes are used, make sure the test file is saved in one
    TESTRESTORE_FILE=.dar-testrestore-${BACKUP_NAME}-${DATE}
    OIFS=$IFS
        # loop includes
        IFS=';' read -ra my_array <<< "$INCLUDES"
        for i in "${my_array[@]}"
        do
          TESTRESTORE_FILE="${i}/.dar-testrestore-${BACKUP_NAME}-${DATE}"
          break
        done
    IFS=$OIFS


    if [[ $MODE == "FULL"  ]]; then 
      # backup
      backupTestRestore "$ARCHIVEPATH" "$FS_ROOT" \
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}"
    else
      PREV=`ls "${MOUNT_POINT}"|grep -P ${BACKUP_NAME}_FULL|grep dar$|tail -n 1`
      NEWEST_ARCHIVE=${PREV%%.*}
      echo NEWEST archive: $NEWEST_ARCHIVE
      # backup
      diffBackupTestRestore "$ARCHIVEPATH" "$FS_ROOT" "${MOUNT_POINT}/$NEWEST_ARCHIVE" \
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}"
    fi
done
