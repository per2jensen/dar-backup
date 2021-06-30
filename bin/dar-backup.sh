#! /bin/bash 
# Run script as a non-root user 
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"


# $1: name of the backup definition in backups.d
runBackupDef () {
    local backupdef="$1"
    source "${SCRIPTDIRPATH}/../backups.d/${backupdef}"

    DAR_ARCHIVE="${BACKUP_NAME}_${MODE}_${DATE}"
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"

    # if includes are used, make sure the test file is saved in one
    TESTRESTORE_FILE=".dar-testrestore-${BACKUP_NAME}-${DATE}"
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
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}" "${LOG_LOCATION}"
    else
      PREV=`ls "${MOUNT_POINT}"|grep -P ${BACKUP_NAME}_FULL|grep dar$|tail -n 1`
      NEWEST_ARCHIVE=${PREV%%.*}
      echo NEWEST archive: $NEWEST_ARCHIVE
      # backup
      diffBackupTestRestore "$ARCHIVEPATH" "$FS_ROOT" "${MOUNT_POINT}/$NEWEST_ARCHIVE" \
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}"  "${LOG_LOCATION}"
    fi
}


MODE=""
BACKUPDEF=""

# which mode: FULL or DIFF
SCRIPTNAME=`basename $0`

# Get the options
while [ ! -z "$1" ]; do
  case "$1" in
      --backupdef|-d)
          shift
          BACKUPDEF="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  --backupdef|-d <backup definition>"
          exit
          ;;
  esac
  shift
done



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
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs


# check if a single backup definition is to be run
if [[ "$BACKUPDEF" == "" ]]; then
  # loop over backup definition in backups.d/
  for file in $(ls "${SCRIPTDIRPATH}/../backups.d/"); do
      log "== start processing backup: ${file}"
      runBackupDef "$file"
  done
else
  if [[ -f "${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"  ]]; then
    echo Per was here
    runBackupDef "$BACKUPDEF"
  fi
fi


