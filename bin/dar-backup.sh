#! /bin/bash -x
# Run script as a non-root user 
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"

MODE=""
BACKUPDEF=""
CURRENT_BACKUPDEF=""
DAR_ARCHIVE=""
ARCHIVEPATH=""
DRY_RUN=""
LOCAL_BACKUP_DIR=""

# which mode: FULL or DIFF
SCRIPTNAME=`basename $0`

# Get the options
while [ ! -z "$1" ]; do
  case "$1" in
      --dry-run)
          DRY_RUN=--dry-run
          ;;
      --backupdef|-d)
          shift
          BACKUPDEF="$1"
          ;;
      --local-backup-dir)
          echo '$MOUNT_POINT' used as local backup directory....
          LOCAL_BACKUP_DIR=1
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  --backupdef|-d <backup definition>"
          exit
          ;;
  esac
  shift
done

export DATE=`date -I`
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

if [[ $SCRIPTNAME == "dar-backup.sh"  ]]; then
  MODE=FULL
else
  if [[ $SCRIPTNAME == "dar-diff-backup.sh" ]]; then
    MODE=DIFF
  else
    log "== script called with wrong name: $0, exiting"
    exit 1
  fi
fi


# make sure mounts are in order
mountPrereqs

# copy dar_static to server
copyDarStatic

# check if a single backup definition is to be run
if [[ "$BACKUPDEF" == "" ]]; then
  # loop over backup definition in backups.d/
  for CURRENT_BACKUPDEF in $(ls "${SCRIPTDIRPATH}/../backups.d/"); do
      log "== start processing backup: ${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}"
      runBackupDef
  done
else
  if [[ -f "${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"  ]]; then
    log "== start processing a single backup: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"
    CURRENT_BACKUPDEF="$BACKUPDEF"
    runBackupDef
  else 
    log "== backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF} does not exist"
  fi
fi


