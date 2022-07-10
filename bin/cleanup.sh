#! /bin/bash
#
# This script deletes the following
# - DIFF archives + par2 files older than DIFF_AGE
# - INC archives + par2 files older than INC_AGE
# 
# DIFF_AGE & INC_AGE is defined in the conf file

LOCAL_BACKUP_DIR=""

# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --local-backup-dir)
          echo "$MOUNT_POINT" used as local backup directory....
          LOCAL_BACKUP_DIR=1
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--local-backup-dir]"
          echo "   --local-backup-dir, don't mount a remote directory for cleanup operations"
          exit
          ;;
  esac
  shift
done

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

SCRIPTNAME=$(basename "$0")
STARTTIME="$(date -Iseconds)"
log "======================================================="
log "$SCRIPTNAME started: $STARTTIME"
log "======================================================="

# make sure mounts are in order
mountPrereqs

# delete DIFFs older than DIFF_AGE days
while IFS= read -r -d "" file
do
  rm -f "${file}" &&  log "clean up: \"${file}\""
done <   <(find "${MOUNT_POINT}" -name "*DIFF*.dar*" -ctime "+${DIFF_AGE}" -print0)

# delete INCs older than INC_AGE days
while IFS= read -r -d "" file
do
  rm -f "${file}"  &&  log "clean up: \"${file}\""
done <   <(find "${MOUNT_POINT}" -name "*INC*.dar*" -ctime "+${INC_AGE}" -print0)

log "$0 ended normally"
