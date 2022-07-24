#! /bin/bash
#
# This script deletes the following
# - DIFF archives + par2 files older than DIFF_AGE
# - INC archives + par2 files older than INC_AGE
# 
# DIFF_AGE & INC_AGE is defined in the conf file

LOCAL_BACKUP_DIR=""
ALTERNATE_ARCHIVE_DIR=""

# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --local-backup-dir)
          echo "$MOUNT_POINT" used as local backup directory....
          LOCAL_BACKUP_DIR=1
          ;;
      --alternate-archive-dir)
          shift
          ALTERNATE_ARCHIVE_DIR="$1"
          echo Cleaning up in: \"$ALTERNATE_ARCHIVE_DIR\"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--local-backup-dir]"
          echo "   --local-backup-dir, don't mount a remote directory for cleanup operations"
          echo "   --alternate-archive-dir, cleanup in another directory than the one configure, this probably requires --local-backup-dir also"
          exit
          ;;
  esac
  shift
done

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# set MOUNT_POINT to the alternate archive dir
# this (most probably) requires the --local-backup-dir option to be set also
if [[ $ALTERNATE_ARCHIVE_DIR != "" ]]; then
  MOUNT_POINT="$ALTERNATE_ARCHIVE_DIR"
fi

SCRIPTNAME=$(basename "$0")
STARTTIME="$(date -Iseconds)"
log "======================================================="
log "$SCRIPTNAME started: $STARTTIME"
log "======================================================="
log "Cleanup in: \"$MOUNT_POINT\""

# make sure mounts are in order
mountPrereqs


# date --date="-1 days" -I

# ls /tmp/dar-backup-test/archives/*.dar|grep -o -E "[0-9]{4}-[0-9]{2}-[0-9]{2}"
# 

DIFF_AGE_DATE=$(date --date="-${DIFF_AGE} days" -I)
DIFF_AGE_SECS=$(date +%s --date "$DIFF_AGE_DATE")
#echo DIFF_AGE_DATE: $DIFF_AGE_DATE
#echo DIFF_AGE_SECS: $DIFF_AGE_SECS

#clean up DIFFs
while IFS= read -r -d "" file
do
  #echo $file
  FILE_DATE=$(echo $file|grep -o -E "_DIFF_[0-9]{4}-[0-9]{2}-[0-9]{2}")
  FILE_DATE=$(echo $FILE_DATE|grep -o -E "[0-9]{4}-[0-9]{2}-[0-9]{2}")
  #echo date: $FILE_DATE
  FILE_DATE_SECS=$(date +%s --date "$FILE_DATE")
  #echo file date secs: $FILE_DATE_SECS
  #echo DIFFS secs:     $DIFF_AGE_SECS
  if (( DIFF_AGE_SECS >= FILE_DATE_SECS )); then
    #echo should be deleted: $file
    rm -f "${file}" &&  log "clean up: \"${file}\""
  fi
done <   <(find "$MOUNT_POINT" -type f -name "*_DIFF_*.dar*" -print0)



INC_AGE_DATE=$(date --date="-${INC_AGE} days" -I)
INC_AGE_SECS=$(date +%s --date "$INC_AGE_DATE")
#echo INC_AGE_DATE: $INC_AGE_DATE
#echo INC_AGE_SECS: $INC_AGE_SECS

#clean up INCs
while IFS= read -r -d "" file
do
  #echo $file
  FILE_DATE=$(echo $file|grep -o -E "_INC_[0-9]{4}-[0-9]{2}-[0-9]{2}")
  FILE_DATE=$(echo $FILE_DATE|grep -o -E "[0-9]{4}-[0-9]{2}-[0-9]{2}") 
  #echo date: $FILE_DATE
  FILE_DATE_SECS=$(date +%s --date "$FILE_DATE")
  #echo file date secs: $FILE_DATE_SECS
  #echo INC secs:       $INC_AGE_SECS
  if (( INC_AGE_SECS >= FILE_DATE_SECS )); then
    #echo should be deleted: $file
    rm -f "${file}" &&  log "clean up: \"${file}\""
  fi
done <   <(find "$MOUNT_POINT" -type f -name "*_INC_*.dar*" -print0)

log "$SCRIPTNAME ended normally"

