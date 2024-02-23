#! /bin/bash
#
# This script deletes the following
# - DIFF archives + par2 files older than DIFF_AGE
# - INC archives + par2 files older than INC_AGE
# 
# will only work on DIFF and INC, not FULL archives
#
# DIFF_AGE & INC_AGE is defined in the conf file

LOCAL_BACKUP_DIR=""
ALTERNATE_ARCHIVE_DIR=""
SPECIFIC_ARCHIVE=""

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
SCRIPTNAME=$(basename "$0")

VERSION=@@DEV-VERSION@@

# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --local-backup-dir)
          LOCAL_BACKUP_DIR=1
          ;;
      --alternate-archive-dir)
          shift
          ALTERNATE_ARCHIVE_DIR="$1"
          ;;
      --cleanup-specific-archive)
          shift
          SPECIFIC_ARCHIVE="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME [--help|-h]  [--version|-v] [--local-backup-dir] [--alternate-archive-dir <directory>] [--cleanup-specific-archive]"
          echo " --local-backup-dir, don't mount a remote directory for cleanup operations"
          echo " --alternate-archive-dir, cleanup in another directory than the one configured, this probably requires --local-backup-dir also"
          echo " --cleanup-specific-archive, cleanup a specific archive no matter the date"
          echo " --version, show version number and license"
          exit
          ;;
      --version|-v)
          echo "$SCRIPTNAME $VERSION"
          echo "Licensed under GNU GENERAL PUBLIC LICENSE v3, see \"LICENSE\" file for details"
          echo "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW, see section 15 and section 16 in the \"LICENSE\" file"
          exit
          ;;
      *)
          echo option \"$1\" not recognized, exiting
          exit
          ;;
  esac
  shift
done


grep "\*" <<< $ALTERNATE_ARCHIVE_DIR
if [[ $? == "0"  ]]; then
  echo "\"*\" not allowed in \"ALTERNATE_ARCHIVE_DIR\""
  exit 1
fi


source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# set MOUNT_POINT to the alternate archive dir
# this (most probably) requires the --local-backup-dir option to be set also
if [[ $ALTERNATE_ARCHIVE_DIR != "" ]]; then
  if [[ ! -d "$ALTERNATE_ARCHIVE_DIR"  ]]; then
    log "ERROR alternate archive directory: \"$ALTERNATE_ARCHIVE_DIR\" not found, $SCRIPTNAME exiting"
    exit 1
  fi
  MOUNT_POINT="$ALTERNATE_ARCHIVE_DIR"
fi


STARTTIME="$(date -Iseconds)"
log "======================================================="
log "$SCRIPTNAME started: $STARTTIME"
log "======================================================="
log "Cleanup in: \"$MOUNT_POINT\""
log "Alternate directory: \"$ALTERNATE_ARCHIVE_DIR\""
log "Specific archive: \"$SPECIFIC_ARCHIVE\""


grep "\*" <<< $SPECIFIC_ARCHIVE 
if [[ $? == "0"  ]]; then
  log_error "\"*\" not allowed in \"SPECIFIC_ARCHIVE\""
  exit 1
fi


# make sure mounts are in order
mountPrereqs

# check if type and date given for the --cleanup-archive seems reasonable, and then delete files
if [[ $SPECIFIC_ARCHIVE != ""  ]]; then 
  TODAYS_SECS=$(date +%s --date $(date -I))
  REGEX_END_OF_DATE_SECS=$(date +%s --date "2029-12-31")
  if (( $TODAYS_SECS > $REGEX_END_OF_DATE_SECS  )); then
    log "ERROR regex date checker no longer valid, please modify it, exiting"
    exit 1
  fi
  CLEANUP_DATE=$(echo "$SPECIFIC_ARCHIVE"|grep -E -o "202[2-9]-(0[1-9]|1[012])-([0-2][0-9]|3[01])")
  if [[ $CLEANUP_DATE == "" ]]; then
    log "ERROR archive date is bad, exiting"
    exit 1
  fi
  
  # will only work on DIFF and INC, not FULL archives
  TYPE=$(echo $SPECIFIC_ARCHIVE|grep -E -o "DIFF|INC")
  if [[ $TYPE == "" ]]; then
    log "ERROR archive type is not DIFF or INC, exiting"
    exit 1
  fi

    while IFS= read -r -d "" file
  do
    rm -f "${file}" &&  log "clean up: \"${file}\""
  done <   <(find "$MOUNT_POINT" -type f -name "${SPECIFIC_ARCHIVE}*.dar*" -print0)

  log "$SCRIPTNAME ended normally"
  exit
fi


DIFF_AGE_DATE=$(date --date="-${DIFF_AGE} days" -I)
if [[ $? != "0" ]]; then
  log "ERROR \"DIFF_AGE_DATE\" calc error"
  exit 1
fi
DIFF_AGE_SECS=$(date +%s --date "$DIFF_AGE_DATE")
#clean up DIFFs
while IFS= read -r -d "" file
do
  FILE_DATE=$(echo $file|grep -o -E "_DIFF_[0-9]{4}-[0-9]{2}-[0-9]{2}")  # does no find dates in directory names due to _DIFF_
  FILE_DATE=$(echo $FILE_DATE|grep -o -E "[0-9]{4}-[0-9]{2}-[0-9]{2}")
  FILE_DATE_SECS=$(date +%s --date "$FILE_DATE")
  if (( DIFF_AGE_SECS >= FILE_DATE_SECS )); then
    rm -f "${file}" &&  log "clean up: \"${file}\""
  fi
done <   <(find "$MOUNT_POINT" -type f -name "*_DIFF_*.dar*" -print0)



INC_AGE_DATE=$(date --date="-${INC_AGE} days" -I)
if [[ $? != "0" ]]; then
  log "ERROR \"INC_AGE_DATE\" calc error"
  exit 1
fi
INC_AGE_SECS=$(date +%s --date "$INC_AGE_DATE")
#clean up INCs
while IFS= read -r -d "" file
do
  FILE_DATE=$(echo $file|grep -o -E "_INC_[0-9]{4}-[0-9]{2}-[0-9]{2}") # does not find dates in directory names due to _INC_
  FILE_DATE=$(echo $FILE_DATE|grep -o -E "[0-9]{4}-[0-9]{2}-[0-9]{2}") 
  FILE_DATE_SECS=$(date +%s --date "$FILE_DATE")
  if (( INC_AGE_SECS >= FILE_DATE_SECS )); then
    rm -f "${file}" &&  log "clean up: \"${file}\""
  fi
done <   <(find "$MOUNT_POINT" -type f -name "*_INC_*.dar*" -print0)

log "$SCRIPTNAME ended normally"
