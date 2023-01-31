#! /bin/bash
#
# This script creates/maintains the dar catalogs from existing dar archives for backup definitions.
#

# TODO skal LOCAL_BACKUP_DIR bruges ?

LOCAL_BACKUP_DIR=""
ALTERNATE_ARCHIVE_DIR=""
CREATE_CATALOG=""
ADD_DIR=""
ARCHIVE_DIR_TO_ADD=""

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
SCRIPTNAME=$(basename "$0")

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
      --create-catalog)
          CREATE_CATALOG="1"
          ;;
      --add-dir)
          ADD_DIR="1"
          shift
          ARCHIVE_DIR_TO_ADD="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--local-backup-dir] [--alternate-archive-dir <directory>]"
          echo " --local-backup-dir, don't mount a remote directory for cleanup operations"
          echo " --alternate-archive-dir, cleanup in another directory than the one configured, this probably requires --local-backup-dir also"
          echo " --create-catalog"
          echo " --add-dir <dir name>"

          exit
          ;;
      *)
          echo option "\"$1\"" not recognized, exiting
          exit
          ;;
  esac
  shift
done


source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

if [[ $ADD_DIR == "1" && $ARCHIVE_DIR_TO_ADD == "" ]]; then
    log "ERROR archive dir not given, exiting"
    exit 1
fi



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
log "Alternate directory: \"$ALTERNATE_ARCHIVE_DIR\""
log "Specific archive: \"$SPECIFIC_ARCHIVE\""
log "Create catalog: \"$CREATE_CATALOG\""
log "Add directory:  \"$ADD_DIR\""
log "Directory to add to catalog: \"$ARCHIVE_DIR_TO_ADD\""


# make sure mounts are in order
mountPrereqs


# create catalog
if [[ $CREATE_CATALOG == "1"  ]]; then
    for CURRENT_BACKUPDEF in "${SCRIPTDIRPATH}"/../backups.d/*; do
        CURRENT_BACKUPDEF=$(basename "$CURRENT_BACKUPDEF")
        CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
        if [[ -e "$MOUNT_POINT/$CATALOG" ]]; then 
            log "WARN  \"$MOUNT_POINT/$CATALOG\" already exists, go to next"
        else
            log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG\""    
            dar_manager --create "$MOUNT_POINT"/"$CATALOG"
            if [[ $? != "0" ]]; then
                log "ERROR somethin went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG\""
                exit $?
            fi
        fi
    done
fi


# add archives in $ARCHIVE_DIR_TO_ADD to the catalog
# loop over all archives in the directory
if [[  $ADD_DIR == "1" && $ARCHIVE_DIR_TO_ADD != "" ]]; then
    for CURRENT_BACKUPDEF in "${SCRIPTDIRPATH}"/../backups.d/*; do
        CURRENT_BACKUPDEF=$(basename "$CURRENT_BACKUPDEF")
        CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
        log "Now adding archives for backup definition \"$CURRENT_BACKUPDEF\" to catalog \"$CATALOG\""
        SEARCHCRIT="${CURRENT_BACKUPDEF}*.dar"
        for archive in $(find "${MOUNT_POINT}" -type f -name "$SEARCHCRIT"|grep -E "${CURRENT_BACKUPDEF}_FULL_.*|${CURRENT_BACKUPDEF}_DIFF_.*|${CURRENT_BACKUPDEF}_INC_.*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u|sort -s); do
            ARCHIVE=$(basename "${archive}")
            log "INFO add \"$MOUNT_POINT/$ARCHIVE\" to catalog \"$CATALOG\""
            dar_manager --base "$MOUNT_POINT/$CATALOG"  --add $(realpath "$MOUNT_POINT/$ARCHIVE")
            RESULT=$?
            if [[ $RESULT != "0" ]]; then
                log "ERROR something went wrong, dar error: \"$RESULT\""
                exit $RESULT
            fi
        done
    done
fi
log "$SCRIPTNAME ended normally"
