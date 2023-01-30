#! /bin/bash
#
# This script creates the dar catalog from existing dar archives.
#
# It is used for initialization of the catalog.
#
LOCAL_BACKUP_DIR=""
ALTERNATE_ARCHIVE_DIR=""
CREATE_CATALOG=""
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
          shift
          ARCHIVE_DIR_TO_ADD="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--local-backup-dir] [--alternate-archive-dir <directory>] [--cleanup-archive]"
          echo " --local-backup-dir, don't mount a remote directory for cleanup operations"
          echo " --alternate-archive-dir, cleanup in another directory than the one configured, this probably requires --local-backup-dir also"
          echo " --create-catalog"
          echo " --add-dir <dir name>"

          exit
          ;;
      *)
          echo option \"$1\" not recognized, exiting
          exit
          ;;
  esac
  shift
done


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
log "Alternate directory: \"$ALTERNATE_ARCHIVE_DIR\""
log "Specific archive: \"$SPECIFIC_ARCHIVE\""
log "Create catalog: \"$CREATE_CATALOG\""
log "Directory to add to catalog: \"$ARCHIVE_DIR_TO_ADD\""


# make sure mounts are in order
mountPrereqs


# create catalog
if [[ $CREATE_CATALOG == "1"  ]]; then
    if [[ -e "$MOUNT_POINT/$CATALOG_DB" ]]; then 
        log "ERROR  \"$MOUNT_POINT/$CATALOG_DB\" already exists, exiting"
        exit 1
    fi

    echo ######################################################################################
    echo must loop over all backup definitions and create a catalog for each definitions
    echo "exciting until that code change has been made :-)"
    echo ######################################################################################
    exit 1

    log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG_DB\""    
    dar_manager --create "$MOUNT_POINT"/"$CATALOG_DB"
    if [[ $? != "0" ]]; then
        log "ERROR somethin went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG_DB\""
        exit $?
    fi
fi


# add archives in $ARCHIVE_DIR_TO_ADD to the catalog
# loop over all archives in the directory
if [[ $ARCHIVE_DIR_TO_ADD != "" ]]; then
    SEARCHCRIT="*.dar"
    for archive in $(find ${MOUNT_POINT} -type f -name "$SEARCHCRIT"|grep -E ".*_FULL_.*|.*_DIFF_.*|.*_INC_.*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u|sort -s); do
        BASE=$(basename ${archive})
        log "INFO add \"$MOUNT_POINT/$BASE\" to catalog"
        dar_manager --base "$MOUNT_POINT/$CATALOG_DB"  --add $(realpath "$MOUNT_POINT/$BASE")
        RESULT=$?
        if [[ $RESULT != "0" ]]; then
            log "ERROR something went wrong, dar error: \"$RESULT\""
            exit $RESULT
        fi
    done
fi
log "$SCRIPTNAME ended normally"
