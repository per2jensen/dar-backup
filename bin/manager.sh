#! /bin/bash
#
# This script creates/maintains the dar catalogs from existing dar archives for backup definitions.
#

# TODO skal LOCAL_BACKUP_DIR bruges ?
LOCAL_BACKUP_DIR=""

# work on this dir, instead of MOUNT_POINT
ALTERNATE_ARCHIVE_DIR=""

# boolean, True=do create missing catalogs
CREATE_CATALOG=""

# add all archives in a dir
ADD_DIR=""
ARCHIVE_DIR_TO_ADD=""

# restict --create-catalog and --alternate-archive-dir to add only archives for this backup definition
BACKUP_DEF=""

# add this archive to catalog
ADD_SPECIFIC_ARCHIVE=""

# remove this archive from catalog
REMOVE_SPECIFIC_ARCHIVE=""

# when used in normal backup operations, outputs a single notice on adding an archive to it's catalog
ALMOST_QUIET="n"

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
      --backup-def)
          shift
          BACKUP_DEF="$1"
          ;;
      --add-specific-archive)
          _ADD_SPECIFIC_ARCHIVE=1
          shift
          ADD_SPECIFIC_ARCHIVE="$1"
          ;;
      --remove-specific-archive)
          _REMOVE_SPECIFIC_ARCHIVE=1
          shift
          REMOVE_SPECIFIC_ARCHIVE="$1"
          ;;
      --almost-quiet)
          ALMOST_QUIET="y"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--create-catalog] [--add-specific-archive <archive name>] [--remove-specific-archive <archive name>] [--almost-quiet] [--backup-def <backup definition>] [--add-dir <dir name>] [--alternate-archive-dir <directory>] [--local-backup-dir]"
          echo " --local-backup-dir, don't mount a remote directory for operations"
          echo " --alternate-archive-dir, estrict to one backup definition using --backup-def, this probably requires --local-backup-dir also"
          echo " --create-catalog, create missing catalogs. Restrict to one backup definition using --backup-def"
          echo " --add-dir <dir name>, add all archives in <dir_name> for existing backup definitions to catalogs"
          echo " --backup-def <backup definition>, restict --create-catalog and --alternate-archive-dir"
          echo " --add-specific-archive <archive name>, the short form without .<slice>.dar"
          echo " --remove-specific-archive <archive name>, the short form without .<slice>.dar"
          echo " --almost-quiet, outputs a single notice on an archive operation in the catalog"
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

# sanity chekcs before starting
if [[ $ADD_DIR == "1" && $ARCHIVE_DIR_TO_ADD == "" ]]; then
    log "ERROR archive dir not given, exiting"
    exit 1
fi

if [[ $_ADD_SPECIFIC_ARCHIVE == "1" && $_ADD_SPECIFIC_ARCHIVE == "" ]]; then
    log "ERROR specific archive to add not given, exiting"
    exit 1
fi

if [[ $_REMOVE_SPECIFIC_ARCHIVE == "1" && $REMOVE_SPECIFIC_ARCHIVE == "" ]]; then
    log "ERROR specific archive to remove not given, exiting"
    exit 1
fi

if [[ $_ADD_SPECIFIC_ARCHIVE == "1" && $_REMOVE_SPECIFIC_ARCHIVE == "1" ]]; then
    log "ERROR you can't add and remove archives in the same operation, exiting"
    exit 1
fi


if [[ $BACKUP_DEF != "" ]]; then
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$BACKUP_DEF"  ]]; then
        log "ERROR backup definition \"$BACKUP_DEF\" not found, exiting"
        exit 1
    fi
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
if [[ $ALMOST_QUIET == "n" ]]; then
    log "======================================================="
    log "$SCRIPTNAME started: $STARTTIME"
    log "======================================================="
    log "Alternate directory: \"$ALTERNATE_ARCHIVE_DIR\""
    log "Add specific archive: \"$ADD_SPECIFIC_ARCHIVE\""
    log "Remove specific archive: \"$REMOVE_SPECIFIC_ARCHIVE\""
    log "Create catalog: \"$CREATE_CATALOG\""
    log "Add directory: \"$ADD_DIR\", \"$ARCHIVE_DIR_TO_ADD\""
    log "Backup definition: \"$BACKUP_DEF\""
fi

# make sure mounts are in order
mountPrereqs


# create catalog for all backup definitions
if [[ $CREATE_CATALOG == "1" ]]; then
    if [[ $BACKUP_DEF == "" ]]; then
        while IFS= read -r "file"
        do
            CURRENT_BACKUPDEF=$(basename "$file")
            CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
            if [[ -e "$MOUNT_POINT/$CATALOG" ]]; then
                log "WARN  \"$MOUNT_POINT/$CATALOG\" already exists, go to next"
            else
                log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG\""
                dar_manager --create "$MOUNT_POINT"/"$CATALOG"
                if [[ $? != "0" ]]; then
                    log "ERROR something went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG\", continuing..."
                fi
            fi
        done <  <(find "${SCRIPTDIRPATH}"/../backups.d -type f -print)
    else
        CATALOG=${BACKUP_DEF}${CATALOG_SUFFIX}
        if [[ -e "$MOUNT_POINT/$CATALOG" ]]; then
            log "WARN  \"$MOUNT_POINT/$CATALOG\" already exists, exiting"
            exit 0
        else
            log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG\""
            dar_manager --create "$MOUNT_POINT"/"$CATALOG"
            if [[ $? != "0" ]]; then
                log "ERROR something went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG\""
                exit $?
            fi
        fi
    fi
fi


# add archives in $ARCHIVE_DIR_TO_ADD to the catalog
# loop over all archives in the directory
if [[  $ADD_DIR == "1" && $ARCHIVE_DIR_TO_ADD != "" ]]; then
    if [[ $BACKUP_DEF == "" ]]; then
        while IFS= read -r "file"
        do
            CURRENT_BACKUPDEF=$(basename "$file")
            CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
            log "Now adding archives for backup definition \"$CURRENT_BACKUPDEF\" to catalog \"$CATALOG\""
            SEARCHCRIT="${CURRENT_BACKUPDEF}_*.dar"
            while IFS= read -r "archive"
            do
                ARCHIVE="$(basename "${archive}")"
                _REALPATH="$(realpath "$MOUNT_POINT"/"$ARCHIVE")"
                log "INFO add \"$_REALPATH\" to catalog \"$CATALOG\""
                dar_manager --base "$MOUNT_POINT/$CATALOG"  --add "$_REALPATH"
                RESULT=$?
                if [[ $RESULT != "0" ]]; then
                    log "ERROR something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
                    exit $RESULT
                fi
            done <  <(find "${MOUNT_POINT}" -type f -name "$SEARCHCRIT" -print|grep -E "${CURRENT_BACKUP_DEF}_FULL_.*|${CURRENT_BACKUP_DEF}_DIFF_.*|${CURRENT_BACKUP_DEF}_INC_.*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u|sort -s)
        done <  <(find "${SCRIPTDIRPATH}"/../backups.d -type f -print)
    else
        CATALOG=${BACKUP_DEF}${CATALOG_SUFFIX}
        log "Now adding archives for backup definition \"$BACKUP_DEF\" to catalog \"$CATALOG\""
        SEARCHCRIT="${BACKUP_DEF}_*.dar"

        while IFS= read -r "archive"
        do
            ARCHIVE="$(basename "${archive}")"
            _REALPATH="$(realpath "$MOUNT_POINT"/"$ARCHIVE")"
            log "INFO add \"$_REALPATH\" to catalog \"$CATALOG\""
            dar_manager --base "$MOUNT_POINT/$CATALOG"  --add "$_REALPATH"
            RESULT=$?
            if [[ $RESULT != "0" ]]; then
                log "ERROR something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
                exit $RESULT
            fi
        done <  <(find "${MOUNT_POINT}" -type f -name "$SEARCHCRIT" -print|grep -E "${BACKUP_DEF}_FULL_.*|${BACKUP_DEF}_DIFF_.*|${BACKUP_DEF}_INC_.*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u|sort -s)
    fi
fi

# add a specific archive to it's catalog (catalog deduced from archive name)
if [[ $ADD_SPECIFIC_ARCHIVE != "" ]]; then
    _DEF_=$(echo "$ADD_SPECIFIC_ARCHIVE" |grep -E "^.*?_" | cut -d _ -f 1)
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$_DEF_"  ]]; then
        log "ERROR backup definition \"$_DEF_\" not found (--add-specific-archive option probably not correct), exiting"
        exit 1
    fi
    CATALOG="${_DEF_}""${CATALOG_SUFFIX}"
    _REALPATH="$(realpath "$MOUNT_POINT"/"$ADD_SPECIFIC_ARCHIVE")"
    log "INFO add \"$MOUNT_POINT/$ADD_SPECIFIC_ARCHIVE\" to catalog \"$CATALOG\""
    dar_manager --base "$MOUNT_POINT"/"$CATALOG"  --add "$_REALPATH"
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        log "ERROR something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
        exit $RESULT
    fi
fi



# remove a specific archive from it's catalog (catalog deduced from archive name)
# Observe it only removes one entry - so if the database has multiple entries, only 1 is removed
if [[ $REMOVE_SPECIFIC_ARCHIVE != "" ]]; then
    _DEF_=$(echo "$REMOVE_SPECIFIC_ARCHIVE" |grep -E "^.*?_" | cut -d _ -f 1)
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$_DEF_"  ]]; then
        log "ERROR backup definition \"$_DEF_\" not found (--remove-specific-archive option probably not correct), exiting"
        exit 1
    fi
    CATALOG="${_DEF_}""${CATALOG_SUFFIX}"
    log "INFO remove \"$MOUNT_POINT/$REMOVE_SPECIFIC_ARCHIVE\" from catalog \"$CATALOG\""
    _REALPATH="$(realpath "$MOUNT_POINT"/"$REMOVE_SPECIFIC_ARCHIVE")"
    while IFS=$'\n' read -r "line"
    do
        ARCHIVE_LINE=$(echo "$line"|grep "$REMOVE_SPECIFIC_ARCHIVE")
        GREP_RESULT=$?
        if [[  $GREP_RESULT == "0" ]]; then
            CATALOG_NO=$(echo "$ARCHIVE_LINE"|grep -E "^\s+[0-9]+" -o|grep -E [0-9]+ -o)
            log "found archive \"$REMOVE_SPECIFIC_ARCHIVE\" with CATALOG_NO: $CATALOG_NO"
            dar_manager --base "$MOUNT_POINT"/"$CATALOG"  --delete $CATALOG_NO
            break
        fi
    done <  <(dar_manager --base "$MOUNT_POINT"/"$CATALOG" --list)
fi

log "$SCRIPTNAME ended normally"
