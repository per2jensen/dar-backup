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

# list catalog for backup definition
LIST_CATALOG=""

# when used in normal backup operations, outputs a single notice on adding an archive to it's catalog
VERBOSE="n"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
SCRIPTNAME=$(basename "$0")


show_help() {
    cat << EOF

NAME
    $SCRIPTNAME - creates/maintains dar catalogs for dar archives for backup definitions

SYNOPSIS
    $SCRIPTNAME  --list|-1 [--backup-def <definition>] 

    $SCRIPTNAME  --create-catalog [--backup-def|-d <definition>]

    $SCRIPTNAME  --add-dir <directory> [--backup-def <definition>]

    $SCRIPTNAME  --add-specific-archive <archive name>

    $SCRIPTNAME  --remove-specific-archive <archive name>

    $SCRIPTNAME  --help|-h


OPTIONS
    --list|-l, list catalogs for all backup definitions, or a single definition (use --backup-def)
    --local-backup-dir, don't mount a remote directory for operations
    --alternate-archive-dir, override MOUNT_POINT (from .conf file)
    --create-catalog, create missing catalogs. Restrict to one backup definition using --backup-def
    --add-dir <dir name>, add all archives in <dir_name> for existing backup definitions to catalogs
    --backup-def|-d <backup definition>, restict another operation to work only on this backup definition
    --add-specific-archive <archive name>, the short form without .<slice>.dar
    --remove-specific-archive <archive name>, the short form without .<slice>.dar
    --verbose|-v, output start up params and more
    --help|-h, output this help message
EOF
}


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
      --backup-def|-d)
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
      --list|-l)
          LIST_CATALOG="1"
          ;;
      --verbose|-v)
          VERBOSE="y"
          ;;
      --help|-h)
          show_help
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
    log_error "archive dir not given, exiting"
    exit 1
fi

if [[ $_ADD_SPECIFIC_ARCHIVE == "1" && $_ADD_SPECIFIC_ARCHIVE == "" ]]; then
    log_error "specific archive to add not given, exiting"
    exit 1
fi

if [[ $_REMOVE_SPECIFIC_ARCHIVE == "1" && $REMOVE_SPECIFIC_ARCHIVE == "" ]]; then
    log_error "specific archive to remove not given, exiting"
    exit 1
fi

if [[ $_ADD_SPECIFIC_ARCHIVE == "1" && $_REMOVE_SPECIFIC_ARCHIVE == "1" ]]; then
    log_error "you can't add and remove archives in the same operation, exiting"
    exit 1
fi


if [[ $BACKUP_DEF != "" ]]; then
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$BACKUP_DEF"  ]]; then
        log_error "backup definition \"$BACKUP_DEF\" not found, exiting"
        exit 1
    fi
fi

# set MOUNT_POINT to the alternate archive dir
# this (most probably) requires the --local-backup-dir option to be set also
if [[ $ALTERNATE_ARCHIVE_DIR != "" ]]; then
  if [[ ! -d "$ALTERNATE_ARCHIVE_DIR"  ]]; then
    log_error "alternate archive directory: \"$ALTERNATE_ARCHIVE_DIR\" not found, $SCRIPTNAME exiting"
    exit 1
  fi
  MOUNT_POINT="$ALTERNATE_ARCHIVE_DIR"
fi


STARTTIME="$(date -Iseconds)"
log_verbose "======================================================="
log_verbose "$SCRIPTNAME started: $STARTTIME"
log_verbose "======================================================="
log_verbose "Alternate directory: \"$ALTERNATE_ARCHIVE_DIR\""
log_verbose "Add specific archive: \"$ADD_SPECIFIC_ARCHIVE\""
log_verbose "Remove specific archive: \"$REMOVE_SPECIFIC_ARCHIVE\""
log_verbose "Create catalog: \"$CREATE_CATALOG\""
log_verbose "Add directory: \"$ADD_DIR\", \"$ARCHIVE_DIR_TO_ADD\""
log_verbose "Backup definition: \"$BACKUP_DEF\""

# make sure mounts are in order
mountPrereqs


# list catalogs for all backup definitions
# or for a specific backup definition given 
# by --backup-def
if [[ $LIST_CATALOG == "1" ]]; then
    if [[ $BACKUP_DEF == "" ]]; then
        while IFS= read -r "file"
        do
            CURRENT_BACKUPDEF=$(basename "$file")
            CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
            dar_manager --list -Q --base "$MOUNT_POINT"/"$CATALOG" | grep -E -v "^[[:alnum:]]"
        done <  <(find "${SCRIPTDIRPATH}"/../backups.d -type f -print)
    else
        CATALOG=${BACKUP_DEF}${CATALOG_SUFFIX}
        dar_manager --list -Q --base "$MOUNT_POINT"/"$CATALOG" | grep -E -v "^[[:alnum:]]"
    fi
    exit
fi


# create catalog for all backup definitions
if [[ $CREATE_CATALOG == "1" ]]; then
    if [[ $BACKUP_DEF == "" ]]; then
        while IFS= read -r "file"
        do
            CURRENT_BACKUPDEF=$(basename "$file")
            CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
            if [[ -e "$MOUNT_POINT/$CATALOG" ]]; then
                log_warn "\"$MOUNT_POINT/$CATALOG\" already exists, go to next"
            else
                log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG\""
                dar_manager --create "$MOUNT_POINT"/"$CATALOG"
                if [[ $? != "0" ]]; then
                    log_error "something went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG\", continuing..."
                fi
            fi
        done <  <(find "${SCRIPTDIRPATH}"/../backups.d -type f -print)
    else
        CATALOG=${BACKUP_DEF}${CATALOG_SUFFIX}
        if [[ -e "$MOUNT_POINT/$CATALOG" ]]; then
            log_warn "\"$MOUNT_POINT/$CATALOG\" already exists, exiting"
            exit 0
        else
            log "INFO create catalog DB: \"$MOUNT_POINT/$CATALOG\""
            dar_manager --create "$MOUNT_POINT"/"$CATALOG"
            if [[ $? != "0" ]]; then
                log_error "something went wrong creating the catalog: \"$MOUNT_POINT/$CATALOG\""
                exit $?
            fi
        fi
    fi
    exit
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
                dar_manager --base "$MOUNT_POINT/$CATALOG" -Q --add "$_REALPATH"
                RESULT=$?
                case $RESULT in
                0)
                    ;;
                5)
                    log_warn "Some error(s) were found while adding \"${ARCHIVE}\" to it's catalog"
                    ;;
                *)
                    log_error "something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
                    exit $RESULT
                    ;;
                esac
            done <  <(find "${MOUNT_POINT}" -type f -name "$SEARCHCRIT" -print|grep -E "${CURRENT_BACKUP_DEF}_FULL_.*|${CURRENT_BACKUP_DEF}_DIFF_.*|${CURRENT_BACKUP_DEF}_INC_.*"| grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o| sort -u| sort -t "_" -k 3,3)
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
            dar_manager --base "$MOUNT_POINT/$CATALOG" -Q --add "$_REALPATH"
            RESULT=$?
            case $RESULT in
            0)
                ;;
            5)
                log_warn "Some error(s) were found while adding \"${ARCHIVE}\" to it's catalog"
                ;;
            *)
                log_error "something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
                exit $RESULT
                ;;
            esac
        done <  <(find "${MOUNT_POINT}" -type f -name "$SEARCHCRIT" -print|grep -E "${BACKUP_DEF}_FULL_.*|${BACKUP_DEF}_DIFF_.*|${BACKUP_DEF}_INC_.*"| grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o| sort -u| sort -t "_" -k 3,3)
    fi
fi

# add a specific archive to it's catalog (catalog deduced from archive name)
if [[ $ADD_SPECIFIC_ARCHIVE != "" ]]; then
    _DEF_=$(echo "$ADD_SPECIFIC_ARCHIVE" |grep -E "^.*?_" | cut -d _ -f 1)
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$_DEF_"  ]]; then
        log_error "backup definition \"$_DEF_\" not found (--add-specific-archive option probably not correct), exiting"
        exit 1
    fi
    CATALOG="${_DEF_}""${CATALOG_SUFFIX}"
    _REALPATH="$(realpath "$MOUNT_POINT"/"$ADD_SPECIFIC_ARCHIVE")"
    log "INFO add \"$MOUNT_POINT/$ADD_SPECIFIC_ARCHIVE\" to catalog \"$CATALOG\""
    dar_manager --base "$MOUNT_POINT"/"$CATALOG"  --add "$_REALPATH"
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        log_error "something went wrong populating \"$MOUNT_POINT/$CATALOG\", dar_manager error: \"$RESULT\""
        exit $RESULT
    fi
fi



# remove a specific archive from it's catalog (catalog deduced from archive name)
# Observe it only removes one entry - so if the database has multiple entries, only 1 is removed
if [[ $REMOVE_SPECIFIC_ARCHIVE != "" ]]; then
    _DEF_=$(echo "$REMOVE_SPECIFIC_ARCHIVE" |grep -E "^.*?_" | cut -d _ -f 1)
    if [[ ! -e "${SCRIPTDIRPATH}"/../backups.d/"$_DEF_"  ]]; then
        log_error "backup definition \"$_DEF_\" not found (--remove-specific-archive option probably not correct), exiting"
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
