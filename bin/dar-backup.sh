#! /bin/bash
#
#    Copyright (C) 2024  Per Jensen
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Run script as a non-root user if sshfs mounts are used
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"


# which mode: FULL, DIFF or INC
SCRIPTNAME=$(basename "$0")

VERSION=@@DEV-VERSION@@


MODE=""
BACKUPDEF=""
FSA_SCOPE_NONE="" 
CURRENT_BACKUPDEF=""
DAR_ARCHIVE=""
ARCHIVEPATH=""
LOCAL_BACKUP_DIR=""
export EVERYTHING_OK=0 # report this at the end, will be set to 1 if something goes wrong
export BACKUP_OK=0
export CATALOG_OK=0
export CMD_DEBUG="n"
export CMD_USE_CATALOGS="n"
export VERBOSE="n"
RUN_RESTORE_TEST="n"

export NO_SAVED_FILES="unknown"
export NO_REMOVED_FILES="unknown"


# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --backupdef|-d)
          shift
          BACKUPDEF="$1"
          ;;
      --local-backup-dir)
          echo "$MOUNT_POINT" used as local backup directory....
          LOCAL_BACKUP_DIR=1
          ;;
      --fsa-scope-none)
          FSA_SCOPE_NONE="y"
          ;;
      --debug)
          CMD_DEBUG=y
          ;;
      --run-restore-test)
          RUN_RESTORE_TEST="y"
          shift
          DAR_ARCHIVE="$1"
          ;;
      --use-catalogs)
          CMD_USE_CATALOGS="y"
          ;;
      --help|-h)
          echo "$SCRIPTNAME [--backupdef|-d <backup definition>] [--local-backup-dir] [--fsa-scope-none] [--run-restore-test  <dar archive>] [--version|-v] [--verbose] [--debug] [--help|-h]"
          echo "   --backupdef <backup definition>, run a single definition (a filename in backups.d/)"
          echo "   --local-backup-dir, don't sshfs-mount a remote directory on MOUNT_POINT"
          echo "   --fsa-scope-none, useful when restoring to different file system type, do not fail on unsupported file attributes"
          echo "   --verbose, more log messages included being sent to Discord"
          echo "   --run-restore-test <dar archive> (archive name without <slice#>.dar)"
          echo "   --debug, give bash the '-x' option to log all activity to configured file"
          echo "   --use-catalogs, override default config file setting to use dar catalogs"
          echo "   --version, show version number and license"
          echo "   --help, this terse usage info"
          exit
          ;;
      --verbose)
          CMD_VERBOSE="y"
          ;;
      --version|-v)
          echo "$SCRIPTNAME $VERSION"
          echo "Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file \"LICENSE\" for details."
          echo "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE." 
          echo "See section 15 and section 16 in the supplied \"LICENSE\" file."
          exit
          ;;
      *)
          echo option \"$1\" not recognized, exiting
          exit
          ;;
  esac
  shift
done

export DATE=""
DATE=$(date -I)

export SCRIPTPATH=""
SCRIPTPATH=$(realpath "$0")

export SCRIPTDIRPATH=""
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
if [[ $CMD_VERBOSE == "y" ]]; then
    VERBOSE="y"
fi


if [[ $DEBUG == "y" || $CMD_DEBUG == "y" ]]; then
  set -x
  exec > >(tee -a "${DEBUG_LOCATION}")  2>&1
fi

source "${SCRIPTDIRPATH}/dar-util.sh"

if [[ -f "${LOG_LOCATION}/dar-backup.log" &&  -w "${LOG_LOCATION}/dar-backup.log" || -w "${LOG_LOCATION}" ]]; then
  echo "Log location \"$LOG_LOCATION\" is writable, good."
else
  echo -e "\e[1m\e[31mERROR\e[0m log file \"$LOG_LOCATION\" is NOT writable, continuing"
fi



STARTTIME="$(date -Iseconds)"
log =======================================================
log "  $SCRIPTNAME started: $STARTTIME"
log =======================================================
log_verbose "BACKUPDEF=${BACKUPDEF}"
log_verbose "LOCAL_BACKUP_DIR=${LOCAL_BACKUP_DIR}"
log_verbose "FSA_SCOPE_NONE=${FSA_SCOPE_NONE}"
log_verbose "RUN_RESTORE_TEST=${RUN_RESTORE_TEST}"
log_verbose "CMD_DEBUG=${CMD_DEBUG}"
log_verbose "CMD_USE_CATALOGS=${CMD_USE_CATALOGS}"
log_verbose "VERBOSE=${VERBOSE}"



if [[ $SCRIPTNAME == "dar-backup.sh"  ]]; then
  MODE=FULL
fi
if [[ $SCRIPTNAME == "dar-diff-backup.sh"  ]]; then
  MODE=DIFF
fi
if [[ $SCRIPTNAME == "dar-inc-backup.sh"  ]]; then
  MODE=INC
fi

if [[ $MODE == "" ]]; then
    log "ERROR script called with wrong name: $0, exiting"
    exit 1
fi


# make sure mounts are in order
mountPrereqs

# check if catalogs have been initialized, if configured to be used
if  [[ "$USE_CATALOGS" == "y" || "$CMD_USE_CATALOGS" == "y" ]]; then
  while IFS= read -r -d "" file
  do
      _CURRENT_BACKUPDEF=$(basename "$file")
      CATALOG=${_CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
      log_verbose "check if CATALOG: \"$MOUNT_POINT/$CATALOG\" exists"
      if [[ ! -e  "$MOUNT_POINT/$CATALOG" ]]; then
        log_error "Catalog \"$CATALOG\" for backup definition \"$_CURRENT_BACKUPDEF\" is missing, continuing"
        CATALOG_OK=1
      else 
        log_verbose "CATALOG: \"$CATALOG\" does exist"
      fi
  done <  <(find "${SCRIPTDIRPATH}"/../backups.d -type f -print0)
fi

# copy dar_static to server
copyDarStatic

# check if a restore test is chosen
if [[ "$RUN_RESTORE_TEST" == "y"  ]]; then
  # set up variables the restore function expects
  setArchivePath
  darRestoreTest
else
  # check if a single backup definition is to be run
  if [[ "$BACKUPDEF" == "" ]]; then
    # loop over backup definition in backups.d/
    for _BACKUPDEF in "${SCRIPTDIRPATH}"/../backups.d/*; do
      CURRENT_BACKUPDEF=$(basename "$_BACKUPDEF")
      if is_definition_name_ok "$CURRENT_BACKUPDEF"; then
        log "==> start processing backup definition: ${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}"
        runBackupDef
      else
        log_error "Backup definition: \"$CURRENT_BACKUPDEF\" contains an \"_\" => backup discarded"
      fi
    done
  else
    if [[ -f "${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"  ]]; then
        CURRENT_BACKUPDEF="$BACKUPDEF"
        if is_definition_name_ok "$CURRENT_BACKUPDEF"; then
          log "==> start processing a single backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"
          runBackupDef
        else
          log_error "Backup definition: \"CURRENT_BACKUPDEF\" contains an \"_\" => backup discarded"
        fi
    else 
      log_error "backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF} does not exist"
    fi
  fi
fi

if [[ "$BACKUP_OK" -eq "0" ]]; then
  log_success "Backup ended ok"
else
  log_error "Errors found during backup, test or restore-test"
fi 

if [[ "$CATALOG_OK" -eq "0" ]]; then
  log_success "Catalog operations ended ok"
else
  log_error "Catalog operations had errors"
fi 


if [[ "$BACKUP_OK" -eq "0"  &&  "$CATALOG_OK" -eq "0" ]]; then
  sendDiscordMsg "$SCRIPTNAME ended without errors"
  exit 0
else
  sendDiscordMsg "ERROR: $SCRIPTNAME ended with errors"
  exit 1
fi 
